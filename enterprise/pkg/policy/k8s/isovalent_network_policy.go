// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This file originates from Ciliums's codebase and is governed by an
// Apache 2.0 license (see original header below):
//
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/enterprise/pkg/k8s/types"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func (p *policyWatcher) onUpsert(
	inp *types.SlimINP,
	key resource.Key,
	apiGroup string,
	resourceID ipcacheTypes.ResourceID,
	dc chan uint64,
) error {
	initialRecvTime := time.Now()

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	oldINP, ok := p.inpCache[key]
	if ok {
		// no generation change; this was a status update.
		if oldINP.Generation == inp.Generation {
			return nil
		}
		if oldINP.DeepEqual(inp) {
			return nil
		}

		p.log.Debug(
			"Modified IsovalentNetworkPolicy",
			logfields.K8sAPIVersion, inp.TypeMeta.APIVersion,
			logfields.IsovalentNetworkPolicyName, inp.ObjectMeta.Name,
			logfields.K8sNamespace, inp.ObjectMeta.Namespace,
			logfields.Annotations, inp.ObjectMeta.Annotations,
		)
	}

	// check if this cnp was referencing or is now referencing at least one ToServices rule
	if hasToServices(inp) {
		p.toServicesPolicies[key] = struct{}{}
	} else {
		if _, hadToServices := p.toServicesPolicies[key]; hadToServices {
			// transitioning from with toServices to without toServices
			delete(p.toServicesPolicies, key)
			// Clear ToServices index
			for svcID := range p.inpByServiceID {
				p.clearINPForService(key, svcID)
			}
		}
	}

	return p.resolveIsovalentNetworkPolicyRefs(inp, key, initialRecvTime, resourceID, dc)
}

func (p *policyWatcher) onDelete(
	inp *types.SlimINP,
	key resource.Key,
	apiGroup string,
	resourceID ipcacheTypes.ResourceID,
	dc chan uint64,
) {
	p.deleteIsovalentNetworkPolicy(inp, resourceID, dc)

	delete(p.inpCache, key)

	// Clear ToServices index
	for svcID := range p.inpByServiceID {
		p.clearINPForService(key, svcID)
	}
	delete(p.toServicesPolicies, key)

	p.k8sResourceSynced.SetEventTimestamp(apiGroup)
}

// resolveIsovalentNetworkPolicyRefs resolves all the references to external resources
// (e.g. CiliumCIDRGroups) in a INP/ICNP, inlines them into a "translated" INP,
// and then adds the translated INP to the policy repository.
// If the INP was successfully imported, the raw (i.e. untranslated) INP/ICNP
// is also added to p.inpCache.
func (p *policyWatcher) resolveIsovalentNetworkPolicyRefs(
	inp *types.SlimINP,
	key resource.Key,
	initialRecvTime time.Time,
	resourceID ipcacheTypes.ResourceID,
	dc chan uint64,
) error {
	// We need to deepcopy this structure because we are writing
	// fields in cnp.Parse() in upsertCiliumNetworkPolicyV2.
	// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
	translatedINP := inp.DeepCopy()

	// Resolve ToService references
	if _, exists := p.toServicesPolicies[key]; exists {
		p.resolveToServices(key, translatedINP)
	}

	err := p.upsertIsovalentNetworkPolicy(translatedINP, initialRecvTime, resourceID, dc)
	if err == nil {
		p.inpCache[key] = inp
	}

	return err
}

func (p *policyWatcher) upsertIsovalentNetworkPolicy(inp *types.SlimINP, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID, dc chan uint64) error {
	scopedLog := p.log.With(
		logfields.IsovalentNetworkPolicyName, inp.ObjectMeta.Name,
		logfields.K8sAPIVersion, inp.TypeMeta.APIVersion,
		logfields.K8sNamespace, inp.ObjectMeta.Namespace,
	)

	scopedLog.Debug(
		"Adding IsovalentNetworkPolicy",
	)

	rules, err := inp.Parse(scopedLog, p.clusterName)
	if err != nil {
		scopedLog.Warn(
			"Unable to add IsovalentNetworkPolicy",
			logfields.Error, err,
		)
		return fmt.Errorf("failed to parse IsovalentNetworkPolicy %s/%s: %w", inp.ObjectMeta.Namespace, inp.ObjectMeta.Name, err)
	}
	if dc != nil {
		if inp.ObjectMeta.Namespace == "" {
			p.icnpSyncPending.Add(1)
		} else {
			p.inpSyncPending.Add(1)
		}
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:               rules,
		Source:              source.CustomResource,
		ProcessingStartTime: initialRecvTime,
		Resource:            resourceID,
		DoneChan:            dc,
	})
	scopedLog.Info(
		"Imported IsovalentNetworkPolicy",
	)
	return nil
}

func (p *policyWatcher) deleteIsovalentNetworkPolicy(inp *types.SlimINP, resourceID ipcacheTypes.ResourceID, dc chan uint64) {
	p.log.Debug("Deleting IsovalentNetworkPolicy",
		logfields.IsovalentNetworkPolicyName, inp.ObjectMeta.Name,
		logfields.K8sAPIVersion, inp.TypeMeta.APIVersion,
		logfields.K8sNamespace, inp.ObjectMeta.Namespace,
	)

	if dc != nil {
		if inp.ObjectMeta.Namespace == "" {
			p.icnpSyncPending.Add(1)
		} else {
			p.inpSyncPending.Add(1)
		}
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Source:   source.CustomResource,
		Resource: resourceID,
		DoneChan: dc,
	})
	p.log.Info("Deleted IsovalentNetworkPolicy",
		logfields.IsovalentNetworkPolicyName, inp.ObjectMeta.Name,
		logfields.K8sAPIVersion, inp.TypeMeta.APIVersion,
		logfields.K8sNamespace, inp.ObjectMeta.Namespace,
	)
}

func (p *policyWatcher) registerResourceWithSyncFn(ctx context.Context, resource string, syncFn func() bool) {
	p.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, syncFn, resource)
	p.k8sAPIGroups.AddAPI(resource)
}

// reportCNPChangeMetrics generates metrics for changes(Update, Delete) to
// Cilium Network Policies depending on the operation's success.
func reportINPChangeMetrics(op string, err error) {
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(string(source.CustomResource), op, metrics.LabelValueOutcomeFail).Inc()
	} else {
		metrics.PolicyChangeTotal.WithLabelValues(string(source.CustomResource), op, metrics.LabelValueOutcomeSuccess).Inc()
	}
}

func resourceIDForIsovalentNetworkPolicy(key resource.Key, cnp *types.SlimINP) ipcacheTypes.ResourceID {
	resourceKind := ipcacheTypes.ResourceKindCNP
	if len(key.Namespace) == 0 {
		resourceKind = ipcacheTypes.ResourceKindCCNP
	}
	return ipcacheTypes.NewResourceID(
		resourceKind,
		cnp.ObjectMeta.Namespace,
		cnp.ObjectMeta.Name,
	)
}

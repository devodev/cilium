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

package networkpolicy

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/runtime/schema"

	extgrps "github.com/cilium/cilium/operator/pkg/networkpolicy/external-groups"
	"github.com/cilium/cilium/operator/pkg/networkpolicy/external-groups/provider"
	isovalent_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

type ToGroupCtlParams struct {
	cell.In

	Logger *slog.Logger
	JG     job.Group
	GM     extgrps.ExternalGroupManager

	INPResource  resource.Resource[*isovalent_v1.IsovalentNetworkPolicy]
	ICNPResource resource.Resource[*isovalent_v1.IsovalentClusterwideNetworkPolicy]
}

// policyExternalGroupController watches CNPs and CCNPs for changes,
// extracts the set of referenced external groups, and updates their
// entries in the external-group-controller.
type policyExternalGroupController struct {
	params ToGroupCtlParams
}

var gkINP = schema.GroupKind{Group: isovalent_v1.CustomResourceDefinitionGroup, Kind: isovalent_v1.IsovalentNetworkPolicyKindDefinition}
var gkICNP = schema.GroupKind{Group: isovalent_v1.CustomResourceDefinitionGroup, Kind: isovalent_v1.IsovalentClusterwideNetworkPolicyKindDefinition}

func registerPolicyToGroupController(params ToGroupCtlParams) *policyExternalGroupController {
	if !provider.Enabled() {
		return nil
	}

	pc := &policyExternalGroupController{
		params: params,
	}

	params.GM.RegisterResourceKind(gkINP)
	params.GM.RegisterResourceKind(gkICNP)

	params.JG.Add(job.Observer(
		"policy-inp-external-group-watcher",
		pc.handleINPEvent,
		params.INPResource,
	))

	params.JG.Add(job.Observer(
		"policy-ccnp-external-group-watcher",
		pc.handleICNPEvent,
		params.ICNPResource,
	))

	return pc
}

func (pc *policyExternalGroupController) handleINPEvent(ctx context.Context, event resource.Event[*isovalent_v1.IsovalentNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()

	switch event.Kind {
	case resource.Sync:
		pc.params.GM.ResourceKindSynced(gkINP)
	case resource.Delete:
		pc.params.GM.SetResourceGroups(gkINP, event.Key.Namespace, event.Key.Name, nil)
	case resource.Upsert:
		pol := event.Object
		pc.setRules(gkINP, pol.Namespace, pol.Name, pol.Spec, pol.Specs)
	}
	return nil
}

func (pc *policyExternalGroupController) handleICNPEvent(ctx context.Context, event resource.Event[*isovalent_v1.IsovalentClusterwideNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()

	switch event.Kind {
	case resource.Sync:
		pc.params.GM.ResourceKindSynced(gkICNP)
	case resource.Delete:
		pc.params.GM.SetResourceGroups(gkICNP, event.Key.Namespace, event.Key.Name, nil)
	case resource.Upsert:
		pol := event.Object
		pc.setRules(gkICNP, pol.Namespace, pol.Name, pol.Spec, pol.Specs)
	}
	return nil
}

func (pc *policyExternalGroupController) setRules(gk schema.GroupKind, namespace, name string, rule *isovalent_v1.IsovalentNetworkPolicyRule, rules []*isovalent_v1.IsovalentNetworkPolicyRule) {
	groups := extractGroups(rule)
	for _, r := range rules {
		groups = append(groups, extractGroups(r)...)
	}

	if len(groups) > 0 {
		pc.params.Logger.Info("Found ToGroups / FromGroups rules in policy",
			logfields.K8sAPIVersion, gk.Group,
			logfields.Kind, gk.Kind,
			logfields.K8sNamespace, namespace,
			logfields.Name, name,
			logfields.Count, len(groups))
	}

	pc.params.GM.SetResourceGroups(gk, namespace, name, groups)
}

func extractGroups(rule *isovalent_v1.IsovalentNetworkPolicyRule) []*api.Groups {
	if rule == nil {
		return nil
	}

	out := []*api.Groups{}
	for _, stanza := range rule.Egress {
		for i := range stanza.ToGroups {
			out = append(out, &stanza.ToGroups[i])
		}
	}
	for _, stanza := range rule.EgressDeny {
		for i := range stanza.ToGroups {
			out = append(out, &stanza.ToGroups[i])
		}
	}
	for _, stanza := range rule.EgressPass {
		for i := range stanza.ToGroups {
			out = append(out, &stanza.ToGroups[i])
		}
	}
	for _, stanza := range rule.Ingress {
		for i := range stanza.FromGroups {
			out = append(out, &stanza.FromGroups[i])
		}
	}
	for _, stanza := range rule.IngressDeny {
		for i := range stanza.FromGroups {
			out = append(out, &stanza.FromGroups[i])
		}
	}
	for _, stanza := range rule.IngressPass {
		for i := range stanza.FromGroups {
			out = append(out, &stanza.FromGroups[i])
		}
	}
	return out
}

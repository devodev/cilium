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
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/operator/pkg/networkpolicy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	isovalent_api_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type PolicyValidatorParams struct {
	cell.In

	Logger       *slog.Logger
	JobGroup     job.Group
	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig

	Cfg networkpolicy.Config

	Scheme *runtime.Scheme

	INPResource  resource.Resource[*isovalent_api_v1.IsovalentNetworkPolicy]
	ICNPResource resource.Resource[*isovalent_api_v1.IsovalentClusterwideNetworkPolicy]
}

// The policyValidator validates network policy and reports the results in to the
// policy's Status field. It validates both IsovalentNetworkPolicy and
// IsovalentClusterwideNetworkPolicy.
type policyValidator struct {
	params *PolicyValidatorParams
}

func registerPolicyValidator(params PolicyValidatorParams) {
	if !params.Cfg.ValidateNetworkPolicy {
		params.Logger.Debug("INP / ICNP validator disabled")
		return
	}

	if err := isovalent_api_v1.AddToScheme(params.Scheme); err != nil {
		params.Logger.Error("INP / ICNP validator can't run due to failure to add scheme.", logfields.Error, err)
		return
	}

	// LRU size of 1 since we are only doing one-off validation of policies and
	// the FQDN regexes are not referenced again.
	re.Resize(params.Logger, 1)

	pv := &policyValidator{
		params: &params,
	}

	params.Logger.Info("Registering INP / ICNP validator")
	params.JobGroup.Add(job.Observer(
		"inp-validation",
		pv.handleINPEvent,
		params.INPResource,
	))
	params.JobGroup.Add(job.Observer(
		"icnp-validation",
		pv.handleICNPEvent,
		params.ICNPResource,
	))
}

func (pv *policyValidator) handleINPEvent(ctx context.Context, event resource.Event[*isovalent_api_v1.IsovalentNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()
	if event.Kind != resource.Upsert {
		return nil
	}

	pol := event.Object
	log := pv.params.Logger.With(
		logfields.K8sNamespace, pol.Namespace,
		logfields.IsovalentNetworkPolicyName, pol.Name,
	)

	polErrs := pol.Sanitize()

	newPol := pol.DeepCopy()
	newPol.Status.Conditions = updateCondition(event.Object.Status.Conditions, polErrs)
	if newPol.Status.DeepEqual(&pol.Status) {
		return nil
	}

	if polErrs != nil {
		log.Debug("Detected invalid INP, setting condition", logfields.Error, polErrs)
	} else {
		log.Debug("INP now valid, setting condition")
	}
	// Using the UpdateStatus subresource will prevent the generation from being bumped.
	_, err = pv.params.Clientset.IsovalentV1().IsovalentNetworkPolicies(pol.Namespace).UpdateStatus(
		ctx,
		newPol,
		metav1.UpdateOptions{},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		log.Error("failed to update INP status", logfields.Error, err)
	}

	return err
}

func (pv *policyValidator) handleICNPEvent(ctx context.Context, event resource.Event[*isovalent_api_v1.IsovalentClusterwideNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()
	if event.Kind != resource.Upsert {
		return nil
	}

	pol := event.Object
	log := pv.params.Logger.With(
		logfields.K8sNamespace, pol.Namespace,
		logfields.IsovalentClusterwideNetworkPolicyName, pol.Name,
	)

	polErrs := pol.Sanitize()

	newPol := pol.DeepCopy()
	newPol.Status.Conditions = updateCondition(event.Object.Status.Conditions, polErrs)
	if newPol.Status.DeepEqual(&pol.Status) {
		return nil
	}

	if polErrs != nil {
		log.Debug("Detected invalid ICNP, setting condition", logfields.Error, polErrs)
	} else {
		log.Debug("ICNP now valid, setting condition")
	}
	// Using the UpdateStatus subresource will prevent the generation from being bumped.
	_, err = pv.params.Clientset.IsovalentV1().IsovalentClusterwideNetworkPolicies().UpdateStatus(
		ctx,
		newPol,
		metav1.UpdateOptions{},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		log.Error("failed to update ICNP status", logfields.Error, err)
	}

	return err
}

// updateCondition creates or updates the policy validation condition in Conditions, setting
// the transition time as necessary.
func updateCondition(conditions []isovalent_api_v1.NetworkPolicyCondition, errs error) []isovalent_api_v1.NetworkPolicyCondition {
	wantCondition := corev1.ConditionTrue
	message := "Policy validation succeeded"
	if errs != nil {
		wantCondition = corev1.ConditionFalse
		message = errs.Error()
	}

	// look for the condition type already existing.
	foundIdx := -1
	for i, cond := range conditions {
		if cond.Type == isovalent_api_v1.PolicyConditionValid {
			foundIdx = i
			// If nothing important changed, short-circuit
			if cond.Status == wantCondition && cond.Message == message {
				return conditions
			}
			break
		}
	}

	// Otherwise, set / update the condition
	newCond := isovalent_api_v1.NetworkPolicyCondition{
		Type:               isovalent_api_v1.PolicyConditionValid,
		Status:             wantCondition,
		LastTransitionTime: slimv1.Now(),
		Message:            message,
	}

	out := slices.Clone(conditions)

	if foundIdx >= 0 {
		// If the status did not change (just the message), don't bump the
		// LastTransitionTime.
		if out[foundIdx].Status == newCond.Status {
			newCond.LastTransitionTime = out[foundIdx].LastTransitionTime
		}
		out[foundIdx] = newCond
	} else {
		out = append(out, newCond)
	}
	return out
}

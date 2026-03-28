//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package wafpolicy

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type ResolutionState string

const (
	ResolutionStateResolved ResolutionState = "Resolved"
	ResolutionStatePending  ResolutionState = "Pending"
	ResolutionStateConflict ResolutionState = "Conflict"
)

type EffectiveRuleSource string

const (
	EffectiveRuleSourceDefault EffectiveRuleSource = "Default"
	EffectiveRuleSourceManaged EffectiveRuleSource = "Managed"
	EffectiveRuleSourceInline  EffectiveRuleSource = "Inline"
)

// EffectiveRules is the resolved rules union for an LBService. It mirrors the
// policy API shape: exactly one rules source is active after resolution.
type EffectiveRules struct {
	Source        EffectiveRuleSource
	PolicyProfile isovalentv1alpha1.IsovalentWAFPolicyProfileType
	Inline        InlineRules
}

type EffectiveConfig struct {
	Enabled     bool
	Mode        isovalentv1alpha1.IsovalentWAFPolicyModeType
	FailureMode isovalentv1alpha1.WAFFailureModeType
	Rules       EffectiveRules
}

type Resolution struct {
	State      ResolutionState
	Config     EffectiveConfig
	PolicyRefs []types.NamespacedName
}

type policyState string

const (
	policyStatePending  policyState = "Pending"
	policyStateAccepted policyState = "Accepted"
	policyStateRejected policyState = "Rejected"
)

func Validate(policy *isovalentv1alpha1.IsovalentWAFPolicy) error {
	if policy.Spec.Targets.LBServices == nil {
		return fmt.Errorf("spec.targets.lbServices must be specified")
	}

	_, err := slim_metav1.LabelSelectorAsSelector(policy.Spec.Targets.LBServices.LabelSelector)
	if err != nil {
		return fmt.Errorf("invalid spec.targets.lbServices.labelSelector: %w", err)
	}

	if policy.Spec.Rules == nil {
		return nil
	}

	hasManaged := policy.Spec.Rules.Managed != nil
	hasCustom := policy.Spec.Rules.Custom != nil
	if hasManaged == hasCustom {
		return fmt.Errorf("exactly one of spec.rules.managed or spec.rules.custom must be specified")
	}

	if hasCustom {
		return ValidateInlineRules(policy.Spec.Rules.Custom.Inline)
	}

	return nil
}

func Condition(policy *isovalentv1alpha1.IsovalentWAFPolicy, err error) metav1.Condition {
	condition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeIsovalentWAFPolicyAccepted,
		ObservedGeneration: policy.Generation,
		LastTransitionTime: metav1.Now(),
	}

	if err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.IsovalentWAFPolicyAcceptedConditionReasonInvalid
		condition.Message = err.Error()
		return condition
	}

	condition.Status = metav1.ConditionTrue
	condition.Reason = isovalentv1alpha1.IsovalentWAFPolicyAcceptedConditionReasonValid
	condition.Message = "policy selector and rules are valid"
	return condition
}

func SetCondition(policy *isovalentv1alpha1.IsovalentWAFPolicy, condition metav1.Condition) bool {
	existing := policy.GetStatusCondition(condition.Type)
	if existing != nil &&
		existing.Status == condition.Status &&
		existing.Reason == condition.Reason &&
		existing.Message == condition.Message &&
		existing.ObservedGeneration == condition.ObservedGeneration {
		return false
	}

	policy.UpsertStatusCondition(condition.Type, condition)
	policy.UpdateResourceStatus()
	return true
}

func ResolveForLBService(
	service *isovalentv1alpha1.LBService,
	policies []isovalentv1alpha1.IsovalentWAFPolicy,
	defaults GlobalDefaults,
) (Resolution, error) {
	resolved := EffectiveConfig{
		Enabled:     defaults.Enabled,
		Mode:        defaults.Mode,
		FailureMode: defaults.FailureMode,
		Rules: EffectiveRules{
			Source:        EffectiveRuleSourceDefault,
			PolicyProfile: defaults.PolicyProfile,
		},
	}

	matches, pending, err := matchLBServicePolicies(service, policies)
	if err != nil {
		return Resolution{}, err
	}
	if len(pending) > 0 {
		return Resolution{
			State:      ResolutionStatePending,
			Config:     resolved,
			PolicyRefs: pending,
		}, nil
	}
	if len(matches) == 0 {
		return Resolution{
			State:  ResolutionStateResolved,
			Config: resolved,
		}, nil
	}
	if len(matches) > 1 {
		conflicts := make([]types.NamespacedName, 0, len(matches))
		for _, policy := range matches {
			conflicts = append(conflicts, types.NamespacedName{
				Namespace: policy.Namespace,
				Name:      policy.Name,
			})
		}
		return Resolution{
			State:      ResolutionStateConflict,
			Config:     resolved,
			PolicyRefs: conflicts,
		}, nil
	}

	policy := matches[0]
	resolved.Enabled = policy.Spec.Enabled

	if policy.Spec.Mode != nil {
		resolved.Mode = *policy.Spec.Mode
	}
	if policy.Spec.Rules != nil && policy.Spec.Rules.Managed != nil {
		resolved.Rules.Source = EffectiveRuleSourceManaged
		resolved.Rules.PolicyProfile = policy.Spec.Rules.Managed.Profile
	}
	if policy.Spec.FailureMode != nil {
		resolved.FailureMode = *policy.Spec.FailureMode
	}
	if policy.Spec.Rules != nil && policy.Spec.Rules.Custom != nil {
		inlineRules, err := BuildInlineRules(policy.Spec.Rules.Custom.Inline)
		if err != nil {
			return Resolution{}, err
		}
		resolved.Rules = EffectiveRules{
			Source: EffectiveRuleSourceInline,
			Inline: inlineRules,
		}
	}

	return Resolution{
		State:  ResolutionStateResolved,
		Config: resolved,
		PolicyRefs: []types.NamespacedName{{
			Namespace: policy.Namespace,
			Name:      policy.Name,
		}},
	}, nil
}

func matchLBServicePolicies(
	service *isovalentv1alpha1.LBService,
	policies []isovalentv1alpha1.IsovalentWAFPolicy,
) ([]*isovalentv1alpha1.IsovalentWAFPolicy, []types.NamespacedName, error) {
	serviceLabels := labels.Set(service.Labels)

	matches := make([]*isovalentv1alpha1.IsovalentWAFPolicy, 0)
	pending := make([]types.NamespacedName, 0)

	for i := range policies {
		policy := &policies[i]
		if policy.Namespace != service.Namespace {
			continue
		}
		if policy.Spec.Targets.LBServices == nil {
			continue
		}

		selector, err := slim_metav1.LabelSelectorAsSelector(policy.Spec.Targets.LBServices.LabelSelector)
		if err != nil {
			return nil, nil, fmt.Errorf("policy %s/%s has invalid label selector: %w", policy.Namespace, policy.Name, err)
		}
		if !selector.Matches(serviceLabels) {
			continue
		}

		switch stateFor(policy) {
		case policyStatePending:
			pending = append(pending, types.NamespacedName{
				Namespace: policy.Namespace,
				Name:      policy.Name,
			})
		case policyStateAccepted:
			matches = append(matches, policy)
		}
	}

	return matches, pending, nil
}

func stateFor(policy *isovalentv1alpha1.IsovalentWAFPolicy) policyState {
	condition := policy.GetStatusCondition(isovalentv1alpha1.ConditionTypeIsovalentWAFPolicyAccepted)
	if condition == nil || condition.ObservedGeneration != policy.Generation {
		return policyStatePending
	}
	if condition.Status == metav1.ConditionTrue {
		return policyStateAccepted
	}
	return policyStateRejected
}

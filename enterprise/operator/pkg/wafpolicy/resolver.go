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
	"context"
	"fmt"
	"log/slog"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
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

type EffectiveHandlingOverrides struct {
	BodyLimitBytes          *int64
	BlockResponseStatusCode *int32
	BlockResponseBody       *string
}

type EffectiveConfig struct {
	Enabled           bool
	Mode              isovalentv1alpha1.IsovalentWAFPolicyModeType
	FailureMode       isovalentv1alpha1.WAFFailureModeType
	Rules             EffectiveRules
	HandlingOverrides EffectiveHandlingOverrides
}

type PolicyTarget struct {
	Name      string
	Namespace string
	Labels    map[string]string
}

type Resolver struct {
	client   client.Client
	logger   *slog.Logger
	defaults GlobalDefaults
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

func NewResolver(client client.Client, logger *slog.Logger, defaults GlobalDefaults) *Resolver {
	return &Resolver{
		client:   client,
		logger:   logger,
		defaults: defaults,
	}
}

func (r *Resolver) Enabled() bool {
	return r.defaults.Enabled
}

func (r *Resolver) ResolveConfig(ctx context.Context, target PolicyTarget) (*EffectiveConfig, error) {
	if !r.Enabled() {
		return nil, nil
	}

	policies, err := r.loadPolicies(ctx, target.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to load IsovalentWAFPolicies: %w", err)
	}

	if len(policies) == 0 {
		return nil, nil
	}

	matches, pending, err := matchPolicies(target, policies)
	if err != nil {
		return nil, err
	}

	if len(pending) > 0 {
		r.logger.Debug(
			"matching WAF policies are still pending validation, deferring WAF config resolution",
			logfields.K8sNamespace, target.Namespace,
			logfields.Service, target.Name,
			logfields.PolicyLogString, policiesToString(pending),
		)
		return nil, nil
	}

	if len(matches) == 0 {
		r.logger.Debug(
			"no accepted WAF policy matches LBService, skipping WAF config resolution for this reconcile",
			logfields.K8sNamespace, target.Namespace,
			logfields.Service, target.Name,
		)
		return nil, nil
	}

	if len(matches) > 1 {
		r.logger.Warn(
			"multiple accepted WAF policies match LBService, skipping WAF config resolution for this reconcile",
			logfields.K8sNamespace, target.Namespace,
			logfields.Service, target.Name,
			logfields.PolicyLogString, policiesToString(matches),
		)
		return nil, nil
	}

	config, err := r.policyToConfig(matches[0])
	if err != nil {
		return nil, fmt.Errorf("failed to resolve effective WAF config: %w", err)
	}

	r.logger.Debug(
		"resolved effective WAF config for LBService",
		logfields.K8sNamespace, target.Namespace,
		logfields.Service, target.Name,
		logfields.PolicyLogString, policiesToString(matches),
	)
	return &config, nil
}

func (r *Resolver) loadPolicies(ctx context.Context, namespace string) ([]isovalentv1alpha1.IsovalentWAFPolicy, error) {
	policyList := &isovalentv1alpha1.IsovalentWAFPolicyList{}
	if err := r.client.List(ctx, policyList, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	return policyList.Items, nil
}

func matchPolicies(
	target PolicyTarget,
	policies []isovalentv1alpha1.IsovalentWAFPolicy,
) ([]*isovalentv1alpha1.IsovalentWAFPolicy, []*isovalentv1alpha1.IsovalentWAFPolicy, error) {
	serviceLabels := labels.Set(target.Labels)

	matches := make([]*isovalentv1alpha1.IsovalentWAFPolicy, 0)
	pending := make([]*isovalentv1alpha1.IsovalentWAFPolicy, 0)

	for i := range policies {
		policy := &policies[i]
		if policy.Namespace != target.Namespace {
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
			pending = append(pending, policy)
		case policyStateAccepted:
			matches = append(matches, policy)
		}
	}

	return matches, pending, nil
}

func (r *Resolver) policyToConfig(policy *isovalentv1alpha1.IsovalentWAFPolicy) (EffectiveConfig, error) {
	config := EffectiveConfig{
		Enabled:     policy.Spec.Enabled,
		Mode:        valueOrDefault(policy.Spec.Mode, r.defaults.Mode),
		FailureMode: valueOrDefault(policy.Spec.FailureMode, r.defaults.FailureMode),
		Rules: EffectiveRules{
			Source:        EffectiveRuleSourceDefault,
			PolicyProfile: r.defaults.PolicyProfile,
		},
	}

	if policy.Spec.Handling != nil {
		if policy.Spec.Handling.Request != nil {
			config.HandlingOverrides.BodyLimitBytes = policy.Spec.Handling.Request.BodyLimitBytes
		}
		if policy.Spec.Handling.Response != nil && policy.Spec.Handling.Response.BlockResponse != nil {
			config.HandlingOverrides.BlockResponseStatusCode = policy.Spec.Handling.Response.BlockResponse.StatusCode
			config.HandlingOverrides.BlockResponseBody = policy.Spec.Handling.Response.BlockResponse.Body
		}
	}

	if policy.Spec.Rules != nil && policy.Spec.Rules.Managed != nil {
		config.Rules.Source = EffectiveRuleSourceManaged
		config.Rules.PolicyProfile = policy.Spec.Rules.Managed.Profile
	}

	if policy.Spec.Rules != nil && policy.Spec.Rules.Custom != nil {
		inlineRules, err := BuildInlineRules(policy.Spec.Rules.Custom.Inline)
		if err != nil {
			return EffectiveConfig{}, err
		}
		config.Rules = EffectiveRules{
			Source: EffectiveRuleSourceInline,
			Inline: inlineRules,
		}
	}

	return config, nil
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

func policiesToString(policies []*isovalentv1alpha1.IsovalentWAFPolicy) string {
	names := make([]string, 0, len(policies))
	for _, p := range policies {
		names = append(names, p.Name)
	}
	return strings.Join(names, ",")
}

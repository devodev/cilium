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
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestResolveForLBService(t *testing.T) {
	defaults := GlobalDefaults{
		Enabled:       false,
		Mode:          isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
		PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
		FailureMode:   isovalentv1alpha1.WAFFailureModeOpen,
	}

	service := &isovalentv1alpha1.LBService{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api",
			Namespace: "team-a",
			Labels: map[string]string{
				"app": "api",
			},
		},
	}

	inline := `SecAction "id:1000,phase:1,pass,nolog"`
	mode := isovalentv1alpha1.IsovalentWAFPolicyModeMonitor
	overridePolicy := acceptedPolicy(
		"team-a",
		"api-waf",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	overridePolicy.Spec.Enabled = true
	overridePolicy.Spec.Mode = &mode
	overridePolicy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
		Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{
			Inline: inline,
		},
	}
	managedPolicy := acceptedPolicy(
		"team-a",
		"api-waf-managed",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	profile := isovalentv1alpha1.IsovalentWAFPolicyProfileHighSecurity
	managedPolicy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
		Managed: &isovalentv1alpha1.IsovalentWAFManagedRules{
			Profile: profile,
		},
	}
	bodyLimitBytes := int64(2048)
	blockStatusCode := int32(418)
	blockBody := "blocked by policy"
	managedPolicyWithOverrides := acceptedPolicy(
		"team-a",
		"api-waf-managed-overrides",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	managedPolicyWithOverrides.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
		Managed: &isovalentv1alpha1.IsovalentWAFManagedRules{
			Profile: profile,
		},
	}
	managedPolicyWithOverrides.Spec.Handling = &isovalentv1alpha1.IsovalentWAFPolicyHandling{
		Request: &isovalentv1alpha1.IsovalentWAFRequestHandling{
			BodyLimitBytes: &bodyLimitBytes,
		},
		Response: &isovalentv1alpha1.IsovalentWAFResponseHandling{
			BlockResponse: &isovalentv1alpha1.IsovalentWAFBlockResponse{
				StatusCode: &blockStatusCode,
				Body:       &blockBody,
			},
		},
	}

	conflictFirst := acceptedPolicy(
		"team-a",
		"first",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	conflictSecond := acceptedPolicy(
		"team-a",
		"second",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)

	pendingPolicy := acceptedPolicy(
		"team-a",
		"pending",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	pendingPolicy.Generation = 2

	testCases := []struct {
		desc     string
		policies []isovalentv1alpha1.IsovalentWAFPolicy
		expected Resolution
	}{
		{
			desc: "uses global defaults when no accepted match exists",
			expected: Resolution{
				State: ResolutionStateResolved,
				Config: EffectiveConfig{
					Enabled:     defaults.Enabled,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceDefault,
						PolicyProfile: defaults.PolicyProfile,
					},
				},
			},
		},
		{
			desc:     "applies matching accepted policy overrides",
			policies: []isovalentv1alpha1.IsovalentWAFPolicy{overridePolicy},
			expected: Resolution{
				State: ResolutionStateResolved,
				Config: EffectiveConfig{
					Enabled:     true,
					Mode:        mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source: EffectiveRuleSourceInline,
						Inline: mustInlineRulesForTest(t, inline),
					},
				},
				PolicyRefs: []types.NamespacedName{{
					Namespace: "team-a",
					Name:      "api-waf",
				}},
			},
		},
		{
			desc:     "applies managed profile when selected",
			policies: []isovalentv1alpha1.IsovalentWAFPolicy{managedPolicy},
			expected: Resolution{
				State: ResolutionStateResolved,
				Config: EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: profile,
					},
				},
				PolicyRefs: []types.NamespacedName{{
					Namespace: "team-a",
					Name:      "api-waf-managed",
				}},
			},
		},
		{
			desc:     "applies managed profile overrides when selected",
			policies: []isovalentv1alpha1.IsovalentWAFPolicy{managedPolicyWithOverrides},
			expected: Resolution{
				State: ResolutionStateResolved,
				Config: EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: profile,
					},
					HandlingOverrides: EffectiveHandlingOverrides{
						BodyLimitBytes:          &bodyLimitBytes,
						BlockResponseStatusCode: &blockStatusCode,
						BlockResponseBody:       &blockBody,
					},
				},
				PolicyRefs: []types.NamespacedName{{
					Namespace: "team-a",
					Name:      "api-waf-managed-overrides",
				}},
			},
		},
		{
			desc:     "rejects multiple accepted matches",
			policies: []isovalentv1alpha1.IsovalentWAFPolicy{conflictFirst, conflictSecond},
			expected: Resolution{
				State: ResolutionStateConflict,
				Config: EffectiveConfig{
					Enabled:     defaults.Enabled,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceDefault,
						PolicyProfile: defaults.PolicyProfile,
					},
				},
				PolicyRefs: []types.NamespacedName{
					{Namespace: "team-a", Name: "first"},
					{Namespace: "team-a", Name: "second"},
				},
			},
		},
		{
			desc:     "waits for matching policy validation from current generation",
			policies: []isovalentv1alpha1.IsovalentWAFPolicy{pendingPolicy},
			expected: Resolution{
				State: ResolutionStatePending,
				Config: EffectiveConfig{
					Enabled:     defaults.Enabled,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceDefault,
						PolicyProfile: defaults.PolicyProfile,
					},
				},
				PolicyRefs: []types.NamespacedName{{
					Namespace: "team-a",
					Name:      "pending",
				}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			actual, err := ResolveForLBService(service, tc.policies, defaults)

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		desc        string
		policy      isovalentv1alpha1.IsovalentWAFPolicy
		expectError bool
	}{
		{
			desc: "valid policy",
			policy: acceptedPolicy(
				"team-a",
				"valid",
				&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			),
			expectError: false,
		},
		{
			desc: "invalid policy",
			policy: acceptedPolicy("team-a", "invalid", &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "BadOperator",
					},
				},
			}),
			expectError: true,
		},
		{
			desc: "invalid inline rules",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"inline-invalid",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				inline := `SecRule REQUEST_URI "@rx (" "id:1000,phase:1,deny"`
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{Inline: inline},
				}
				return policy
			}(),
			expectError: true,
		},
		{
			desc: "rejects empty inline rules",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"inline-empty",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{Inline: "\n\t \r\n"},
				}
				return policy
			}(),
			expectError: true,
		},
		{
			desc: "rejects empty rules object",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"invalid-empty-rules",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{}
				return policy
			}(),
			expectError: true,
		},
		{
			desc: "rejects policies that specify both managed and custom rules",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"invalid-mixed-rules",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				inline := `SecAction "id:1000,phase:1,pass,nolog"`
				profile := isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Managed: &isovalentv1alpha1.IsovalentWAFManagedRules{Profile: profile},
					Custom:  &isovalentv1alpha1.IsovalentWAFCustomRules{Inline: inline},
				}
				return policy
			}(),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			err := Validate(&tc.policy)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func acceptedPolicy(
	namespace string,
	name string,
	selector *slim_metav1.LabelSelector,
) isovalentv1alpha1.IsovalentWAFPolicy {
	policy := isovalentv1alpha1.IsovalentWAFPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
			Targets: isovalentv1alpha1.IsovalentWAFPolicyTargets{
				LBServices: &isovalentv1alpha1.IsovalentWAFPolicyLBServices{
					LabelSelector: selector,
				},
			},
			Enabled: true,
		},
	}

	policy.Status.Conditions = []metav1.Condition{{
		Type:               isovalentv1alpha1.ConditionTypeIsovalentWAFPolicyAccepted,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.IsovalentWAFPolicyAcceptedConditionReasonValid,
		Message:            "policy selector is valid",
		ObservedGeneration: policy.Generation,
		LastTransitionTime: metav1.Now(),
	}}
	policy.UpdateResourceStatus()

	return policy
}

func mustInlineRulesForTest(t *testing.T, inline string) InlineRules {
	t.Helper()

	compiled, err := BuildInlineRules(inline)
	require.NoError(t, err)
	return compiled
}

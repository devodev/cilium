//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlFakeClient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestResolverResolveConfig(t *testing.T) {
	defaults := GlobalDefaults{
		Enabled:       true,
		Mode:          isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
		PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
		FailureMode:   isovalentv1alpha1.WAFFailureModeOpen,
	}

	target := PolicyTarget{
		GroupKind: isovalentv1alpha1.SchemeGroupVersion.WithKind(isovalentv1alpha1.LBServiceKindDefinition).GroupKind(),
		NamespacedName: types.NamespacedName{
			Name:      "api",
			Namespace: "team-a",
		},
		Labels: map[string]string{
			"app": "api",
		},
	}

	inline := `SecAction "id:1000,phase:1,pass,nolog"`
	mode := isovalentv1alpha1.IsovalentWAFPolicyModeMonitor
	customProfile := isovalentv1alpha1.IsovalentWAFCustomProfile{
		BlockingParanoiaLevel:         2,
		DetectionParanoiaLevel:        3,
		InboundAnomalyScoreThreshold:  7,
		OutboundAnomalyScoreThreshold: 6,
	}
	ruleOverrideTarget := "ARGS:note"
	ruleOverrides := []isovalentv1alpha1.IsovalentWAFRuleOverride{
		{RuleID: 949110, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable},
		{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: ruleOverrideTarget},
	}
	profile := isovalentv1alpha1.IsovalentWAFPolicyProfileHighSecurity
	bodyLimitBytes := int64(2048)
	blockStatusCode := int32(418)
	blockBody := "blocked by policy"

	testCases := []struct {
		desc     string
		objects  []ctrlClient.Object
		expected Resolution
	}{
		{
			desc: "no accepted match returns nil",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"other-waf",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}},
				)
				return &policy
			}()},
			expected: Resolution{},
		},
		{
			desc:     "no policies returns nil",
			expected: Resolution{},
		},
		{
			desc: "applies matching accepted policy overrides",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Enabled = true
				policy.Spec.Mode = &mode
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Inline: inline,
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source: EffectiveRuleSourceInline,
						Inline: mustInlineRulesForTest(t, inline),
					},
				},
			},
		},
		{
			desc: "applies default managed profile when rules are omitted",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-default-managed",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: defaults.PolicyProfile,
					},
				},
			},
		},
		{
			desc: "applies managed profile when selected",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-managed",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Managed: &isovalentv1alpha1.IsovalentWAFManagedProfile{Name: profile},
					},
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: profile,
					},
				},
			},
		},
		{
			desc: "applies managed profile with inline additions",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-managed-inline",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Managed: &isovalentv1alpha1.IsovalentWAFManagedProfile{Name: profile},
					},
					Inline: inline,
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: profile,
						Inline:        mustInlineRulesForTest(t, inline),
					},
				},
			},
		},
		{
			desc: "applies managed profile overrides when selected",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-managed-overrides",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Managed: &isovalentv1alpha1.IsovalentWAFManagedProfile{Name: profile},
					},
					Overrides: ruleOverrides,
				}
				policy.Spec.Handling = &isovalentv1alpha1.IsovalentWAFPolicyHandling{
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
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: profile,
						Overrides:     ruleOverrides,
					},
					HandlingOverrides: EffectiveHandlingOverrides{
						BodyLimitBytes:          &bodyLimitBytes,
						BlockResponseStatusCode: &blockStatusCode,
						BlockResponseBody:       &blockBody,
					},
				},
			},
		},
		{
			desc: "applies custom profile when selected",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-custom-profile",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Custom: &customProfile,
					},
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceProfile,
						CustomProfile: customProfile,
					},
				},
			},
		},
		{
			desc: "applies custom profile overrides when selected",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-custom-profile-overrides",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Custom: &customProfile,
					},
					Overrides: ruleOverrides,
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceProfile,
						CustomProfile: customProfile,
						Overrides:     ruleOverrides,
					},
				},
			},
		},
		{
			desc: "applies default managed profile overrides when selected",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-default-managed-overrides",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Overrides: ruleOverrides,
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: defaults.PolicyProfile,
						Overrides:     ruleOverrides,
					},
				},
			},
		},
		{
			desc: "applies custom profile with inline additions when selected",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"api-waf-custom-profile-inline",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Custom: &customProfile,
					},
					Inline:    inline,
					Overrides: ruleOverrides,
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceProfile,
						CustomProfile: customProfile,
						Inline:        mustInlineRulesForTest(t, inline),
						Overrides:     ruleOverrides,
					},
				},
			},
		},
		{
			desc: "matches all LBServices in namespace when selector is omitted",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy("team-a", "match-all", nil)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Managed: &isovalentv1alpha1.IsovalentWAFManagedProfile{Name: profile},
					},
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: profile,
					},
				},
			},
		},
		{
			desc: "multiple targets are ORed",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"or-semantics",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}},
				)
				policy.Spec.Targets = append(policy.Spec.Targets,
					isovalentv1alpha1.IsovalentWAFPolicyTarget{
						APIGroup: isovalentv1alpha1.CustomResourceDefinitionGroup,
						Kind:     isovalentv1alpha1.LBServiceKindDefinition,
						LabelSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "api"},
						},
					},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Managed: &isovalentv1alpha1.IsovalentWAFManagedProfile{Name: profile},
					},
				}
				return &policy
			}()},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: profile,
					},
				},
			},
		},
		{
			desc: "multiple accepted matches use owning policy",
			objects: []ctrlClient.Object{
				func() ctrlClient.Object {
					policy := acceptedPolicy(
						"team-a",
						"first",
						&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
					)
					return &policy
				}(),
				func() ctrlClient.Object {
					policy := acceptedPolicy(
						"team-a",
						"second",
						&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
					)
					return &policy
				}(),
			},
			expected: Resolution{
				Config: &EffectiveConfig{
					Enabled:     true,
					Mode:        defaults.Mode,
					FailureMode: defaults.FailureMode,
					Rules: EffectiveRules{
						Source:        EffectiveRuleSourceManaged,
						PolicyProfile: defaults.PolicyProfile,
					},
				},
			},
		},
		{
			desc: "pending matching policy defers reconciliation",
			objects: []ctrlClient.Object{func() ctrlClient.Object {
				policy := acceptedPolicy(
					"team-a",
					"pending",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Generation = 2
				return &policy
			}()},
			expected: Resolution{
				DeferReconcile: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, isovalentv1alpha1.AddToScheme(scheme))

			builder := ctrlFakeClient.NewClientBuilder().WithScheme(scheme)
			if len(tc.objects) > 0 {
				builder = builder.WithObjects(tc.objects...)
			}

			resolver := NewResolver(builder.Build(), hivetest.Logger(t), defaults)

			actual, err := resolver.ResolveConfig(context.Background(), target)

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestValidate(t *testing.T) {
	ruleOverrides := []isovalentv1alpha1.IsovalentWAFRuleOverride{
		{RuleID: 949110, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable},
		{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: "ARGS:note"},
	}

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
			desc: "valid policy without selector",
			policy: acceptedPolicy(
				"team-a",
				"valid-without-selector",
				nil,
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
					Inline: inline,
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
					Inline: "\n\t \r\n",
				}
				return policy
			}(),
			expectError: true,
		},
		{
			desc: "accepts empty rules object and uses defaults",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"empty-rules",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{}
				return policy
			}(),
			expectError: false,
		},
		{
			desc: "rejects policies that specify both managed and custom profiles",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"invalid-mixed-profile",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				managedProfile := isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced
				customProfile := isovalentv1alpha1.IsovalentWAFCustomProfile{
					BlockingParanoiaLevel:         2,
					DetectionParanoiaLevel:        3,
					InboundAnomalyScoreThreshold:  7,
					OutboundAnomalyScoreThreshold: 6,
				}
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Managed: &isovalentv1alpha1.IsovalentWAFManagedProfile{Name: managedProfile},
						Custom:  &customProfile,
					},
				}
				return policy
			}(),
			expectError: true,
		},
		{
			desc: "accepts custom profile with inline additions",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"custom-profile-inline",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				inline := `SecAction "id:1000,phase:1,pass,nolog"`
				profile := isovalentv1alpha1.IsovalentWAFCustomProfile{
					BlockingParanoiaLevel:         2,
					DetectionParanoiaLevel:        3,
					InboundAnomalyScoreThreshold:  7,
					OutboundAnomalyScoreThreshold: 6,
				}
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
						Custom: &profile,
					},
					Inline: inline,
				}
				return policy
			}(),
			expectError: false,
		},
		{
			desc: "accepts default managed overrides",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"default-managed-overrides",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Overrides: ruleOverrides,
				}
				return policy
			}(),
			expectError: false,
		},
		{
			desc: "rejects overrides with standalone custom inline rules",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"invalid-inline-overrides",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
					Inline:    `SecAction "id:1000,phase:1,pass,nolog"`,
					Overrides: ruleOverrides,
				}
				return policy
			}(),
			expectError: true,
		},
		{
			desc: "rejects unsupported target kinds",
			policy: func() isovalentv1alpha1.IsovalentWAFPolicy {
				policy := acceptedPolicy(
					"team-a",
					"unsupported-target",
					&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				)
				policy.Spec.Targets[0].Kind = isovalentv1alpha1.LBVIPKindDefinition
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
			Targets: []isovalentv1alpha1.IsovalentWAFPolicyTarget{{
				APIGroup:      isovalentv1alpha1.CustomResourceDefinitionGroup,
				Kind:          isovalentv1alpha1.LBServiceKindDefinition,
				LabelSelector: selector,
			}},
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

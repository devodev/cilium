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
	"testing"

	"github.com/stretchr/testify/require"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestValidateRuleOverrides(t *testing.T) {
	testCases := []struct {
		name        string
		rules       *isovalentv1alpha1.IsovalentWAFPolicyRules
		expectError string
	}{
		{
			name:  "accepts nil rules",
			rules: nil,
		},
		{
			name:  "accepts rules without overrides",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{},
		},
		{
			name: "accepts managed overrides",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
					Managed: &isovalentv1alpha1.IsovalentWAFManagedProfile{Name: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced},
				},
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{RuleID: 949110, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable},
					{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: "ARGS:note"},
				},
			},
		},
		{
			name: "accepts custom profile with inline overrides",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
					Custom: &isovalentv1alpha1.IsovalentWAFCustomProfile{
						BlockingParanoiaLevel:         2,
						DetectionParanoiaLevel:        3,
						InboundAnomalyScoreThreshold:  7,
						OutboundAnomalyScoreThreshold: 6,
					},
				},
				Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: "REQUEST_HEADERS:User-Agent"},
				},
			},
		},
		{
			name: "rejects standalone inline overrides",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{RuleID: 949110, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable},
				},
			},
			expectError: "spec.rules.overrides are not supported with standalone inline rules",
		},
		{
			name: "rejects non-positive rule id",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{RuleID: 0, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable},
				},
			},
			expectError: "spec.rules.overrides[0].ruleID must be greater than 0",
		},
		{
			name: "rejects disable with target",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{
						RuleID: 949110,
						Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable,
						Target: "ARGS:note",
					},
				},
			},
			expectError: `spec.rules.overrides[0].target must be omitted for action "Disable"`,
		},
		{
			name: "rejects exclude target without target",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{
						RuleID: 942100,
						Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget,
					},
				},
			},
			expectError: `spec.rules.overrides[0].target must be specified for action "ExcludeTarget"`,
		},
		{
			name: "rejects malformed target",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: "ARGS"},
				},
			},
			expectError: "spec.rules.overrides[0].target must be in COLLECTION:name form",
		},
		{
			name: "rejects target with whitespace",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: "ARGS:bad target"},
				},
			},
			expectError: "spec.rules.overrides[0].target must not contain whitespace or target separators",
		},
		{
			name: "rejects target with exclusion prefix",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: "!ARGS:note"},
				},
			},
			expectError: "spec.rules.overrides[0].target must not include exclusion prefixes",
		},
		{
			name: "rejects unsupported action",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Overrides: []isovalentv1alpha1.IsovalentWAFRuleOverride{
					{
						RuleID: 942100,
						Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionType("Rewrite"),
					},
				},
			},
			expectError: `unsupported spec.rules.overrides[0].action "Rewrite"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRuleOverrides(tc.rules)
			if tc.expectError != "" {
				require.EqualError(t, err, tc.expectError)
				return
			}

			require.NoError(t, err)
		})
	}
}

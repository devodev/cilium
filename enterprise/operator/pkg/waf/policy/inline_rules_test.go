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

func TestNormalize(t *testing.T) {
	testCases := []struct {
		name     string
		inline   string
		expected string
	}{
		{
			name:     "empty",
			inline:   "",
			expected: "",
		},
		{
			name:     "normalizes line endings and trailing newlines",
			inline:   "SecRuleRemoveById 949110\r\nSecRuleEngine On\r\n\r\n",
			expected: "SecRuleRemoveById 949110\nSecRuleEngine On",
		},
		{
			name:     "trims leading and trailing blank symbols",
			inline:   "\n \tSecAction \"id:1000,phase:1,pass,nolog\"\r\n\r\n\t ",
			expected: "SecAction \"id:1000,phase:1,pass,nolog\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, normalize(tc.inline))
		})
	}
}

func TestHashKey(t *testing.T) {
	testCases := []struct {
		name        string
		inline      string
		expected    string
		expectError bool
	}{
		{
			name:     "empty",
			inline:   "",
			expected: "",
		},
		{
			name:     "hashes normalized inline rules",
			inline:   "SecRuleRemoveById 949110\nSecRuleEngine On\n",
			expected: "crs_inline_sha256_v1_24b978d9ec57e1c0bcb4c5bf615a2faccda8fdf23426f25ff1b85cb37bab8603",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := hashKey(tc.inline)
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestValidateCustomRules(t *testing.T) {
	testCases := []struct {
		name        string
		rules       *isovalentv1alpha1.IsovalentWAFPolicyRules
		expectError string
	}{
		{
			name:  "accepts nil custom rules",
			rules: nil,
		},
		{
			name: "accepts profile only custom rules",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
					Custom: &isovalentv1alpha1.IsovalentWAFCustomProfile{
						BlockingParanoiaLevel:         2,
						DetectionParanoiaLevel:        3,
						InboundAnomalyScoreThreshold:  7,
						OutboundAnomalyScoreThreshold: 6,
					},
				},
			},
		},
		{
			name: "accepts valid inline rules",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Inline: `SecAction "id:1000,phase:1,pass,nolog"` + "\r\n",
			},
		},
		{
			name: "accepts profile with valid inline rules",
			rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Profile: &isovalentv1alpha1.IsovalentWAFRuleProfile{
					Custom: &isovalentv1alpha1.IsovalentWAFCustomProfile{
						BlockingParanoiaLevel:         2,
						DetectionParanoiaLevel:        3,
						InboundAnomalyScoreThreshold:  7,
						OutboundAnomalyScoreThreshold: 6,
					},
				},
				Inline: `SecAction "id:1000,phase:1,pass,nolog"` + "\r\n",
			},
		},
		{
			name:        "rejects inline rules that declare SecRuleEngine",
			rules:       &isovalentv1alpha1.IsovalentWAFPolicyRules{Inline: "SecRuleEngine DetectionOnly\r\n"},
			expectError: "inline rules must not declare SecRuleEngine",
		},
		{
			name:        "rejects inline rules that declare Include",
			rules:       &isovalentv1alpha1.IsovalentWAFPolicyRules{Inline: "Include @crs-setup.conf.example\r\n"},
			expectError: "inline rules must not declare Include",
		},
		{
			name:        "rejects syntactically invalid inline rules",
			rules:       &isovalentv1alpha1.IsovalentWAFPolicyRules{Inline: `SecRule REQUEST_URI "@rx (" "id:1000,phase:1,deny"`},
			expectError: "effective WAF rule validation failed",
		},
		{
			name:        "rejects whitespace only inline rules",
			rules:       &isovalentv1alpha1.IsovalentWAFPolicyRules{Inline: "\r\n\t  \r\n"},
			expectError: "spec.rules.inline must not be empty",
		},
		{
			name:        "rejects comment only inline rules",
			rules:       &isovalentv1alpha1.IsovalentWAFPolicyRules{Inline: "# comment only"},
			expectError: "spec.rules.inline must not be empty",
		},
		{
			name:        "rejects blank and comment only inline rules",
			rules:       &isovalentv1alpha1.IsovalentWAFPolicyRules{Inline: "\n\t# comment only\r\n\n# another comment"},
			expectError: "spec.rules.inline must not be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCustomRules(tc.rules)
			if tc.expectError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectError)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestBuildInlineRules(t *testing.T) {
	validInline := `SecAction "id:1000,phase:1,pass,nolog"` + "\r\n"
	validHashKey, err := hashKey(normalize(validInline))
	require.NoError(t, err)

	testCases := []struct {
		name        string
		config      string
		expected    InlineRules
		expectError string
	}{
		{
			name:   "compiles full custom inline rules",
			config: validInline,
			expected: InlineRules{
				Inline:  `SecAction "id:1000,phase:1,pass,nolog"`,
				HashKey: validHashKey,
			},
		},
		{
			name:        "rejects empty inline rules",
			config:      "",
			expectError: "spec.rules.inline must not be empty",
		},
		{
			name:        "rejects whitespace only inline rules",
			config:      "\r\n\t  \r\n",
			expectError: "spec.rules.inline must not be empty",
		},
		{
			name:        "rejects comment only inline rules",
			config:      "# comment only",
			expectError: "spec.rules.inline must not be empty",
		},
		{
			name:        "rejects blank and comment only inline rules",
			config:      "\n\t# comment only\r\n\n# another comment",
			expectError: "spec.rules.inline must not be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := BuildInlineRules(tc.config)
			if tc.expectError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

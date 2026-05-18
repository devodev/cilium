//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package envoy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestProxyConfigBuilderBuild(t *testing.T) {
	bodyLimitBytes := int64(2048)
	blockStatusCode := int32(418)
	blockBody := "blocked by policy"

	testCases := []struct {
		name          string
		config        policy.EffectiveConfig
		expected      *ProxyConfig
		expectedError string
	}{
		{
			name: "disabled WAF returns nil",
			config: policy.EffectiveConfig{
				Enabled: false,
			},
			expected: nil,
		},
		{
			name: "inline rules return nil",
			config: policy.EffectiveConfig{
				Enabled: true,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceInline,
				},
			},
			expected: nil,
		},
		{
			name: "default rules build proxy config with defaults",
			config: policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeMonitor,
				FailureMode: isovalentv1alpha1.WAFFailureModeOpen,
				Rules: policy.EffectiveRules{
					Source:        policy.EffectiveRuleSourceDefault,
					PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
				},
			},
			expected: &ProxyConfig{
				DefaultMode:         "detection",
				BodyLimitBytes:      1024 * 1024,
				FailPolicy:          "open",
				RouteModeHeader:     "",
				BlockPath:           "/__coraza_block__",
				ResponseBlockStatus: 403,
				ResponseBlockBody:   "blocked by waf",
				Directives:          "Include /etc/coraza/rules/profiles/balanced.conf",
			},
		},
		{
			name: "managed rules apply overrides",
			config: policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
				FailureMode: isovalentv1alpha1.WAFFailureModeClose,
				Rules: policy.EffectiveRules{
					Source:        policy.EffectiveRuleSourceManaged,
					PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileHighSecurity,
				},
				HandlingOverrides: policy.EffectiveHandlingOverrides{
					BodyLimitBytes:          &bodyLimitBytes,
					BlockResponseStatusCode: &blockStatusCode,
					BlockResponseBody:       &blockBody,
				},
			},
			expected: &ProxyConfig{
				DefaultMode:         "block",
				BodyLimitBytes:      bodyLimitBytes,
				FailPolicy:          "closed",
				RouteModeHeader:     "",
				BlockPath:           "/__coraza_block__",
				ResponseBlockStatus: int(blockStatusCode),
				ResponseBlockBody:   blockBody,
				Directives:          "Include /etc/coraza/rules/profiles/high_security.conf",
			},
		},
		{
			name: "unsupported rules source returns error",
			config: policy.EffectiveConfig{
				Enabled: true,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSource("Unsupported"),
				},
			},
			expectedError: `unsupported WAF rules source "Unsupported"`,
		},
	}

	builder := NewProxyConfigBuilder()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := builder.Build(tc.config)

			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
				require.Nil(t, actual)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

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
	ruleOverrideTarget := "ARGS:note"
	ruleOverrides := []isovalentv1alpha1.IsovalentWAFRuleOverride{
		{RuleID: 949110, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable},
		{RuleID: 942100, Action: isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget, Target: ruleOverrideTarget},
	}

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
			name: "inline rules build proxy config",
			config: policy.EffectiveConfig{
				Enabled: true,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceInline,
					Inline: policy.InlineRules{
						Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
					},
				},
			},
			expected: &ProxyConfig{
				DefaultMode:         "block",
				BodyLimitBytes:      1024 * 1024,
				FailPolicy:          "open",
				RouteModeHeader:     "",
				BlockPath:           wafBlockPath,
				ResponseBlockStatus: 403,
				ResponseBlockBody:   "blocked by waf",
				Directives:          `SecAction "id:1000,phase:1,pass,nolog"`,
			},
		},
		{
			name: "custom profile with inline rules and CRS overrides build proxy config",
			config: policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
				FailureMode: isovalentv1alpha1.WAFFailureModeOpen,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceProfile,
					CustomProfile: isovalentv1alpha1.IsovalentWAFCustomProfile{
						BlockingParanoiaLevel:         2,
						DetectionParanoiaLevel:        3,
						InboundAnomalyScoreThreshold:  7,
						OutboundAnomalyScoreThreshold: 6,
					},
					Inline: policy.InlineRules{
						Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
					},
					Overrides: ruleOverrides,
				},
			},
			expected: &ProxyConfig{
				DefaultMode:         "block",
				BodyLimitBytes:      1024 * 1024,
				FailPolicy:          "open",
				RouteModeHeader:     "",
				BlockPath:           wafBlockPath,
				ResponseBlockStatus: 403,
				ResponseBlockBody:   "blocked by waf",
				Directives: `SecAction "id:1000000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=2,setvar:tx.detection_paranoia_level=3,setvar:tx.inbound_anomaly_score_threshold=7,setvar:tx.outbound_anomaly_score_threshold=6"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
Include /etc/coraza/crs/crs-setup.conf
Include /etc/coraza/crs/rules/*.conf
SecRuleRemoveById 949110
SecRuleUpdateTargetById 942100 !ARGS:note
SecAction "id:1000,phase:1,pass,nolog"`,
			},
		},
		{
			name: "managed profile with inline rules and CRS overrides build proxy config",
			config: policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
				FailureMode: isovalentv1alpha1.WAFFailureModeOpen,
				Rules: policy.EffectiveRules{
					Source:        policy.EffectiveRuleSourceManaged,
					PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileHighSecurity,
					Inline: policy.InlineRules{
						Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
					},
					Overrides: ruleOverrides,
				},
			},
			expected: &ProxyConfig{
				DefaultMode:         "block",
				BodyLimitBytes:      1024 * 1024,
				FailPolicy:          "open",
				RouteModeHeader:     "",
				BlockPath:           wafBlockPath,
				ResponseBlockStatus: 403,
				ResponseBlockBody:   "blocked by waf",
				Directives: `SecAction "id:1100002,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=2,setvar:tx.detection_paranoia_level=2,setvar:tx.inbound_anomaly_score_threshold=7,setvar:tx.outbound_anomaly_score_threshold=6"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
Include /etc/coraza/crs/crs-setup.conf
Include /etc/coraza/crs/rules/*.conf
SecRuleRemoveById 949110
SecRuleUpdateTargetById 942100 !ARGS:note
SecAction "id:1000,phase:1,pass,nolog"`,
			},
		},

		{
			name: "custom profile builds inline CRS tuning directives",
			config: policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
				FailureMode: isovalentv1alpha1.WAFFailureModeOpen,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceProfile,
					CustomProfile: isovalentv1alpha1.IsovalentWAFCustomProfile{
						BlockingParanoiaLevel:         2,
						DetectionParanoiaLevel:        3,
						InboundAnomalyScoreThreshold:  7,
						OutboundAnomalyScoreThreshold: 6,
					},
				},
			},
			expected: &ProxyConfig{
				DefaultMode:         "block",
				BodyLimitBytes:      1024 * 1024,
				FailPolicy:          "open",
				RouteModeHeader:     "",
				BlockPath:           wafBlockPath,
				ResponseBlockStatus: 403,
				ResponseBlockBody:   "blocked by waf",
				Directives: `SecAction "id:1000000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=2,setvar:tx.detection_paranoia_level=3,setvar:tx.inbound_anomaly_score_threshold=7,setvar:tx.outbound_anomaly_score_threshold=6"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
Include /etc/coraza/crs/crs-setup.conf
Include /etc/coraza/crs/rules/*.conf`,
			},
		},
		{
			name: "default rules build proxy config with defaults",
			config: policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeMonitor,
				FailureMode: isovalentv1alpha1.WAFFailureModeOpen,
				Rules: policy.EffectiveRules{
					Source:        policy.EffectiveRuleSourceManaged,
					PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
				},
			},
			expected: &ProxyConfig{
				DefaultMode:         "detection",
				BodyLimitBytes:      1024 * 1024,
				FailPolicy:          "open",
				RouteModeHeader:     "",
				BlockPath:           wafBlockPath,
				ResponseBlockStatus: 403,
				ResponseBlockBody:   "blocked by waf",
				Directives: `SecAction "id:1100003,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=10,setvar:tx.outbound_anomaly_score_threshold=8"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
Include /etc/coraza/crs/crs-setup.conf
Include /etc/coraza/crs/rules/*.conf`,
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
				BlockPath:           wafBlockPath,
				ResponseBlockStatus: int(blockStatusCode),
				ResponseBlockBody:   blockBody,
				Directives: `SecAction "id:1100002,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=2,setvar:tx.detection_paranoia_level=2,setvar:tx.inbound_anomaly_score_threshold=7,setvar:tx.outbound_anomaly_score_threshold=6"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
Include /etc/coraza/crs/crs-setup.conf
Include /etc/coraza/crs/rules/*.conf`,
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

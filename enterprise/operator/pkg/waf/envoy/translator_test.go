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

	"github.com/cilium/hive/hivetest"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPFilter(t *testing.T) {
	testCases := []struct {
		name           string
		config         *policy.EffectiveConfig
		expectedFilter bool
	}{
		{
			name:           "disabled WAF returns nil",
			config:         nil,
			expectedFilter: false,
		},
		{
			name: "inline rules emit filter",
			config: &policy.EffectiveConfig{
				Enabled: true,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceInline,
					Inline: policy.InlineRules{
						Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
					},
				},
			},
			expectedFilter: true,
		},
		{
			name: "managed monitor defaults",
			config: &policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeMonitor,
				FailureMode: isovalentv1alpha1.WAFFailureModeOpen,
				Rules: policy.EffectiveRules{
					Source:        policy.EffectiveRuleSourceManaged,
					PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
				},
			},
			expectedFilter: true,
		},
		{
			name: "custom profile emits filter",
			config: &policy.EffectiveConfig{
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
			expectedFilter: true,
		},
		{
			name: "managed enforce close with overrides",
			config: &policy.EffectiveConfig{
				Enabled:     true,
				Mode:        isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
				FailureMode: isovalentv1alpha1.WAFFailureModeClose,
				Rules: policy.EffectiveRules{
					Source:        policy.EffectiveRuleSourceManaged,
					PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
				},
			},
			expectedFilter: true,
		},
	}

	translator := NewTranslator(hivetest.Logger(t), NewProxyConfigBuilder())

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := translator.HTTPFilter("test-service", "test-namespace", tc.config)

			require.NoError(t, err)
			if !tc.expectedFilter {
				require.Nil(t, filter)
				return
			}

			require.NotNil(t, filter)
			require.Equal(t, HTTPFilterName, filter.Name)
			require.NotNil(t, filter.GetTypedConfig())
		})
	}
}

func TestBlockRoute(t *testing.T) {
	blockStatusCode := int32(418)
	blockBody := "blocked by policy"

	testCases := []struct {
		name     string
		config   *policy.EffectiveConfig
		expected *envoy_config_route_v3.Route
	}{
		{
			name:     "disabled WAF returns nil",
			config:   nil,
			expected: nil,
		},
		{
			name: "inline rules build block route",
			config: &policy.EffectiveConfig{
				Enabled: true,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceInline,
					Inline: policy.InlineRules{
						Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
					},
				},
			},
			expected: &envoy_config_route_v3.Route{
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
						Path: "/__coraza_block__",
					},
				},
				Action: &envoy_config_route_v3.Route_DirectResponse{
					DirectResponse: &envoy_config_route_v3.DirectResponseAction{
						Status: 403,
						Body: &envoy_config_core_v3.DataSource{
							Specifier: &envoy_config_core_v3.DataSource_InlineString{
								InlineString: "blocked by waf",
							},
						},
					},
				},
			},
		},
		{
			name: "managed defaults",
			config: &policy.EffectiveConfig{
				Enabled: true,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceManaged,
				},
			},
			expected: &envoy_config_route_v3.Route{
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
						Path: "/__waf_block__",
					},
				},
				Action: &envoy_config_route_v3.Route_DirectResponse{
					DirectResponse: &envoy_config_route_v3.DirectResponseAction{
						Status: 403,
						Body: &envoy_config_core_v3.DataSource{
							Specifier: &envoy_config_core_v3.DataSource_InlineString{
								InlineString: "blocked by waf",
							},
						},
					},
				},
			},
		},
		{
			name: "custom profile builds block route",
			config: &policy.EffectiveConfig{
				Enabled: true,
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
			expected: &envoy_config_route_v3.Route{
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
						Path: "/__coraza_block__",
					},
				},
				Action: &envoy_config_route_v3.Route_DirectResponse{
					DirectResponse: &envoy_config_route_v3.DirectResponseAction{
						Status: 403,
						Body: &envoy_config_core_v3.DataSource{
							Specifier: &envoy_config_core_v3.DataSource_InlineString{
								InlineString: "blocked by waf",
							},
						},
					},
				},
			},
		},
		{
			name: "managed overrides",
			config: &policy.EffectiveConfig{
				Enabled: true,
				Rules: policy.EffectiveRules{
					Source: policy.EffectiveRuleSourceManaged,
				},
				HandlingOverrides: policy.EffectiveHandlingOverrides{
					BlockResponseStatusCode: &blockStatusCode,
					BlockResponseBody:       &blockBody,
				},
			},
			expected: &envoy_config_route_v3.Route{
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
						Path: "/__waf_block__",
					},
				},
				Action: &envoy_config_route_v3.Route_DirectResponse{
					DirectResponse: &envoy_config_route_v3.DirectResponseAction{
						Status: uint32(blockStatusCode),
						Body: &envoy_config_core_v3.DataSource{
							Specifier: &envoy_config_core_v3.DataSource_InlineString{
								InlineString: blockBody,
							},
						},
					},
				},
			},
		},
	}

	translator := NewTranslator(hivetest.Logger(t), NewProxyConfigBuilder())

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			route, err := translator.BlockRoute("test-service", "test-namespace", tc.config)

			require.NoError(t, err)
			if tc.expected == nil {
				require.Nil(t, route)
				return
			}

			require.NotNil(t, route)
			requireProtoEqual(t, tc.expected, route)
		})
	}
}

func requireProtoEqual(t *testing.T, expected proto.Message, actual proto.Message) {
	t.Helper()

	expectedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(expected)
	require.NoError(t, err)

	actualBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(actual)
	require.NoError(t, err)

	require.Equal(t, expectedBytes, actualBytes)
}

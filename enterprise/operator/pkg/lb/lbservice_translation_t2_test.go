//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"

	wafenvoy "github.com/cilium/cilium/enterprise/operator/pkg/waf/envoy"
	wafpolicy "github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestDesiredManagedWAFHTTPRouteConfig(t *testing.T) {
	blockStatusCode := int32(418)
	blockBody := "blocked by policy"

	testCases := []struct {
		name             string
		config           *wafpolicy.EffectiveConfig
		expectedRouteLen int
		assertRoutes     func(*testing.T, []*envoy_config_route_v3.Route)
	}{
		{
			name: "managed route prepends block route",
			config: &wafpolicy.EffectiveConfig{
				Enabled: true,
				Mode:    isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
				Rules: wafpolicy.EffectiveRules{
					Source: wafpolicy.EffectiveRuleSourceManaged,
				},
				HandlingOverrides: wafpolicy.EffectiveHandlingOverrides{
					BlockResponseStatusCode: &blockStatusCode,
					BlockResponseBody:       &blockBody,
				},
			},
			expectedRouteLen: 2,
			assertRoutes: func(t *testing.T, routes []*envoy_config_route_v3.Route) {
				t.Helper()
				blockRoute := routes[0]
				require.Equal(t, "/__coraza_block__", blockRoute.GetMatch().GetPath())
				require.Equal(t, uint32(blockStatusCode), blockRoute.GetDirectResponse().GetStatus())
				require.Equal(t, blockBody, blockRoute.GetDirectResponse().GetBody().GetInlineString())

				backendRoute := routes[1]
				require.Equal(t, "/api/foo-insecure", backendRoute.GetMatch().GetPath())
				require.Equal(t, "backend_cluster_app", backendRoute.GetRoute().GetCluster())
				require.Empty(t, backendRoute.GetRequestHeadersToAdd())
			},
		},
		{
			name: "inline rules skip block route",
			config: &wafpolicy.EffectiveConfig{
				Enabled: true,
				Rules: wafpolicy.EffectiveRules{
					Source: wafpolicy.EffectiveRuleSourceInline,
				},
			},
			expectedRouteLen: 1,
			assertRoutes: func(t *testing.T, routes []*envoy_config_route_v3.Route) {
				t.Helper()
				backendRoute := routes[0]
				require.Equal(t, "/api/foo-insecure", backendRoute.GetMatch().GetPath())
				require.Equal(t, "backend_cluster_app", backendRoute.GetRoute().GetCluster())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			translator := &lbServiceT2Translator{
				logger:        hivetest.Logger(t),
				wafTranslator: wafenvoy.NewTranslator(hivetest.Logger(t), wafenvoy.NewProxyConfigBuilder()),
			}
			model := newManagedWAFHTTPRouteModel(tc.config)

			routeConfig, err := translator.desiredEnvoyHttpRouteConfig(model)

			require.NoError(t, err)
			require.Len(t, routeConfig.VirtualHosts, 1)
			require.Len(t, routeConfig.VirtualHosts[0].Routes, tc.expectedRouteLen)
			tc.assertRoutes(t, routeConfig.VirtualHosts[0].Routes)
		})
	}
}

func newManagedWAFHTTPRouteModel(config *wafpolicy.EffectiveConfig) *lbService {
	return &lbService{
		namespace: "default",
		name:      "managed-waf",
		applications: lbApplications{
			httpProxy: &lbApplicationHTTPProxy{
				routes: map[string][]lbRouteHTTP{
					"insecure.acme.io": {
						{
							match: lbRouteHTTPMatch{
								path:     "/api/foo-insecure",
								pathType: routePathTypeExact,
							},
							backendRef: backendRef{name: "app"},
						},
					},
				},
			},
		},
		effectiveWAFConfig: config,
	}
}

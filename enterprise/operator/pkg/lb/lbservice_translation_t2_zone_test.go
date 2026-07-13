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
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lbextension "github.com/cilium/cilium/enterprise/operator/pkg/lb/extension"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestDesiredEnvoyClusterLoadAssignment(t *testing.T) {
	tr := &lbServiceT2Translator{}

	testCases := []struct {
		name     string
		mode     lbServiceZoneAwareModeType
		zone     string
		backend  backend
		expected *envoy_config_endpoint_v3.ClusterLoadAssignment
	}{
		{
			name: "groups endpoints per known zone",
			mode: lbServiceZoneAwareModeDisabled,
			backend: backend{
				lbBackends: []lbBackend{
					{
						addresses:    []string{"10.0.0.1", "10.0.0.2"},
						addressZones: map[string]string{"10.0.0.1": "zone-a", "10.0.0.2": "zone-b"},
						port:         8080,
						weight:       1,
					},
				},
			},
			expected: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "backend_cluster_test",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-a"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.1", 8080, 1),
						},
					},
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-b"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.2", 8080, 1),
						},
					},
				},
			},
		},
		{
			name: "adds fallback bucket for unknown or missing zones",
			mode: lbServiceZoneAwareModeDisabled,
			backend: backend{
				lbBackends: []lbBackend{
					{
						addresses:    []string{"10.0.0.1", "10.0.0.9"},
						addressZones: map[string]string{"10.0.0.1": "zone-a", "10.0.0.9": lbServiceZoneUnknown},
						port:         8080,
						weight:       1,
					},
				},
			},
			expected: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "backend_cluster_test",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-a"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.1", 8080, 1),
						},
					},
					{
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.9", 8080, 1),
						},
					},
				},
			},
		},
		{
			name: "unknown only stays in single no-locality bucket",
			mode: lbServiceZoneAwareModeDisabled,
			backend: backend{
				lbBackends: []lbBackend{
					{
						addresses:    []string{"10.0.0.9"},
						addressZones: map[string]string{"10.0.0.9": lbServiceZoneUnknown},
						port:         8080,
						weight:       1,
					},
				},
			},
			expected: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "backend_cluster_test",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.9", 8080, 1),
						},
					},
				},
			},
		},
		{
			name: "require same zone keeps only matching zoned backends",
			mode: lbServiceZoneAwareModeRequireSameZone,
			zone: "zone-a",
			backend: backend{
				lbBackends: []lbBackend{
					{
						addresses:    []string{"10.0.0.1", "10.0.0.9", "10.0.0.2"},
						addressZones: map[string]string{"10.0.0.1": "zone-a", "10.0.0.9": lbServiceZoneUnknown, "10.0.0.2": "zone-b"},
						port:         8080,
						weight:       1,
					},
				},
			},
			expected: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "backend_cluster_test",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-a"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.1", 8080, 1),
						},
					},
				},
			},
		},
		{
			name: "require same zone fails closed when no local backends exist",
			mode: lbServiceZoneAwareModeRequireSameZone,
			zone: "zone-c",
			backend: backend{
				lbBackends: []lbBackend{
					{
						addresses:    []string{"10.0.0.1", "10.0.0.9", "10.0.0.2"},
						addressZones: map[string]string{"10.0.0.1": "zone-a", "10.0.0.9": lbServiceZoneUnknown, "10.0.0.2": "zone-b"},
						port:         8080,
						weight:       1,
					},
				},
			},
			expected: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "backend_cluster_test",
				Endpoints:   []*envoy_config_endpoint_v3.LocalityLbEndpoints{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tr.desiredEnvoyClusterLoadAssignment("backend_cluster_test", tc.backend, tc.mode, tc.zone)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestDesiredEnvoyClusterLocalityAwarePolicy(t *testing.T) {
	testCases := []struct {
		name                      string
		mode                      lbServiceZoneAwareModeType
		serviceMinBackendCount    uint64
		expectedZoneAwareLbConfig *envoy_config_cluster_v3.Cluster_CommonLbConfig_ZoneAwareLbConfig
	}{
		{
			name: "disabled zone-aware mode does not set zone-aware LB config",
			mode: lbServiceZoneAwareModeDisabled,
		},
		{
			name:                   "prefer same zone sets default zone-aware LB config",
			mode:                   lbServiceZoneAwareModePreferSameZone,
			serviceMinBackendCount: 2,
			expectedZoneAwareLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig_ZoneAwareLbConfig{
				MinClusterSize: wrapperspb.UInt64(2),
			},
		},
		{
			name:                   "prefer same zone uses per-service min backend count override",
			mode:                   lbServiceZoneAwareModePreferSameZone,
			serviceMinBackendCount: 7,
			expectedZoneAwareLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig_ZoneAwareLbConfig{
				MinClusterSize: wrapperspb.UInt64(7),
			},
		},
		{
			name: "require same zone does not set zone-aware LB config",
			mode: lbServiceZoneAwareModeRequireSameZone,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &lbServiceT2Translator{
				config: reconcilerConfig{},
			}

			lbService := &lbService{
				zoneAwareMode:            tc.mode,
				zoneAwareMinBackendCount: tc.serviceMinBackendCount,
			}

			cluster := tr.desiredEnvoyCluster(lbService, "backend_cluster_test", backend{
				tcpConfig: &lbBackendTCPConfig{},
			}, "")

			require.Equal(t, tc.expectedZoneAwareLbConfig, cluster.CommonLbConfig.GetZoneAwareLbConfig())
		})
	}
}

func TestDesiredEnvoyZoneAwarenessLoadAssignment(t *testing.T) {
	tr := &lbServiceT2Translator{}

	testCases := []struct {
		name     string
		model    *lbService
		expected *envoy_config_endpoint_v3.ClusterLoadAssignment
	}{
		{
			name: "prefer same zone generates locality endpoints for zoned T2 nodes only",
			model: &lbService{
				zoneAwareMode:       lbServiceZoneAwareModePreferSameZone,
				t2NodeIPv4Addresses: []string{"10.0.0.2", "10.0.0.3", "10.0.0.9"},
				t2NodeIPv4Zones: map[string]string{
					"10.0.0.2": "zone-a",
					"10.0.0.3": "zone-b",
					"10.0.0.9": lbServiceZoneUnknown,
				},
			},
			expected: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: envoy.LocalityClusterName,
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-a"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.2", 1, 1),
						},
					},
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-b"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.3", 1, 1),
						},
					},
				},
			},
		},
		{
			name: "all unknown-zone T2 nodes omit locality cluster assignment",
			model: &lbService{
				zoneAwareMode:       lbServiceZoneAwareModePreferSameZone,
				t2NodeIPv4Addresses: []string{"10.0.0.9"},
				t2NodeIPv4Zones: map[string]string{
					"10.0.0.9": lbServiceZoneUnknown,
				},
			},
		},
		{
			name: "disabled mode does not generate locality cluster assignment",
			model: &lbService{
				zoneAwareMode:       lbServiceZoneAwareModeDisabled,
				t2NodeIPv4Addresses: []string{"10.0.0.2"},
				t2NodeIPv4Zones:     map[string]string{"10.0.0.2": "zone-a"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, tr.desiredEnvoyZoneAwarenessLoadAssignment(tc.model))
		})
	}
}

func TestDesiredCiliumEnvoyConfigsRequireSameZone(t *testing.T) {
	tr := &lbServiceT2Translator{
		logger: hivetest.Logger(t),
		httpExtensions: []lbextension.HTTPExtension{
			&testHTTPRouteExtension{},
		},
	}

	vip := "100.64.0.100"
	testCases := []struct {
		name         string
		model        *lbService
		expectedCECs []*ciliumv2.CiliumEnvoyConfig
	}{
		{
			name: "creates core CEC and one endpoint CEC per known T2 zone",
			model: &lbService{
				namespace: "default",
				name:      "lb-1",
				vip: lbVIP{
					name:         "lb-1",
					ipFamily:     ipFamilyV4,
					assignedIPv4: &vip,
					bindStatus: lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: true,
						bindIssue:      "",
					},
				},
				zoneAwareMode: lbServiceZoneAwareModeRequireSameZone,
				applications: lbApplications{
					tcpProxy: &lbApplicationTCPProxy{
						tierMode: tierModeT2,
						routes: []lbRouteTCPProxy{
							{backendRef: backendRef{name: "app"}},
						},
					},
				},
				referencedBackends: map[string]backend{
					"app": {
						lbAlgorithm: lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin},
						lbBackends: []lbBackend{
							{
								addresses:    []string{"10.0.0.1", "10.0.0.2"},
								addressZones: map[string]string{"10.0.0.1": "zone-a", "10.0.0.2": "zone-b"},
								port:         8080,
								weight:       1,
							},
						},
						tcpConfig: &lbBackendTCPConfig{connectTimeoutSeconds: 5},
					},
				},
				t2NodeIPv4Zones: map[string]string{
					"172.18.0.2": "zone-a",
					"172.18.0.3": "zone-b",
				},
				t2LabelSelector: labels.Everything(),
			},
			expectedCECs: []*ciliumv2.CiliumEnvoyConfig{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "lbfe-lb-1"},
					Spec: ciliumv2.CiliumEnvoyConfigSpec{
						NodeSelector: &slim_metav1.LabelSelector{
							MatchLabels:      map[string]string{},
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "lbfe-zone-a-lb-1"},
					Spec: ciliumv2.CiliumEnvoyConfigSpec{
						NodeSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"topology.kubernetes.io/zone": "zone-a",
							},
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "lbfe-zone-b-lb-1"},
					Spec: ciliumv2.CiliumEnvoyConfigSpec{
						NodeSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"topology.kubernetes.io/zone": "zone-b",
							},
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cecs, err := tr.DesiredCiliumEnvoyConfigs(tc.model)
			require.NoError(t, err)
			require.Len(t, cecs, len(tc.expectedCECs))
			require.Equal(t, tc.expectedCECs, expectedCECs(cecs))

			requireNoBackendResources(t, cecs[0], "backend_cluster_app")
			requireZonedBackendResources(t, cecs[1], "default/lbfe-lb-1/backend_cluster_app", &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "default/lbfe-lb-1/backend_cluster_app",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-a"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.1", 8080, 1),
						},
					},
				},
			})
			requireZonedBackendResources(t, cecs[2], "default/lbfe-lb-1/backend_cluster_app", &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "default/lbfe-lb-1/backend_cluster_app",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-b"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("10.0.0.2", 8080, 1),
						},
					},
				},
			})
		})
	}
}

func TestDesiredCiliumEnvoyConfigsRequireSameZoneHostnameBackend(t *testing.T) {
	tr := &lbServiceT2Translator{
		logger: hivetest.Logger(t),
		httpExtensions: []lbextension.HTTPExtension{
			&testHTTPRouteExtension{},
		},
	}

	vip := "100.64.0.100"
	testCases := []struct {
		name                        string
		model                       *lbService
		expectedCECNames            []string
		coreBackendClusterName      string
		expectedBackendClusterName  string
		expectedZoneALoadAssignment *envoy_config_endpoint_v3.ClusterLoadAssignment
		expectedZoneBLoadAssignment *envoy_config_endpoint_v3.ClusterLoadAssignment
	}{
		{
			name: "creates core CEC and zoned CECs with inline hostname load assignments",
			model: &lbService{
				namespace: "default",
				name:      "lb-hostname",
				vip: lbVIP{
					name:         "lb-hostname",
					ipFamily:     ipFamilyV4,
					assignedIPv4: &vip,
					bindStatus: lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: true,
					},
				},
				zoneAwareMode: lbServiceZoneAwareModeRequireSameZone,
				applications: lbApplications{
					tcpProxy: &lbApplicationTCPProxy{
						tierMode: tierModeT2,
						routes: []lbRouteTCPProxy{
							{backendRef: backendRef{name: "app"}},
						},
					},
				},
				referencedBackends: map[string]backend{
					"app": {
						typ:         lbBackendTypeHostname,
						lbAlgorithm: lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin},
						lbBackends: []lbBackend{
							{
								addresses:    []string{"app-a.example.com", "app-b.example.com"},
								addressZones: map[string]string{"app-a.example.com": "zone-a", "app-b.example.com": "zone-b"},
								port:         8080,
								weight:       1,
							},
						},
						tcpConfig: &lbBackendTCPConfig{connectTimeoutSeconds: 5},
					},
				},
				t2NodeIPv4Zones: map[string]string{
					"172.18.0.2": "zone-a",
					"172.18.0.3": "zone-b",
				},
				t2LabelSelector: labels.Everything(),
			},
			expectedCECNames:           []string{"lbfe-lb-hostname", "lbfe-zone-a-lb-hostname", "lbfe-zone-b-lb-hostname"},
			coreBackendClusterName:     "backend_cluster_app",
			expectedBackendClusterName: "default/lbfe-lb-hostname/backend_cluster_app",
			expectedZoneALoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "default/lbfe-lb-hostname/backend_cluster_app",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-a"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("app-a.example.com", 8080, 1),
						},
					},
				},
			},
			expectedZoneBLoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "default/lbfe-lb-hostname/backend_cluster_app",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
					{
						Locality: &envoy_config_core_v3.Locality{Zone: "zone-b"},
						LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
							newLBEndpoint("app-b.example.com", 8080, 1),
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cecs, err := tr.DesiredCiliumEnvoyConfigs(tc.model)
			require.NoError(t, err)
			require.Len(t, cecs, len(tc.expectedCECNames))
			require.Equal(t, tc.expectedCECNames, []string{cecs[0].Name, cecs[1].Name, cecs[2].Name})

			requireNoBackendResources(t, cecs[0], tc.coreBackendClusterName)
			requireZonedHostnameBackendResources(t, cecs[1], tc.expectedBackendClusterName, tc.expectedZoneALoadAssignment)
			requireZonedHostnameBackendResources(t, cecs[2], tc.expectedBackendClusterName, tc.expectedZoneBLoadAssignment)
		})
	}
}

func expectedCECs(cecs []*ciliumv2.CiliumEnvoyConfig) []*ciliumv2.CiliumEnvoyConfig {
	result := make([]*ciliumv2.CiliumEnvoyConfig, 0, len(cecs))
	for _, cec := range cecs {
		result = append(result, &ciliumv2.CiliumEnvoyConfig{
			ObjectMeta: metav1.ObjectMeta{Name: cec.Name},
			Spec:       ciliumv2.CiliumEnvoyConfigSpec{NodeSelector: cec.Spec.NodeSelector},
		})
	}

	return result
}

func requireNoBackendResources(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, backendClusterName string) {
	t.Helper()
	require.NotEmpty(t, cec.Spec.Resources)
	for _, res := range cec.Spec.Resources {
		require.NotEqual(t, envoy.EndpointTypeURL, res.GetTypeUrl())
		if res.GetTypeUrl() != envoy.ClusterTypeURL {
			continue
		}
		message, err := res.UnmarshalNew()
		require.NoError(t, err)
		cluster, ok := message.(*envoy_config_cluster_v3.Cluster)
		require.True(t, ok)
		require.NotEqual(t, backendClusterName, cluster.Name)
	}
}

func requireZonedBackendResources(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, expectedClusterName string, expectedLoadAssignment *envoy_config_endpoint_v3.ClusterLoadAssignment) {
	t.Helper()
	require.Len(t, cec.Spec.Resources, 2)

	clusterResource := cec.Spec.Resources[0]
	require.Equal(t, envoy.ClusterTypeURL, clusterResource.GetTypeUrl())
	message, err := clusterResource.UnmarshalNew()
	require.NoError(t, err)
	cluster, ok := message.(*envoy_config_cluster_v3.Cluster)
	require.True(t, ok)
	require.Equal(t, expectedClusterName, cluster.Name)
	require.Nil(t, cluster.LoadAssignment)

	loadAssignmentResource := cec.Spec.Resources[1]
	require.Equal(t, envoy.EndpointTypeURL, loadAssignmentResource.GetTypeUrl())
	message, err = loadAssignmentResource.UnmarshalNew()
	require.NoError(t, err)
	loadAssignment, ok := message.(*envoy_config_endpoint_v3.ClusterLoadAssignment)
	require.True(t, ok)
	require.Truef(t, proto.Equal(expectedLoadAssignment, loadAssignment), "expected %s, got %s", expectedLoadAssignment, loadAssignment)
}

func requireZonedHostnameBackendResources(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, expectedClusterName string, expectedLoadAssignment *envoy_config_endpoint_v3.ClusterLoadAssignment) {
	t.Helper()
	require.Len(t, cec.Spec.Resources, 1)

	clusterResource := cec.Spec.Resources[0]
	require.Equal(t, envoy.ClusterTypeURL, clusterResource.GetTypeUrl())
	message, err := clusterResource.UnmarshalNew()
	require.NoError(t, err)
	cluster, ok := message.(*envoy_config_cluster_v3.Cluster)
	require.True(t, ok)
	require.Equal(t, expectedClusterName, cluster.Name)
	require.Truef(t, proto.Equal(expectedLoadAssignment, cluster.LoadAssignment), "expected %s, got %s", expectedLoadAssignment, cluster.LoadAssignment)
}

func newLBEndpoint(addr string, port uint32, weight uint32) *envoy_config_endpoint_v3.LbEndpoint {
	return &envoy_config_endpoint_v3.LbEndpoint{
		LoadBalancingWeight: wrapperspb.UInt32(weight),
		HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
			Endpoint: &envoy_config_endpoint_v3.Endpoint{
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Address:       addr,
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: port},
						},
					},
				},
			},
		},
	}
}

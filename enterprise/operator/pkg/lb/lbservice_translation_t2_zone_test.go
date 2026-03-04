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

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/envoy"
)

func TestDesiredEnvoyClusterLoadAssignmentZones(t *testing.T) {
	tr := &lbServiceT2Translator{}

	testCases := []struct {
		name     string
		backend  backend
		expected *envoy_config_endpoint_v3.ClusterLoadAssignment
	}{
		{
			name: "groups endpoints per known zone",
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tr.desiredEnvoyClusterLoadAssignment("backend_cluster_test", tc.backend)
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
			})

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

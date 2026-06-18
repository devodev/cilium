// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"bytes"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	ciliumMetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestExpectedStatus(t *testing.T) {
	testCases := []struct {
		ok             int
		total          int
		expectedStatus string
	}{
		{
			ok:             1,
			total:          1,
			expectedStatus: "OK",
		},
		{
			ok:             1,
			total:          2,
			expectedStatus: "DEG",
		},
		{
			ok:             0,
			total:          0,
			expectedStatus: "DEG",
		},
	}

	lb := &LoadbalancerClient{}
	for _, tc := range testCases {
		require.Equal(t, tc.expectedStatus, lb.statusText(tc.ok, tc.total))
	}
}

func TestOverallStatus(t *testing.T) {
	testCases := []struct {
		name           string
		bgpRouteStatus LoadbalancerStatusModelSimpleStatus
		bgpPeerStatus  LoadbalancerStatusModelSimpleStatus
		expected       string
	}{
		{
			name: "online requires both bgp routes and peers",
			bgpRouteStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "OK",
				OK:     1,
				Total:  1,
			},
			bgpPeerStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "OK",
				OK:     1,
				Total:  1,
			},
			expected: "ONLINE",
		},
		{
			name: "offline when peers are missing",
			bgpRouteStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "OK",
				OK:     1,
				Total:  1,
			},
			bgpPeerStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "DEG",
				OK:     0,
				Total:  1,
			},
			expected: "OFFLINE",
		},
		{
			name: "offline when vip is not assigned",
			bgpRouteStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "N/A",
			},
			bgpPeerStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "N/A",
			},
			expected: "OFFLINE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, overallStatus(tc.bgpRouteStatus, tc.bgpPeerStatus))
		})
	}
}

func TestRelationText(t *testing.T) {
	testCases := []struct {
		name           string
		status         string
		ok             int
		total          int
		relationOutput string
		expected       string
	}{
		{
			name:           "percentage with zero total falls back to zero percent",
			status:         "DEG",
			ok:             0,
			total:          0,
			relationOutput: RelationOutputPercentage,
			expected:       "[0%]",
		},
		{
			name:           "percentage with non-zero total is computed normally",
			status:         "DEG",
			ok:             1,
			total:          2,
			relationOutput: RelationOutputPercentage,
			expected:       "[50%]",
		},
		{
			name:           "numbers output preserves zero total",
			status:         "DEG",
			ok:             0,
			total:          0,
			relationOutput: RelationOutputNumbers,
			expected:       "[0/0]",
		},
		{
			name:           "n/a status omits relation text",
			status:         "N/A",
			ok:             0,
			total:          0,
			relationOutput: RelationOutputPercentage,
			expected:       "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, relationText(tc.status, tc.ok, tc.total, tc.relationOutput))
		})
	}
}

func TestOutputSortsModelDeterministically(t *testing.T) {
	testCases := []struct {
		name     string
		model    *LoadbalancerStatusModel
		params   Parameters
		expected string
	}{
		{
			name: "json output",
			model: &LoadbalancerStatusModel{
				Services: []LoadbalancerStatusModelService{
					{
						Namespace: "default",
						Name:      "svc-b",
						VIP:       "100.64.0.20",
						Port:      81,
						BGPPeerStatus: BGPPeerStatus{
							Peers: []BGPPeer{
								{Name: "10.0.0.2-65002", IsHealthy: true},
								{Name: "10.0.0.1-65001", IsHealthy: false},
							},
						},
						T1T2HCStatus: HealthChecksStatus{
							HealthChecks: []HCStatus{
								{From: "node-b", Endpoint: "10.0.1.20:8080", IsHealthy: true},
								{From: "node-a", Endpoint: "10.0.1.10:8080", IsHealthy: false},
							},
						},
						T2BackendHCStatus: HealthChecksStatus{
							HealthChecks: []HCStatus{
								{From: "node-b", Endpoint: "10.0.2.20:8080", IsHealthy: true},
								{From: "node-a", Endpoint: "10.0.2.10:8080", IsHealthy: false},
							},
						},
						BackendpoolStatus: LoadbalancerStatusModelGroupedStatus{
							Groups: []LoadbalancerStatusModelSimpleStatus{
								{Status: "OK", OK: 2, Total: 2},
								{Status: "DEG", OK: 1, Total: 2},
							},
						},
					},
					{
						Namespace: "default",
						Name:      "svc-a",
						VIP:       "100.64.0.10",
						Port:      80,
					},
				},
			},
			params: Parameters{
				Output: "json",
			},
			expected: `{"summary":{"nrOfT1Nodes":0,"nrOfT2Nodes":0,"nrOfServices":0,"nrOfVips":0},"services":[{"namespace":"default","name":"svc-a","vip":"100.64.0.10","port":80,"type":"","deploymentMode":"","bgpPeerStatus":{"status":"","ok":0,"total":0,"peers":null},"bgpRouteStatus":{"status":"","ok":0,"total":0},"t1NodeStatus":{"status":"","ok":0,"total":0},"t1t2HealthcheckStatus":{"status":"","ok":0,"total":0,"endpoints":null},"t2NodeStatus":{"status":"","ok":0,"total":0},"t2BackendHealthcheckStatus":{"status":"","ok":0,"total":0,"endpoints":null},"backendpoolStatus":{"status":"","groups":null},"status":""},{"namespace":"default","name":"svc-b","vip":"100.64.0.20","port":81,"type":"","deploymentMode":"","bgpPeerStatus":{"status":"","ok":0,"total":0,"peers":[{"name":"10.0.0.1-65001","healthy":false},{"name":"10.0.0.2-65002","healthy":true}]},"bgpRouteStatus":{"status":"","ok":0,"total":0},"t1NodeStatus":{"status":"","ok":0,"total":0},"t1t2HealthcheckStatus":{"status":"","ok":0,"total":0,"endpoints":[{"from":"node-a","endpoint":"10.0.1.10:8080","healthy":false},{"from":"node-b","endpoint":"10.0.1.20:8080","healthy":true}]},"t2NodeStatus":{"status":"","ok":0,"total":0},"t2BackendHealthcheckStatus":{"status":"","ok":0,"total":0,"endpoints":[{"from":"node-a","endpoint":"10.0.2.10:8080","healthy":false},{"from":"node-b","endpoint":"10.0.2.20:8080","healthy":true}]},"backendpoolStatus":{"status":"","groups":[{"status":"DEG","ok":1,"total":2},{"status":"OK","ok":2,"total":2}]},"status":""}]}
`,
		},
		{
			name: "summary output",
			model: &LoadbalancerStatusModel{
				Services: []LoadbalancerStatusModelService{
					{
						Namespace: "default",
						Name:      "svc-b",
						VIP:       "100.64.0.20",
						Port:      81,
						BGPPeerStatus: BGPPeerStatus{
							Peers: []BGPPeer{
								{Name: "10.0.0.2-65002", IsHealthy: true},
								{Name: "10.0.0.1-65001", IsHealthy: false},
							},
						},
						T1T2HCStatus: HealthChecksStatus{
							HealthChecks: []HCStatus{
								{From: "node-b", Endpoint: "10.0.1.20:8080", IsHealthy: true},
								{From: "node-a", Endpoint: "10.0.1.10:8080", IsHealthy: false},
							},
						},
						T2BackendHCStatus: HealthChecksStatus{
							HealthChecks: []HCStatus{
								{From: "node-b", Endpoint: "10.0.2.20:8080", IsHealthy: true},
								{From: "node-a", Endpoint: "10.0.2.10:8080", IsHealthy: false},
							},
						},
						BackendpoolStatus: LoadbalancerStatusModelGroupedStatus{
							Groups: []LoadbalancerStatusModelSimpleStatus{
								{Status: "OK", OK: 2, Total: 2},
								{Status: "DEG", OK: 1, Total: 2},
							},
						},
					},
					{
						Namespace: "default",
						Name:      "svc-a",
						VIP:       "100.64.0.10",
						Port:      80,
					},
				},
			},
			params: Parameters{
				Output:         "summary",
				RelationOutput: RelationOutputNumbers,
			},
			expected: `=========
Summary
=========

T1 Nodes:   0
T2 Nodes:   0
Services:   0
VIPs:       0

=========
Services
=========

Namespace   Name    VIP           Port   Type   D-Mode   BGP Peers   BGP Routes   T1   HC T1->[T2|B]   T2   HC T2->B   Backendpools   Status
---------   ----    ---           ----   ----   ------   ---------   ----------   --   -------------   --   --------   ------------   ------
default     svc-a   100.64.0.10   80                                                                                                  
default     svc-b   100.64.0.20   81                                                                                                  
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual bytes.Buffer
			require.NoError(t, tc.model.Output(&actual, tc.params))
			require.Equal(t, tc.expected, actual.String())
		})
	}
}

func TestOutputColorsDoNotLeakAcrossCalls(t *testing.T) {
	lsm := &LoadbalancerStatusModel{
		Services: []LoadbalancerStatusModelService{
			{
				Namespace:      "test-ns",
				Name:           "test-svc",
				VIP:            "100.64.0.10",
				Port:           80,
				Type:           "TCP Proxy",
				DeploymentMode: "T1",
				BGPPeerStatus: BGPPeerStatus{
					LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
						Status: "OK",
						OK:     1,
						Total:  1,
					},
				},
				BGPRouteStatus: LoadbalancerStatusModelSimpleStatus{
					Status: "OK",
					OK:     1,
					Total:  1,
				},
				T1NodeStatus: LoadbalancerStatusModelSimpleStatus{
					Status: "OK",
					OK:     1,
					Total:  1,
				},
				T1T2HCStatus: HealthChecksStatus{
					LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
						Status: "OK",
						OK:     1,
						Total:  1,
					},
				},
				T2NodeStatus: LoadbalancerStatusModelSimpleStatus{
					Status: "OK",
					OK:     1,
					Total:  1,
				},
				T2BackendHCStatus: HealthChecksStatus{
					LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
						Status: "OK",
						OK:     1,
						Total:  1,
					},
				},
				BackendpoolStatus: LoadbalancerStatusModelGroupedStatus{
					Status: "OK",
				},
				Status: "ONLINE",
			},
		},
	}

	var noColorOut bytes.Buffer
	err := lsm.Output(&noColorOut, Parameters{Output: "summary", Colors: false})
	require.NoError(t, err)
	require.NotContains(t, noColorOut.String(), ansiDefault)

	var colorOut bytes.Buffer
	err = lsm.Output(&colorOut, Parameters{Output: "summary", Colors: true})
	require.NoError(t, err)
	require.Contains(t, colorOut.String(), ansiDefault)
}

func TestGetT2Status(t *testing.T) {
	ipv4 := "1.1.1.1"
	testCases := []struct {
		lbsvc           isovalentv1alpha1.LBService
		nodeEnvoyConfig map[string]*EnvoyConfigModel
		expectedStatus  LoadbalancerStatusModelSimpleStatus
	}{
		{
			expectedStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "N/A",
			},
		},
		{
			lbsvc: isovalentv1alpha1.LBService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-svc",
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: &ipv4,
					},
				},
			},
			nodeEnvoyConfig: map[string]*EnvoyConfigModel{
				"t2-node": {
					Configs: []struct {
						Type                  string "json:\"@type\""
						DynamicActiveClusters []struct {
							Cluster struct {
								Name string "json:\"name\""
							} "json:\"cluster,omitempty\""
						} "json:\"dynamic_active_clusters,omitempty\""
						DynamicEndpointConfigs []struct {
							EndpointConfig struct {
								ClusterName string "json:\"cluster_name\""
								Endpoints   []struct {
									LbEndpoints []struct {
										Endpoint struct {
											Address struct {
												SocketAddress struct {
													Address   string "json:\"address\""
													PortValue int    "json:\"port_value\""
												} "json:\"socket_address\""
											} "json:\"address\""
										} "json:\"endpoint\""
										HealthStatus string "json:\"health_status\""
									} "json:\"lb_endpoints\""
								} "json:\"endpoints\""
							} "json:\"endpoint_config\""
						} "json:\"dynamic_endpoint_configs,omitempty\""
						DynamicListeners []struct {
							Name        string "json:\"name\""
							ActiveState struct {
								Listener struct {
									Name    string "json:\"name\""
									Address struct {
										SocketAddress struct {
											Address   string "json:\"address\""
											PortValue int    "json:\"port_value\""
										} "json:\"socket_address\""
									} "json:\"address\""
								} "json:\"listener\""
							} "json:\"active_state\""
						} "json:\"dynamic_listeners,omitempty\""
						DynamicRouteConfigs []struct {
							RouteConfig struct {
								Name string "json:\"name\""
							} "json:\"route_config,omitempty\""
						} "json:\"dynamic_route_configs,omitempty\""
						DynamicActiveSecrets []struct {
							Name   string "json:\"name\""
							Secret struct {
								Name string "json:\"name\""
							} "json:\"secret,omitempty\""
						} "json:\"dynamic_active_secrets,omitempty\""
					}{
						{
							Type: "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump",
							DynamicEndpointConfigs: []struct {
								EndpointConfig struct {
									ClusterName string "json:\"cluster_name\""
									Endpoints   []struct {
										LbEndpoints []struct {
											Endpoint struct {
												Address struct {
													SocketAddress struct {
														Address   string "json:\"address\""
														PortValue int    "json:\"port_value\""
													} "json:\"socket_address\""
												} "json:\"address\""
											} "json:\"endpoint\""
											HealthStatus string "json:\"health_status\""
										} "json:\"lb_endpoints\""
									} "json:\"endpoints\""
								} "json:\"endpoint_config\""
							}{
								{
									EndpointConfig: struct {
										ClusterName string "json:\"cluster_name\""
										Endpoints   []struct {
											LbEndpoints []struct {
												Endpoint struct {
													Address struct {
														SocketAddress struct {
															Address   string "json:\"address\""
															PortValue int    "json:\"port_value\""
														} "json:\"socket_address\""
													} "json:\"address\""
												} "json:\"endpoint\""
												HealthStatus string "json:\"health_status\""
											} "json:\"lb_endpoints\""
										} "json:\"endpoints\""
									}{
										ClusterName: "test-ns/lbfe-test-svc/",
										Endpoints: []struct {
											LbEndpoints []struct {
												Endpoint struct {
													Address struct {
														SocketAddress struct {
															Address   string "json:\"address\""
															PortValue int    "json:\"port_value\""
														} "json:\"socket_address\""
													} "json:\"address\""
												} "json:\"endpoint\""
												HealthStatus string "json:\"health_status\""
											} "json:\"lb_endpoints\""
										}{
											{
												[]struct {
													Endpoint struct {
														Address struct {
															SocketAddress struct {
																Address   string "json:\"address\""
																PortValue int    "json:\"port_value\""
															} "json:\"socket_address\""
														} "json:\"address\""
													} "json:\"endpoint\""
													HealthStatus string "json:\"health_status\""
												}{
													{
														HealthStatus: "HEALTHY",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "OK",
				OK:     1,
				Total:  1,
			},
		},
	}

	lb := &LoadbalancerClient{}
	for _, tc := range testCases {
		require.Equal(t, tc.expectedStatus, lb.getT2Status(tc.lbsvc, tc.nodeEnvoyConfig))
	}
}

func TestGetBackends(t *testing.T) {
	ipv4 := "100.64.0.10"
	forceT1 := isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1

	testCases := []struct {
		name         string
		lbsvc        isovalentv1alpha1.LBService
		t1NodeZones  map[string]string
		nodeServices map[string][]*models.Service
		expected     LoadbalancerStatusModelGroupedStatus
	}{
		{
			name: "preferSameZone counts only matching T1 nodes",
			lbsvc: isovalentv1alpha1.LBService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-svc",
				},
				Spec: isovalentv1alpha1.LBServiceSpec{
					Port: 80,
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: &forceT1,
						},
					},
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{
							Mode: isovalentv1alpha1.LBZoneAwareModePreferSameZone,
						},
					},
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: &ipv4,
					},
				},
			},
			t1NodeZones: map[string]string{
				"t1-a": "zone-a",
				"t1-b": "zone-b",
			},
			nodeServices: map[string][]*models.Service{
				"t1-a": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.7", 8080, "zone-a"),
				},
				"t1-b": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.8", 8080, "zone-b"),
				},
			},
			expected: LoadbalancerStatusModelGroupedStatus{
				Status: "OK",
				Groups: []LoadbalancerStatusModelSimpleStatus{
					{
						Status: "OK",
						OK:     2,
						Total:  2,
					},
				},
			},
		},
		{
			name: "non zone aware is OK when all backends are active on all T1 nodes",
			lbsvc: isovalentv1alpha1.LBService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-svc",
				},
				Spec: isovalentv1alpha1.LBServiceSpec{
					Port: 80,
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: &forceT1,
						},
					},
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: &ipv4,
					},
				},
			},
			t1NodeZones: map[string]string{
				"t1-a": "zone-a",
				"t1-b": "zone-b",
			},
			nodeServices: map[string][]*models.Service{
				"t1-a": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.7", 8080, ""),
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.8", 8080, ""),
				},
				"t1-b": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.7", 8080, ""),
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.8", 8080, ""),
				},
			},
			expected: LoadbalancerStatusModelGroupedStatus{
				Status: "OK",
				Groups: []LoadbalancerStatusModelSimpleStatus{
					{
						Status: "OK",
						OK:     2,
						Total:  2,
					},
				},
			},
		},
		{
			name: "non zone aware is DEG when not all backends are active on all T1 nodes",
			lbsvc: isovalentv1alpha1.LBService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-svc",
				},
				Spec: isovalentv1alpha1.LBServiceSpec{
					Port: 80,
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: &forceT1,
						},
					},
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: &ipv4,
					},
				},
			},
			t1NodeZones: map[string]string{
				"t1-a": "zone-a",
				"t1-b": "zone-b",
			},
			nodeServices: map[string][]*models.Service{
				"t1-a": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.7", 8080, ""),
				},
				"t1-b": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.8", 8080, ""),
				},
			},
			expected: LoadbalancerStatusModelGroupedStatus{
				Status: "DEG",
				Groups: []LoadbalancerStatusModelSimpleStatus{
					{
						Status: "DEG",
						OK:     0,
						Total:  2,
					},
				},
			},
		},
		{
			name: "preferSameZone falls back when some T1 nodes have no zone",
			lbsvc: isovalentv1alpha1.LBService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-svc",
				},
				Spec: isovalentv1alpha1.LBServiceSpec{
					Port: 80,
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: &forceT1,
						},
					},
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{
							Mode: isovalentv1alpha1.LBZoneAwareModePreferSameZone,
						},
					},
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: &ipv4,
					},
				},
			},
			t1NodeZones: map[string]string{
				"t1-a": "zone-a",
			},
			nodeServices: map[string][]*models.Service{
				"t1-a": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.7", 8080, "zone-a"),
				},
				"t1-b": {
					newT1BackendStatusService("test-ns", "lbfe-test-svc", ipv4, 80, "172.18.0.8", 8080, "zone-b"),
				},
			},
			expected: LoadbalancerStatusModelGroupedStatus{
				Status: "DEG",
				Groups: []LoadbalancerStatusModelSimpleStatus{
					{
						Status: "DEG",
						OK:     0,
						Total:  2,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lb := &LoadbalancerClient{t1NodeZones: tc.t1NodeZones}
			require.Equal(t, tc.expected, lb.getBackends(tc.lbsvc, tc.nodeServices, nil))
		})
	}
}

func TestMatchLabelsToLabelSelector(t *testing.T) {
	testCases := []struct {
		labelValues map[string]ciliumMetav1.MatchLabelsValue
		expected    []string
	}{
		{
			labelValues: nil,
			expected:    []string{},
		},
		{
			labelValues: map[string]ciliumMetav1.MatchLabelsValue{
				"key1": "value1",
				"key2": "value2",
			},
			expected: []string{
				"key1 in ( value1 )",
				"key2 in ( value2 )",
			},
		},
	}

	for _, tc := range testCases {
		actual := matchLabelsToLabelSelectors(tc.labelValues)

		slices.Sort(actual)
		require.Equal(t, tc.expected, actual)
	}
}

func TestMatchExpressionsToLabelSelector(t *testing.T) {
	testCases := []struct {
		requirements []ciliumMetav1.LabelSelectorRequirement
		expected     []string
	}{
		{
			requirements: nil,
			expected:     []string{},
		},
		{
			requirements: []ciliumMetav1.LabelSelectorRequirement{
				{
					Key:      "key1",
					Operator: ciliumMetav1.LabelSelectorOpIn,
					Values:   []string{"value1"},
				},
			},
			expected: []string{"key1 in ( value1 )"},
		},
		{
			requirements: []ciliumMetav1.LabelSelectorRequirement{
				{
					Key:      "key1",
					Operator: ciliumMetav1.LabelSelectorOpIn,
					Values:   []string{"value1", "value2"},
				},
				{
					Key:      "key2",
					Operator: ciliumMetav1.LabelSelectorOpIn,
					Values:   []string{"value3", "value4"},
				},
			},
			expected: []string{
				"key1 in ( value1 , value2 )",
				"key2 in ( value3 , value4 )",
			},
		},
	}

	for _, tc := range testCases {
		actual := matchExpressionsToLabelSelectors(tc.requirements)

		require.Equal(t, tc.expected, actual)
	}
}

func TestDeduplicateSlice(t *testing.T) {
	testCases := []struct {
		actual   []string
		expected []string
	}{
		{
			actual:   []string{},
			expected: []string{},
		},
		{
			actual: []string{
				"key1 in ( value1 , value2 )",
				"key2 in ( value1 , value2 )",
				"key1 in ( value1 , value2 )",
				"key2 in ( value1 , value2 )",
			},
			expected: []string{
				"key1 in ( value1 , value2 )",
				"key2 in ( value1 , value2 )",
			},
		},
	}

	for _, tc := range testCases {
		actual := deduplicateSlice(tc.actual)

		require.Equal(t, tc.expected, actual)
	}
}

func newT1BackendStatusService(namespace, name, frontendIP string, frontendPort uint16, backendIP string, backendPort uint16, backendZone string) *models.Service {
	backendIPCopy := backendIP

	spec := &models.ServiceSpec{
		Flags: &models.ServiceSpecFlags{
			Name:      name,
			Namespace: namespace,
		},
		FrontendAddress: &models.FrontendAddress{
			IP:   frontendIP,
			Port: frontendPort,
		},
	}

	realized := &models.ServiceSpec{
		Flags: &models.ServiceSpecFlags{
			Name:      name,
			Namespace: namespace,
			Type:      "LoadBalancer",
		},
		FrontendAddress: &models.FrontendAddress{
			IP:   frontendIP,
			Port: frontendPort,
		},
		BackendAddresses: []*models.BackendAddress{
			{
				IP:    &backendIPCopy,
				Port:  backendPort,
				State: "active",
				Zone:  backendZone,
			},
		},
	}

	return &models.Service{
		Spec: spec,
		Status: &models.ServiceStatus{
			Realized: realized,
		},
	}
}

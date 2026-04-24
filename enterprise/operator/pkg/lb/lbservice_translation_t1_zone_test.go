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

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

func TestEndpointSubsetsFromT2Nodes(t *testing.T) {
	tr := &lbServiceT1Translator{}

	testCases := []struct {
		name              string
		model             *lbService
		ipv6              bool
		expectedEndpoints []discoveryv1.Endpoint
		expectedPorts     []discoveryv1.EndpointPort
	}{
		{
			name: "all addresses zoned [IPv4]",
			model: &lbService{
				port:                443,
				t2NodeIPv4Addresses: []string{"10.0.0.2", "10.0.0.3"},
				t2NodeIPv4Zones: map[string]string{
					"10.0.0.2": "zone-a",
					"10.0.0.3": "zone-b",
				},
			},
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"10.0.0.2"},
					Zone:      ptr.To("zone-a"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
					},
				},
				{
					Addresses: []string{"10.0.0.3"},
					Zone:      ptr.To("zone-b"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-b"}},
					},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(443)),
				},
			},
		},
		{
			name: "mixed zoned and non-zoned addresses [IPv4]",
			model: &lbService{
				port:                443,
				t2NodeIPv4Addresses: []string{"10.0.0.2", "10.0.0.9"},
				t2NodeIPv4Zones: map[string]string{
					"10.0.0.2": "zone-a",
				},
			},
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"10.0.0.2"},
					Zone:      ptr.To("zone-a"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
					},
				},
				{
					Addresses: []string{"10.0.0.9"},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(443)),
				},
			},
		},
		{
			name: "all addresses without zone [IPv4]",
			model: &lbService{
				port:                443,
				t2NodeIPv4Addresses: []string{"10.0.0.9"},
				t2NodeIPv4Zones:     map[string]string{},
			},
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"10.0.0.9"},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(443)),
				},
			},
		},
		{
			name: "all addresses zoned [IPv6]",
			model: &lbService{
				port:                443,
				t2NodeIPv6Addresses: []string{"fd00::2", "fd00::3"},
				t2NodeIPv6Zones: map[string]string{
					"fd00::2": "zone-a",
					"fd00::3": "zone-b",
				},
			},
			ipv6: true,
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"fd00::2"},
					Zone:      ptr.To("zone-a"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
					},
				},
				{
					Addresses: []string{"fd00::3"},
					Zone:      ptr.To("zone-b"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-b"}},
					},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(443)),
				},
			},
		},
		{
			name: "mixed zoned and non-zoned addresses [IPv6]",
			model: &lbService{
				port:                443,
				t2NodeIPv6Addresses: []string{"fd00::2", "fd00::9"},
				t2NodeIPv6Zones: map[string]string{
					"fd00::2": "zone-a",
				},
			},
			ipv6: true,
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"fd00::2"},
					Zone:      ptr.To("zone-a"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
					},
				},
				{
					Addresses: []string{"fd00::9"},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(443)),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpoints, ports := tr.endpointSubsetsFromT2Nodes(tc.model, tc.ipv6)
			require.Equal(t, tc.expectedEndpoints, endpoints)
			require.Equal(t, tc.expectedPorts, ports)
		})
	}
}

func TestTCPEndpointSubsetsFromBackends(t *testing.T) {
	tr := &lbServiceT1Translator{}
	zoneA := "zone-a"

	testCases := []struct {
		name              string
		model             *lbService
		ipv6              bool
		expectedEndpoints []discoveryv1.Endpoint
		expectedPorts     []discoveryv1.EndpointPort
	}{
		{
			name: "zoned backend endpoint gets zone and hints [IPv4]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{{addresses: []string{"192.0.2.10"}, addressZones: map[string]string{"192.0.2.10": zoneA}, port: 8443}},
					},
				},
				applications: lbApplications{tcpProxy: &lbApplicationTCPProxy{routes: []lbRouteTCPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"192.0.2.10"},
					Zone:      ptr.To("zone-a"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
					},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(8443)),
				},
			},
		},
		{
			name: "mixed zoned and unzoned backend endpoints [IPv4]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{
							{addresses: []string{"192.0.2.10"}, addressZones: map[string]string{"192.0.2.10": zoneA}, port: 8443},
							{addresses: []string{"192.0.2.11"}, port: 8443},
						},
					},
				},
				applications: lbApplications{tcpProxy: &lbApplicationTCPProxy{routes: []lbRouteTCPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"192.0.2.10"},
					Zone:      ptr.To("zone-a"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
					},
				},
				{
					Addresses: []string{"192.0.2.11"},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(8443)),
				},
			},
		},
		{
			name: "no matching family returns nil [IPv4]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{{addresses: []string{"192.0.2.10"}, port: 8443}},
					},
				},
				applications: lbApplications{tcpProxy: &lbApplicationTCPProxy{routes: []lbRouteTCPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			ipv6:              true,
			expectedEndpoints: nil,
			expectedPorts:     nil,
		},
		{
			name: "zoned backend endpoint gets zone and hints [IPv6]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{{addresses: []string{"fd00::10"}, addressZones: map[string]string{"fd00::10": zoneA}, port: 8443}},
					},
				},
				applications: lbApplications{tcpProxy: &lbApplicationTCPProxy{routes: []lbRouteTCPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			ipv6: true,
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"fd00::10"},
					Zone:      ptr.To("zone-a"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
					},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("tcp"),
					Protocol: ptr.To(corev1.ProtocolTCP),
					Port:     ptr.To(int32(8443)),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpoints, ports := tr.tcpEndpointSubsetsFromBackends(tc.model, tc.ipv6)
			require.Equal(t, tc.expectedEndpoints, endpoints)
			require.Equal(t, tc.expectedPorts, ports)
		})
	}
}

func TestUDPEndpointSubsetsFromBackends(t *testing.T) {
	tr := &lbServiceT1Translator{}
	zoneB := "zone-b"

	testCases := []struct {
		name              string
		model             *lbService
		ipv6              bool
		expectedEndpoints []discoveryv1.Endpoint
		expectedPorts     []discoveryv1.EndpointPort
	}{
		{
			name: "zoned UDP backend endpoint gets zone and hints [IPv4]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{{addresses: []string{"198.51.100.10"}, addressZones: map[string]string{"198.51.100.10": zoneB}, port: 5353}},
					},
				},
				applications: lbApplications{udpProxy: &lbApplicationUDPProxy{routes: []lbRouteUDPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"198.51.100.10"},
					Zone:      ptr.To("zone-b"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-b"}},
					},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("udp"),
					Protocol: ptr.To(corev1.ProtocolUDP),
					Port:     ptr.To(int32(5353)),
				},
			},
		},
		{
			name: "mixed zoned and unzoned UDP backend endpoints [IPv4]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{
							{addresses: []string{"198.51.100.10"}, addressZones: map[string]string{"198.51.100.10": zoneB}, port: 5353},
							{addresses: []string{"198.51.100.11"}, port: 5353},
						},
					},
				},
				applications: lbApplications{udpProxy: &lbApplicationUDPProxy{routes: []lbRouteUDPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"198.51.100.10"},
					Zone:      ptr.To("zone-b"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-b"}},
					},
				},
				{
					Addresses: []string{"198.51.100.11"},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("udp"),
					Protocol: ptr.To(corev1.ProtocolUDP),
					Port:     ptr.To(int32(5353)),
				},
			},
		},
		{
			name: "zoned UDP backend endpoint gets zone and hints [IPv6]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{{addresses: []string{"fd00::53"}, addressZones: map[string]string{"fd00::53": zoneB}, port: 5353}},
					},
				},
				applications: lbApplications{udpProxy: &lbApplicationUDPProxy{routes: []lbRouteUDPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			ipv6: true,
			expectedEndpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"fd00::53"},
					Zone:      ptr.To("zone-b"),
					Hints: &discoveryv1.EndpointHints{
						ForZones: []discoveryv1.ForZone{{Name: "zone-b"}},
					},
				},
			},
			expectedPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("udp"),
					Protocol: ptr.To(corev1.ProtocolUDP),
					Port:     ptr.To(int32(5353)),
				},
			},
		},
		{
			name: "no matching family returns nil [IPv4]",
			model: &lbService{
				referencedBackends: map[string]backend{
					"backend-a": {
						lbBackends: []lbBackend{{addresses: []string{"198.51.100.10"}, port: 5353}},
					},
				},
				applications: lbApplications{udpProxy: &lbApplicationUDPProxy{routes: []lbRouteUDPProxy{{backendRef: backendRef{name: "backend-a"}}}}},
			},
			ipv6:              true,
			expectedEndpoints: nil,
			expectedPorts:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpoints, ports := tr.udpEndpointSubsetsFromBackends(tc.model, tc.ipv6)
			require.Equal(t, tc.expectedEndpoints, endpoints)
			require.Equal(t, tc.expectedPorts, ports)
		})
	}
}

func TestDesiredServiceZoneAwareMode(t *testing.T) {
	tr := &lbServiceT1Translator{}
	vip := "100.64.0.100"

	testCases := []struct {
		name                     string
		mode                     lbServiceZoneAwareModeType
		applications             lbApplications
		expectedTrafficDistValue *string
		expectedAnnotation       string
	}{
		{
			name:                     "disabled does not set traffic distribution",
			mode:                     lbServiceZoneAwareModeDisabled,
			expectedTrafficDistValue: nil,
		},
		{
			name:                     "prefer same zone sets prefer close",
			mode:                     lbServiceZoneAwareModePreferSameZone,
			applications:             lbApplications{tcpProxy: &lbApplicationTCPProxy{tierMode: tierModeT1}},
			expectedTrafficDistValue: ptr.To(corev1.ServiceTrafficDistributionPreferClose),
		},
		{
			name: "require same zone adds annotation for tcp t1-only",
			mode: lbServiceZoneAwareModeRequireSameZone,
			applications: lbApplications{
				tcpProxy: &lbApplicationTCPProxy{tierMode: tierModeT1},
			},
			expectedTrafficDistValue: nil,
			expectedAnnotation:       annotation.ServiceTrafficPolicyZoneRequireSameZone,
		},
		{
			name: "require same zone adds annotation for udp t1-only",
			mode: lbServiceZoneAwareModeRequireSameZone,
			applications: lbApplications{
				udpProxy: &lbApplicationUDPProxy{tierMode: tierModeT1},
			},
			expectedTrafficDistValue: nil,
			expectedAnnotation:       annotation.ServiceTrafficPolicyZoneRequireSameZone,
		},
		{
			name: "prefer same zone does not add annotation",
			mode: lbServiceZoneAwareModePreferSameZone,
			applications: lbApplications{
				tcpProxy: &lbApplicationTCPProxy{tierMode: tierModeT1},
			},
			expectedTrafficDistValue: ptr.To(corev1.ServiceTrafficDistributionPreferClose),
		},
		{
			name: "require same zone does not add annotation for t1 t2 tcp",
			mode: lbServiceZoneAwareModeRequireSameZone,
			applications: lbApplications{
				tcpProxy: &lbApplicationTCPProxy{tierMode: tierModeT2},
			},
			expectedTrafficDistValue: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			model := &lbService{
				namespace: "default",
				name:      "lb-1",
				vip: lbVIP{
					name:         "vip-1",
					ipFamily:     ipFamilyV4,
					assignedIPv4: &vip,
				},
				zoneAwareMode:   tc.mode,
				applications:    tc.applications,
				t1LabelSelector: labels.Everything(),
			}

			svc := tr.DesiredService(model)
			require.NotNil(t, svc)
			require.Equal(t, tc.expectedTrafficDistValue, svc.Spec.TrafficDistribution)
			require.Equal(t, tc.expectedAnnotation, svc.Annotations[annotation.ServiceTrafficPolicyZone])
		})
	}
}

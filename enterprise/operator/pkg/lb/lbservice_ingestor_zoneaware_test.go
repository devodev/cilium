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
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestIngestorResolveZoneAwareMode(t *testing.T) {
	ing := &ingestor{}

	testCases := []struct {
		name   string
		lbsvc  *isovalentv1alpha1.LBService
		expect lbServiceZoneAwareModeType
	}{
		{
			name:   "defaults to disabled when traffic policy is unset",
			lbsvc:  &isovalentv1alpha1.LBService{},
			expect: lbServiceZoneAwareModeDisabled,
		},
		{
			name: "maps preferSameZone from spec",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{Mode: isovalentv1alpha1.LBZoneAwareModePreferSameZone},
					},
				},
			},
			expect: lbServiceZoneAwareModePreferSameZone,
		},
		{
			name: "maps requireSameZone from spec",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{Mode: isovalentv1alpha1.LBZoneAwareModeRequireSameZone},
					},
				},
			},
			expect: lbServiceZoneAwareModeRequireSameZone,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expect, ing.resolveZoneAwareMode(tc.lbsvc))
		})
	}
}

func TestIngestorResolveZoneAwareMinBackendCount(t *testing.T) {
	ing := &ingestor{}

	testCases := []struct {
		name   string
		lbsvc  *isovalentv1alpha1.LBService
		expect uint64
	}{
		{
			name:   "defaults to zero when traffic policy is unset",
			lbsvc:  &isovalentv1alpha1.LBService{},
			expect: 0,
		},
		{
			name: "defaults to two for non-defaulted zone aware policy without min backend count",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{Mode: isovalentv1alpha1.LBZoneAwareModePreferSameZone},
					},
				},
			},
			expect: 1,
		},
		{
			name: "maps explicit min backend count from spec",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{
							Mode:            isovalentv1alpha1.LBZoneAwareModePreferSameZone,
							MinBackendCount: 7,
						},
					},
				},
			},
			expect: 7,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expect, ing.resolveZoneAwareMinBackendCount(tc.lbsvc))
		})
	}
}

func TestResolveNodeZone(t *testing.T) {
	testCases := []struct {
		name       string
		nodeLabels map[string]string
		expect     string
	}{
		{
			name: "use kubernetes topology zone label",
			nodeLabels: map[string]string{
				corev1.LabelTopologyZone: "zone-k8s",
			},
			expect: "zone-k8s",
		},
		{
			name:       "returns unknown when labels are missing",
			nodeLabels: map[string]string{},
			expect:     lbServiceZoneUnknown,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expect, resolveNodeZone(tc.nodeLabels))
		})
	}
}

func TestIngestorLoadNodeAddressesByLabelSelector(t *testing.T) {
	nodes := []*slim_corev1.Node{
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:   "node-a",
				Labels: map[string]string{"service.cilium.io/node": "t2"},
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.10"},
					{Type: slim_corev1.NodeInternalIP, Address: "fd00::10"},
					{Type: slim_corev1.NodeExternalIP, Address: "203.0.113.10"},
				},
			},
		},
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:   "node-b",
				Labels: map[string]string{"service.cilium.io/node": "t1"},
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.11"},
				},
			},
		},
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:   "node-c",
				Labels: map[string]string{"service.cilium.io/node": "t2"},
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "not-an-ip"},
				},
			},
		},
	}

	selector := labels.SelectorFromSet(labels.Set{"service.cilium.io/node": "t2"})
	ing := &ingestor{logger: slog.Default()}
	ipv4Addrs, ipv6Addrs, err := ing.loadNodeAddressesByLabelSelector(context.Background(), ipFamilyDual, nodes, selector)
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.10"}, ipv4Addrs)
	require.Equal(t, []string{"fd00::10"}, ipv6Addrs)
}

func TestIngestorLoadNodeAddressZonesByLabelSelector(t *testing.T) {
	nodes := []*slim_corev1.Node{
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: "node-a",
				Labels: map[string]string{
					"service.cilium.io/node": "t2",
					corev1.LabelTopologyZone: "zone-a",
				},
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.10"},
					{Type: slim_corev1.NodeInternalIP, Address: "fd00::10"},
					{Type: slim_corev1.NodeExternalIP, Address: "203.0.113.10"},
				},
			},
		},
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:   "node-b",
				Labels: map[string]string{"service.cilium.io/node": "t2"},
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.11"},
				},
			},
		},
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: "node-c",
				Labels: map[string]string{
					"service.cilium.io/node": "t1",
					corev1.LabelTopologyZone: "zone-c",
				},
			},
			Status: slim_corev1.NodeStatus{
				Addresses: []slim_corev1.NodeAddress{
					{Type: slim_corev1.NodeInternalIP, Address: "10.0.0.12"},
				},
			},
		},
	}

	selector := labels.SelectorFromSet(labels.Set{"service.cilium.io/node": "t2"})
	ing := &ingestor{logger: slog.Default()}
	ipv4Zones, ipv6Zones := ing.loadNodeAddressZonesByLabelSelector(ipFamilyDual, nodes, selector)
	require.Equal(t, map[string]string{"10.0.0.10": "zone-a"}, ipv4Zones)
	require.Equal(t, map[string]string{"fd00::10": "zone-a"}, ipv6Zones)
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"

	"github.com/cilium/hive/hivetest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

func Test_computeHealthyGateways(t *testing.T) {
	policyHealthyGatewayIPs := []gatewayNodeIP{
		{
			ip:                    netip.MustParseAddr("10.0.0.1"),
			selectingGroupIndices: []int{0},
			zone:                  "az0",
			available:             true,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.2"),
			selectingGroupIndices: []int{3, 2, 1},
			zone:                  "az0",
			available:             true,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.3"),
			selectingGroupIndices: []int{},
			zone:                  "az0",
			available:             false,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.4"),
			selectingGroupIndices: []int{3, 2, 0},
			zone:                  "",
			available:             true,
		},
	}

	expected := []gatewayNodeIP{
		{
			ip:                    netip.MustParseAddr("10.0.0.1"),
			selectingGroupIndices: []int{0},
			zone:                  "az0",
			available:             true,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.4"),
			selectingGroupIndices: []int{3, 2, 0},
			zone:                  "",
			available:             true,
		},
	}
	out := computeHealthyGateways(policyHealthyGatewayIPs, 0)
	assert.Equal(t, expected, out)

	expected = []gatewayNodeIP{
		{
			ip:                    netip.MustParseAddr("10.0.0.2"),
			selectingGroupIndices: []int{3, 2, 1},
			zone:                  "az0",
			available:             true,
		},
	}
	out = computeHealthyGateways(policyHealthyGatewayIPs, 1)
	assert.Equal(t, expected, out)

}

func Test_computeAvailableHealthyGatewaysByAZ(t *testing.T) {
	tests := []struct {
		name           string
		allAZs         sets.Set[string]
		groupIndex     int
		gateways       []gatewayNodeIP
		expectedAZGWs  map[string][]netip.Addr
		expectedCounts map[string]int
	}{
		{
			name:       "no preseeded AZs picks up zones from gateways",
			allAZs:     sets.New[string](),
			groupIndex: 0,
			gateways: []gatewayNodeIP{
				{ip: netip.MustParseAddr("10.0.0.1"), selectingGroupIndices: []int{0}, zone: "az0", available: true},
				{ip: netip.MustParseAddr("10.0.0.2"), selectingGroupIndices: []int{1}, zone: "az1", available: true},
			},
			expectedAZGWs: map[string][]netip.Addr{
				"az0": {netip.MustParseAddr("10.0.0.1")},
			},
			expectedCounts: map[string]int{
				"az0": 1,
				"az1": 1,
			},
		},
		{
			name:       "preseeded AZs retain empty slices",
			allAZs:     sets.New[string]("az0", "az1"),
			groupIndex: 1,
			gateways: []gatewayNodeIP{
				{ip: netip.MustParseAddr("10.0.0.1"), selectingGroupIndices: []int{0}, zone: "az0", available: true},
				{ip: netip.MustParseAddr("10.0.0.2"), selectingGroupIndices: []int{1, 3}, zone: "az0", available: true},
				{ip: netip.MustParseAddr("10.0.0.3"), selectingGroupIndices: []int{2}, zone: "az1", available: false},
			},
			expectedAZGWs: map[string][]netip.Addr{
				"az0": {netip.MustParseAddr("10.0.0.2")},
				"az1": {}, // must span all zones.
			},
			expectedCounts: map[string]int{
				"az0": 2, // both az0 nodes are available
				"az1": 0, // for completeness, we seed with allAZs.
			},
		},
		{
			name:       "zoneless and unavailable gateways are ignored",
			allAZs:     sets.New[string]("az0"),
			groupIndex: 0,
			gateways: []gatewayNodeIP{
				{ip: netip.MustParseAddr("10.0.0.1"), selectingGroupIndices: []int{0}, zone: "", available: true},
				{ip: netip.MustParseAddr("10.0.0.2"), selectingGroupIndices: []int{0}, zone: "az0", available: false},
				{ip: netip.MustParseAddr("10.0.0.3"), selectingGroupIndices: []int{0}, zone: "az0", available: true},
			},
			expectedAZGWs: map[string][]netip.Addr{
				"az0": {netip.MustParseAddr("10.0.0.3")},
			},
			expectedCounts: map[string]int{
				"az0": 1,
			},
		},
		{
			name:       "no gateways match group index",
			allAZs:     sets.New[string]("az0", "az1"),
			groupIndex: 5,
			gateways: []gatewayNodeIP{
				{ip: netip.MustParseAddr("10.0.0.1"), selectingGroupIndices: []int{0}, zone: "az0", available: true},
				{ip: netip.MustParseAddr("10.0.0.2"), selectingGroupIndices: []int{1}, zone: "az1", available: true},
			},
			expectedAZGWs: map[string][]netip.Addr{
				"az0": {},
				"az1": {},
			},
			expectedCounts: map[string]int{
				"az0": 1,
				"az1": 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualGWs, actualCounts := computeAvailableHealthyGatewaysByAZ(tt.allAZs, tt.gateways, tt.groupIndex)
			assert.Equal(t, tt.expectedAZGWs, actualGWs)
			assert.Equal(t, tt.expectedCounts, map[string]int(actualCounts))
		})
	}
}

var (
	selectorFooBar = policyTypes.NewLabelSelector(api.EndpointSelector{
		LabelSelector: &slimv1.LabelSelector{
			MatchLabels: map[string]string{"foo": "bar"},
		},
	})
	selectorXY = policyTypes.NewLabelSelector(api.EndpointSelector{
		LabelSelector: &slimv1.LabelSelector{
			MatchLabels: map[string]string{"x": "y"},
		},
	})
	selectorZW = policyTypes.NewLabelSelector(api.EndpointSelector{
		LabelSelector: &slimv1.LabelSelector{
			MatchLabels: map[string]string{"z": "w"},
		},
	})

	labelsFooBarAZ0    = map[string]string{"foo": "bar", core_v1.LabelTopologyZone: "az0"}
	labelsFooBarAZ1    = map[string]string{"foo": "bar", core_v1.LabelTopologyZone: "az1"}
	labelsFooBarAZ2    = map[string]string{"foo": "bar", core_v1.LabelTopologyZone: "az2"}
	labelsFooBarMulti  = map[string]string{"foo": "bar", "x": "y", "z": "w", core_v1.LabelTopologyZone: "az3"}
	labelsXYAZ1        = map[string]string{"x": "y", core_v1.LabelTopologyZone: "az1"}
	labelsMatchNoneAZ2 = map[string]string{"match": "none", core_v1.LabelTopologyZone: "az2"}
)

func Test_preComputePolicyHealthyGatewaysWithAZAffinity(t *testing.T) {
	tests := []struct {
		name            string
		nodes           []nodeTypes.Node
		policyConfig    *PolicyConfig
		expectedAZKeys  sets.Set[string]
		expectedGWs     []gatewayNodeIP
		healthOverrides map[string]healthcheck.NodeHealth
	}{
		{
			name: "basic multiple groups with overlapping and distinct selectors",
			nodes: []nodeTypes.Node{
				{
					Labels: labelsFooBarAZ0,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 1},
					}},
				},
				{
					Labels: labelsXYAZ1,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 2},
					}},
				},
				{
					Labels: labelsMatchNoneAZ2,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 3},
					}},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p0", Namespace: "default"},
				uid: "0",
				groupConfigs: []groupConfig{
					{nodeSelector: selectorFooBar},
					{nodeSelector: selectorFooBar},
					{nodeSelector: selectorXY},
				},
			},
			expectedGWs: []gatewayNodeIP{
				{
					ip:                    netip.MustParseAddr("10.0.0.1"),
					selectingGroupIndices: []int{0, 1},
					available:             true,
					zone:                  "az0",
				},
				{
					ip:                    netip.MustParseAddr("10.0.0.2"),
					selectingGroupIndices: []int{2},
					available:             true,
					zone:                  "az1",
				},
			},
			expectedAZKeys: sets.New("az0", "az1", "az2"),
		},
		{
			name:  "empty nodes list",
			nodes: []nodeTypes.Node{},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p1", Namespace: "default"},
				uid:          "1",
				groupConfigs: []groupConfig{{nodeSelector: selectorFooBar}},
			},
			expectedGWs: []gatewayNodeIP{},
		},
		{
			name: "no matching nodes",
			nodes: []nodeTypes.Node{
				{
					Labels: labelsMatchNoneAZ2,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 1},
					}},
				},
			},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p2", Namespace: "default"},
				uid:          "0",
				groupConfigs: []groupConfig{{nodeSelector: selectorFooBar}},
			},
			expectedGWs:    []gatewayNodeIP{},
			expectedAZKeys: sets.New("az2"),
		},
		{
			name: "node with no internal IP address should not be added to output",
			nodes: []nodeTypes.Node{
				{
					Labels: labelsFooBarAZ0,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeCiliumInternalIP,
						IP:   net.IP{10, 0, 10, 1},
					}},
				},
			},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p3", Namespace: "default"},
				uid:          "1",
				groupConfigs: []groupConfig{{nodeSelector: selectorFooBar}},
			},
			expectedGWs:    []gatewayNodeIP{},
			expectedAZKeys: sets.New("az0"),
		},
		{
			name: "single node matching all groups",
			nodes: []nodeTypes.Node{
				{
					Labels: labelsFooBarMulti,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 1},
					}},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p5", Namespace: "default"},
				uid: "5",
				groupConfigs: []groupConfig{
					{nodeSelector: selectorFooBar},
					{nodeSelector: selectorFooBar},
					{nodeSelector: selectorZW},
				},
			},
			expectedGWs: []gatewayNodeIP{
				{
					ip:                    netip.MustParseAddr("10.0.0.1"),
					selectingGroupIndices: []int{0, 1, 2},
					available:             true,
					zone:                  "az3",
				},
			},
			expectedAZKeys: sets.New("az3"),
		},
		{
			name: "empty group configs",
			nodes: []nodeTypes.Node{
				{
					Labels: labelsFooBarAZ1,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 1},
					}},
				},
			},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p6", Namespace: "default"},
				uid:          "000",
				groupConfigs: []groupConfig{},
			},
			expectedGWs:    []gatewayNodeIP{},
			expectedAZKeys: sets.New("az1"),
		},
		{
			name: "nodes with nil labels",
			nodes: []nodeTypes.Node{
				{
					Labels: nil,
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 1},
					}},
				},
			},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p7", Namespace: "default"},
				uid:          "000",
				groupConfigs: []groupConfig{{nodeSelector: selectorFooBar}},
			},
			expectedGWs:    []gatewayNodeIP{},
			expectedAZKeys: sets.New[string](),
		},
		{
			name: "reachable and unreachable nodes",
			nodes: []nodeTypes.Node{
				{
					Labels: labelsFooBarAZ0,
					Name:   "node0",
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 1},
					}},
				},
				{
					Labels: labelsFooBarAZ0,
					Name:   "node1",
					IPAddresses: []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.IP{10, 0, 0, 2},
					}},
				},
			},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p8", Namespace: "default"},
				groupConfigs: []groupConfig{{nodeSelector: selectorFooBar}},
			},
			expectedGWs: []gatewayNodeIP{
				{
					ip:                    netip.MustParseAddr("10.0.0.2"),
					selectingGroupIndices: []int{0},
					available:             false,
					zone:                  "az0",
				},
			},
			healthOverrides: map[string]healthcheck.NodeHealth{
				"node0": {Reachable: false, AgentUp: false},
				"node1": {Reachable: true, AgentUp: false},
			},
			expectedAZKeys: sets.New("az0"),
		},
		{
			name: "invalid nodes",
			nodes: []nodeTypes.Node{
				{
					Labels:      labelsFooBarAZ2,
					IPAddresses: []nodeTypes.Address{},
				},
			},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p9", Namespace: "default"},
				groupConfigs: []groupConfig{{nodeSelector: selectorFooBar}},
			},
			expectedGWs:    []gatewayNodeIP{},
			expectedAZKeys: sets.New("az2"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hc := &mockHealthChecker{m: tt.healthOverrides}
			m := &OperatorManager{
				logger:        hivetest.Logger(t),
				nodes:         tt.nodes,
				healthchecker: hc,
			}

			azs, actual := tt.policyConfig.preComputePolicyHealthyGateways(hivetest.Logger(t), m)
			require.Len(t, actual, len(tt.expectedGWs))
			for i, gw := range actual {
				expected := tt.expectedGWs[i]
				gw.Node = nil
				assert.Equal(t, expected, gw)
			}

			if tt.expectedAZKeys != nil {
				assert.Equal(t, tt.expectedAZKeys, azs)
			}
		})
	}
}

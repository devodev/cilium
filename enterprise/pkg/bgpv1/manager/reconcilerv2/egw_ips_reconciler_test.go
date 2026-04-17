// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	// policy 1
	egwPolicyKey = resource.Key{
		Namespace: "default",
		Name:      "egress-gateway",
	}
	egwLabels = map[string]string{
		"egress": "policy-1",
	}
	egwLabelSelector = &slimv1.LabelSelector{
		MatchLabels: egwLabels,
	}
	egwAddr   = netip.MustParseAddr("10.2.0.1")
	egwPrefix = netip.MustParsePrefix("10.2.0.1/32")

	// policy 2
	egwPolicyKey2 = resource.Key{
		Namespace: "default",
		Name:      "egress-gateway-2",
	}
	egwLabels2 = map[string]string{
		"egress": "policy-2",
	}
	egwLabelSelector2 = &slimv1.LabelSelector{
		MatchLabels: egwLabels2,
	}
	egwAddr2   = netip.MustParseAddr("10.2.0.2")
	egwPrefix2 = netip.MustParsePrefix("10.2.0.2/32")

	// peer config
	peer = v1.IsovalentBGPNodePeer{
		Name:        "peer-65001",
		PeerAddress: ptr.To[string]("10.10.10.1"),
		PeerConfigRef: &v1.PeerConfigReference{
			Name: "peer-config",
		},
	}

	peer2 = v1.IsovalentBGPNodePeer{
		Name:        "peer-65001-2",
		PeerAddress: ptr.To[string]("10.10.10.2"),
		PeerConfigRef: &v1.PeerConfigReference{
			Name: "peer-config",
		},
	}

	peerConfig = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "bgp",
						},
					},
				},
			},
		},
	}

	egwAdvert = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egw-advertisement",
			Labels: map[string]string{
				"advertise": "bgp",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				{
					AdvertisementType: v1.BGPEGWAdvert,
					Selector:          egwLabelSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard: []v2.BGPStandardCommunity{"65000:100"},
						},
					},
				},
				{
					AdvertisementType: v1.BGPEGWAdvert,
					Selector:          egwLabelSelector2,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard: []v2.BGPStandardCommunity{"65000:200"},
						},
					},
				},
			},
		},
	}

	egw1Peer1RPName = PolicyName("peer-65001", "ipv4", v1.BGPEGWAdvert, egwPolicyKey.Name)
	egw1Peer1RP     = &entTypes.ExtendedRoutePolicy{
		Name: egw1Peer1RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type: types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{
							netip.MustParseAddr("10.10.10.1"),
						},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         egwPrefix,
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:100"}},
				},
			},
		},
	}

	egw1Peer2RPName = PolicyName("peer-65001-2", "ipv4", v1.BGPEGWAdvert, egwPolicyKey.Name)
	egw1Peer2RP     = &entTypes.ExtendedRoutePolicy{
		Name: egw1Peer2RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type: types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{
							netip.MustParseAddr("10.10.10.2"),
						},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         egwPrefix,
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:100"}},
				},
			},
		},
	}

	egw2RPName = PolicyName("peer-65001", "ipv4", v1.BGPEGWAdvert, egwPolicyKey2.Name)
	egw2RP     = &entTypes.ExtendedRoutePolicy{
		Name: egw2RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type: types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{
							netip.MustParseAddr("10.10.10.1"),
						},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         egwPrefix2,
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:200"}},
				},
			},
		},
	}

	egw2RPOld = &entTypes.ExtendedRoutePolicy{
		Name: egw2RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type: types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{
							netip.MustParseAddr("10.10.10.1"),
						},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         egwPrefix2,
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:222"}},
				},
			},
		},
	}
)

func TestEgressGatewayAdvertisements(t *testing.T) {
	tests := []struct {
		name                    string
		advertisement           *v1.IsovalentBGPAdvertisement
		preconfiguredEGWAFPaths map[resource.Key]map[types.Family]map[string]struct{}
		preconfiguredRPs        ResourceRoutePolicyMap
		testEGWPolicies         []mockEGWPolicy
		testBGPInstanceConfig   *v1.IsovalentBGPNodeInstance
		expectedEGWAFPaths      map[resource.Key]map[types.Family]map[string]struct{}
		expectedRPs             ResourceRoutePolicyMap
	}{
		{
			name:             "EGW correct advertisement",
			advertisement:    egwAdvert,
			preconfiguredRPs: make(ResourceRoutePolicyMap),
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
				},
			},
		},
		{
			name:          "Test update: Preconfigured path and policy, add another egw policy",
			advertisement: egwAdvert,
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
				},
			},
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey2.Namespace,
						Name:      egwPolicyKey2.Name,
					},
					labels:    egwLabels2,
					egressIPs: []netip.Addr{egwAddr2},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: { // new path added
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
				},
				egwPolicyKey2: RoutePolicyMap{ // new route policy added
					egw2RPName: egw2RP,
				},
			},
		},
		{
			name:          "Test update: Preconfigured path and policy, advert updated community",
			advertisement: egwAdvert,
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
				},
				egwPolicyKey2: RoutePolicyMap{ // old route policy, contains old community
					egw2RPName: egw2RPOld,
				},
			},
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey2.Namespace,
						Name:      egwPolicyKey2.Name,
					},
					labels:    egwLabels2,
					egressIPs: []netip.Addr{egwAddr2},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
				},
				egwPolicyKey2: RoutePolicyMap{ // updated route policy added
					egw2RPName: egw2RP,
				},
			},
		},
		{
			name:          "Test deletion: Preconfigured path and policy, egw policy removed",
			advertisement: egwAdvert,
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
				},
				egwPolicyKey2: RoutePolicyMap{
					egw2RPName: egw2RP,
				},
			},
			testEGWPolicies: []mockEGWPolicy{}, // no egw policy present in EGW manager
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:        ResourceRoutePolicyMap{},
		},

		{
			name:          "Test deletion: Preconfigured path and policy, advert removed",
			advertisement: nil, // no advertisement
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
				},
				egwPolicyKey2: RoutePolicyMap{
					egw2RPName: egw2RP,
				},
			},
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey2.Namespace,
						Name:      egwPolicyKey2.Name,
					},
					labels:    egwLabels2,
					egressIPs: []netip.Addr{egwAddr2},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:        ResourceRoutePolicyMap{},
		},
		{
			name:             "Test with two peers",
			advertisement:    egwAdvert,
			preconfiguredRPs: make(ResourceRoutePolicyMap),
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1.IsovalentBGPNodePeer{peer, peer2},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				egwPolicyKey: RoutePolicyMap{
					egw1Peer1RPName: egw1Peer1RP,
					egw1Peer2RPName: egw1Peer2RP,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			mockPeerConfigStore := store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
			mockAdvertStore := store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()

			egwReconciler := EgressGatewayIPsReconciler{
				logger:         logger,
				egwIPsProvider: newEGWManagerMock(tt.testEGWPolicies),
				upgrader:       newUpgraderMock(tt.testBGPInstanceConfig),
				peerAdvert: &IsovalentAdvertisement{
					logger:      logger,
					peerConfigs: mockPeerConfigStore,
					adverts:     mockAdvertStore,
				},
				metadata: make(map[string]EgressGatewayIPsMetadata),
			}

			// set peer advert state
			mockPeerConfigStore.Upsert(peerConfig)
			if tt.advertisement != nil {
				mockAdvertStore.Upsert(tt.advertisement)
			}

			router := fake.NewEnterpriseFakeRouter()
			testOSSBGPInstance := &instance.BGPInstance{
				Name:   "fake-instance",
				Config: nil,
				Router: router,
			}
			testBGPInstance := &EnterpriseBGPInstance{
				Name:   testOSSBGPInstance.Name,
				Router: router,
			}

			// set preconfigured data
			presetEGWAFPaths := make(reconciler.ResourceAFPathsMap)
			for key, preAFPaths := range tt.preconfiguredEGWAFPaths {
				presetEGWAFPaths[key] = make(reconciler.AFPathsMap)
				for fam, afPaths := range preAFPaths {
					pathSet := make(reconciler.PathMap)
					for prePath := range afPaths {
						path := types.NewPathForPrefix(netip.MustParsePrefix(prePath))
						path.Family = fam
						pathSet[prePath] = path
					}
					presetEGWAFPaths[key][fam] = pathSet
				}
			}

			egwReconciler.setMetadata(testBGPInstance, EgressGatewayIPsMetadata{
				EGWAFPaths:       presetEGWAFPaths,
				EGWRoutePolicies: tt.preconfiguredRPs,
			})

			// run podIPPoolReconciler twice to ensure idempotency
			for range 2 {
				err := egwReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
					BGPInstance: testOSSBGPInstance,
				})
				req.NoError(err)
			}

			// check if the advertisement is as expected
			runningEGWAFPaths := make(map[resource.Key]map[types.Family]map[string]struct{})
			for key, egwAFPaths := range egwReconciler.getMetadata(testBGPInstance).EGWAFPaths {
				runningEGWAFPaths[key] = make(map[types.Family]map[string]struct{})
				for fam, afPaths := range egwAFPaths {
					pathSet := make(map[string]struct{})
					for pathKey := range afPaths {
						pathSet[pathKey] = struct{}{}
					}
					runningEGWAFPaths[key][fam] = pathSet
				}
			}

			req.Equal(tt.expectedEGWAFPaths, runningEGWAFPaths)
			req.Equal(tt.expectedRPs, egwReconciler.getMetadata(testBGPInstance).EGWRoutePolicies)
		})
	}
}

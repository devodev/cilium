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
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossReconciler "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

func Test_PodCIDRAdvertisement(t *testing.T) {
	podCIDR1v4 := "10.10.1.0/24"
	podCIDR1v6 := "2001:db8:1::/96"
	podCIDR2v4 := "10.10.2.0/24"
	podCIDR2v6 := "2001:db8:2::/96"
	podCIDR3v4 := "10.10.3.0/24"
	podCIDR3v6 := "2001:db8:3::/96"

	redPeerConfig := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red",
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
							"advertise": "red_bgp",
						},
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "red_bgp",
						},
					},
				},
			},
		},
	}

	redPeerConfigV4 := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red-v4",
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
							"advertise": "red_bgp",
						},
					},
				},
			},
		},
	}

	bluePeerConfig := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-blue",
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
							"advertise": "blue_bgp",
						},
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "blue_bgp",
						},
					},
				},
			},
		},
	}

	redPodCIDRAdvert := v1.BGPAdvertisement{
		AdvertisementType: v1.BGPPodCIDRAdvert,
		Attributes: &v1.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65000:100",
				},
			},
		},
	}

	redAdvert := &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				redPodCIDRAdvert,
			},
		},
	}

	bluePodCIDRAdvert := v1.BGPAdvertisement{
		AdvertisementType: v1.BGPPodCIDRAdvert,
		Attributes: &v1.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65355:100",
				},
			},
		},
	}

	blueAdvert := &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blue-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "blue_bgp",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				bluePodCIDRAdvert,
			},
		},
	}

	redPeer65001 := v1.IsovalentBGPNodePeer{
		Name:        "red-peer-65001",
		PeerAddress: ptr.To[string]("10.10.10.1"),
		PeerConfigRef: &v1.PeerConfigReference{
			Name: "peer-config-red",
		},
	}

	bluePeer65001 := v1.IsovalentBGPNodePeer{
		Name:        "blue-peer-65001",
		PeerAddress: ptr.To[string]("10.10.10.2"),
		PeerConfigRef: &v1.PeerConfigReference{
			Name: "peer-config-blue",
		},
	}

	redPeer65001v4PodCIDRRoutePolicy := &entTypes.ExtendedRoutePolicy{
		Name: "red-peer-65001-ipv4-PodCIDR",
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
								CIDR:         netip.MustParsePrefix(podCIDR1v4),
								PrefixLenMin: netip.MustParsePrefix(podCIDR1v4).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR1v4).Bits(),
							},
							{
								CIDR:         netip.MustParsePrefix(podCIDR2v4),
								PrefixLenMin: netip.MustParsePrefix(podCIDR2v4).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR2v4).Bits(),
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

	redPeer65001v6PodCIDRRoutePolicy := &entTypes.ExtendedRoutePolicy{
		Name: "red-peer-65001-ipv6-PodCIDR",
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
								CIDR:         netip.MustParsePrefix(podCIDR1v6),
								PrefixLenMin: netip.MustParsePrefix(podCIDR1v6).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR1v6).Bits(),
							},
							{
								CIDR:         netip.MustParsePrefix(podCIDR2v6),
								PrefixLenMin: netip.MustParsePrefix(podCIDR2v6).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR2v6).Bits(),
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

	bluePeer65001v4PodCIDRRoutePolicy := &entTypes.ExtendedRoutePolicy{
		Name: "blue-peer-65001-ipv4-PodCIDR",
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
								CIDR:         netip.MustParsePrefix(podCIDR1v4),
								PrefixLenMin: netip.MustParsePrefix(podCIDR1v4).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR1v4).Bits(),
							},
							{
								CIDR:         netip.MustParsePrefix(podCIDR2v4),
								PrefixLenMin: netip.MustParsePrefix(podCIDR2v4).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR2v4).Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65355:100"}},
				},
			},
		},
	}

	bluePeer65001v6PodCIDRRoutePolicy := &entTypes.ExtendedRoutePolicy{
		Name: "blue-peer-65001-ipv6-PodCIDR",
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
								CIDR:         netip.MustParsePrefix(podCIDR1v6),
								PrefixLenMin: netip.MustParsePrefix(podCIDR1v6).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR1v6).Bits(),
							},
							{
								CIDR:         netip.MustParsePrefix(podCIDR2v6),
								PrefixLenMin: netip.MustParsePrefix(podCIDR2v6).Bits(),
								PrefixLenMax: netip.MustParsePrefix(podCIDR2v6).Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65355:100"}},
				},
			},
		},
	}

	tests := []struct {
		name                  string
		peerConfig            []*v1.IsovalentBGPPeerConfig
		advertisements        []*v1.IsovalentBGPAdvertisement
		preconfiguredPaths    map[types.Family]map[string]struct{}
		preconfiguredRPs      RoutePolicyMap
		testCiliumNode        *v2.CiliumNode
		testBGPInstanceConfig *v1.IsovalentBGPNodeInstance
		expectedPaths         map[types.Family]map[string]struct{}
		expectedRPs           RoutePolicyMap
	}{
		{
			name: "pod cidr advertisement with no preconfigured advertisements",
			peerConfig: []*v1.IsovalentBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{},
			preconfiguredRPs:   RoutePolicyMap{},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{
							podCIDR1v4,
							podCIDR2v4,
							podCIDR1v6,
							podCIDR2v6,
						},
					},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1.IsovalentBGPNodePeer{
					redPeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
			},
			expectedRPs: RoutePolicyMap{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name: redPeer65001v6PodCIDRRoutePolicy,
			},
		},
		{
			name: "pod cidr advertisement with no preconfigured advertisements - two peers",
			peerConfig: []*v1.IsovalentBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{
							podCIDR1v4,
							podCIDR2v4,
							podCIDR1v6,
							podCIDR2v6,
						},
					},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1.IsovalentBGPNodePeer{
					redPeer65001,
					bluePeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
			},
			expectedRPs: RoutePolicyMap{
				redPeer65001v4PodCIDRRoutePolicy.Name:  redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name:  redPeer65001v6PodCIDRRoutePolicy,
				bluePeer65001v4PodCIDRRoutePolicy.Name: bluePeer65001v4PodCIDRRoutePolicy,
				bluePeer65001v6PodCIDRRoutePolicy.Name: bluePeer65001v6PodCIDRRoutePolicy,
			},
		},
		{
			name: "pod cidr advertisement - cleanup old pod cidr",
			peerConfig: []*v1.IsovalentBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{
				// pod cidr 3 is extra advertisement, reconcile should clean this.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR3v4: struct{}{},
					podCIDR3v6: struct{}{},
				},
			},
			preconfiguredRPs: RoutePolicyMap{
				bluePeer65001v4PodCIDRRoutePolicy.Name: bluePeer65001v4PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
					},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1.IsovalentBGPNodePeer{
					redPeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: RoutePolicyMap{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
			},
		},
		{
			name: "pod cidr advertisement - disable",
			peerConfig: []*v1.IsovalentBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				//no pod cidr advertisement configured
				//redPodCIDRAdvert,
				//bluePodCIDRAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{
				// pod cidr 1,2 already advertised, reconcile should clean this as there is no matching pod cidr advertisement.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
			},
			preconfiguredRPs: RoutePolicyMap{
				redPeer65001v4PodCIDRRoutePolicy.Name:  redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name:  redPeer65001v6PodCIDRRoutePolicy,
				bluePeer65001v4PodCIDRRoutePolicy.Name: bluePeer65001v4PodCIDRRoutePolicy,
				bluePeer65001v6PodCIDRRoutePolicy.Name: bluePeer65001v6PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
					},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1.IsovalentBGPNodePeer{
					redPeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: RoutePolicyMap{},
		},
		{
			name: "pod cidr advertisement - v4 only",
			peerConfig: []*v1.IsovalentBGPPeerConfig{
				redPeerConfigV4,
			},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redAdvert,
				//bluePodCIDRAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
			},
			preconfiguredRPs: RoutePolicyMap{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name: redPeer65001v6PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
					},
				},
			},
			testBGPInstanceConfig: &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v1.IsovalentBGPNodePeer{
					{
						Name:        "red-peer-65001",
						PeerAddress: ptr.To[string]("10.10.10.1"),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "peer-config-red-v4",
						},
					},
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
			},
			expectedRPs: RoutePolicyMap{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			out := NewPodCIDRReconciler(PodCIDRReconcilerIn{
				BGPConfig: config.Config{Enabled: true, StatusReportEnabled: false},
				Logger:    logger,
				PeerAdvert: &IsovalentAdvertisement{
					logger:      logger,
					peerConfigs: store.InitMockStore(tt.peerConfig),
					adverts:     store.InitMockStore(tt.advertisements),
					vrfs:        store.InitMockStore([]*v1alpha1.IsovalentBGPVRFConfig{}),
				},
				DaemonConfig: &option.DaemonConfig{IPAM: "Kubernetes"},
			})
			podCIDRReconciler := out.EnterpriseReconciler.(*PodCIDRReconciler)

			router := fake.NewEnterpriseFakeRouter()

			// preconfigure advertisements
			testBGPInstance := &EnterpriseBGPInstance{
				Name:   "fake-instance",
				Config: nil,
				Router: router,
			}

			presetAdverts := make(ossReconciler.AFPathsMap)
			for preAdvertFam, preAdverts := range tt.preconfiguredPaths {
				pathSet := make(map[string]*types.Path)
				for preAdvert := range preAdverts {
					path := types.MustNewPathForPrefix(netip.MustParsePrefix(preAdvert))
					path.Family = preAdvertFam
					pathSet[preAdvert] = path
				}
				presetAdverts[preAdvertFam] = pathSet
			}
			podCIDRReconciler.setMetadata(testBGPInstance, PodCIDRReconcilerMetadata{
				AFPaths:       presetAdverts,
				RoutePolicies: tt.preconfiguredRPs,
			})

			// reconcile pod cidr
			// run reconciler twice to ensure idempotency
			for range 2 {
				err := podCIDRReconciler.Reconcile(context.Background(), EnterpriseReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: tt.testBGPInstanceConfig,
					CiliumNode:    tt.testCiliumNode,
				})
				req.NoError(err)
			}

			// check if the advertisements are as expected
			runningFamilyPaths := make(map[types.Family]map[string]struct{})
			for family, paths := range podCIDRReconciler.getMetadata(testBGPInstance).AFPaths {
				pathSet := make(map[string]struct{})
				for pathKey := range paths {
					pathSet[pathKey] = struct{}{}
				}
				runningFamilyPaths[family] = pathSet
			}

			req.Equal(tt.expectedPaths, runningFamilyPaths)

			// check if the route policies are as expected
			runningRPs := podCIDRReconciler.getMetadata(testBGPInstance).RoutePolicies
			req.Equal(tt.expectedRPs, runningRPs)
		})
	}
}

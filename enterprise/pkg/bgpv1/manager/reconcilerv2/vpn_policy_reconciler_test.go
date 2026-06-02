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

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

var (
	peerConfigIPv4Unicast = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-ipv4-unicast",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
				},
			},
		},
	}

	peerConfigIPv4VPN = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-ipv4-mpls_vpn",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
				},
			},
		},
	}

	peerConfigEVPN = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-l2vpn-evpn",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "l2vpn",
						Safi: "evpn",
					},
				},
			},
		},
	}

	peerConfigIPv4VPNAndEVPN = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-ipv4-mpls_vpn-and-l2vpn-evpn",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "l2vpn",
						Safi: "evpn",
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
				},
			},
		},
	}

	expectedPeerRoutePolicy = func(policyType types.RoutePolicyType, name string, peerAddr netip.Addr, families []types.Family) *entTypes.ExtendedRoutePolicy {
		return &entTypes.ExtendedRoutePolicy{
			Name: name,
			Type: policyType,
			Statements: []*entTypes.ExtendedRoutePolicyStatement{
				{
					Conditions: entTypes.ExtendedRoutePolicyConditions{
						RoutePolicyConditions: types.RoutePolicyConditions{
							MatchNeighbors: &types.RoutePolicyNeighborMatch{
								Type:      types.RoutePolicyMatchAny,
								Neighbors: []netip.Addr{peerAddr},
							},
							MatchFamilies: families,
						},
					},
					Actions: entTypes.ExtendedRoutePolicyActions{
						RoutePolicyActions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
						},
					},
				},
			},
		}
	}

	importPeerPolicyVPNv4 = expectedPeerRoutePolicy(
		types.RoutePolicyTypeImport,
		"VPNRoutePolicy-import-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
		[]types.Family{{Afi: types.AfiIPv4, Safi: types.SafiMplsVpn}},
	)

	exportPeerPolicyVPNv4 = expectedPeerRoutePolicy(
		types.RoutePolicyTypeExport,
		"VPNRoutePolicy-export-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
		[]types.Family{{Afi: types.AfiIPv4, Safi: types.SafiMplsVpn}},
	)

	importPeerPolicyEVPN = expectedPeerRoutePolicy(
		types.RoutePolicyTypeImport,
		"VPNRoutePolicy-import-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
		[]types.Family{{Afi: types.AfiL2VPN, Safi: types.SafiEvpn}},
	)

	exportPeerPolicyEVPN = expectedPeerRoutePolicy(
		types.RoutePolicyTypeExport,
		"VPNRoutePolicy-export-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
		[]types.Family{{Afi: types.AfiL2VPN, Safi: types.SafiEvpn}},
	)

	importPeerPolicyIPv4VPNAndEVPN = expectedPeerRoutePolicy(
		types.RoutePolicyTypeImport,
		"VPNRoutePolicy-import-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
		[]types.Family{
			{Afi: types.AfiL2VPN, Safi: types.SafiEvpn},
			{Afi: types.AfiIPv4, Safi: types.SafiMplsVpn},
		},
	)

	exportPeerPolicyIPv4VPNAndEVPN = expectedPeerRoutePolicy(
		types.RoutePolicyTypeExport,
		"VPNRoutePolicy-export-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
		[]types.Family{
			{Afi: types.AfiL2VPN, Safi: types.SafiEvpn},
			{Afi: types.AfiIPv4, Safi: types.SafiMplsVpn},
		},
	)
)

func TestVPNRoutePolicy(t *testing.T) {
	tests := []struct {
		name        string
		preRPs      RoutePolicyMap
		peerConfigs []*v1.IsovalentBGPPeerConfig
		peers       []v1.IsovalentBGPNodePeer
		expectedRPs RoutePolicyMap
	}{
		{
			name:        "ipv4-unicast peer, no policy",
			preRPs:      nil,
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4Unicast},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-ipv4-unicast",
					},
				},
			},
			expectedRPs: make(RoutePolicyMap),
		},
		{
			name:        "ipv4-vpn peer, policies applied",
			preRPs:      nil,
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4VPN},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-ipv4-mpls_vpn",
					},
				},
			},
			expectedRPs: RoutePolicyMap{
				importPeerPolicyVPNv4.Name: importPeerPolicyVPNv4,
				exportPeerPolicyVPNv4.Name: exportPeerPolicyVPNv4,
			},
		},
		{
			name: "ipv4-unicast peer, cleanup old policies",
			preRPs: RoutePolicyMap{
				importPeerPolicyVPNv4.Name: importPeerPolicyVPNv4,
				exportPeerPolicyVPNv4.Name: exportPeerPolicyVPNv4,
			},
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4Unicast},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-ipv4-unicast",
					},
				},
			},
			expectedRPs: make(RoutePolicyMap),
		},
		{
			name: "no peer found, cleanup old policies",
			preRPs: RoutePolicyMap{
				importPeerPolicyVPNv4.Name: importPeerPolicyVPNv4,
				exportPeerPolicyVPNv4.Name: exportPeerPolicyVPNv4,
			},
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4Unicast},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "no_matching_peer_config",
					},
				},
			},
			expectedRPs: make(RoutePolicyMap),
		},
		{
			name:        "l2vpn-evpn peer, policies applied",
			preRPs:      nil,
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigEVPN},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-l2vpn-evpn",
					},
				},
			},
			expectedRPs: RoutePolicyMap{
				importPeerPolicyEVPN.Name: importPeerPolicyEVPN,
				exportPeerPolicyEVPN.Name: exportPeerPolicyEVPN,
			},
		},
		{
			name:        "ipv4-vpn and l2vpn-evpn peer, policies applied",
			preRPs:      nil,
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4VPNAndEVPN},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-ipv4-mpls_vpn-and-l2vpn-evpn",
					},
				},
			},
			expectedRPs: RoutePolicyMap{
				importPeerPolicyIPv4VPNAndEVPN.Name: importPeerPolicyIPv4VPNAndEVPN,
				exportPeerPolicyIPv4VPNAndEVPN.Name: exportPeerPolicyIPv4VPNAndEVPN,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			testBGPInstance := &EnterpriseBGPInstance{
				Name:   "fake-instance",
				Router: fake.NewEnterpriseFakeRouter(),
			}
			iNodeInstance := &v1.IsovalentBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](65001),
				Peers:    tt.peers,
			}

			vpnReconciler := &VPNRoutePolicyReconciler{
				logger:          hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
				peerConfigStore: newMockResourceStore[*v1.IsovalentBGPPeerConfig](),
				metadata:        make(map[string]VPNRoutePolicyMetadata),
			}

			if len(tt.peerConfigs) > 0 {
				vpnReconciler.peerConfigStore = InitMockStore[*v1.IsovalentBGPPeerConfig](tt.peerConfigs)
			}

			vpnReconciler.Init(testBGPInstance)
			defer vpnReconciler.Cleanup(testBGPInstance)
			vpnReconciler.initialized.Store(true)

			// set preconfigured route policies
			vpnReconciler.SetMetadata(testBGPInstance, VPNRoutePolicyMetadata{
				VPNPolicies: tt.preRPs,
			})

			// reconcile peer configs
			for range 2 {
				err := vpnReconciler.Reconcile(context.Background(), EnterpriseReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: iNodeInstance,
					CiliumNode:    &v2.CiliumNode{},
				})
				req.NoError(err)
			}

			req.Equal(tt.expectedRPs, vpnReconciler.GetMetadata(testBGPInstance).VPNPolicies)
		})
	}
}

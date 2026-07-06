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
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/YutaroHayakawa/bgplay/pkg/replayer"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	enterpriseConfig "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/time"
)

func TestEVPNParseMPReachNLRI(t *testing.T) {
	tests := []struct {
		name           string
		mpReachNLRI    *bgp.PathAttributeMpReachNLRI
		expectedPrefix netip.Prefix
		expectedVNI    vni.VNI
		expectedVTEPIP netip.Addr
		expectedError  error
	}{
		{
			name: "Unexpected AFI",
			mpReachNLRI: &bgp.PathAttributeMpReachNLRI{
				AFI:  bgp.AFI_IP,
				SAFI: bgp.SAFI_EVPN,
			},
			expectedError: errUnexpectedAFI,
		},
		{
			name: "Unexpected SAFI",
			mpReachNLRI: &bgp.PathAttributeMpReachNLRI{
				AFI:  bgp.AFI_L2VPN,
				SAFI: bgp.SAFI_UNICAST,
			},
			expectedError: errUnexpectedSAFI,
		},
		{
			name: "Unsupported ESI",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"10.0.0.1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100), // RD
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_AS},  // ESI
					0,          // ETag
					24,         // IP prefix length
					"10.0.0.0", // IP prefix
					"",         // GatewayIP
					100,        // VNI (Label)
				),
			),
			expectedError: errUnsupportedESI,
		},
		{
			name: "Unexpected number of NLRI",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"10.0.0.1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),       // RD
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY}, // ESI
					0,          // ETag
					24,         // IP prefix length
					"10.0.0.0", // IP prefix
					"",         // GatewayIP
					100,        // VNI (Label)
				),
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 200),       // RD
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY}, // ESI
					0,          // ETag
					24,         // IP prefix length
					"10.0.0.0", // IP prefix
					"",         // GatewayIP
					200,        // VNI (Label)
				),
			),
			expectedError: errUnexpectedNumberOfNLRI,
		},
		{
			name: "Self-originated route (zero nexthop v4)",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"0.0.0.0",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					32,
					"10.0.0.1",
					"",
					100,
				),
			),
			expectedError: errSelfOriginatedRoute,
		},
		{
			name: "Self-originated route (zero nexthop v6)",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"::",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					128,
					"2001:db8::1",
					"",
					100,
				),
			),
			expectedError: errSelfOriginatedRoute,
		},
		{
			name: "Malformed NLRI (non-EVPN type in Value)",
			mpReachNLRI: &bgp.PathAttributeMpReachNLRI{
				AFI:     bgp.AFI_L2VPN,
				SAFI:    bgp.SAFI_EVPN,
				Nexthop: netip.MustParseAddr("10.0.0.1"),
				Value: []bgp.PathNLRI{
					{NLRI: mustIPAddrPrefixNLRI("10.0.0.0/24")}, // Not an EVPN NLRI
				},
			},
			expectedError: errMalformedPath,
		},
		{
			name: "Unsupported EVPN route type",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"10.0.0.1",
				mustEVPNMacIPAdvertisementRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					"aa:bb:cc:dd:ee:ff",
					"10.0.0.2",
					[]uint32{100},
				),
			),
			expectedError: errUnsupportedEVPNRouteType,
		},
		{
			name: "Unsupported ETag (non-zero)",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"10.0.0.1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					1, // non-zero ETag
					24,
					"10.0.0.0",
					"",
					100,
				),
			),
			expectedError: errUnsupportedETag,
		},
		{
			name: "Unsupported Gateway IP (non-zero IPv4)",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"10.0.0.1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					24,
					"10.0.0.0",
					"1.1.1.1", // non-zero GW IP
					100,
				),
			),
			expectedError: errUnsupportedGatewayIP,
		},
		{
			name: "Unsupported Gateway IP (non-zero IPv6)",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"2001:db8::1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					128,
					"2001:db8::100",
					"2001:db8::2", // non-zero GW IP
					100,
				),
			),
			expectedError: errUnsupportedGatewayIP,
		},
		{
			name: "Valid IPv4 prefix IPv4 VTEP IP",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"100.64.0.1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					24,
					"10.0.0.0",
					"",
					100,
				),
			),
			expectedPrefix: netip.MustParsePrefix("10.0.0.0/24"),
			expectedVNI:    vni.MustFromUint32(100),
			expectedVTEPIP: netip.MustParseAddr("100.64.0.1"),
		},
		{
			name: "Valid IPv6 prefix IPv4 VTEP IP",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"100.64.0.1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					120,
					"2001:db8::",
					"",
					100,
				),
			),
			expectedPrefix: netip.MustParsePrefix("2001:db8::/120"),
			expectedVNI:    vni.MustFromUint32(100),
			expectedVTEPIP: netip.MustParseAddr("100.64.0.1"),
		},
		{
			name: "Valid IPv4 prefix IPv6 VTEP IP",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"fd00::1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					24,
					"10.0.0.0",
					"",
					100,
				),
			),
			expectedPrefix: netip.MustParsePrefix("10.0.0.0/24"),
			expectedVNI:    vni.MustFromUint32(100),
			expectedVTEPIP: netip.MustParseAddr("fd00::1"),
		},
		{
			name: "Valid IPv6 prefix IPv4 VTEP IP",
			mpReachNLRI: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
				"fd00::1",
				mustEVPNIPPrefixRoute(
					bgp.NewRouteDistinguisherFourOctetAS(65000, 100),
					bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY},
					0,
					120,
					"2001:db8::",
					"",
					100,
				),
			),
			expectedPrefix: netip.MustParsePrefix("2001:db8::/120"),
			expectedVNI:    vni.MustFromUint32(100),
			expectedVTEPIP: netip.MustParseAddr("fd00::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &importEVPNRouteReconciler{}
			prefix, vni, vtepIP, err := r.parseMPReachNLRI(tt.mpReachNLRI)
			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedPrefix, prefix)
				require.Equal(t, tt.expectedVNI, vni)
				require.Equal(t, tt.expectedVTEPIP, vtepIP)
			}
		})
	}
}

func TestEVPNParseExtendedCommunity(t *testing.T) {
	tests := []struct {
		name          string
		extComm       *bgp.PathAttributeExtendedCommunities
		expectedRTs   []string
		expectedRTMAC net.HardwareAddr
		expectedError error
	}{
		{
			name: "Missing RT",
			extComm: bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
				bgp.NewRoutersMacExtended("aa:bb:cc:dd:ee:ff"),
				bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN),
			}),
			expectedError: errMissingRouteTargetExtComm,
		},
		{
			name: "Missing Router's MAC",
			extComm: bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
				bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true),
				bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN),
			}),
			expectedError: errMissingRoutersMACExtComm,
		},
		{
			name: "Missing Encap",
			extComm: bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
				bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true),
				bgp.NewRoutersMacExtended("aa:bb:cc:dd:ee:ff"),
			}),
			expectedError: errMissingEncapExtComm,
		},
		{
			name: "Unsupported Tunnel Type",
			extComm: bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
				bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true),
				bgp.NewRoutersMacExtended("aa:bb:cc:dd:ee:ff"),
				bgp.NewEncapExtended(bgp.TUNNEL_TYPE_GENEVE),
			}),
			expectedError: errUnsupportedEncapType,
		},
		{
			name: "Valid multiple RTs",
			extComm: bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
				bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true),
				bgp.NewFourOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 200, true),
				bgp.NewRoutersMacExtended("aa:bb:cc:dd:ee:ff"),
				bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN),
			}),
			expectedRTs:   []string{"65000:100", "65000:200"},
			expectedRTMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		},
		{
			name: "Valid multiple Router's MAC (takes the first one)",
			extComm: bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
				bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true),
				bgp.NewRoutersMacExtended("aa:bb:cc:dd:ee:ff"),
				bgp.NewRoutersMacExtended("11:22:33:44:55:66"),
				bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN),
			}),
			expectedRTs:   []string{"65000:100"},
			expectedRTMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		},
		{
			name: "Valid multiple Encap (takes the first one)",
			extComm: bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
				bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true),
				bgp.NewRoutersMacExtended("aa:bb:cc:dd:ee:ff"),
				bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN),
				bgp.NewEncapExtended(bgp.TUNNEL_TYPE_GENEVE),
			}),
			expectedRTs:   []string{"65000:100"},
			expectedRTMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &importEVPNRouteReconciler{}
			rts, mac, err := r.parseExtendedCommunity(tt.extComm)
			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedRTs, rts)
				require.Equal(t, tt.expectedRTMAC, mac)
			}
		})
	}
}

func TestEVPNRouteImport(t *testing.T) {
	var (
		RIB    *rib.RIB
		router entTypes.EnterpriseRouter
	)

	h := hive.New(cell.Module(
		"test",
		"test module",
		rib.Cell,
		rib.NopDataPlaneCell,
		evpnConfig.Cell,
		privnetConfig.Cell,
		cell.Config(enterpriseConfig.DefaultConfig),
		cell.Provide(
			tables.NewPrivateNetworksTable,
			statedb.RWTable[tables.PrivateNetwork].ToTable,
			newImportEVPNRouteReconciler,
			newErrorPathStore,
			func() types.StateNotificationCh {
				return make(chan struct{}, 1)
			},
			func() types.BGPGlobal {
				opt := &types.RouteSelectionOptions{}
				return types.BGPGlobal{
					ASN:                   65111,
					RouterID:              "10.0.0.1",
					ListenPort:            11799,
					RouteSelectionOptions: opt,
				}
			},
			func(
				logger *slog.Logger,
				global types.BGPGlobal,
				stateCh types.StateNotificationCh,
			) (entTypes.EnterpriseRouter, error) {
				return gobgp.NewEnterpriseGoBGPServer(
					t.Context(),
					logger,
					entTypes.EnterpriseServerParameters{
						Global:            entTypes.EnterpriseBGPGlobal{BGPGlobal: global},
						StateNotification: stateCh,
					},
				)
			},
			func(router entTypes.EnterpriseRouter, global types.BGPGlobal) *EnterpriseBGPInstance {
				return &EnterpriseBGPInstance{
					Name:   "test",
					Global: entTypes.EnterpriseBGPGlobal{BGPGlobal: global},
					Router: router,
					Config: &v1.IsovalentBGPNodeInstance{
						Name:     "test",
						LocalASN: ptr.To[int64](65000),
						VRFs: []v1.IsovalentBGPNodeVRF{
							{
								PrivateNetworkRef: &v1.BGPPrivateNetworkReference{
									Name: "privnet0",
								},
								ImportRTs: []string{"65000:100"},
							},
							{
								PrivateNetworkRef: &v1.BGPPrivateNetworkReference{
									Name: "privnet1",
								},
								ImportRTs: []string{"65000:200"},
							},
						},
					},
				}
			},
			tunnel.NewTestConfig,
			func() tunnel.EncapProtocol {
				return tunnel.VXLAN
			},
		),
		cell.Invoke(
			registerMockStateReconciler,
			func(
				db *statedb.DB,
				table statedb.RWTable[tables.PrivateNetwork],
				r *rib.RIB,
				rtr entTypes.EnterpriseRouter,
			) {
				RIB = r
				router = rtr

				wtxn := db.WriteTxn(table)
				table.Insert(wtxn, tables.PrivateNetwork{
					Name: "privnet0",
					ID:   1,
				})
				table.Insert(wtxn, tables.PrivateNetwork{
					Name: "privnet1",
					ID:   2,
				})
				wtxn.Commit()
			},
		),
	))

	hive.AddConfigOverride(h, func(c *enterpriseConfig.Config) {
		c.Enabled = true
	})
	hive.AddConfigOverride(h, func(c *evpnConfig.Config) {
		c.Enabled = true
	})
	hive.AddConfigOverride(h, func(c *privnetConfig.Flags) {
		c.Enabled = true
	})

	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	err := h.Start(logger, t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		h.Stop(logger, t.Context())
		router.Stop(t.Context(), types.StopRequest{FullDestroy: true})
	})

	// Allow all route import for EVPN paths. As we don't have
	// EVPNPolicyReconciler.
	policy := entTypes.RoutePolicyExtendedRequest{
		DefaultExportAction: types.RoutePolicyActionReject,
		Policy: &entTypes.ExtendedRoutePolicy{
			Name: "allow-all-evpn-routes",
			Type: types.RoutePolicyTypeImport,
			Statements: []*entTypes.ExtendedRoutePolicyStatement{
				{
					Conditions: entTypes.ExtendedRoutePolicyConditions{
						RoutePolicyConditions: types.RoutePolicyConditions{
							MatchFamilies: []types.Family{
								{
									Afi:  types.AfiL2VPN,
									Safi: types.SafiEvpn,
								},
							},
						},
					},
					Actions: entTypes.ExtendedRoutePolicyActions{
						RoutePolicyActions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
						},
					},
				},
			},
		},
	}
	err = router.AddRoutePolicyExtended(t.Context(), policy)
	require.NoError(t, err)

	// Peering locally
	err = router.AddNeighbor(t.Context(), &types.Neighbor{
		Address: netip.MustParseAddr("127.0.0.1"),
		ASN:     65000,
		Timers: &types.NeighborTimers{
			ConnectRetry: 1,
		},
		Transport: &types.NeighborTransport{
			RemotePort: 11799,
		},
		AfiSafis: []*types.Family{
			{
				Afi:  types.AfiL2VPN,
				Safi: types.SafiEvpn,
			},
		},
	})
	require.NoError(t, err)

	tests := []struct {
		name           string
		bgpcapfile     string
		expectedRoutes map[uint32][]*rib.Route
	}{
		{
			name:       "Nexus EVPN Pure RT5",
			bgpcapfile: "testdata/evpn-pure-rt5-nexus.bgpcap",
			expectedRoutes: map[uint32][]*rib.Route{
				1: {
					&rib.Route{
						Prefix:   netip.MustParsePrefix("10.0.0.0/32"),
						Owner:    ribOwnerName("test"),
						Protocol: rib.ProtocolIBGP,
						NextHop: &rib.VXLANEncap{
							VNI:         vni.MustFromUint32(100),
							VTEPIP:      netip.MustParseAddr("100.64.1.0"),
							InnerDstMAC: net.HardwareAddr{0x0c, 0xfe, 0x45, 0x00, 0x1b, 0x08},
						},
					},
					&rib.Route{
						Prefix:   netip.MustParsePrefix("10.0.0.1/32"),
						Owner:    ribOwnerName("test"),
						Protocol: rib.ProtocolIBGP,
						NextHop: &rib.VXLANEncap{
							VNI:         vni.MustFromUint32(100),
							VTEPIP:      netip.MustParseAddr("100.64.1.1"),
							InnerDstMAC: net.HardwareAddr{0x3e, 0x68, 0xa9, 0x25, 0x48, 0xca},
						},
					},
				},
				2: {
					&rib.Route{
						Prefix:   netip.MustParsePrefix("10.0.0.0/32"),
						Owner:    ribOwnerName("test"),
						Protocol: rib.ProtocolIBGP,
						NextHop: &rib.VXLANEncap{
							VNI:         vni.MustFromUint32(200),
							VTEPIP:      netip.MustParseAddr("100.64.1.0"),
							InnerDstMAC: net.HardwareAddr{0x0c, 0xfe, 0x45, 0x00, 0x1b, 0x08},
						},
					},
					&rib.Route{
						Prefix:   netip.MustParsePrefix("10.0.0.1/32"),
						Owner:    ribOwnerName("test"),
						Protocol: rib.ProtocolIBGP,
						NextHop: &rib.VXLANEncap{
							VNI:         vni.MustFromUint32(200),
							VTEPIP:      netip.MustParseAddr("100.64.1.1"),
							InnerDstMAC: net.HardwareAddr{0x3e, 0x68, 0xa9, 0x25, 0x48, 0xca},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := replayer.New(logger, replayer.ReplayerSpec{
				PeerAddr: "127.0.0.1",
				PeerPort: 11799,
				FileName: tt.bgpcapfile,
			})
			defer rep.Close()

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				err := rep.Replay()
				if !assert.NoError(ct, err, "Failed to connect to GoBGP server") {
					return
				}
			}, time.Second*5, 100*time.Millisecond)

			expectedRoutes := map[uint32]*bitlpm.CIDRTrie[*rib.Route]{}
			for vrfID, routes := range tt.expectedRoutes {
				trie := bitlpm.NewCIDRTrie[*rib.Route]()
				for _, route := range routes {
					trie.Upsert(route.Prefix, route)
				}
				if trie.Len() > 0 {
					expectedRoutes[vrfID] = trie
				}
			}

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				toUpsert, toDelete := calculateRouteDiffs(
					expectedRoutes,
					RIB.ListRoutes(ribOwnerName("test")),
				)
				if !assert.True(
					ct,
					len(toUpsert) == 0 && len(toDelete) == 0,
					"Still have diff between expected and actual routes: %d upsert, %d delete",
					len(toUpsert),
					len(toDelete),
				) {
					return
				}
			}, time.Second*5, 100*time.Millisecond)
		})
	}
}

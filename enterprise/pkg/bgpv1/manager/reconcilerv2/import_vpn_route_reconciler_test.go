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
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
	"github.com/YutaroHayakawa/bgplay/pkg/replayer"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	bgpv3 "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/option"
)

// This test covers the most complicated MPReachNLRI parsing logic.
// Rest of the path attribute parsing doesn't have much logic and
// about extracting the values from the path attribute.
func TestParseMPReachNLRI(t *testing.T) {
	tests := []struct {
		name           string
		attr           *bgp.PathAttributeMpReachNLRI
		expectedPrefix netip.Prefix
		expectedLabel  uint32
		expectedError  error
	}{
		{
			name: "VPNv4 NLRI",
			attr: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN),
				"fd00::1",
				mustLabeledVPNIPAddrPrefix(
					netip.MustParsePrefix("10.0.0.0/24"),
					bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
					bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
				),
			),
			expectedPrefix: netip.MustParsePrefix("10.0.0.0/24"),
			expectedLabel:  0x12345,
			expectedError:  nil,
		},
		{
			name: "More than one NLRI",
			attr: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN),
				"fd00::1",
				mustLabeledVPNIPAddrPrefix(
					netip.MustParsePrefix("10.0.0.0/24"),
					bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
					bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
				),
				mustLabeledVPNIPAddrPrefix(
					netip.MustParsePrefix("20.0.0.0/24"),
					bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
					bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
				),
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errUnexpectedNumberOfNLRI,
		},
		{
			name: "Non-IPv4 AFI",
			attr: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST),
				"fd00::1",
				mustIPAddrPrefixNLRI("fd00::/64"),
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errUnexpectedAFI,
		},
		{
			name: "Non-Labeled-VPN SAFI",
			attr: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST),
				"fd00::1",
				mustIPAddrPrefixNLRI("10.0.0.0/24"),
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errUnexpectedSAFI,
		},
		{
			name: "Self-originated route v4",
			attr: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN),
				"0.0.0.0",
				mustLabeledVPNIPAddrPrefix(
					netip.MustParsePrefix("10.0.0.0/24"),
					bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
					bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
				),
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errSelfOriginatedRoute,
		},
		{
			name: "Self-originated route v6",
			attr: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN),
				"::",
				mustLabeledVPNIPAddrPrefix(
					netip.MustParsePrefix("10.0.0.0/24"),
					bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
					bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
				),
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errSelfOriginatedRoute,
		},
		{
			name: "More than one label",
			attr: mustPathAttributeMpReachNLRI(
				bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN),
				"fd00::1",
				mustLabeledVPNIPAddrPrefix(
					netip.MustParsePrefix("10.0.0.0/24"),
					bgp.MPLSLabelStack{Labels: []uint32{0x12345, 0x54321}},
					bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
				),
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errMoreThanOneLabel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := importVPNRouteReconciler{}
			prefix, label, err := r.parseMPReachNLRI(tt.attr)
			require.Equal(t, tt.expectedPrefix, prefix)
			require.Equal(t, tt.expectedLabel, label)
			require.ErrorIs(t, tt.expectedError, err)
		})
	}
}

func TestSRv6RouteImport(t *testing.T) {
	var (
		RIB    *rib.RIB
		router types.Router
	)

	hive := hive.New(cell.Module(
		"test",
		"test module",
		rib.Cell,
		rib.NopDataPlaneCell,
		k8sfake.FakeClientCell(),
		cell.Provide(
			k8s.IsovalentVRFResource,
			newImportVPNRouteReconciler,
			newImportVPNRouteStateReconciler,
			func() Config {
				return Config{
					SvcHealthCheckingEnabled:    false,
					RouterAdvertisementInterval: time.Second,
					EnableLegacySRv6Responder:   false,
				}
			},
			func() config.Config {
				return config.Config{
					Enabled:             true,
					StatusReportEnabled: false,
				}
			},
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableSRv6: true,
				}
			},
			func() *legacyImportVPNRouteReconciler {
				return nil
			},
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
			) (types.Router, error) {
				return gobgp.NewGoBGPServer(
					t.Context(),
					logger,
					types.ServerParameters{
						Global:            global,
						StateNotification: stateCh,
					},
				)
			},
			func(router types.Router, global types.BGPGlobal) *instance.BGPInstance {
				return &instance.BGPInstance{
					Name:   "test",
					Global: global,
					Router: router,
					Config: &v2.CiliumBGPNodeInstance{
						Name:     "test",
						LocalASN: ptr.To[int64](65000),
					},
				}
			},
			func(inst *instance.BGPInstance) paramUpgrader {
				return newUpgraderMock(&v1.IsovalentBGPNodeInstance{
					Name:     inst.Name,
					LocalASN: inst.Config.LocalASN,
					VRFs: []v1.IsovalentBGPNodeVRF{
						{
							VRFRef:    ptr.To("vrf0"),
							ImportRTs: []string{"65000:1"},
						},
						{
							VRFRef:    ptr.To("vrf1"),
							ImportRTs: []string{"65000:2"},
						},
					},
				})
			},
		),
		cell.Invoke(
			registerMockStateReconciler,
			func(
				r *rib.RIB,
				rtr types.Router,
			) {
				RIB = r
				router = rtr
			},
			func(cs *k8sfake.FakeClientset) {
				_, err := cs.IsovalentV1alpha1().IsovalentVRFs().Create(
					t.Context(),
					&v1alpha1.IsovalentVRF{
						ObjectMeta: metav1.ObjectMeta{
							Name: "vrf0",
						},
						Spec: v1alpha1.IsovalentVRFSpec{
							VRFID: 1,
						},
					},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)
				_, err = cs.IsovalentV1alpha1().IsovalentVRFs().Create(
					t.Context(),
					&v1alpha1.IsovalentVRF{
						ObjectMeta: metav1.ObjectMeta{
							Name: "vrf1",
						},
						Spec: v1alpha1.IsovalentVRFSpec{
							VRFID: 2,
						},
					},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)
			},
		),
	))

	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	err := hive.Start(logger, t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		hive.Stop(logger, t.Context())
		router.Stop(t.Context(), types.StopRequest{FullDestroy: true})
	})

	// Allow all route import for VPNv4 paths. As we don't have
	// VPNPolicyReconciler.
	policy := entTypes.RoutePolicyExtendedRequest{
		DefaultExportAction: types.RoutePolicyActionReject,
		Policy: &entTypes.ExtendedRoutePolicy{
			Name: "allow-all-vpnv4-routes",
			Type: types.RoutePolicyTypeImport,
			Statements: []*entTypes.ExtendedRoutePolicyStatement{
				{
					Conditions: entTypes.ExtendedRoutePolicyConditions{
						RoutePolicyConditions: types.RoutePolicyConditions{
							MatchFamilies: []types.Family{
								{
									Afi:  types.AfiIPv4,
									Safi: types.SafiMplsVpn,
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
	err = router.(entTypes.EnterpriseRouter).AddRoutePolicyExtended(t.Context(), policy)
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
				Afi:  types.AfiIPv4,
				Safi: types.SafiMplsVpn,
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
			name:       "FRR VPNv4",
			bgpcapfile: "testdata/vpnv4-frr.bgpcap",
			expectedRoutes: map[uint32][]*rib.Route{
				1: {
					&rib.Route{
						Prefix:   netip.MustParsePrefix("10.3.0.0/24"),
						Owner:    ribOwnerName("test"),
						Protocol: rib.ProtocolIBGP,
						NextHop: &rib.HEncaps{
							Segments: []srv6Types.SID{
								{
									Addr: netip.MustParseAddr("fd00:2222:0:0:1::"),
								},
							},
						},
					},
				},
				2: {
					&rib.Route{
						Prefix:   netip.MustParsePrefix("10.3.0.0/24"),
						Owner:    ribOwnerName("test"),
						Protocol: rib.ProtocolIBGP,
						NextHop: &rib.HEncaps{
							Segments: []srv6Types.SID{
								{
									Addr: netip.MustParseAddr("fd00:2222:0:0:2::"),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := bgpcap.Open(tt.bgpcapfile)
			require.NoError(t, err)
			defer file.Close()

			openMsg, err := file.Read()
			require.NoError(t, err)

			require.IsType(t, &bgpv3.BGPOpen{}, openMsg.Body,
				"The first message should be an OPEN message")

			d := replayer.Dialer{
				OpenMessage: openMsg,
			}

			var conn *replayer.Conn
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				conn, err = d.Connect(
					t.Context(),
					netip.MustParseAddrPort("127.0.0.1:11799"),
				)
				if !assert.NoError(ct, err, "Failed to connect to GoBGP server") {
					return
				}
			}, time.Second*5, 100*time.Millisecond)
			defer conn.Close()

			for {
				msg, err := file.Read()
				if err != nil && errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err)

				err = conn.Write(msg)
				require.NoError(t, err)
			}

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

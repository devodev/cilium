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
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
)

func TestRouteImportReconcilerParseV4Path(t *testing.T) {
	nlri := mustIPAddrPrefixNLRI("10.0.0.0/24")
	linkLocalNexthop := netip.MustParseAddr("fe80::1")
	neighborAddrWithZone := netip.MustParseAddr("fe80::1%if0")

	mpReachNLRI_G := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), "fd00::1", nlri)
	mpReachNLRI_L := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), "fe80::1", nlri)
	mpReachNLRI_GL := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), "fd00::1", nlri)
	mpReachNLRI_GL.LinkLocalNexthop = linkLocalNexthop

	mpReachNLRI_ZL := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), "::", nlri)
	mpReachNLRI_ZL.LinkLocalNexthop = linkLocalNexthop

	mpReachNLRI_LL := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), "fe80::1", nlri)
	mpReachNLRI_LL.LinkLocalNexthop = linkLocalNexthop

	tests := []struct {
		name        string
		inputPath   *types.ExtendedPath
		outputPath  *path
		expectedErr error
	}{
		{
			name: "Valid IPv4 NEXT_HOP",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI: nlri,
					PathAttributes: []bgp.PathAttributeInterface{
						mustPathAttributeNextHop("192.168.0.1"),
					},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("192.168.0.1"),
			},
		},
		{
			name: "Valid IPv4 NEXT_HOP self-originated",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI: nlri,
					PathAttributes: []bgp.PathAttributeInterface{
						mustPathAttributeNextHop("0.0.0.0"),
					},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errSelfOriginatedRoute,
		},
		{
			name: "Valid IPv4 MP_REACH_NLRI",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI: nlri,
					PathAttributes: []bgp.PathAttributeInterface{
						mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), "192.168.0.1", nlri),
					},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("192.168.0.1"),
			},
		},
		{
			name: "Valid IPv4 MP_REACH_NLRI self-originated",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI: nlri,
					PathAttributes: []bgp.PathAttributeInterface{
						mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), "0.0.0.0", nlri),
					},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errSelfOriginatedRoute,
		},
		{
			name: "Invalid missing required attributes",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errMalformedPath,
		},
		{
			name: "Unsupported v6 nexthop NEXT_HOP",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI: nlri,
					PathAttributes: []bgp.PathAttributeInterface{
						mustPathAttributeNextHop("fd00::1"),
					},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
		// For RFC8950 handling, we have 10 possible cases. The
		// following five nexthop encoding:
		//
		// 1. G (Global=True global address, LinkLocal=N/A)
		// 2. L (Global=Link-local address, LinkLocal=N/A)
		// 3. G/L (Global=True global address, LinkLocal=Link-local address)
		// 4. ::/L (Global=::, LinkLocal=Link-local address)
		// 5. L/L (Global=Link-local address, LinkLocal=Link-local address)
		//
		// And with or without zone information derived from the
		// neighbor. The link-local address is only valid when the
		// neighbor address contains zone information.
		{
			name: "Valid RFC8960 G with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_G},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fd00::1"),
			},
		},
		{
			name: "Valid RFC8960 L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_L},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid RFC8960 G/L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_GL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid RFC8960 ::/L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_ZL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid RFC8960 L/L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_LL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid RFC8960 G without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_G},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fd00::1"),
			},
		},
		{
			name: "Invalid RFC8960 L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_L},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
		{
			name: "Valid RFC8960 G/L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_GL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fd00::1"),
			},
		},
		{
			name: "Invalid RFC8960 ::/L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_ZL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
		{
			name: "Invalid RFC8960 L/L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_LL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv4,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &importRouteReconciler{}
			parsedPath, err := reconciler.parseV4Path(tt.inputPath)
			if tt.expectedErr != nil {
				require.ErrorIs(t, tt.expectedErr, err)
			} else {
				require.Equal(t, tt.outputPath, parsedPath, "Unexpected result (error=%s)", err)
			}
		})
	}
}

func TestRouteImportReconcilerParseV6Path(t *testing.T) {
	nlri := mustIPAddrPrefixNLRI("2001:db8::/64")
	linkLocalNexthop := netip.MustParseAddr("fe80::1")
	neighborAddrWithZone := netip.MustParseAddr("fe80::1%if0")

	mpReachNLRI_G := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), "fd00::1", nlri)
	mpReachNLRI_G_SelfOriginated := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), "::", nlri)
	mpReachNLRI_L := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), "fe80::1", nlri)
	mpReachNLRI_GL := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), "fd00::1", nlri)
	mpReachNLRI_GL.LinkLocalNexthop = linkLocalNexthop

	mpReachNLRI_ZL := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), "::", nlri)
	mpReachNLRI_ZL.LinkLocalNexthop = linkLocalNexthop

	mpReachNLRI_LL := mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), "fe80::1", nlri)
	mpReachNLRI_LL.LinkLocalNexthop = linkLocalNexthop

	tests := []struct {
		name        string
		inputPath   *types.ExtendedPath
		outputPath  *path
		expectedErr error
	}{
		// For IPv6 nexthop handling, we have 10 possible cases. The
		// following five nexthop encoding:
		//
		// 1. G (Global=True global address, LinkLocal=N/A)
		// 2. L (Global=Link-local address, LinkLocal=N/A)
		// 3. G/L (Global=True global address, LinkLocal=Link-local address)
		// 4. ::/L (Global=::, LinkLocal=Link-local address)
		// 5. L/L (Global=Link-local address, LinkLocal=Link-local address)
		//
		// And with or without zone information derived from the
		// neighbor. The link-local address is only valid when the
		// neighbor address contains zone information.
		{
			name: "Valid G with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_G},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fd00::1"),
			},
		},
		{
			name: "Valid G self-originated",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_G_SelfOriginated},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			expectedErr: errSelfOriginatedRoute,
		},
		{
			name: "Valid L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_L},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid G/L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_GL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid ::/L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_ZL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid L/L with zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_LL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
				NeighborAddr: neighborAddrWithZone,
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fe80::1%if0"),
			},
		},
		{
			name: "Valid G without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_G},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fd00::1"),
			},
		},
		{
			name: "Invalid L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_L},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
		{
			name: "Valid G/L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_GL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			outputPath: &path{
				nexthop: netip.MustParseAddr("fd00::1"),
			},
		},
		{
			name: "Invalid ::/L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_ZL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
		{
			name: "Invalid L/L without zone",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{mpReachNLRI_LL},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
		{
			name: "Invalid missing required attributes",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI:           nlri,
					PathAttributes: []bgp.PathAttributeInterface{},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errMalformedPath,
		},
		{
			name: "Unsupported v4 nexthop MP_REACH_NLRI (non-standard)",
			inputPath: &types.ExtendedPath{
				Path: ossTypes.Path{
					NLRI: nlri,
					PathAttributes: []bgp.PathAttributeInterface{
						mustPathAttributeMpReachNLRI(bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), "10.0.0.1", nlri),
					},
					Family: ossTypes.Family{
						Afi:  ossTypes.AfiIPv6,
						Safi: ossTypes.SafiUnicast,
					},
					SourceASN: 65000,
				},
			},
			expectedErr: errUnsupportedNexthop,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &importRouteReconciler{}
			parsedPath, err := reconciler.parseV6Path(tt.inputPath)
			if tt.expectedErr != nil {
				require.ErrorIs(t, tt.expectedErr, err)
			} else {
				require.Equal(t, tt.outputPath, parsedPath, "Unexpected result (error=%s)", err)
			}
		})
	}
}

// This test ensures that converting the path with toTableRoute and back with
// toPath ends up with the same path. This is important to correctly calculate
// the diffs of current and desired routes.
func TestRouteImportReconcilerToPath(t *testing.T) {
	var owner reconciler.RouteOwner

	// This is a workaround for the issue that the RouteOwner struct cannot
	// be directly instantiated due to unexported fields.
	err := yaml.Unmarshal([]byte("name: test-owner"), &owner)
	require.NoError(t, err)

	tests := []struct {
		name  string
		owner *reconciler.RouteOwner
		dst   *destination
	}{
		{
			name:  "Valid IPv4 route iBGP",
			owner: &owner,
			dst: &destination{
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("192.168.0.1"),
					},
				},
			},
		},
		{
			name:  "Valid IPv4 route eBGP",
			owner: &owner,
			dst: &destination{
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("192.168.0.1"),
					},
				},
			},
		},
		{
			name:  "Valid IPv6 route",
			owner: &owner,
			dst: &destination{
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("2001:db8::1"),
					},
				},
			},
		},
		{
			name:  "Valid IPv4 route with link-local nexthop",
			owner: &owner,
			dst: &destination{
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("fe80::1%if0"),
					},
				},
			},
		},
		{
			name:  "Valid IPv6 route with link-local nexthop",
			owner: &owner,
			dst: &destination{
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("fe80::1%if0"),
					},
				},
			},
		},
		{
			name:  "Valid multi path",
			owner: &owner,
			dst: &destination{
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("192.168.0.1"),
					},
					{
						nexthop: netip.MustParseAddr("2001:db8::1"),
					},
					{
						nexthop: netip.MustParseAddr("fe80::1%if0"),
					},
				},
			},
		},
		{
			name:  "Valid IPv4 route with VRF table ID",
			owner: &owner,
			dst: &destination{
				destinationKey: destinationKey{tableID: 1000},
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("192.168.0.1"),
					},
				},
			},
		},
		{
			name:  "Valid IPv6 route with VRF table ID",
			owner: &owner,
			dst: &destination{
				destinationKey: destinationKey{tableID: 1000},
				paths: []*path{
					{
						nexthop: netip.MustParseAddr("2001:db8::1"),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := statedb.New()

			deviceTable, err := tables.NewDeviceTable(db)
			require.NoError(t, err)

			reconciler := &importRouteReconciler{
				db:          db,
				deviceTable: deviceTable,
			}

			wtxn := db.WriteTxn(deviceTable)
			deviceTable.Insert(wtxn, &tables.Device{
				Index: 1,
				Name:  "if0",
			})
			wtxn.Commit()

			tableRoute, err := reconciler.toTableRoute(db.ReadTxn(), tt.owner, tt.dst)
			require.NoError(t, err)

			dst, err := reconciler.toDestination(tt.owner, &tableRoute)
			require.NoError(t, err)

			require.Equal(t, tt.dst, dst, "The converted path does not match the original")
		})
	}
}

// TestRouteImportReconcilerReconcileSamePrefixInDifferentTables verifies that
// reconciliation removes a stale route when an instance's VRF table changes.
// During the transition, the same prefix can exist in both the old and new
// tables. Both routes must be considered independently so that only the route
// in the old table is deleted.
//
// It's hard to reproduce this behavior in script test as currently, changing
// the VRF tableID recreates the instance itself, but it's still worth having
// this test as we may be able to get rid of this limitation in the future.
func TestRouteImportReconcilerReconcileSamePrefixInDifferentTables(t *testing.T) {
	var (
		db                *statedb.DB
		drm               *reconciler.DesiredRouteManager
		desiredRouteTable statedb.Table[*reconciler.DesiredRoute]
	)
	logger := hivetest.Logger(t)
	// Construct the desired-route manager used by Reconcile to read and update
	// the DesiredRoute table.
	h := ciliumhive.New(
		reconciler.TableCell,
		cell.Provide(func() statedbReconciler.Reconciler[*reconciler.DesiredRoute] {
			return nil
		}),
		cell.Invoke(func(
			_db *statedb.DB,
			_drm *reconciler.DesiredRouteManager,
			_desiredRouteTable statedb.Table[*reconciler.DesiredRoute],
		) {
			db = _db
			drm = _drm
			desiredRouteTable = _desiredRouteTable
		}),
	)
	require.NoError(t, h.Populate(logger))

	// Use the owner name that the import route reconciler assigns to instance0.
	owner, err := drm.GetOrRegisterOwner("bgp-instance0")
	require.NoError(t, err)

	const prefix = "192.0.2.0/24"
	// Seed routes for the same prefix in the old and new VRF tables. Reconcile
	// must remove only the route in table 1000.
	for _, route := range []*reconciler.DesiredRoute{
		{
			Owner:         owner,
			Table:         1000,
			Prefix:        netip.MustParsePrefix(prefix),
			AdminDistance: AdminDistanceEBGP,
			Nexthop:       netip.MustParseAddr("192.0.2.1"),
			Type:          reconciler.RTN_UNICAST,
		},
		{
			Owner:         owner,
			Table:         2000,
			Prefix:        netip.MustParsePrefix(prefix),
			AdminDistance: AdminDistanceEBGP,
			Nexthop:       netip.MustParseAddr("192.0.2.1"),
			Type:          reconciler.RTN_UNICAST,
		},
	} {
		err = drm.UpsertRoute(*route)
		require.NoError(t, err)
	}

	// Make the router report the prefix that should remain imported into table
	// 2000 for the current instance.
	router := fake.NewEnterpriseFakeRouter()
	_, err = router.AdvertisePath(t.Context(), ossTypes.PathRequest{Path: &ossTypes.Path{
		NLRI: mustIPAddrPrefixNLRI(prefix),
		PathAttributes: []bgp.PathAttributeInterface{
			mustPathAttributeNextHop("192.0.2.1"),
		},
		Family: ossTypes.Family{
			Afi:  ossTypes.AfiIPv4,
			Safi: ossTypes.SafiUnicast,
		},
		Best:      true,
		SourceASN: 65001,
	}})
	require.NoError(t, err)

	// Reconcile the instance after its VRF table has changed to 2000.
	r := &importRouteReconciler{
		logger:            logger,
		drm:               drm,
		db:                db,
		desiredRoutetable: desiredRouteTable,
		errorPathStore:    newErrorPathStore(),
	}
	err = r.Reconcile(t.Context(), EnterpriseStateReconcileParams{
		UpdatedInstance: &EnterpriseBGPInstance{
			Name:   "instance0",
			Router: router,
			VRF: types.EnterpriseBGPVRF{
				TableID: 2000,
			},
		},
	})
	require.NoError(t, err)

	// The stale table-1000 route must be gone while the table-2000 route stays.
	routes := statedb.Collect(desiredRouteTable.All(db.ReadTxn()))
	require.Len(t, routes, 1)
	require.Equal(t, reconciler.TableID(2000), routes[0].Table)
	require.Equal(t, netip.MustParsePrefix(prefix), routes[0].Prefix)
}

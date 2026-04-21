// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gobgp

import (
	"net/netip"
	"testing"
	"time"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

func TestToAgentPathsExtended(t *testing.T) {
	validPath, err := apiutil.NewPath(
		bgp.NewIPAddrPrefix(24, "10.0.0.0"),
		false,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeNextHop("192.168.0.1"),
		},
		time.Time{},
	)
	require.NoError(t, err)

	invalidPath, err := apiutil.NewPath(
		bgp.NewIPAddrPrefix(24, "10.0.0.0"),
		false,
		[]bgp.PathAttributeInterface{},
		time.Time{},
	)
	require.NoError(t, err)
	invalidPath.Nlri = nil // Force an invalid NLRI

	p, err := ToAgentPath(validPath)
	require.NoError(t, err)

	expectedPath := &types.ExtendedPath{
		Path: *p,
	}

	tests := []struct {
		name    string
		paths   []*gobgp.Path
		want    []*types.ExtendedPath
		wantErr bool
	}{
		{
			name: "Complete Result",
			paths: []*gobgp.Path{
				validPath,
			},
			want: []*types.ExtendedPath{
				expectedPath,
			},
			wantErr: false,
		},
		{
			name: "Partial Result with Error",
			paths: []*gobgp.Path{
				invalidPath,
				validPath,
			},
			want: []*types.ExtendedPath{
				expectedPath,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToAgentPathsExtended(tt.paths)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToAgentPathsExtended() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestToAgentPathExtended(t *testing.T) {
	tests := []struct {
		name           string
		extendInput    func(*gobgp.Path)
		extendExpected func(*types.ExtendedPath)
	}{
		{
			name:           "No extension",
			extendInput:    func(p *gobgp.Path) {},
			extendExpected: func(p *types.ExtendedPath) {},
		},
		{
			name: "NeighborIp extension",
			extendInput: func(p *gobgp.Path) {
				p.NeighborIp = "fe80::1%eth0"
			},
			extendExpected: func(p *types.ExtendedPath) {
				p.NeighborAddr = netip.MustParseAddr("fe80::1%eth0")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validPath, err := apiutil.NewPath(
				bgp.NewIPAddrPrefix(24, "10.0.0.0"),
				false,
				[]bgp.PathAttributeInterface{
					bgp.NewPathAttributeNextHop("192.168.0.1"),
				},
				time.Time{},
			)
			require.NoError(t, err)

			p, err := ToAgentPath(validPath)
			require.NoError(t, err)

			expectedPath := &types.ExtendedPath{
				Path: *p,
			}

			tt.extendInput(validPath)
			tt.extendExpected(expectedPath)

			got, err := ToAgentPathExtended(validPath)
			require.NoError(t, err)
			require.Equal(t, expectedPath, got)
		})
	}
}

func TestToGoBGPPeerExtended(t *testing.T) {
	tests := []struct {
		name     string
		neighbor *types.EnterpriseNeighbor
		want     *gobgp.Peer
	}{
		{
			name: "with RouteReflector only",
			neighbor: &types.EnterpriseNeighbor{
				Neighbor: ossTypes.Neighbor{
					Address: netip.MustParseAddr("1.2.3.4"),
					ASN:     65001,
				},
				RouteReflector: &types.NeighborRouteReflector{
					Client:    true,
					ClusterID: "1.2.3.4",
				},
			},
			want: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "1.2.3.4",
					PeerAsn:         65001,
				},
				AfiSafis: defaultAfiSafi,
				RouteReflector: &gobgp.RouteReflector{
					RouteReflectorClient:    true,
					RouteReflectorClusterId: "1.2.3.4",
				},
			},
		},
		{
			name: "With AddPaths only",
			neighbor: &types.EnterpriseNeighbor{
				Neighbor: ossTypes.Neighbor{
					Address: netip.MustParseAddr("1.2.3.4"),
					ASN:     65001,
					AfiSafis: []*ossTypes.Family{
						{
							Afi:  ossTypes.AfiIPv4,
							Safi: ossTypes.SafiUnicast,
						},
						{
							Afi:  ossTypes.AfiIPv6,
							Safi: ossTypes.SafiUnicast,
						},
					},
				},
				AddPath: &types.NeighborAddPath{
					SendMax: 4,
				},
			},
			want: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "1.2.3.4",
					PeerAsn:         65001,
				},
				AfiSafis: []*gobgp.AfiSafi{
					{
						Config: &gobgp.AfiSafiConfig{
							Family: GoBGPIPv4Family,
						},
						AddPaths: &gobgp.AddPaths{
							Config: &gobgp.AddPathsConfig{
								SendMax: 4,
							},
						},
					},
					{
						Config: &gobgp.AfiSafiConfig{
							Family: GoBGPIPv6Family,
						},
						AddPaths: &gobgp.AddPaths{
							Config: &gobgp.AddPathsConfig{
								SendMax: 4,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toGoBGPPeerExtended(tt.neighbor, nil, true)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestToGoBGPPolicyStatementExtended(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *types.ExtendedRoutePolicyStatement
		wantStmt    *gobgp.Statement
		wantDefSets []*gobgp.DefinedSet
	}{
		{
			name: "Enterprise-specific conditions and actions",
			stmt: &types.ExtendedRoutePolicyStatement{
				Conditions: types.ExtendedRoutePolicyConditions{
					MatchCommunities: &types.RoutePolicyCommunityMatch{
						Type:        ossTypes.RoutePolicyMatchAny,
						Communities: []string{"65000:100", "65000:200"},
					},
					MatchLargeCommunities: &types.RoutePolicyCommunityMatch{
						Type:        ossTypes.RoutePolicyMatchAll,
						Communities: []string{"65000:100:1", "65000:200:2"},
					},
				},
				Actions: types.ExtendedRoutePolicyActions{
					ASPathPrepend: &types.ExtendedRoutePolicyActionASPathPrepend{
						Repeat: 3,
					},
				},
			},
			wantStmt: &gobgp.Statement{
				Name: "test-statement",
				Conditions: &gobgp.Conditions{
					CommunitySet: &gobgp.MatchSet{
						Name: "test-statement-community",
						Type: gobgp.MatchSet_ANY,
					},
					LargeCommunitySet: &gobgp.MatchSet{
						Name: "test-statement-large-community",
						Type: gobgp.MatchSet_ALL,
					},
				},
				Actions: &gobgp.Actions{
					AsPrepend: &gobgp.AsPrependAction{
						Repeat:      3,
						UseLeftMost: true,
					},
				},
			},
			wantDefSets: []*gobgp.DefinedSet{
				{
					DefinedType: gobgp.DefinedType_COMMUNITY,
					Name:        "test-statement-community",
					List:        []string{"65000:100", "65000:200"},
				},
				{
					DefinedType: gobgp.DefinedType_LARGE_COMMUNITY,
					Name:        "test-statement-large-community",
					List:        []string{"65000:100:1", "65000:200:2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStmt, gotDefSets := toGoBGPPolicyStatementExtended(tt.stmt, "test-statement")
			require.Equal(t, tt.wantStmt, gotStmt)
			require.Equal(t, tt.wantDefSets, gotDefSets)
		})
	}
}

func TestToAgentRoutePolicyExtended(t *testing.T) {
	tests := []struct {
		name string
		stmt *gobgp.Statement
		want *types.ExtendedRoutePolicyStatement
	}{
		{
			name: "Enterprise-specific conditions and actions",
			stmt: &gobgp.Statement{
				Name: "test-statement",
				Conditions: &gobgp.Conditions{
					CommunitySet: &gobgp.MatchSet{
						Name: "test-statement-community",
						Type: gobgp.MatchSet_ANY,
					},
					LargeCommunitySet: &gobgp.MatchSet{
						Name: "test-statement-large-community",
						Type: gobgp.MatchSet_ALL,
					},
				},
				Actions: &gobgp.Actions{
					AsPrepend: &gobgp.AsPrependAction{
						Repeat:      3,
						UseLeftMost: true,
					},
				},
			},
			want: &types.ExtendedRoutePolicyStatement{
				Conditions: types.ExtendedRoutePolicyConditions{
					MatchCommunities: &types.RoutePolicyCommunityMatch{
						Type:        ossTypes.RoutePolicyMatchAny,
						Communities: []string{"65000:100", "65000:200"},
					},
					MatchLargeCommunities: &types.RoutePolicyCommunityMatch{
						Type:        ossTypes.RoutePolicyMatchAll,
						Communities: []string{"65000:100:1", "65000:200:2"},
					},
				},
				Actions: types.ExtendedRoutePolicyActions{
					ASPathPrepend: &types.ExtendedRoutePolicyActionASPathPrepend{
						Repeat: 3,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toAgentPolicyStatementExtended(tt.stmt, map[string]*gobgp.DefinedSet{
				"test-statement-community": {
					DefinedType: gobgp.DefinedType_COMMUNITY,
					Name:        "test-statement-community",
					List:        []string{"65000:100", "65000:200"},
				},
				"test-statement-large-community": {
					DefinedType: gobgp.DefinedType_LARGE_COMMUNITY,
					Name:        "test-statement-large-community",
					List:        []string{"65000:100:1", "65000:200:2"},
				},
			})
			require.Equal(t, tt.want, got)
		})
	}
}

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

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	enterpriseTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/types"
)

func Test_MergeRoutePolicies(t *testing.T) {
	neighbor1 := []netip.Addr{netip.MustParseAddr("192.168.1.1")}

	v4PrefixAExact1 := types.RoutePolicyPrefix{
		CIDR:         netip.MustParsePrefix("10.100.1.1/32"),
		PrefixLenMin: 32,
		PrefixLenMax: 32,
	}

	v4PrefixALen24 := types.RoutePolicyPrefix{
		CIDR:         netip.MustParsePrefix("10.100.1.0/24"),
		PrefixLenMin: 24,
		PrefixLenMax: 24,
	}

	ipv4UnicastFamily := types.Family{
		Afi:  types.AfiIPv4,
		Safi: types.SafiUnicast,
	}

	condition1 := types.RoutePolicyConditions{
		MatchNeighbors: &types.RoutePolicyNeighborMatch{
			Type:      types.RoutePolicyMatchAny,
			Neighbors: neighbor1,
		},
		MatchPrefixes: &types.RoutePolicyPrefixMatch{
			Type:     types.RoutePolicyMatchAny,
			Prefixes: []types.RoutePolicyPrefix{v4PrefixAExact1},
		},
		MatchFamilies: []types.Family{ipv4UnicastFamily},
	}

	condition2 := types.RoutePolicyConditions{
		MatchNeighbors: &types.RoutePolicyNeighborMatch{
			Type:      types.RoutePolicyMatchAny,
			Neighbors: neighbor1,
		},
		MatchPrefixes: &types.RoutePolicyPrefixMatch{
			Type:     types.RoutePolicyMatchAny,
			Prefixes: []types.RoutePolicyPrefix{v4PrefixALen24},
		},
		MatchFamilies: []types.Family{ipv4UnicastFamily},
	}

	action1 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:1"},
	}

	action2 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:2"},
	}

	action3 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:3"},
	}

	mergedAction12 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:1", "65000:2"},
	}

	// statement1 and statement2 have same matching condition but different actions
	// This is the scenario when 2 advertisements match same service but have different
	// community values.
	statement1 := &enterpriseTypes.ExtendedRoutePolicyStatement{
		Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
			RoutePolicyConditions: condition1,
		},
		Actions: enterpriseTypes.ExtendedRoutePolicyActions{
			RoutePolicyActions: action1,
		},
	}

	statement2 := &enterpriseTypes.ExtendedRoutePolicyStatement{
		Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
			RoutePolicyConditions: condition1,
		},
		Actions: enterpriseTypes.ExtendedRoutePolicyActions{
			RoutePolicyActions: action2,
		},
	}

	// statement3 has different matching condition ( prefix length 24)
	statement3 := &enterpriseTypes.ExtendedRoutePolicyStatement{
		Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
			RoutePolicyConditions: condition2,
		},
		Actions: enterpriseTypes.ExtendedRoutePolicyActions{
			RoutePolicyActions: action3,
		},
	}

	mergedStatement12 := &enterpriseTypes.ExtendedRoutePolicyStatement{
		Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
			RoutePolicyConditions: condition1,
		},
		Actions: enterpriseTypes.ExtendedRoutePolicyActions{
			RoutePolicyActions: mergedAction12,
		},
	}

	policy1 := &enterpriseTypes.ExtendedRoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
			statement1,
		},
	}

	policy2 := &enterpriseTypes.ExtendedRoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
			statement2,
		},
	}

	policy3 := &enterpriseTypes.ExtendedRoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
			statement3,
		},
	}

	mergedPolicy12 := &enterpriseTypes.ExtendedRoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
			mergedStatement12,
		},
	}

	mergedPolicy123 := &enterpriseTypes.ExtendedRoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
			// order of the statements is important, statement3 should come after mergedStatement12
			// since statement3 has a prefix length of 24 compared to 32 in mergedStatement12
			mergedStatement12,
			statement3,
		},
	}

	tests := []struct {
		name           string
		policyA        *enterpriseTypes.ExtendedRoutePolicy
		policyB        *enterpriseTypes.ExtendedRoutePolicy
		expectedError  bool
		expectedPolicy *enterpriseTypes.ExtendedRoutePolicy
	}{
		{
			name:           "nil policies",
			policyA:        nil,
			policyB:        nil,
			expectedError:  true,
			expectedPolicy: nil,
		},
		{
			name:           "merge policies with same prefix",
			policyA:        policy1,
			policyB:        policy2,
			expectedPolicy: mergedPolicy12,
		},
		{
			name:           "merge policies with different prefix lengths",
			policyA:        mergedPolicy12,
			policyB:        policy3,
			expectedPolicy: mergedPolicy123,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			mergedPolicy, err := MergeRoutePolicies(tt.policyA, tt.policyB)
			if tt.expectedError {
				req.Error(err)
			} else {
				req.NoError(err)
			}

			req.Equal(tt.expectedPolicy, mergedPolicy)
		})
	}
}

func TestRoutePolicySoftReset(t *testing.T) {
	logger := hivetest.Logger(t)
	peer0 := netip.MustParseAddr("10.0.0.1")
	peer1 := netip.MustParseAddr("fd00::2")
	peer2 := netip.MustParseAddr("fe80::1%eth0")
	allPeer := netip.Addr{}

	// In this test, we're only interested in which neighbors are resetted with which
	// direction. This is an abstructed policy to make the test easier.
	type policy struct {
		name      string
		typ       types.RoutePolicyType
		neighbors []netip.Addr
	}

	tests := []struct {
		name            string
		currentPolicies []*policy
		desiredPolicies []*policy
		expectedResets  map[netip.Addr]types.SoftResetDirection
	}{
		{
			name:            "new outbound policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,
				peer1: types.SoftResetDirectionOut,
				peer2: types.SoftResetDirectionOut,
			},
		},
		{
			name:            "new inbound policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionIn,
				peer1: types.SoftResetDirectionIn,
				peer2: types.SoftResetDirectionIn,
			},
		},
		{
			name:            "new outbound and inbound policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionBoth,
				peer1: types.SoftResetDirectionBoth,
				peer2: types.SoftResetDirectionBoth,
			},
		},
		{
			name:            "new mixed policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "outbound0",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0},
				},
				{
					name:      "outbound1",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer1},
				},
				{
					name:      "inbound0",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1},
				},
				{
					name:      "inbound1",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,
				peer1: types.SoftResetDirectionBoth,
				peer2: types.SoftResetDirectionIn,
			},
		},
		// Update test cases
		{
			name: "update outbound policy neighbors",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut, // was in old policy
				peer1: types.SoftResetDirectionOut, // in both old and new policy
				peer2: types.SoftResetDirectionOut, // in new policy
			},
		},
		{
			name: "update inbound policy neighbors",
			currentPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionIn, // was in old policy
				peer1: types.SoftResetDirectionIn, // in both old and new policy
				peer2: types.SoftResetDirectionIn, // in new policy
			},
		},
		{
			name: "update policy type from export to import",
			currentPolicies: []*policy{
				{
					name:      "policy",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "policy",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionBoth, // affected by both old export and new import policy
				peer1: types.SoftResetDirectionBoth, // affected by both old export and new import policy
			},
		},
		{
			name: "update mixed policies with neighbor changes",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer2},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionBoth, // affected by both policy types
				peer1: types.SoftResetDirectionBoth, // affected by both policy types
				peer2: types.SoftResetDirectionBoth, // affected by both policy types
			},
		},
		// Delete test cases
		{
			name: "delete outbound policy",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,
				peer1: types.SoftResetDirectionOut,
				peer2: types.SoftResetDirectionOut,
			},
		},
		{
			name: "delete inbound policy",
			currentPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionIn,
				peer1: types.SoftResetDirectionIn,
				peer2: types.SoftResetDirectionIn,
			},
		},
		{
			name: "delete one of multiple policies",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut, // outbound policy deleted
				peer1: types.SoftResetDirectionOut, // outbound policy deleted, inbound remains
				// peer2 has no reset because it only had inbound policy which remains unchanged
			},
		},
		{
			name: "delete all policies",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,  // had outbound policy
				peer1: types.SoftResetDirectionBoth, // had both policies
				peer2: types.SoftResetDirectionIn,   // had inbound policy
			},
		},
		{
			name: "no changes - same policies",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{},
		},
		{
			name:            "new policy with empty neighbors (all neighbors)",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name:            "new policy with empty neighbors for import (all neighbors)",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionIn,
			},
		},
		{
			name:            "new policies with empty neighbors for both import and export (all neighbors)",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
				{
					name:      "all-inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionBoth,
			},
		},
		{
			name:            "mixed policy - some specific neighbors and all neighbors",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "specific-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "all-inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionIn,
				peer0:   types.SoftResetDirectionOut,
				peer1:   types.SoftResetDirectionOut,
			},
		},
		{
			name: "update policy from specific neighbors to all neighbors",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name: "update policy from all neighbors to specific neighbors",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name: "delete policy with all neighbors",
			currentPolicies: []*policy{
				{
					name:      "all-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name:            "all neighbors export, specific neighbors import",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-export",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
				{
					name:      "specific-import",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
				peer0:   types.SoftResetDirectionIn,
				peer1:   types.SoftResetDirectionIn,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			router := fake.NewEnterpriseFakeRouter()

			current := RoutePolicyMap{}
			for _, policy := range tt.currentPolicies {
				current[policy.name] = &enterpriseTypes.ExtendedRoutePolicy{
					Name: policy.name,
					Type: policy.typ,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type:      types.RoutePolicyMatchAny,
										Neighbors: policy.neighbors,
									},
								},
							},
						},
					},
				}
			}

			desired := RoutePolicyMap{}
			for _, policy := range tt.desiredPolicies {
				desired[policy.name] = &enterpriseTypes.ExtendedRoutePolicy{
					Name: policy.name,
					Type: policy.typ,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type:      types.RoutePolicyMatchAny,
										Neighbors: policy.neighbors,
									},
								},
							},
						},
					},
				}
			}

			_, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
				Logger:          logger,
				Ctx:             t.Context(),
				Router:          router,
				CurrentPolicies: current,
				DesiredPolicies: desired,
			})
			req.NoError(err)

			// Check if the reset happened for expected peers
			req.Equal(tt.expectedResets, router.Resets)
		})
	}
}

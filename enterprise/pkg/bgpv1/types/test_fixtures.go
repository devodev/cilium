// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"net/netip"

	"k8s.io/utils/ptr"

	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

var (
	// TestCommonExtendedRoutePolicies contains common route policy values to be used in tests
	TestCommonExtendedRoutePolicies = []struct {
		Name   string
		Policy *ExtendedRoutePolicy
		Valid  bool
	}{
		{
			Name: "simple policy",
			Policy: &ExtendedRoutePolicy{
				Name: "testpolicy1",
				Type: ossTypes.RoutePolicyTypeExport,
				Statements: []*ExtendedRoutePolicyStatement{
					{
						Conditions: ExtendedRoutePolicyConditions{
							RoutePolicyConditions: ossTypes.RoutePolicyConditions{
								MatchNeighbors: &ossTypes.RoutePolicyNeighborMatch{
									Type:      ossTypes.RoutePolicyMatchAny,
									Neighbors: []netip.Addr{netip.MustParseAddr("172.16.0.1")},
								},
								MatchPrefixes: &ossTypes.RoutePolicyPrefixMatch{
									Type: ossTypes.RoutePolicyMatchAny,
									Prefixes: []ossTypes.RoutePolicyPrefix{
										{
											CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
											PrefixLenMin: 24,
											PrefixLenMax: 32,
										},
									},
								},
							},
						},
						Actions: ExtendedRoutePolicyActions{
							RoutePolicyActions: ossTypes.RoutePolicyActions{
								RouteAction:         ossTypes.RoutePolicyActionNone,
								AddCommunities:      []string{"65000:100"},
								AddLargeCommunities: []string{"4294967295:0:100"},
								SetLocalPreference:  ptr.To[int64](150),
								NextHop: &ossTypes.RoutePolicyActionNextHop{
									Self: true,
								},
							},
						},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "complex policy",
			Policy: &ExtendedRoutePolicy{
				Name: "testpolicy1",
				Type: ossTypes.RoutePolicyTypeExport,
				Statements: []*ExtendedRoutePolicyStatement{
					{
						Conditions: ExtendedRoutePolicyConditions{
							RoutePolicyConditions: ossTypes.RoutePolicyConditions{
								MatchNeighbors: &ossTypes.RoutePolicyNeighborMatch{
									Type:      ossTypes.RoutePolicyMatchInvert,
									Neighbors: []netip.Addr{netip.MustParseAddr("172.16.0.1"), netip.MustParseAddr("10.10.10.10")},
								},
								MatchPrefixes: &ossTypes.RoutePolicyPrefixMatch{
									Type: ossTypes.RoutePolicyMatchInvert,
									Prefixes: []ossTypes.RoutePolicyPrefix{
										{
											CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
											PrefixLenMin: 24,
											PrefixLenMax: 32,
										},
										{
											CIDR:         netip.MustParsePrefix("192.188.0.0/16"),
											PrefixLenMin: 24,
											PrefixLenMax: 32,
										},
									},
								},
								MatchFamilies: []ossTypes.Family{
									{
										Afi:  ossTypes.AfiIPv4,
										Safi: ossTypes.SafiUnicast,
									},
								},
							},
							MatchCommunities: &RoutePolicyCommunityMatch{
								Type:        ossTypes.RoutePolicyMatchInvert,
								Communities: []string{"^65000:100$", "^65000:1.+"},
							},
						},
						Actions: ExtendedRoutePolicyActions{
							RoutePolicyActions: ossTypes.RoutePolicyActions{
								RouteAction:        ossTypes.RoutePolicyActionAccept,
								AddCommunities:     []string{"65000:100", "65000:101"},
								SetLocalPreference: ptr.To[int64](150),
								NextHop: &ossTypes.RoutePolicyActionNextHop{
									Unchanged: true,
								},
							},
						},
					},
					{
						Conditions: ExtendedRoutePolicyConditions{
							RoutePolicyConditions: ossTypes.RoutePolicyConditions{
								MatchNeighbors: &ossTypes.RoutePolicyNeighborMatch{
									Type:      ossTypes.RoutePolicyMatchAny,
									Neighbors: []netip.Addr{netip.MustParseAddr("fe80::210:5aff:feaa:20a2")},
								},
								MatchPrefixes: &ossTypes.RoutePolicyPrefixMatch{
									Type: ossTypes.RoutePolicyMatchAny,
									Prefixes: []ossTypes.RoutePolicyPrefix{
										{
											CIDR:         netip.MustParsePrefix("2001:0DB8::/64"),
											PrefixLenMin: 24,
											PrefixLenMax: 32,
										},
										{
											CIDR:         netip.MustParsePrefix("2002::/16"),
											PrefixLenMin: 24,
											PrefixLenMax: 32,
										},
									},
								},
								MatchFamilies: []ossTypes.Family{
									{
										Afi:  ossTypes.AfiIPv6,
										Safi: ossTypes.SafiUnicast,
									},
								},
							},
							MatchLargeCommunities: &RoutePolicyCommunityMatch{
								Type:        ossTypes.RoutePolicyMatchAll,
								Communities: []string{"^1111:1111:1111$", "^2222:2222:*"},
							},
						},
						Actions: ExtendedRoutePolicyActions{
							RoutePolicyActions: ossTypes.RoutePolicyActions{
								RouteAction:        ossTypes.RoutePolicyActionReject,
								AddCommunities:     []string{"65000:100", "65000:101"},
								SetLocalPreference: ptr.To[int64](150),
							},
						},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "invalid policy",
			Policy: &ExtendedRoutePolicy{
				Name: "testpolicy1",
				Type: ossTypes.RoutePolicyTypeExport,
				Statements: []*ExtendedRoutePolicyStatement{
					// valid statement
					{
						Conditions: ExtendedRoutePolicyConditions{
							RoutePolicyConditions: ossTypes.RoutePolicyConditions{
								MatchNeighbors: &ossTypes.RoutePolicyNeighborMatch{
									Type:      ossTypes.RoutePolicyMatchAny,
									Neighbors: []netip.Addr{netip.MustParseAddr("172.16.0.1")},
								},
								MatchPrefixes: &ossTypes.RoutePolicyPrefixMatch{
									Type: ossTypes.RoutePolicyMatchAny,
									Prefixes: []ossTypes.RoutePolicyPrefix{
										{
											CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
											PrefixLenMin: 24,
											PrefixLenMax: 32,
										},
									},
								},
							},
						},
						Actions: ExtendedRoutePolicyActions{
							RoutePolicyActions: ossTypes.RoutePolicyActions{
								RouteAction:        ossTypes.RoutePolicyActionNone,
								AddCommunities:     []string{"65000:100"},
								SetLocalPreference: ptr.To[int64](150),
							},
						},
					},
					// invalid statement - wrong neighbor address
					{
						Conditions: ExtendedRoutePolicyConditions{
							RoutePolicyConditions: ossTypes.RoutePolicyConditions{
								MatchNeighbors: &ossTypes.RoutePolicyNeighborMatch{
									Type:      ossTypes.RoutePolicyMatchAny,
									Neighbors: []netip.Addr{{}},
								},
								MatchPrefixes: &ossTypes.RoutePolicyPrefixMatch{
									Type: ossTypes.RoutePolicyMatchAny,
									Prefixes: []ossTypes.RoutePolicyPrefix{
										{
											CIDR:         netip.MustParsePrefix("192.188.0.0/16"),
											PrefixLenMin: 24,
											PrefixLenMax: 32,
										},
									},
								},
							},
						},
						Actions: ExtendedRoutePolicyActions{
							RoutePolicyActions: ossTypes.RoutePolicyActions{
								RouteAction: ossTypes.RoutePolicyActionNone,
							},
						},
					},
				},
			},
			Valid: false,
		},
	}
)

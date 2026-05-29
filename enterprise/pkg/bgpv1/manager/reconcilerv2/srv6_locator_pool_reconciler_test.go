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
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestExportSRv6LocatorPoolReconciler(t *testing.T) {
	locator1 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:1::/48"),
	)
	locator2 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:2::/48"),
	)
	locator3 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:3::/48"),
	)
	structure := srv6Types.MustNewSIDStructure(32, 16, 16, 0)

	testInstanceConfig := &v1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				Name:        "peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config",
				},
			},
			{
				Name:        "peer-65001-2",
				PeerAddress: ptr.To[string]("10.10.10.2"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config",
				},
			},
		},
	}

	testPeerConfig := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "bgp",
						},
					},
				},
				// Unrelated address family. Make sure it doesn't produce any error.
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

	testAdvertisement := &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "srv6-lp-advertisement",
			Labels: map[string]string{
				"advertise": "bgp",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				{
					AdvertisementType: v1.BGPSRv6LocatorPoolAdvert,
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"export": "true",
						},
					},
				},
			},
		},
	}

	pool1RPNamePeer1 := PolicyName("peer-65001", "ipv6", v1.BGPSRv6LocatorPoolAdvert, "pool1")
	pool1Locator1RPPeer1 := &entTypes.ExtendedRoutePolicy{
		Name: pool1RPNamePeer1,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator1.Prefix,
								PrefixLenMin: locator1.Prefix.Bits(),
								PrefixLenMax: locator1.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}
	pool1Locator2RPPeer1 := &entTypes.ExtendedRoutePolicy{
		Name: pool1RPNamePeer1,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator2.Prefix,
								PrefixLenMin: locator2.Prefix.Bits(),
								PrefixLenMax: locator2.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}

	pool1RPNamePeer2 := PolicyName("peer-65001-2", "ipv6", v1.BGPSRv6LocatorPoolAdvert, "pool1")
	pool1Locator1RPPeer2 := &entTypes.ExtendedRoutePolicy{
		Name: pool1RPNamePeer2,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator1.Prefix,
								PrefixLenMin: locator1.Prefix.Bits(),
								PrefixLenMax: locator1.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}
	pool1Locator2RPPeer2 := &entTypes.ExtendedRoutePolicy{
		Name: pool1RPNamePeer2,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator2.Prefix,
								PrefixLenMin: locator2.Prefix.Bits(),
								PrefixLenMax: locator2.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}

	pool2RPNamePeer1 := PolicyName("peer-65001", "ipv6", v1.BGPSRv6LocatorPoolAdvert, "pool2")
	pool2Locator2RPPeer1 := &entTypes.ExtendedRoutePolicy{
		Name: pool2RPNamePeer1,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator2.Prefix,
								PrefixLenMin: locator2.Prefix.Bits(),
								PrefixLenMax: locator2.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}
	pool2Locator3RPPeer1 := &entTypes.ExtendedRoutePolicy{
		Name: pool2RPNamePeer1,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator3.Prefix,
								PrefixLenMin: locator3.Prefix.Bits(),
								PrefixLenMax: locator3.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}

	pool2RPNamePeer2 := PolicyName("peer-65001-2", "ipv6", v1.BGPSRv6LocatorPoolAdvert, "pool2")
	pool2Locator2RPPeer2 := &entTypes.ExtendedRoutePolicy{
		Name: pool2RPNamePeer2,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator2.Prefix,
								PrefixLenMin: locator2.Prefix.Bits(),
								PrefixLenMax: locator2.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}
	pool2Locator3RPPeer2 := &entTypes.ExtendedRoutePolicy{
		Name: pool2RPNamePeer2,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         locator3.Prefix,
								PrefixLenMin: locator3.Prefix.Bits(),
								PrefixLenMax: locator3.Prefix.Bits(),
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				}},
			},
		},
	}

	emptyAFPathMap := func() map[resource.Key]map[types.Family]map[string]struct{} {
		return map[resource.Key]map[types.Family]map[string]struct{}{}
	}
	emptyRPMap := func() ResourceRoutePolicyMap {
		return ResourceRoutePolicyMap{}
	}

	tests := []struct {
		name                 string
		locators             map[string]srv6Types.Locator
		LocatorPools         []v1alpha1.IsovalentSRv6LocatorPool
		preconfiguredAFPaths map[resource.Key]map[types.Family]map[string]struct{}
		preconfiguredRPs     ResourceRoutePolicyMap
		expectedAFPaths      map[resource.Key]map[types.Family]map[string]struct{}
		expectedRPs          ResourceRoutePolicyMap
	}{
		{
			name: "Single Pool Create",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: emptyAFPathMap(),
			preconfiguredRPs:     emptyRPMap(),
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
			},
		},
		{
			name: "Single Pool Locator Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator2,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator2RPPeer1,
					pool1RPNamePeer2: pool1Locator2RPPeer2,
				},
			},
		},
		{
			name: "Single Pool Label Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "false"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
			},
			expectedAFPaths: emptyAFPathMap(),
			expectedRPs:     emptyRPMap(),
		},
		{
			name:         "Single Pool Delete",
			locators:     map[string]srv6Types.Locator{},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
			},
			expectedAFPaths: emptyAFPathMap(),
			expectedRPs:     emptyRPMap(),
		},
		{
			name: "Multi Pool Create",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator2,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: emptyAFPathMap(),
			preconfiguredRPs:     emptyRPMap(),
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
				{Name: "pool2"}: RoutePolicyMap{
					pool2RPNamePeer1: pool2Locator2RPPeer1,
					pool2RPNamePeer2: pool2Locator2RPPeer2,
				},
			},
		},
		{
			name: "Multi Pool Locator Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator3,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
				{Name: "pool2"}: RoutePolicyMap{
					pool2RPNamePeer1: pool2Locator2RPPeer1,
					pool2RPNamePeer2: pool2Locator2RPPeer2,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator3.Prefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
				{Name: "pool2"}: RoutePolicyMap{
					pool2RPNamePeer1: pool2Locator3RPPeer1,
					pool2RPNamePeer2: pool2Locator3RPPeer2,
				},
			},
		},
		{
			name: "Multi Pool Label Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator3,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "false"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
				{Name: "pool2"}: RoutePolicyMap{
					pool2RPNamePeer1: pool2Locator2RPPeer1,
					pool2RPNamePeer2: pool2Locator2RPPeer2,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
			},
		},
		{
			name: "Multi Pool Delete",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
				{Name: "pool2"}: RoutePolicyMap{
					pool2RPNamePeer1: pool2Locator2RPPeer1,
					pool2RPNamePeer2: pool2Locator2RPPeer2,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				{Name: "pool1"}: RoutePolicyMap{
					pool1RPNamePeer1: pool1Locator1RPPeer1,
					pool1RPNamePeer2: pool1Locator1RPPeer2,
				},
			},
		},
		{
			// isovalent/cilium #2609
			name:     "Missing locator is not an error",
			locators: map[string]srv6Types.Locator{},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: emptyAFPathMap(),
			preconfiguredRPs:     emptyRPMap(),
			expectedAFPaths:      emptyAFPathMap(),
			expectedRPs:          emptyRPMap(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			mockPeerConfigStore := store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
			mockAdvertStore := store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
			mockLocatorPoolStore := newMockResourceStore[*v1alpha1.IsovalentSRv6LocatorPool]()

			mockPeerConfigStore.Upsert(testPeerConfig)
			mockAdvertStore.Upsert(testAdvertisement)

			allocators := make(map[string]sidmanager.SIDAllocator)
			for poolName, l := range test.locators {
				sa, err := sidmanager.NewStructuredSIDAllocator(l, structure, srv6Types.BehaviorTypeBase)
				require.NoError(t, err)
				allocators[poolName] = sa
			}
			for _, r := range test.LocatorPools {
				mockLocatorPoolStore.Upsert(&r)
			}

			lpReconciler := LocatorPoolReconciler{
				logger:           logger,
				upgrader:         newUpgraderMock(testInstanceConfig),
				locatorPoolStore: mockLocatorPoolStore,
				sidAllocators:    allocators,
				peerAdvert: &IsovalentAdvertisement{
					logger:      logger,
					peerConfigs: mockPeerConfigStore,
					adverts:     mockAdvertStore,
				},
				metadata: make(map[string]LocatorPoolReconcilerMetadata),
			}

			lpReconciler.initialized.Store(true)

			testOSSBGPInstance := &instance.BGPInstance{
				Name:   "fake-instance",
				Router: fake.NewEnterpriseFakeRouter(),
			}
			testBGPInstance := &EnterpriseBGPInstance{
				Name:   testOSSBGPInstance.Name,
				Router: upgradeRouter(testOSSBGPInstance.Router),
			}
			lpReconciler.Init(testOSSBGPInstance)
			defer lpReconciler.Cleanup(testOSSBGPInstance)

			// set preconfigured data
			presetAFPaths := make(reconciler.ResourceAFPathsMap)
			for key, preAFPaths := range test.preconfiguredAFPaths {
				presetAFPaths[key] = make(reconciler.AFPathsMap)
				for fam, afPaths := range preAFPaths {
					pathSet := make(reconciler.PathMap)
					for prePath := range afPaths {
						path := types.MustNewPathForPrefix(netip.MustParsePrefix(prePath))
						path.Family = fam
						pathSet[prePath] = path
					}
					presetAFPaths[key][fam] = pathSet
				}
			}

			lpReconciler.setMetadata(testBGPInstance, LocatorPoolReconcilerMetadata{
				AFPaths:       presetAFPaths,
				RoutePolicies: test.preconfiguredRPs,
			})

			// run the reconciler twice to ensure idempotency
			for range 2 {
				err := lpReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
					BGPInstance: testOSSBGPInstance,
				})
				req.NoError(err)
			}

			// check if the advertisement is as expected
			runningAFPaths := make(map[resource.Key]map[types.Family]map[string]struct{})
			for key, afPaths := range lpReconciler.getMetadata(testBGPInstance).AFPaths {
				runningAFPaths[key] = make(map[types.Family]map[string]struct{})
				for fam, afPaths := range afPaths {
					pathSet := make(map[string]struct{})
					for pathKey := range afPaths {
						pathSet[pathKey] = struct{}{}
					}
					runningAFPaths[key][fam] = pathSet
				}
			}

			req.Equal(test.expectedAFPaths, runningAFPaths)
			req.Equal(test.expectedRPs, lpReconciler.getMetadata(testBGPInstance).RoutePolicies)
		})
	}
}

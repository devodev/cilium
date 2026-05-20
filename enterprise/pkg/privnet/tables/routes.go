// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"encoding"
	"fmt"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/vni"
)

// Route represents a route for one subnet
type Route struct {
	// Network is the name of the private network CR this route came from
	Network NetworkName

	// Subnet is the name of the subnet this route came from
	Subnet SubnetName

	// Destination is the destination of the route
	Destination netip.Prefix

	// Gateway is the gateway of a route. This is empty for DCN and EVPN routes.
	Gateway netip.Addr

	// EVPNGateway is set if network is reachable via EVPN/Vxlan.
	EVPNGateway bool

	// Peer contains the information on the peer of a peering routes
	Peer RoutePeer
}

// RoutePeer contains the information for a peer in a peering route
type RoutePeer struct {
	// Network is the name of the destination network for the peering.
	// It is provided for convenience only (e.g., in the table output), and shall not be
	// depended on during reconciliation.
	Network NetworkName
	// Subnet is the name of the destination Subnet for the peering.
	// It is provided for convenience only (e.g., in the table output), and shall not be
	// depended on during reconciliation.
	Subnet SubnetName
	// ID contains the SubnetID and NetworkID of the destination subnet for the peering.
	// Only set for peering routes.
	ID SubnetIDPair
}

var _ statedb.TableWritable = Route{}

func (r Route) TableHeader() []string {
	return []string{"Network", "Subnet", "Destination", "Gateway"}
}

func (r Route) TableRow() []string {
	gw := "N/A"
	if r.Gateway.IsValid() {
		gw = r.Gateway.String()
	}
	return []string{
		string(r.Network),
		string(r.Subnet),
		r.Destination.String(),
		func() string {
			if r.EVPNGateway {
				return "evpn"
			}
			if r.isPeeringRoute() {
				return fmt.Sprintf("peer %s/%s", r.Peer.Network, r.Peer.Subnet)
			}
			return gw
		}(),
	}
}

func (r Route) isPeeringRoute() bool {
	return r.Peer.ID.Network != 0 && r.Peer.ID.Subnet != 0
}

func (r Route) MapEntryType() MapEntryType {
	if r.EVPNGateway {
		return MapEntryTypeEVPNRoute
	}
	if r.isPeeringRoute() {
		return MapEntryTypePeeringRoute
	}
	if r.Gateway.IsValid() {
		return MapEntryTypeStaticRoute
	}
	return MapEntryTypeDCNRoute
}

func (r Route) ToMapEntry(subnet SubnetSpec, activeINB INBNode, bridgeMode bool) *MapEntry {
	nexthop, egressIfIndex := r.getNexthop(activeINB, bridgeMode, subnet.EgressIfIndex)
	if !nexthop.IsValid() {
		return nil
	}

	return &MapEntry{
		Type: r.MapEntryType(),
		Target: MapEntryTarget{
			NetworkName: subnet.Network,
			SubnetName:  subnet.Name,
			ID: SubnetIDPair{
				Network: subnet.NetworkID,
				Subnet:  subnet.ID,
			},
			CIDR: r.Destination,
		},
		Routing: MapEntryRouting{
			NextHop:       nexthop,
			VNI:           r.getVNI(subnet),
			PeerID:        r.Peer.ID,
			EgressIfIndex: egressIfIndex,
		},

		Source: MapEntrySource{
			Kind: MapEntrySourceKindRoute,
			Key:  string(r.Key()),
		},

		Status: reconciler.StatusPending(),

		// No need to do gratuitous ARP/ND for routes.
		GneighStatus: reconciler.StatusDone(),
	}
}

func (r Route) Kind() RouteKind {
	switch r.MapEntryType() {
	case MapEntryTypePeeringRoute:
		return RouteKindPeering
	default:
		return RouteKindDefault
	}
}

type RouteKind uint8

var _ encoding.TextMarshaler = RouteKind(0)
var _ encoding.TextUnmarshaler = (*RouteKind)(nil)

const (
	RouteKindDefault RouteKind = iota
	RouteKindPeering
)

func (kind RouteKind) String() string {
	switch kind {
	case RouteKindDefault:
		return "R"
	case RouteKindPeering:
		return "P"
	default:
		return "?"
	}
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (kind *RouteKind) UnmarshalText(text []byte) error {
	switch string(text) {
	case "R":
		*kind = RouteKindDefault
	case "P":
		*kind = RouteKindPeering
	default:
		return fmt.Errorf("invalid RouteKind %q", string(text))
	}
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (kind RouteKind) MarshalText() (text []byte, err error) {
	return []byte(kind.String()), nil
}

func (r Route) Key() RouteKey {
	return newRouteKey(r.Network, r.Subnet, r.Destination, r.Kind())
}

// RouteKey is <network>|<subnet>|<destination>|<kind>
type RouteKey string

func (key RouteKey) Key() index.Key {
	return index.String(string(key))
}

func newRouteKeyFromNetwork(network NetworkName) RouteKey {
	return RouteKey(string(network) + indexDelimiter)
}

func newRouteKeyFromNetworkSubnet(network NetworkName, subnet SubnetName) RouteKey {
	return newRouteKeyFromNetwork(network) + RouteKey(subnet) + indexDelimiter
}

func newRouteKeyFromNetworkSubnetCIDR(network NetworkName, subnet SubnetName, destination netip.Prefix) RouteKey {
	return newRouteKeyFromNetworkSubnet(network, subnet) + RouteKey(destination.Masked().String()) + indexDelimiter
}

func newRouteKey(network NetworkName, subnet SubnetName, destination netip.Prefix, kind RouteKind) RouteKey {
	return newRouteKeyFromNetworkSubnetCIDR(network, subnet, destination) + RouteKey(kind.String())
}

var (
	routeIndex = statedb.Index[Route, RouteKey]{
		Name: "network-subnet-cidr",
		FromObject: func(obj Route) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    RouteKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

// RouteByNetwork queries the private network route table by network name
func RouteByNetwork(network NetworkName) statedb.Query[Route] {
	return routeIndex.Query(newRouteKeyFromNetwork(network))
}

// SubnetRoutesByNetworkSubnet queries the subnet route table by network name and subnet name
func RoutesByNetworkSubnet(network NetworkName, subnet SubnetName) statedb.Query[Route] {
	return routeIndex.Query(newRouteKeyFromNetworkSubnet(network, subnet))
}

// DefaultRouteByNetworkSubnetAndDestination queries the private network route table by network name, subnet name and route destination.
// It will only return "default" routes and not any other type or routes.
func DefaultRouteByNetworkSubnetAndDestination(network NetworkName, subnet SubnetName, cidr netip.Prefix) statedb.Query[Route] {
	return routeIndex.Query(newRouteKey(network, subnet, cidr, RouteKindDefault))
}

func NewRouteTable(db *statedb.DB) (statedb.RWTable[Route], error) {
	return statedb.NewTable(
		db,
		"privnet-routes",
		routeIndex,
	)
}

func (r Route) getNexthop(activeINB INBNode, bridgeMode bool, subnetIfIndex int) (netip.Addr, int) {
	var nexthop netip.Addr
	var egressIfIndex int

	if r.EVPNGateway || r.isPeeringRoute() {
		nexthop = r.unspecifiedNexthop()
	} else if !bridgeMode && subnetIfIndex == 0 {
		if activeINB.IP.IsValid() {
			nexthop = activeINB.IP
		}
	} else {
		switch r.MapEntryType() {
		case MapEntryTypeStaticRoute:
			nexthop = r.Gateway
		case MapEntryTypeDCNRoute:
			nexthop = r.unspecifiedNexthop()
		}
		egressIfIndex = subnetIfIndex
	}

	return nexthop, egressIfIndex
}

func (r Route) unspecifiedNexthop() netip.Addr {
	if r.Destination.Addr().Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func (r Route) getVNI(subnet SubnetSpec) vni.VNI {
	if r.EVPNGateway {
		return subnet.VNI
	}
	return vni.MustFromUint32(0)
}

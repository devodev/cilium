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
	"cmp"
	"encoding"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/mac"
)

// MapEntry represents a single entry of the private networks maps.
type MapEntry struct {
	// Type represents the type of this entry.
	Type MapEntryType

	// Target represents the target network CIDR reachable via this entry.
	Target MapEntryTarget

	// Routing represents the routing information to reach the target network CIDR.
	Routing MapEntryRouting

	// Status is the status of the reconciliation of this entry into the BPF maps.
	Status reconciler.Status

	// GneighStatus is the status of the periodic gratuitous ARP/ND propagation.
	// Applicable on the INB cluster only.
	GneighStatus reconciler.Status
}

// Equal returns whether two MapEntry objects are identical, excluding the reconcilers status.
func (me *MapEntry) Equal(other *MapEntry) bool {
	if me == nil || other == nil {
		return me == other
	}

	return me.Type == other.Type &&
		me.Target.Equal(other.Target) &&
		me.Routing == other.Routing
}

// Key returns the key uniquely identifying this endpoint in the nat table.
func (me *MapEntry) Key() MapEntryKey {
	return newMapEntryKey(me.Target.NetworkName, me.Target.SubnetName, me.Kind(), me.Target.CIDR)
}

func (me MapEntry) String() string {
	return fmt.Sprintf("%s %s/%s/%s -> %s",
		me.Type,
		me.Target.NetworkName,
		me.Target.SubnetName,
		me.Target.CIDR,
		me.Routing.NextHop,
	)
}

var _ statedb.TableWritable = &MapEntry{}

func (me *MapEntry) TableHeader() []string {
	return []string{"Type", "Network", "Subnet", "CIDR", "Nexthop", "IfIndex", "MAC", "L2Ann", "VNI", "Peer", "Status"}
}

func (me MapEntry) TableRow() []string {
	var ifIndex = "N/A"
	if me.Routing.EgressIfIndex != 0 {
		ifIndex = fmt.Sprintf("%d", me.Routing.EgressIfIndex)
	}
	var mac = "N/A"
	if len(me.Target.MAC) > 0 {
		mac = me.Target.MAC.String()
	}
	var l2Announce = "No"
	if me.Routing.L2Announce {
		l2Announce = "Yes"
	}

	return []string{
		me.Type.String(),
		string(me.Target.NetworkName), string(me.Target.SubnetName), me.Target.CIDR.String(),
		me.Routing.NextHop.String(),
		ifIndex,
		mac,
		l2Announce,
		cmp.Or(me.Routing.VNI.String(), "N/A"),
		func() string {
			if me.Routing.PeerID.Network == 0 || me.Routing.PeerID.Subnet == 0 {
				return "N/A"
			}
			return me.Routing.PeerID.String()
		}(),
		me.Status.String(),
	}
}

func (me MapEntry) Kind() MapEntryKind {
	return me.Type.Kind()
}

// MapEntryType represents the type of the PIP/FIB map entry.
type MapEntryType uint8

const (
	// MapEntryTypeEndpoint represents an endpoint.
	MapEntryTypeEndpoint MapEntryType = iota
	// MapEntryTypeExternalEndpoint represents an expoint external to the
	// cluster(mesh), accessible via the INB.
	MapEntryTypeExternalEndpoint
	// MapEntryTypeDCNRoute represents an L2 route.
	MapEntryTypeDCNRoute
	// MapEntryTypeStaticRoute represents an L3 static route.
	MapEntryTypeStaticRoute
	// MapEntryTypeEVPNRoute represents an EVPN route.
	MapEntryTypeEVPNRoute
	// MapEntryTypePeeringRoute represents a peering route, i.e. a route to another subnet.
	MapEntryTypePeeringRoute
)

func (typ MapEntryType) String() string {
	switch typ {
	case MapEntryTypeEndpoint:
		return "E"
	case MapEntryTypeExternalEndpoint:
		return "X"
	case MapEntryTypeDCNRoute:
		return "D"
	case MapEntryTypeStaticRoute:
		return "S"
	case MapEntryTypeEVPNRoute:
		return "V"
	case MapEntryTypePeeringRoute:
		return "P"
	default:
		return "?"
	}
}

var _ encoding.TextMarshaler = MapEntryType(0)
var _ encoding.TextUnmarshaler = (*MapEntryType)(nil)

// MarshalText implements the [encoding.TextMarshaler] interface.
func (typ MapEntryType) MarshalText() ([]byte, error) {
	return []byte(typ.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (typ *MapEntryType) UnmarshalText(in []byte) error {
	switch string(in) {
	case "E":
		*typ = MapEntryTypeEndpoint
	case "X":
		*typ = MapEntryTypeExternalEndpoint
	case "D":
		*typ = MapEntryTypeDCNRoute
	case "S":
		*typ = MapEntryTypeStaticRoute
	case "V":
		*typ = MapEntryTypeEVPNRoute
	case "P":
		*typ = MapEntryTypePeeringRoute
	default:
		return fmt.Errorf("invalid MapEntryType %q", string(in))
	}

	return nil
}

func (typ MapEntryType) Kind() MapEntryKind {
	switch typ {
	case MapEntryTypePeeringRoute:
		return MapEntryKindPeering
	default:
		return MapEntryKindDefault
	}
}

// MapEntryKind indicates the kind of the map entry.
// The kind of an entry is based in its type. There can't
// be two entries with the same NetIP and kind in the same
// subnet.
type MapEntryKind uint8

const (
	// MapEntryKindDefault is the kind of (external) endpoints and routes
	MapEntryKindDefault MapEntryKind = iota
	// MapEntryKindPeering is the kind for peering routes, which may co-exist
	// with other mapentries
	MapEntryKindPeering
)

func (kind MapEntryKind) String() string {
	switch kind {
	case MapEntryKindPeering:
		return "P"
	default:
		return "D"
	}
}

// MapEntryTarget represents the target network CIDR reachable via this entry.
type MapEntryTarget struct {
	// NetworkName is the name of the target private network.
	NetworkName NetworkName

	// SubnetName is the name of the target subnet.
	SubnetName SubnetName

	// ID is the Network and SubnetID of the target subnet
	ID SubnetIDPair

	// CIDR is the CIDR of the target endpoint/route.
	CIDR netip.Prefix

	// MAC is the MAC address of the endpoint.
	// Currently applicable only for [MapEntryTypeEndpoint].
	MAC mac.MAC
}

// Equal returns whether two MapEntryTarget objects are identical.
func (met MapEntryTarget) Equal(other MapEntryTarget) bool {
	return met.NetworkName == other.NetworkName &&
		met.ID == other.ID &&
		met.SubnetName == other.SubnetName &&
		met.CIDR == other.CIDR &&
		slices.Equal(met.MAC, other.MAC)
}

// MapEntryRouting represents the routing information to reach the target network CIDR.
type MapEntryRouting struct {
	// NextHop is the IP address of the next hop to reach the target network prefix.
	// * For [MapEntryTypeEndpoint], NextHop is the PodIP of the endpoint.
	// * For [MapEntryTypeDCNRoute], NextHop is:
	//   - On the main cluster, the IP address of the INB node serving the network.
	//   - On the INB cluster(s), the unspecified address (0.0.0.0/::).
	// * For [MapEntryTypeStaticRoute], NextHop is:
	//   - On the main cluster, the IP address of the INB node serving the network.
	//   - On the INB cluster(s), the actual nexthop configured via the ClusterwidePrivateNetwork.
	NextHop netip.Addr

	// EgressIfIndex is the index of the interface to egress traffic towards the target network.
	// Currently applicable on the INB clusters only.
	EgressIfIndex int

	// VNI associated with the private-network
	VNI vni.VNI

	// L2Announce is whether the local node should announce the target endpoint on
	// the egress facing interface, replying to ARP/ND requests, as well as sending
	// gratuitous ARP and ND packets. Currently applicable for entries of type
	// [MapEntryTypeEndpoint] only.
	L2Announce bool

	// PeerID contains the SubnetID and NetworkID of the target subnet.
	PeerID SubnetIDPair
}

// MapEntryKey is <network>|<subnet>|<type>|<network-cidr>.
type MapEntryKey string

func (key MapEntryKey) Key() index.Key {
	return index.String(string(key))
}

func newMapEntryKeyFromNetwork(network NetworkName) MapEntryKey {
	return MapEntryKey(string(network) + indexDelimiter)
}
func newMapEntryKeyFromNetworkSubnet(network NetworkName, subnet SubnetName) MapEntryKey {
	return newMapEntryKeyFromNetwork(network) + MapEntryKey(subnet) + indexDelimiter
}

func newMapEntryKeyFromNetworkSubnetAndKind(network NetworkName, subnet SubnetName, kind MapEntryKind) MapEntryKey {
	return newMapEntryKeyFromNetworkSubnet(network, subnet) + MapEntryKey(kind.String()+indexDelimiter)
}

func newMapEntryKey(network NetworkName, subnet SubnetName, kind MapEntryKind, networkCIDR netip.Prefix) MapEntryKey {
	return newMapEntryKeyFromNetworkSubnetAndKind(network, subnet, kind) + MapEntryKey(networkCIDR.String())
}

// mapEntryNetTypeKey is <network>|<type>
type mapEntryNetTypeKey string

func (key mapEntryNetTypeKey) Key() index.Key {
	return index.String(string(key))
}

func newMapEntryNetTypeKey(network NetworkName, typ MapEntryType) mapEntryNetTypeKey {
	return mapEntryNetTypeKey(network) + indexDelimiter + mapEntryNetTypeKey(typ.String())
}

// mapEntryNetTypeKey is <network-id>|<network-ip> and is only valid for endpoints and external endpoints and intended to lookup PIPs
type mapEntryIDNetIPKey string

func (key mapEntryIDNetIPKey) Key() index.Key {
	return index.String(string(key))
}

func newMapEntryIDNetIPKey(networkID NetworkID, netIP netip.Addr) mapEntryIDNetIPKey {
	return mapEntryIDNetIPKey(networkID.String()) + indexDelimiter + mapEntryIDNetIPKey(netIP.String())
}

var (
	mapEntriesKindNetCIDRIndex = statedb.Index[*MapEntry, MapEntryKey]{
		Name: "network-subnet-cidr",
		FromObject: func(obj *MapEntry) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    MapEntryKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
	mapEntriesNetTypeIndex = statedb.Index[*MapEntry, mapEntryNetTypeKey]{
		Name: "network-type",
		FromObject: func(obj *MapEntry) index.KeySet {
			return index.NewKeySet(newMapEntryNetTypeKey(obj.Target.NetworkName, obj.Type).Key())
		},
		FromKey:    mapEntryNetTypeKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}
	mapEntriesIDNetIPIndex = statedb.Index[*MapEntry, mapEntryIDNetIPKey]{
		Name: "id-netip",
		FromObject: func(obj *MapEntry) index.KeySet {
			if obj.Type == MapEntryTypeEndpoint || obj.Type == MapEntryTypeExternalEndpoint {
				return index.NewKeySet(
					newMapEntryIDNetIPKey(obj.Target.ID.Network, obj.Target.CIDR.Addr()).Key(),
				)
			}
			// This index is only relevant for (external) endpoints.
			return index.KeySet{}
		},
		FromKey:    mapEntryIDNetIPKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}

	// MapEntryByKey queries the map entries table by entry kind, network name and CIDR.
	MapEntryByKey = mapEntriesKindNetCIDRIndex.Query
)

// MapEntriesByNetwork queries the map entries table by network name.
func MapEntriesByNetwork(network NetworkName) statedb.Query[*MapEntry] {
	return mapEntriesKindNetCIDRIndex.Query(newMapEntryKeyFromNetwork(network))
}

// MapEntriesByNetworkSubnet queries the map entries table by network and subnet name.
func MapEntriesByNetworkSubnet(network NetworkName, subnet SubnetName) statedb.Query[*MapEntry] {
	return mapEntriesKindNetCIDRIndex.Query(newMapEntryKeyFromNetworkSubnet(network, subnet))
}

// MapEntriesByNetworkSubnetAndKind queries the map entries table by network and subnet name and entry kind.
func MapEntriesByNetworkSubnetAndKind(network NetworkName, subnet SubnetName, kind MapEntryKind) statedb.Query[*MapEntry] {
	return mapEntriesKindNetCIDRIndex.Query(newMapEntryKeyFromNetworkSubnetAndKind(network, subnet, kind))
}

// MapEntriesByNetworkAndType queries the map entries table by network name and entry type.
func MapEntriesByNetworkAndType(network NetworkName, typ MapEntryType) statedb.Query[*MapEntry] {
	return mapEntriesNetTypeIndex.Query(newMapEntryNetTypeKey(network, typ))
}

// MapEntryByKindNetworkSubnetCIDR queries the map entries table by entry kind, network and subnet name and CIDR.
func MapEntryByKindNetworkSubnetCIDR(network NetworkName, subnet SubnetName, kind MapEntryKind, networkCIDR netip.Prefix) statedb.Query[*MapEntry] {
	return MapEntryByKey(newMapEntryKey(network, subnet, kind, networkCIDR))
}

// MapEntriesForEndpointsByIDNetIP queries the map entries table by network ID and network IP. It will only return
// endpoint and external endpoint entries.
func MapEntriesForEndpointsByIDNetIP(networkID NetworkID, netIP netip.Addr) statedb.Query[*MapEntry] {
	return mapEntriesIDNetIPIndex.Query(newMapEntryIDNetIPKey(networkID, netIP))
}

func NewMapEntriesTable(db *statedb.DB) (statedb.RWTable[*MapEntry], error) {
	return statedb.NewTable(
		db,
		"privnet-mapentries",
		mapEntriesKindNetCIDRIndex,
		mapEntriesNetTypeIndex,
		mapEntriesIDNetIPIndex,
	)
}

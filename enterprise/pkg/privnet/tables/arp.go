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
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

// ARPSenderKey is <network-name>|<subnet-name>
type ARPSenderKey struct {
	Network NetworkName
	Subnet  SubnetName
}

func (key ARPSenderKey) Key() index.Key {
	return index.String(string(key.Network) + indexDelimiter + string(key.Subnet))
}

func NewARPSenderKey(network NetworkName, subnet SubnetName) ARPSenderKey {
	return ARPSenderKey{Network: network, Subnet: subnet}
}

// ARPSender maps a (network, subnet) pair to the IPv4 address to use as the
// ARP sender IP for that subnet.
type ARPSender struct {
	// NetworkName is the name of the target private network.
	NetworkName NetworkName

	// NetworkID is the identifier of the target private network.
	NetworkID NetworkID

	// SubnetName is the name of the target subnet.
	SubnetName SubnetName

	// SubnetID is the identifier of the target subnet.
	SubnetID SubnetID

	// IPv4 is the sender IPv4 address to program into the ARP sender cache.
	IPv4 netip.Addr

	// Status is the status of the reconciliation of this entry into the BPF map.
	Status reconciler.Status
}

func (as *ARPSender) Equal(other *ARPSender) bool {
	if as == nil || other == nil {
		return as == other
	}

	return as.NetworkID == other.NetworkID &&
		as.SubnetID == other.SubnetID &&
		as.IPv4 == other.IPv4
}

func (as ARPSender) Clone() ARPSender             { return as }
func (as ARPSender) GetStatus() reconciler.Status { return as.Status }
func (as ARPSender) SetStatus(status reconciler.Status) ARPSender {
	as.Status = status
	return as
}

var _ statedb.TableWritable = ARPSender{}

func (as ARPSender) TableHeader() []string {
	return []string{"Network", "NetworkID", "Subnet", "SubnetID", "IPv4", "Status"}
}

func (as ARPSender) TableRow() []string {
	return []string{
		string(as.NetworkName),
		as.NetworkID.String(),
		string(as.SubnetName),
		as.SubnetID.String(),
		as.IPv4.String(),
		as.Status.String(),
	}
}

var (
	arpSenderNetSubIndex = statedb.Index[ARPSender, ARPSenderKey]{
		Name: "network-subnet",
		FromObject: func(obj ARPSender) index.KeySet {
			return index.NewKeySet(NewARPSenderKey(obj.NetworkName, obj.SubnetName).Key())
		},
		FromKey:    ARPSenderKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

func ARPSenderByKey(key ARPSenderKey) statedb.Query[ARPSender] {
	return arpSenderNetSubIndex.Query(key)
}

func NewARPSenderTable(db *statedb.DB) (statedb.RWTable[ARPSender], error) {
	return statedb.NewTable(
		db,
		"privnet-arp-senders",
		arpSenderNetSubIndex,
	)
}

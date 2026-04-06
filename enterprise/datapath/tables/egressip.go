//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tables

import (
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

// EgressIPTableName is the name of the stateDB table that tracks all
// allocated egress IPs on a gateway node.
const EgressIPTableName = "egress-ips"

// EgressIPKey is an egress-ips stateDB table key
type EgressIPKey struct {
	Addr      netip.Addr
	Interface string
}

// Key extracts the key from an EgressIPKey as an index.Key type
func (e EgressIPKey) Key() index.Key {
	key := append(index.NetIPAddr(e.Addr), '+')
	return append(key, index.String(e.Interface)...)
}

// EgressIPEntryIndex is the primary index for the egress-ips table
var EgressIPEntryIndex = statedb.Index[*EgressIPEntry, EgressIPKey]{
	Name: "id",
	FromObject: func(e *EgressIPEntry) index.KeySet {
		return index.NewKeySet(EgressIPKey{e.Addr, e.Interface}.Key())
	},
	FromKey: EgressIPKey.Key,
	Unique:  true,
}

// NewEgressIPTable creates a new instance of the "egress-ips" stateDB table
func NewEgressIPTable(db *statedb.DB) (statedb.RWTable[*EgressIPEntry], error) {
	return statedb.NewTable(
		db,
		EgressIPTableName,
		EgressIPEntryIndex,
	)
}

// TableHeader returns the names of the "egress-ips" table columns
func (e *EgressIPEntry) TableHeader() []string {
	return []string{"Address", "Interface", "Status"}
}

// TableRow returns the values of an "egress-ips" table entry
func (e *EgressIPEntry) TableRow() []string {
	return []string{
		e.Addr.String(),
		e.Interface,
		e.Status.String(),
	}
}

// EgressIPEntry describes a single row of the "egress-ips" stateDB table
type EgressIPEntry struct {
	Addr      netip.Addr
	Interface string

	Status reconciler.Status
}

// GetStatus is a getter for the entry status
func (e *EgressIPEntry) GetStatus() reconciler.Status {
	return e.Status
}

// SetStatus is a setter for the entry status
func (e *EgressIPEntry) SetStatus(newStatus reconciler.Status) *EgressIPEntry {
	e.Status = newStatus
	return e
}

// Clone returns a shallow copy of the entry
func (e *EgressIPEntry) Clone() *EgressIPEntry {
	e2 := *e
	return &e2
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extepspolicy

import (
	"errors"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/maps/policymap"
)

// Writer allows to interact with the policy map.
type Writer interface {
	// Upsert registers a policy map for the given IP address.
	Upsert(ip netip.Addr, pm policymap.PolicyMap) error
	// Delete unregisters the policy map associated with the given IP address.
	Delete(ip netip.Addr) error

	// MarkInitialized must be called when the initial set of entries has been written.
	MarkInitialized()
}

type writer struct {
	en   enabled
	db   *statedb.DB
	tbl  statedb.RWTable[*entry]
	done func(statedb.WriteTxn)
}

func newWriter(en enabled, db *statedb.DB, tbl statedb.RWTable[*entry]) Writer {
	var done func(statedb.WriteTxn)
	if en {
		wtx := db.WriteTxn(tbl)
		done = tbl.RegisterInitializer(wtx, "writer")
		wtx.Commit()
	}

	return &writer{en: en, db: db, tbl: tbl, done: done}
}

type bpfMapFDNameGetter interface {
	FD() int
	Name() string
}

func (w *writer) Upsert(ip netip.Addr, pm policymap.PolicyMap) error {
	if !w.en {
		return errors.New("map is not enabled")
	}

	if !ip.IsValid() {
		return errors.New("invalid ip address")
	}

	if pm == nil {
		return errors.New("invalid policy map")
	}

	m, ok := pm.(bpfMapFDNameGetter)
	if !ok || m.FD() < 0 {
		return errors.New("invalid policy map")
	}

	wtx := w.db.WriteTxn(w.tbl)
	w.tbl.Insert(wtx, &entry{
		ip:            ip,
		policyMapName: m.Name(),
		policyMapFD:   uint32(m.FD()),
		status:        reconciler.StatusPending(),
	})
	wtx.Commit()

	return nil
}

func (w *writer) Delete(ip netip.Addr) error {
	if !w.en {
		return errors.New("map is not enabled")
	}

	if !ip.IsValid() {
		return errors.New("invalid ip address")
	}

	wtx := w.db.WriteTxn(w.tbl)
	w.tbl.Delete(wtx, &entry{ip: ip})
	wtx.Commit()

	return nil
}

func (w *writer) MarkInitialized() {
	if !w.en {
		return
	}

	wtx := w.db.WriteTxn(w.tbl)
	w.done(wtx)
	wtx.Commit()
}

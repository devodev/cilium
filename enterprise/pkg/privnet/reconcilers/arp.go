// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"iter"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/metrics"
)

var ARPMapCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite ARPSender table.
		tables.NewARPSenderTable,

		// Provides the reconciler handling ARP sender entries.
		newARPMap,
	),

	cell.Invoke(
		// Registers the reconciler populating the ARP sender table.
		(*ARPMap).registerReconciler,

		// Registers the reconciler updating the BPF map.
		(*ARPMap).registerBPFReconciler,
	),
)

// ARPMap is a reconciler which watches the MapEntries and Subnets tables
// and populates the ARPSender table with one IPv4 address per (network,
// subnet) pair, chosen from local endpoints (L2Announce == true).
type ARPMap struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db         *statedb.DB
	mapEntries statedb.Table[*tables.MapEntry]
	tbl        statedb.RWTable[tables.ARPSender]
}

func newARPMap(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB         *statedb.DB
	MapEntries statedb.Table[*tables.MapEntry]
	Table      statedb.RWTable[tables.ARPSender]
}) *ARPMap {
	return &ARPMap{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:         in.DB,
		mapEntries: in.MapEntries,
		tbl:        in.Table,
	}
}

func (a *ARPMap) registerReconciler() {
	if !a.cfg.IsLocallyConnected() {
		return
	}

	wtx := a.db.WriteTxn(a.tbl)
	initialized := a.tbl.RegisterInitializer(wtx, "arp-senders-initialized")
	wtx.Commit()

	a.jg.Add(job.OneShot("populate-arp-senders-table", func(ctx context.Context, health cell.Health) error {
		health.OK("Starting")

		var initDone bool

		wtx := a.db.WriteTxn(a.mapEntries)
		meChangeIter, _ := a.mapEntries.Changes(wtx)
		wtx.Commit()

		for {
			watchset := statedb.NewWatchSet()

			wtx := a.db.WriteTxn(a.tbl)
			meChanges, meWatch := meChangeIter.Next(wtx)
			watchset.Add(meWatch)

			// Track which subnets need re-evaluation.
			toUpdate := sets.New[tables.ARPSenderKey]()

			// Process MapEntry changes: only care about endpoint entries.
			for change := range meChanges {
				me := change.Object
				if me.Type != tables.MapEntryTypeEndpoint {
					continue
				}
				key := tables.NewARPSenderKey(me.Target.NetworkName, me.Target.SubnetName)

				if change.Deleted || !me.Routing.L2Announce {
					// If the deleted or no longer local entry - matches the currently tracked IPv4,
					// remove it and schedule re-evaluation.
					if cur, _, ok := a.tbl.Get(wtx, tables.ARPSenderByKey(key)); ok && cur.IPv4 == me.Target.CIDR.Addr() {
						a.tbl.Delete(wtx, cur)
						toUpdate.Insert(key)
					}
					continue
				}

				// New/updated local endpoint: if we have no entry, schedule evaluation.
				if _, _, ok := a.tbl.Get(wtx, tables.ARPSenderByKey(key)); !ok {
					toUpdate.Insert(key)
				}
			}

			// Re-evaluate each subnet that needs updating.
			for key := range toUpdate {
				a.reconcileSubnet(wtx, key)
			}

			if !initDone {
				meInit, mw := a.mapEntries.Initialized(wtx)

				switch {
				case !meInit:
					watchset.Add(mw)
				default:
					initDone = true
					initialized(wtx)
				}
			}

			wtx.Commit()
			health.OK("Reconciliation completed")

			_, err := watchset.Wait(ctx, SettleTime)
			if err != nil {
				return err
			}
		}
	}))
}

// reconcileSubnet queries the MapEntries table for endpoint entries in
// the given (network, subnet), picks the first with L2Announce=true and
// an IPv4 address, and inserts the ARPSender table entry.
func (a *ARPMap) reconcileSubnet(wtx statedb.WriteTxn, key tables.ARPSenderKey) {
	// Query all endpoint entries for this (network, subnet).
	query := tables.MapEntriesByNetworkSubnet(key.Network, key.Subnet)
	for me := range a.mapEntries.Prefix(wtx, query) {
		// TODO: it could be a new key in map entries, skipping that for now
		// as key filtering is getting bit complicated.
		// a.reconcileSubnet should be rarely called - i.e called when first/last local endpoint
		// in the subnet is changed.
		if me.Type != tables.MapEntryTypeEndpoint || !me.Routing.L2Announce {
			continue
		}

		addr := me.Target.CIDR.Addr()
		if !addr.Is4() {
			continue
		}

		// Found a valid candidate — upsert into the table.
		desired := tables.ARPSender{
			NetworkName: me.Target.NetworkName,
			NetworkID:   me.Target.ID.Network,
			SubnetName:  me.Target.SubnetName,
			SubnetID:    me.Target.ID.Subnet,
			IPv4:        addr,
			Status:      reconciler.StatusPending(),
		}
		a.tbl.Insert(wtx, desired)

		return // return early on first valid entry
	}
}

func (a *ARPMap) registerBPFReconciler(
	params reconciler.Params, bpfMap pnmaps.Map[*pnmaps.ARPSenderKeyVal],
	registry *metrics.Registry,
) error {
	if !a.cfg.IsLocallyConnected() {
		return nil
	}

	bpf.TablePressureMetrics(a.jg, registry, params.DB, a.tbl, bpfMap)

	_, err := reconciler.Register(
		params,
		a.tbl,
		tables.ARPSender.Clone,
		tables.ARPSender.SetStatus,
		tables.ARPSender.GetStatus,
		&arpSenderOps{bpfOps: bpfMap.Ops()},
		nil,
		reconciler.WithName("arp-sender"),
	)
	return err
}

type arpSenderOps struct {
	bpfOps reconciler.Operations[*pnmaps.ARPSenderKeyVal]
}

// Update implements reconciler.Operations[tables.ARPSender]
func (ops *arpSenderOps) Update(ctx context.Context,
	txn statedb.ReadTxn, revision statedb.Revision, obj tables.ARPSender,
) error {
	return ops.bpfOps.Update(ctx, txn, revision, ops.KeyVal(obj))
}

// Delete implements reconciler.Operations[tables.ARPSender]
func (ops *arpSenderOps) Delete(ctx context.Context,
	txn statedb.ReadTxn, revision statedb.Revision, obj tables.ARPSender,
) error {
	return ops.bpfOps.Delete(ctx, txn, revision, ops.KeyVal(obj))
}

// Prune implements reconciler.Operations[tables.ARPSender]
func (ops *arpSenderOps) Prune(ctx context.Context,
	txn statedb.ReadTxn, iter iter.Seq2[tables.ARPSender, statedb.Revision],
) error {
	return ops.bpfOps.Prune(ctx, txn, statedb.Map(iter, ops.KeyVal))
}

func (ops *arpSenderOps) KeyVal(obj tables.ARPSender) *pnmaps.ARPSenderKeyVal {
	return &pnmaps.ARPSenderKeyVal{
		Key: pnmaps.NewARPSenderKey(obj.NetworkID, obj.SubnetID),
		Val: pnmaps.NewARPSenderVal(obj.IPv4),
	}
}

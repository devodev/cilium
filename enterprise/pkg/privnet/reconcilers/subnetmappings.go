//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"iter"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/metrics"
)

var SubnetMappingsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite SubnetMappings table.
		tables.NewSubnetMappingsTable,

		// Provides the reconciler handling subnet mappings.
		newSubnetMappings,
	),

	cell.Invoke(
		// Registers the reconciler populating the subnet mappings table.
		(*SubnetMappings).registerReconciler,

		// Registers the reconciler updating the BPF map.
		(*SubnetMappings).registerBPFReconciler,
	),
)

// SubnetMappings is a reconciler which populates the SubnetMappings table,
// and synchronizes the entries into the corresponding BPF map.
type SubnetMappings struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db      *statedb.DB
	subnets statedb.Table[tables.Subnet]
	tbl     statedb.RWTable[tables.SubnetMapping]
}

func newSubnetMappings(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB      *statedb.DB
	Subnets statedb.Table[tables.Subnet]
	Table   statedb.RWTable[tables.SubnetMapping]
}) *SubnetMappings {
	return &SubnetMappings{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:      in.DB,
		subnets: in.Subnets,
		tbl:     in.Table,
	}
}

func (sm *SubnetMappings) registerReconciler() {
	if !sm.cfg.Enabled {
		return
	}

	wtx := sm.db.WriteTxn(sm.tbl)
	initialized := sm.tbl.RegisterInitializer(wtx, "subnet-mappings-initialized")
	wtx.Commit()

	sm.jg.Add(
		job.OneShot(
			"populate-subnet-mappings-table",
			func(ctx context.Context, health cell.Health) error {
				health.OK("Starting")

				var initDone bool

				wtx := sm.db.WriteTxn(sm.subnets)
				changeIter, _ := sm.subnets.Changes(wtx)
				wtx.Commit()

				for {
					var watchset = statedb.NewWatchSet()

					wtx := sm.db.WriteTxn(sm.tbl)
					changes, watch := changeIter.Next(wtx)
					watchset.Add(watch)

					for change := range changes {
						sm.reconcile(wtx, change.Object, change.Deleted)
					}

					if !initDone {
						snInit, sw := sm.subnets.Initialized(wtx)

						switch {
						case !snInit:
							watchset.Add(sw)
						default:
							initDone = true
							initialized(wtx)
						}
					}

					wtx.Commit()
					health.OK("Reconciliation completed")

					// Wait until there's new changes to consume
					_, err := watchset.Wait(ctx, SettleTime)
					if err != nil {
						return nil
					}
				}
			},
		),
	)
}

func (sm *SubnetMappings) reconcile(wtx statedb.WriteTxn, sn tables.Subnet, deleted bool) {
	// Delete all stale entries associated with this subnet, that are not
	// refreshed by the logic below.
	defer func(watermark statedb.Revision) {
		for entry, rev := range sm.tbl.List(wtx, tables.SubnetMappingsBySubnetKey(sn.Key())) {
			if rev <= watermark {
				sm.tbl.Delete(wtx, entry)
			}
		}
	}(sm.tbl.Revision(wtx))

	// The subnet is being deleted, hence nothing to do here. The cleanup logic
	// above will take care of removing the old entries.
	if deleted {
		return
	}

	for cidr := range sn.CIDRs() {
		sm.tbl.Modify(wtx, tables.SubnetMapping{
			NetworkName: sn.Network,
			NetworkID:   sn.NetworkID,
			SubnetName:  sn.Name,
			SubnetID:    sn.ID,
			CIDR:        cidr,
			Status:      reconciler.StatusPending(),
		}, func(old, new tables.SubnetMapping) tables.SubnetMapping {
			if old.Equal(&new) {
				return old
			}

			return new
		})
	}
}

func (sm *SubnetMappings) registerBPFReconciler(
	params reconciler.Params, bpfMap pnmaps.Map[*pnmaps.SubnetKeyVal],
	fence regeneration.Fence, registry *metrics.Registry,
) error {
	if !sm.cfg.Enabled {
		return nil
	}

	// Block regeneration until we populated the map.
	fence.Add(
		"private-network-subnets",
		NewWaitUntilReconciledFn(sm.db, sm.tbl, tables.SubnetMapping.GetStatus),
	)

	bpf.TablePressureMetrics(
		sm.jg, registry, params.DB, sm.tbl, bpfMap,
	)

	_, err := reconciler.Register(
		params, sm.tbl,
		tables.SubnetMapping.Clone,
		tables.SubnetMapping.SetStatus,
		tables.SubnetMapping.GetStatus,
		&subnetMappingsOps{bpfOps: bpfMap.Ops()},
		nil,
		reconciler.WithName("subnet-mappings"),
	)

	return err
}

type subnetMappingsOps struct {
	bpfOps reconciler.Operations[*pnmaps.SubnetKeyVal]
}

// Update implements reconciler.Operations[tables.SubnetMapping]
func (ops *subnetMappingsOps) Update(ctx context.Context,
	txn statedb.ReadTxn, revision statedb.Revision, obj tables.SubnetMapping,
) error {
	return ops.bpfOps.Update(ctx, txn, revision, ops.KeyVal(obj))
}

// Delete implements reconciler.Operations[tables.SubnetMapping]
func (ops *subnetMappingsOps) Delete(ctx context.Context,
	txn statedb.ReadTxn, revision statedb.Revision, obj tables.SubnetMapping,
) error {
	return ops.bpfOps.Delete(ctx, txn, revision, ops.KeyVal(obj))
}

// Prune implements reconciler.Operations[tables.SubnetMapping]
func (ops *subnetMappingsOps) Prune(ctx context.Context,
	txn statedb.ReadTxn, iter iter.Seq2[tables.SubnetMapping, statedb.Revision],
) error {
	return ops.bpfOps.Prune(ctx, txn, statedb.Map(iter, ops.KeyVal))
}

func (ops *subnetMappingsOps) KeyVal(obj tables.SubnetMapping) *pnmaps.SubnetKeyVal {
	return &pnmaps.SubnetKeyVal{
		Key: pnmaps.NewSubnetKey(obj.NetworkID, obj.CIDR),
		Val: pnmaps.NewSubnetVal(obj.SubnetID),
	}
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package migration

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	cslices "github.com/cilium/cilium/pkg/slices"
)

type pipRewriteParams struct {
	cell.In

	Config pncfg.Config

	DB         *statedb.DB
	Endpoints  statedb.Table[tables.Endpoint]
	MapEntries statedb.Table[*tables.MapEntry]
	Rewrites   statedb.RWTable[tables.MigrationPIPRewrite]

	CTMaps           ctmap.CTMaps
	ReconcilerParams reconciler.Params

	Log      *slog.Logger
	JobGroup job.Group
}

// pipRewrite is the reconciler that watches for PIP changes and populates the MigrationPIPRewrite table
// based on pending rewrite tasks
type pipRewrite struct {
	pipRewriteParams
}

// registerPIPRewriteReconciler starts two components for rewriting PIP addresses on the local
// node if we detect that the PIP of an endpoint changed due to node migration:
//  1. A job which detects a new PIP becoming active and creates a MigrationPIPRewrite
//     StateDB row, representing the pending rewrite task.
//  2. A reconciler that executes the pending rewrite tasks sequentially.
func registerPIPRewriteReconciler(params pipRewriteParams) error {
	if !params.Config.Enabled {
		return nil
	}

	p := &pipRewrite{
		pipRewriteParams: params,
	}
	params.JobGroup.Add(job.OneShot("watch-pip-changes", p.watchPIPChanges))

	ops := &pipRewriteOps{
		ctmaps: params.CTMaps,
	}
	_, err := reconciler.Register(
		params.ReconcilerParams,
		params.Rewrites,
		tables.MigrationPIPRewrite.Clone,
		tables.MigrationPIPRewrite.SetStatus,
		tables.MigrationPIPRewrite.GetStatus,
		ops,
		ops,
		reconciler.WithoutPruning(),
		reconciler.WithName("rewrite-pip"),
	)
	return err
}

// watchPIPChanges watches the map entries table for active endpoints. If a new endpoint becomes
// active, it fetches the corresponding endpoint entry to determine if the endpoint has
// `previousAddressing` set. If set, that tells us that the active endpoint is a workload that
// has migrated to a new node with a new PIP, which means we want to trigger a rewrite of
// the PIP addresses in the local CT map.
func (p *pipRewrite) watchPIPChanges(ctx context.Context, health cell.Health) error {
	health.OK("Waiting for endpoints table initialization")
	rtxn := p.DB.ReadTxn()
	_, init := p.Endpoints.Initialized(rtxn)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-init:
	}

	health.OK("Waiting for map entries table initialization")
	_, init = p.MapEntries.Initialized(rtxn)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-init:
	}

	health.OK("Watching for PIP changes")
	wtxn := p.DB.WriteTxn(p.MapEntries)
	changeIter, err := p.MapEntries.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	for {
		// Iterate over all map entry changes
		wtxn = p.DB.WriteTxn(p.Rewrites)
		changes, watch := changeIter.Next(wtxn)
		for change := range changes {
			if change.Object.Source.Kind != tables.MapEntrySourceKindEndpoint {
				continue // we only care about endpoint entries
			}

			// PIP became inactive, remove any completed or pending rewrites
			mapentryKey := change.Object.Key()
			if change.Deleted {
				p.Rewrites.Delete(wtxn, tables.MigrationPIPRewrite{MapEntry: mapentryKey})
				continue
			}

			// Obtain corresponding endpoint object to obtain the previous addressing
			endpointKey := tables.EndpointKey(change.Object.Source.Key)
			endpoint, _, found := p.Endpoints.Get(wtxn, tables.EndpointsByPrimaryKey(endpointKey))
			if !found {
				// When there is no corresponding endpoint entry anymore, we can assume that the corresponding map
				// entry will be deleted soon as well, so we simply bail out here.
				p.Log.Debug("Stale map entry observed", logfields.Key, endpointKey)
				continue
			}

		loopPreviousAddresses:
			for _, prevAddressing := range endpoint.PreviousAddressing {
				if !prevAddressing.IP.IsValid() {
					continue
				}

				// Check if the PIP has been reused by a newer endpoint. The new endpoint must not be active,
				// but having a newer activatedAt means that the PIP has been re-used already, which means
				// we do not want to rewrite unrelated entries
				for previousEndpoint := range p.Endpoints.List(wtxn, tables.EndpointsByPIP(prevAddressing.IP)) {
					if previousEndpoint.ActivatedAt.After(prevAddressing.LastSeen) {
						p.Log.Debug("Previous addressing expired",
							logfields.Endpoint, endpoint.Name,
							logfields.New, previousEndpoint.Name)
						continue loopPreviousAddresses
					}
				}

				// Start a new rewrite job for this PIP pair
				newPIP := endpoint.Endpoint.IP
				oldPIP := prevAddressing.IP
				if oldPIP.Is4() != newPIP.Is4() {
					p.Log.Error("Old and new PIP do not have the same IP family",
						logfields.ClusterName, endpoint.Source.Cluster,
						logfields.K8sNamespace, endpoint.Source.Namespace,
						logfields.Endpoint, endpoint.Name,
						logfields.OldIP, oldPIP,
						logfields.NewIP, newPIP,
					)
					continue
				}

				p.Log.Info("Migrated endpoint detected. Rewriting endpoint IP",
					logfields.ClusterName, endpoint.Source.Cluster,
					logfields.K8sNamespace, endpoint.Source.Namespace,
					logfields.Endpoint, endpoint.Name,
					logfields.OldIP, oldPIP,
					logfields.NewIP, newPIP,
				)

				p.Rewrites.Modify(wtxn, tables.MigrationPIPRewrite{
					MapEntry: mapentryKey,

					Endpoint: tables.Source{
						Cluster:   endpoint.Source.Cluster,
						Namespace: endpoint.Source.Namespace,
						Name:      endpoint.Name,
					},

					OldPIP: oldPIP,
					NewPIP: newPIP,

					Status: reconciler.StatusPending(),
				}, func(old, new tables.MigrationPIPRewrite) tables.MigrationPIPRewrite {
					new.Status = old.Status // retain current status
					return new
				})
			}
		}

		wtxn.Commit()

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

// pipRewriteOps implements reconciler.Operations and reconciler.BatchOperations to ensure all pending PIP
// rewrites are performed sequentially, in batches and re-tried if they fail.
type pipRewriteOps struct {
	ctmaps ctmap.CTMaps
}

// Update implements reconciler.Operations
func (p *pipRewriteOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, task tables.MigrationPIPRewrite) error {
	return p.rewritePIPs(ctx, func(yield func(tables.MigrationPIPRewrite) bool) {
		yield(task)
	})
}

// Delete implements reconciler.Operations
func (p *pipRewriteOps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, task tables.MigrationPIPRewrite) error {
	return nil // no-op
}

// Prune implements reconciler.Operations
func (p *pipRewriteOps) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[tables.MigrationPIPRewrite, statedb.Revision]) error {
	return nil // no-op
}

// UpdateBatch implements reconciler.BatchOperations
func (p *pipRewriteOps) UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[tables.MigrationPIPRewrite]) {
	err := p.rewritePIPs(ctx, cslices.MapIter(
		slices.Values(batch),
		func(in reconciler.BatchEntry[tables.MigrationPIPRewrite]) tables.MigrationPIPRewrite {
			return in.Object
		}),
	)
	for i := range batch {
		batch[i].Result = err
	}
}

// DeleteBatch implements reconciler.BatchOperations
func (p *pipRewriteOps) DeleteBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[tables.MigrationPIPRewrite]) {
	// no-op
}

// pipPairs is a set of IP address pairs where we want to replace all occurrences of the key with the value
type pipPairs map[netip.Addr]netip.Addr

// rewritePIPs takes a sequence of pending rewrites and performs them on the applicable CT maps
func (p *pipRewriteOps) rewritePIPs(ctx context.Context, tasks iter.Seq[tables.MigrationPIPRewrite]) (err error) {
	var ipv4Pairs, ipv6Pairs = pipPairs{}, pipPairs{}
	for task := range tasks {
		if task.OldPIP.Is4() {
			ipv4Pairs[task.OldPIP] = task.NewPIP
		} else if task.OldPIP.Is6() {
			ipv6Pairs[task.OldPIP] = task.NewPIP
		}
	}

	for _, ctMap := range p.ctmaps.ActiveMaps() {
		switch ctMap.Name() {
		case ctmap.MapNameTCP4Global, ctmap.MapNameAny4Global:
			if len(ipv4Pairs) > 0 {
				err = errors.Join(err, rewriteCTMap[ctKey4, *ctKey4](ctx, ctMap, ipv4Pairs))
			}
		case ctmap.MapNameTCP6Global, ctmap.MapNameAny6Global:
			if len(ipv6Pairs) > 0 {
				err = errors.Join(err, rewriteCTMap[ctKey6, *ctKey6](ctx, ctMap, ipv6Pairs))
			}
		}
	}

	return err
}

// ctKey is an IP family agnostic interface to read and write the CT key addresses
type ctKey[T any] interface {
	bpf.MapKey
	GetDestAddr() netip.Addr
	GetSourceAddr() netip.Addr
	SetDestAddr(addr netip.Addr)
	SetSourceAddr(addr netip.Addr)
	*T
}

// ctKey4 wraps ctmap.CtKey4Global to implement the ctKey interface
type ctKey4 struct {
	ctmap.CtKey4Global
}

func (c *ctKey4) SetSourceAddr(addr netip.Addr) {
	c.SourceAddr.FromAddr(addr)
}

func (c *ctKey4) SetDestAddr(addr netip.Addr) {
	c.DestAddr.FromAddr(addr)
}

// ctKey6 wraps ctmap.CtKey6Global to implement the ctKey interface
type ctKey6 struct {
	ctmap.CtKey6Global
}

func (c *ctKey6) SetSourceAddr(addr netip.Addr) {
	c.SourceAddr.FromAddr(addr)
}

func (c *ctKey6) SetDestAddr(addr netip.Addr) {
	c.DestAddr.FromAddr(addr)
}

// rewriteCTMap takes a list of PIP pairs and replaces all occurrences of oldPIP with newPIP in the provided
// ctMap. It returns an error if the operation did not finish and should be retried.
func rewriteCTMap[T any, PT ctKey[T]](ctx context.Context, ctMap *ctmap.Map, toReplace pipPairs) error {
	type ctEntry struct {
		original  PT
		rewritten PT
		value     *ctmap.CtEntry
	}

	// Collect and rewrite all entries that match the oldPIP
	var toUpdate []ctEntry
	iter := bpf.NewBatchIterator[T, ctmap.CtEntry, PT, *ctmap.CtEntry](&ctMap.Map)
	for k, v := range iter.IterateAll(ctx) {
		if ctx.Err() != nil {
			return ctx.Err() // bail out if job has been canceled
		}

		newSource, rewriteSource := toReplace[k.GetSourceAddr()]
		newDest, rewriteDest := toReplace[k.GetDestAddr()]
		if !(rewriteSource || rewriteDest) {
			continue // nothing to rewrite
		}

		// Store original and rewritten CT key and value
		entry := ctEntry{
			original:  k,
			rewritten: new(*k),
			value:     v,
		}
		if rewriteSource {
			entry.rewritten.SetSourceAddr(newSource)
		}
		if rewriteDest {
			entry.rewritten.SetDestAddr(newDest)
		}
		toUpdate = append(toUpdate, entry)
	}

	// Ensure we re-try in case iteration stopped early due to concurrent updates.
	// We do still try to process the toUpdate slice to allow for some partial progress
	// to happen. As a result, some connections will be migrated, while others continue to
	// likley observe drops. The non-migrated entries will be re-tried.
	var errs error
	if iter.Err() != nil {
		errs = errors.Join(errs, iter.Err())
	}

	// Rewriting the entry changes its key. Therefore, we have to insert it with the new
	// key and delete the old one. This is prone to races, i.e. it can happen that the old
	// entry value has been modified (or even deleted) in the meantime. But unfortunately,
	// there is no atomic compare-and-swap available for these kind of map updates, so this
	// is all best effort.
	for _, entry := range toUpdate {
		if ctx.Err() != nil {
			return ctx.Err() // bail out if job has been canceled
		}
		if err := ctMap.Delete(entry.original); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed delete stale CT entry: %w", err))
		}
		if err := ctMap.Update(entry.rewritten, entry.value); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed insert rewritten CT entry: %w", err))
		}
	}

	return errs
}

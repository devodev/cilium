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
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	privnetmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/policy"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var PolicyCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the CIDRMetadata and CIDRIdentity table.
		tables.NewCIDRMetadataTable,
		tables.NewCIDRIdentitiesTable,

		// Provides the CIDR metadata observer consumed by us
		observers.NewGeneric[policy.CIDRMetadata, policy.EventKind],

		newCIDRIdentities,
	),

	cell.Provide(
		// Provides the ReadOnly CIDRMetadata and CIDRIdentity table.
		statedb.RWTable[tables.CIDRIdentity].ToTable,
		statedb.RWTable[tables.CIDRMetadata].ToTable,

		// Provides the policy.CIDRQueuer queuing interface
		func(o *observers.Generic[policy.CIDRMetadata, policy.EventKind]) policy.CIDRQueuer {
			return o
		},
	),

	cell.Invoke(
		(*CIDRIdentities).registerCIDRMetadataObserver,
		(*CIDRIdentities).registerCIDRIdentityAllocator,
		(*CIDRIdentities).registerBPFReconciler,
	),
)

// CIDRIdentities is a collection of reconcilers that populates
// the cilium_privnet_cidr_identity BPF map with Cilium identities
// allocated based on collected CIDR metadata.
type CIDRIdentities struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	alloc cache.IdentityAllocator

	db         *statedb.DB
	metadata   statedb.RWTable[tables.CIDRMetadata]
	identities statedb.RWTable[tables.CIDRIdentity]
}

func newCIDRIdentities(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	IdentityAllocator cache.IdentityAllocator

	DB         *statedb.DB
	Metadata   statedb.RWTable[tables.CIDRMetadata]
	Identities statedb.RWTable[tables.CIDRIdentity]
}) *CIDRIdentities {
	return &CIDRIdentities{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		alloc: in.IdentityAllocator,

		db:         in.DB,
		metadata:   in.Metadata,
		identities: in.Identities,
	}
}

// registerCIDRMetadataObserver starts a reconciler that watches the CIDRMetadata observer and populates the
// CIDRMetadata table based on the observed associations and disassociations.
func (c *CIDRIdentities) registerCIDRMetadataObserver(observer *observers.Generic[policy.CIDRMetadata, policy.EventKind]) {
	if !c.cfg.Enabled {
		return
	}

	// Only mark the table as initialized when two special events are observed:
	// - policy.EventRestored: The numeric identities from the previous BPF map have been collected.
	//   This ensures that the numeric identity of a CIDR doesn't change between restarts.
	// - policy.EventSynced: Policy ingestion has seen all K8s resources that potentially contain CIDR
	//   rules or CIDRGroups.
	wtx := c.db.WriteTxn(c.metadata)
	identitiesRestored := c.metadata.RegisterInitializer(wtx, "identities-restored")
	cachesSynced := c.metadata.RegisterInitializer(wtx, "caches-synced")
	wtx.Commit()

	c.jg.Add(
		job.Observer(
			"cidr-metadata-observer",
			func(ctx context.Context, buf observers.Events[policy.CIDRMetadata, policy.EventKind]) error {
				wtx := c.db.WriteTxn(c.metadata)
				defer wtx.Commit()

				for _, ev := range buf {
					switch ev.EventKind {
					case policy.EventUpsert:
						c.upsertCIDRMetadata(wtx, ev.Object.Owner, ev.Object.Prefix, ev.Object.Metadata)
					case policy.EventDelete:
						c.deleteCIDRMetadata(wtx, ev.Object.Owner, ev.Object.Prefix, ev.Object.Metadata)
					case policy.EventRestored:
						identitiesRestored(wtx)
					case policy.EventSynced:
						cachesSynced(wtx)
					}
				}

				return nil
			},
			observer,
		),
	)
}

// mergedMetadata associates new CIDR metadata with the owning resource
func mergedMetadata(
	oldOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo,
	owner ipcacheTypes.ResourceID, metadata policy.CIDRMetadataType,
) (newOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo) {
	newOwners = maps.Clone(oldOwners)
	if newOwners == nil {
		newOwners = make(map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo, 1)
	}

	// Overwrite (if metadata has same type as existing info) or merge (if metadata has a different type)
	// metadata in the CIDRMetadataInfo of the owner
	ownerInfo := newOwners[owner]
	switch m := metadata.(type) {
	case policy.CIDRLabel:
		ownerInfo.CIDRLabel = true
	case policy.CIDRGroupLabels:
		ownerInfo.CIDRGroupLabels = labels.Labels(m)
	case policy.CIDRRestored:
		ownerInfo.RestoredIdentity = m.Identity
	}
	newOwners[owner] = ownerInfo

	return newOwners
}

// upsertCIDRMetadata is called when an owner (i.e. a resource) has added or updated
// the metadata associated with a particular prefix.
// We update the CIDRMetadata table accordingly.
func (c *CIDRIdentities) upsertCIDRMetadata(wtx statedb.WriteTxn, owner ipcacheTypes.ResourceID, prefix netip.Prefix, metadata policy.CIDRMetadataType) {
	obj := tables.CIDRMetadata{
		Prefix: prefix,
		Owners: mergedMetadata(nil, owner, metadata),
	}
	c.metadata.Modify(wtx, obj, func(old, new tables.CIDRMetadata) tables.CIDRMetadata {
		old.Owners = mergedMetadata(old.Owners, owner, metadata)
		return old
	})
}

// unmergedMetadata disassociates CIDR metadata from the owning resource.
// Only the type of the disassociated metadata has to be provided.
func unmergedMetadata(
	oldOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo,
	owner ipcacheTypes.ResourceID, metadata policy.CIDRMetadataType,
) (newOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo) {
	newOwners = maps.Clone(oldOwners)
	if len(newOwners) == 0 {
		return newOwners
	}

	ownerInfo := oldOwners[owner]
	switch metadata.(type) {
	case policy.CIDRLabel:
		ownerInfo.CIDRLabel = false
	case policy.CIDRGroupLabels:
		ownerInfo.CIDRGroupLabels = nil
	case policy.CIDRRestored:
		ownerInfo.RestoredIdentity = identity.IdentityUnknown
	}

	if ownerInfo.IsEmpty() {
		delete(newOwners, owner)
	} else {
		newOwners[owner] = ownerInfo
	}

	return newOwners
}

// deleteCIDRMetadata is called when an owner (i.e. a resource) has removed
// the metadata associated with a particular prefix.
// We update the CIDRMetadata table accordingly.
func (c *CIDRIdentities) deleteCIDRMetadata(wtx statedb.WriteTxn, owner ipcacheTypes.ResourceID, prefix netip.Prefix, metadata policy.CIDRMetadataType) {
	obj, _, found := c.metadata.Get(wtx, tables.CIDRMetadataByPrefix(prefix))
	if !found {
		c.log.Warn("Observed metadata delete event for unknown prefix",
			logfields.Prefix, prefix,
			logfields.Owner, owner,
		)
		return
	} else if _, ok := obj.Owners[owner]; !ok {
		c.log.Warn("Observed metadata delete event for unknown owner",
			logfields.Prefix, prefix,
			logfields.Owner, owner,
		)
		return
	}

	// Update owners list in object
	obj.Owners = unmergedMetadata(obj.Owners, owner, metadata)
	if len(obj.Owners) == 0 {
		// Last owner removed, remove corresponding entry
		c.metadata.Delete(wtx, obj)
	} else {
		// Upsert object containing updated owners list
		c.metadata.Insert(wtx, obj)
	}
}

// registerCIDRIdentityAllocator starts a reconciler that allocates identities for CIDRs based on the metadata
// associated with that CIDR.
func (c *CIDRIdentities) registerCIDRIdentityAllocator(fence regeneration.Fence) {
	if !c.cfg.Enabled {
		return
	}

	// Block endpoint regeneration until the initialized upstream table has been processed.
	// Note: Technically speaking, we need to block until the BPF reconciler has finished
	// populating the BPF map based on our table. See cilium/statedb#58.
	restored := make(chan struct{})
	fence.Add("privnet-cidr-identities-restored", func(ctx context.Context) error {
		select {
		case <-restored:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	c.jg.Add(job.OneShot("allocate-cidr-identities", func(ctx context.Context, health cell.Health) error {
		// Delay identity allocation until the upstream table is initialized
		health.OK("Waiting for cidr metadata to be initialized")
		_, metadataRestored := c.metadata.Initialized(c.db.ReadTxn())
		select {
		case <-metadataRestored:
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for cidr metadata to be initialized: %w", ctx.Err())
		}

		// Start observing the CIDR metadata table
		health.OK("Watching cidr metadata changes")
		wtx := c.db.WriteTxn(c.metadata)
		changeIter, _ := c.metadata.Changes(wtx)
		wtx.Commit()

		var initDone bool
		for {
			wtx = c.db.WriteTxn(c.identities)
			changes, watch := changeIter.Next(wtx)

			for change := range changes {
				c.log.Debug("Processing table event",
					logfields.Table, c.metadata.Name(),
					logfields.Event, change,
				)

				if !change.Deleted {
					c.upsertCIDRIdentity(wtx, change.Object)
				} else {
					c.deleteCIDRIdentity(wtx, change.Object)
				}
			}

			wtx.Commit()

			// After we've processed the initial snapshot, endpoint restoration may continue
			if !initDone {
				close(restored)
				initDone = true
			}

			// Wait until there's new changes to consume
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
		}
	}))
}

// resolveLabels returns the labels that are associated with CIDR (based on the provided CIDRMetadata).
// It also returns a numeric identity that should be passed to the identity allocator, to nudge the allocator
// to use this numeric identity if possible.
func (c *CIDRIdentities) resolveLabels(metadata tables.CIDRMetadata) (labels.Labels, identity.NumericIdentity) {
	lbls := labels.Labels{}
	restoredIdentity := identity.IdentityUnknown
	for _, o := range metadata.Owners {
		if o.CIDRLabel {
			lbls.MergeLabels(labels.GetCIDRLabels(metadata.Prefix))
		}
		if len(o.CIDRGroupLabels) > 0 {
			lbls.MergeLabels(o.CIDRGroupLabels)
			lbls.AddWorldLabel(metadata.Prefix.Addr())
		}
		if o.RestoredIdentity != identity.IdentityUnknown {
			if restoredIdentity != identity.IdentityUnknown {
				c.log.Error("BUG: More than one owner provided a restored identity for a prefix",
					logfields.Prefix, metadata.Prefix,
					logfields.Owner, metadata.Owners,
				)
			}
			restoredIdentity = o.RestoredIdentity
		}
	}

	// If the CNP or CCG that owned the prefix went away during the agent restart, we will
	// not have any labels. Upsert the identity anyway with an artificial `cidr` label,
	// to match IPCache behavior. The identity will de-allocated after initial
	// endpoint regeneration finishes (unless a new owner appears before that).
	if len(lbls) == 0 {
		c.log.Debug("No label metadata found for restored identity. Adding `cidr:` label",
			logfields.Prefix, metadata.Prefix,
			logfields.Identity, restoredIdentity)
		lbls.MergeLabels(labels.GetCIDRLabels(metadata.Prefix))
	}

	return lbls, restoredIdentity
}

// upsertCIDRIdentity is called when the metadata for a given CIDR has changed.
//
// It will allocate an identity for this CIDR based on the new metadata and upsert that
// new identity into the CIDRIdentity table.
func (c *CIDRIdentities) upsertCIDRIdentity(wtx statedb.WriteTxn, metadata tables.CIDRMetadata) {
	// We always call AllocateLocalIdentity first, and (if it was an update not an insert),
	// also call ReleaseLocalIdentities later. This ensures that the refcount remains balanced, i.e.
	// every entry in the CIDRIdentity table acts as one reference to the identity.
	newLabels, restoredIdentity := c.resolveLabels(metadata)
	newIdentity, _, err := c.alloc.AllocateLocalIdentity(newLabels, true, restoredIdentity)
	if err != nil {
		c.log.Error("Failed to allocate identity",
			logfields.Prefix, metadata.Prefix,
			logfields.Labels, newLabels,
			logfields.Error, err,
		)
		return
	}

	obj := tables.CIDRIdentity{
		Prefix:   metadata.Prefix,
		Identity: newIdentity.ID,
		Status:   reconciler.StatusPending(),
	}

	old, hadOld, _ := c.identities.Modify(wtx, obj, func(old, new tables.CIDRIdentity) tables.CIDRIdentity {
		if old.Identity == new.Identity {
			new.Status = old.Status // retain old BPF reconciler status if nothing has changed
		}
		return new
	})

	if hadOld {
		// Decrease ref count for previous allocation, to ensure our refcount is balanced
		_, err := c.alloc.ReleaseLocalIdentities(old.Identity)
		if err != nil {
			c.log.Error("Failed to release identity",
				logfields.Prefix, old.Prefix,
				logfields.Identity, old.Prefix,
				logfields.Error, err,
			)
			return
		}
	}
}

// deleteCIDRIdentity is called when all metadata for a given CIDR has been removed.
//
// If so, we remove the CIDR from our identities table and release the associated identity.
func (c *CIDRIdentities) deleteCIDRIdentity(wtx statedb.WriteTxn, metadata tables.CIDRMetadata) {
	obj, found, _ := c.identities.Delete(wtx, tables.CIDRIdentity{Prefix: metadata.Prefix})
	if !found {
		c.log.Warn("Observed identity deletion request for unknown prefix",
			logfields.Prefix, metadata.Prefix,
		)
		return
	}

	_, err := c.alloc.ReleaseLocalIdentities(obj.Identity)
	if err != nil {
		c.log.Error("Failed to release identity",
			logfields.Prefix, obj.Prefix,
			logfields.Identity, obj.Identity,
			logfields.Error, err,
		)
		return
	}
}

// cidrIdentitiesMapOps implements reconciler.Operations[tables.CIDRIdentity] (i.e. the type found
// in the StateDB table) on top of reconciler.Operations[*privnetmaps.CIDRIdentityKeyVal] (i.e. the type
// used in the BPF map).
type cidrIdentitiesMapOps struct {
	bpfOps reconciler.Operations[*privnetmaps.CIDRIdentityKeyVal]
}

// registerBPFReconciler starts a reconciler that populates the cilium_privnet_cidr_identity BPF map
// from the CIDRIdentity StateDB table.
func (c *CIDRIdentities) registerBPFReconciler(params reconciler.Params, bpfMap privnetmaps.Map[*privnetmaps.CIDRIdentityKeyVal], registry *metrics.Registry) error {
	if !c.cfg.Enabled {
		return nil
	}

	bpf.TablePressureMetrics(
		c.jg,
		registry,
		params.DB,
		c.identities.ToTable(),
		bpfMap,
	)

	ops := &cidrIdentitiesMapOps{bpfOps: bpfMap.Ops()}
	_, err := reconciler.Register[tables.CIDRIdentity](
		// params
		params,
		// table
		c.identities,
		// clone
		func(e tables.CIDRIdentity) tables.CIDRIdentity {
			return e
		},
		// setStatus
		func(e tables.CIDRIdentity, status reconciler.Status) tables.CIDRIdentity {
			e.Status = status
			return e
		},
		// getStatus
		func(e tables.CIDRIdentity) reconciler.Status {
			return e.Status
		},
		// ops
		ops,
		// batchOps
		nil,

		reconciler.WithName("cidr-identities"),
	)
	return err
}

// Update implements reconciler.Operations[tables.CIDRIdentity]
func (i *cidrIdentitiesMapOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj tables.CIDRIdentity) error {
	return i.bpfOps.Update(ctx, txn, revision, &privnetmaps.CIDRIdentityKeyVal{
		Key: privnetmaps.NewCIDRIdentityKey(obj.Prefix),
		Val: privnetmaps.NewCIDRIdentityVal(obj.Identity),
	})
}

// Delete implements reconciler.Operations[tables.CIDRIdentity]
func (i *cidrIdentitiesMapOps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj tables.CIDRIdentity) error {
	return i.bpfOps.Delete(ctx, txn, revision, &privnetmaps.CIDRIdentityKeyVal{
		Key: privnetmaps.NewCIDRIdentityKey(obj.Prefix),
		Val: privnetmaps.NewCIDRIdentityVal(obj.Identity),
	})
}

// Prune implements reconciler.Operations[tables.CIDRIdentity]
func (i *cidrIdentitiesMapOps) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[tables.CIDRIdentity, statedb.Revision]) error {
	return i.bpfOps.Prune(ctx, txn,
		mapStateDBSeq(objects, func(obj tables.CIDRIdentity, rev statedb.Revision) (*privnetmaps.CIDRIdentityKeyVal, statedb.Revision) {
			return &privnetmaps.CIDRIdentityKeyVal{
				Key: privnetmaps.NewCIDRIdentityKey(obj.Prefix),
				Val: privnetmaps.NewCIDRIdentityVal(obj.Identity),
			}, rev
		}))
}

// mapStateDBSeq applies fn over all items in sequence s
func mapStateDBSeq[In1, In2, Out1, Out2 any](s iter.Seq2[In1, In2], fn func(In1, In2) (Out1, Out2)) iter.Seq2[Out1, Out2] {
	return func(yield func(Out1, Out2) bool) {
		for obj1, obj2 := range s {
			if !yield(fn(obj1, obj2)) {
				return
			}
		}
	}
}

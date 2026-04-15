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
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/metrics"
)

var DeviceMappingsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite DeviceMappings table.
		tables.NewDeviceMappingsTable,

		// Provides the reconciler handling device mappings.
		newDeviceMappings,
	),

	cell.Invoke(
		// Registers the reconciler populating the device mappings table.
		(*DeviceMappings).registerReconciler,

		// Registers the reconciler updating the BPF map.
		(*DeviceMappings).registerBPFReconciler,
	),
)

const (
	// ownerPrefixNodeAttachment prefix used in Owner reference for PrivateNetworkNodeAttachment devices. These are
	// netdev interfaces in Cilium
	ownerPrefixNodeAttachment = "pnna"
	// ownerPrefixLocalWorkload prefix used in Owner reference for LocalWorkload devices. These are lxc interfaces
	// in Cilium.
	ownerPrefixLocalWorkload = "lw"
)

// DeviceMappings is a reconciler which populates the DeviceMappings table,
// and synchronizes the entries into the corresponding BPF map.
type DeviceMappings struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db              *statedb.DB
	networks        statedb.Table[tables.PrivateNetwork]
	workloads       statedb.Table[*tables.LocalWorkload]
	nodeAttachments statedb.Table[*tables.NodeAttachment]
	tbl             statedb.RWTable[tables.DeviceMapping]

	// netIDs caches the mapping between each private network and the
	// corresponding ID. It is not protected by a mutex as access is
	// serialized by write transactions.
	netIDs map[tables.NetworkName]tables.NetworkID
}

func newDeviceMappings(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB              *statedb.DB
	Networks        statedb.Table[tables.PrivateNetwork]
	Workloads       statedb.Table[*tables.LocalWorkload]
	NodeAttachments statedb.Table[*tables.NodeAttachment]
	Table           statedb.RWTable[tables.DeviceMapping]
}) *DeviceMappings {
	return &DeviceMappings{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:              in.DB,
		networks:        in.Networks,
		workloads:       in.Workloads,
		nodeAttachments: in.NodeAttachments,
		tbl:             in.Table,

		netIDs: make(map[tables.NetworkName]tables.NetworkID),
	}
}

func (dm *DeviceMappings) registerReconciler() {
	if !dm.cfg.Enabled {
		return
	}

	wtx := dm.db.WriteTxn(dm.tbl)
	initialized := dm.tbl.RegisterInitializer(wtx, "device-mappings-initialized")
	wtx.Commit()

	dm.jg.Add(
		job.OneShot(
			"populate-device-mappings-table",
			func(ctx context.Context, health cell.Health) error {
				health.OK("Starting")

				var initDone bool

				wtx := dm.db.WriteTxn(dm.networks, dm.workloads, dm.nodeAttachments)
				netChangeIter, _ := dm.networks.Changes(wtx)
				lwChangeIter, _ := dm.workloads.Changes(wtx)
				naChangeIter, _ := dm.nodeAttachments.Changes(wtx)
				wtx.Commit()

				for {
					var watchset = statedb.NewWatchSet()

					wtx := dm.db.WriteTxn(dm.tbl)
					netChanges, netWatch := netChangeIter.Next(wtx)
					lwChanges, lwWatch := lwChangeIter.Next(wtx)
					naChanges, naWatch := naChangeIter.Next(wtx)
					watchset.Add(netWatch, lwWatch, naWatch)

					var lwsProcessed = sets.New[tables.NetworkName]()
					for change := range netChanges {
						var network = change.Object.Name

						if change.Deleted {
							dm.deleteForNetwork(wtx, network)

							delete(dm.netIDs, network)
							lwsProcessed.Insert(network)
						} else {
							dm.reconcileNetworkAttachments(wtx, change.Object)

							if prev, hadPrev := dm.netIDs[network]; !hadPrev || prev != change.Object.ID {
								dm.netIDs[network] = change.Object.ID
								lwsProcessed.Insert(network)

								// Reconcile all local workloads belonging to the network.
								dm.reconcileLocalWorkloads(wtx, network)
							}
						}
					}

					for change := range naChanges {
						network, _, found := dm.networks.Get(wtx, tables.PrivateNetworkByName(change.Object.Network))
						if !found {
							continue // attachment is created before the network
						}
						mapping := dm.forNetworkAttachment(network, change.Object)
						if change.Deleted {
							// Causes [dm.reconcile] to delete the entry.
							mapping.DeviceIndex = 0
						}
						dm.reconcile(wtx, mapping, true)
					}

					for change := range lwChanges {
						var network = tables.NetworkName(change.Object.Interface.Network)
						if lwsProcessed.Has(network) && !change.Deleted {
							continue
						}

						new := dm.forLocalWorkload(change.Object)
						if change.Deleted {
							// Causes [dm.reconcile] to delete the entry.
							new.DeviceIndex = 0
						}

						dm.reconcile(wtx, new, false)
					}

					if !initDone {
						netInit, nw := dm.networks.Initialized(wtx)
						lwInit, lw := dm.workloads.Initialized(wtx)
						naInit, naw := dm.nodeAttachments.Initialized(wtx)

						switch {
						case !netInit:
							watchset.Add(nw)
						case !lwInit:
							watchset.Add(lw)
						case !naInit:
							watchset.Add(naw)
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

func (dm *DeviceMappings) reconcile(wtx statedb.WriteTxn, new tables.DeviceMapping, lookupByDevice bool) {
	var (
		old  tables.DeviceMapping
		olds iter.Seq2[tables.DeviceMapping, statedb.Revision]
	)

	if lookupByDevice {
		olds = dm.tbl.List(wtx, tables.DeviceMappingsByOwnerAndInterface(new.Owner, new.DeviceName))
	} else {
		olds = dm.tbl.Prefix(wtx, tables.DeviceMappingsByOwner(new.Owner))
	}

	for got := range olds {
		if got.DeviceIndex == new.DeviceIndex {
			old = got
		} else {
			// The table is indexed by DeviceIndex, hence we need to explicitly
			// delete the old entry if it changes.
			dm.tbl.Delete(wtx, got)
		}
	}

	if new.DeviceIndex == 0 || new.Equal(&old) {
		return
	}

	new.Status = reconciler.StatusPending()
	dm.tbl.Insert(wtx, new)
}

func (dm *DeviceMappings) deleteForNetwork(wtx statedb.WriteTxn, network tables.NetworkName) {
	for mapping := range dm.tbl.List(wtx, tables.DeviceMappingsByNetwork(network)) {
		dm.tbl.Delete(wtx, mapping)
	}
}

func (dm *DeviceMappings) reconcileLocalWorkloads(wtx statedb.WriteTxn, network tables.NetworkName) {
	for lw := range dm.workloads.List(wtx, tables.LocalWorkloadsByNetwork(string(network))) {
		dm.reconcile(wtx, dm.forLocalWorkload(lw), false)
	}
}

func (dm *DeviceMappings) forNetworkAttachment(network tables.PrivateNetwork, na *tables.NodeAttachment) tables.DeviceMapping {
	mapping := tables.DeviceMapping{
		Owner:       tables.NewDeviceMappingOwner(ownerPrefixNodeAttachment, na.Resource.Name),
		DeviceName:  string(na.Interface.Name),
		NetworkName: network.Name,
		NetworkID:   network.ID,
	}
	if na.IsReady() {
		mapping.DeviceIndex = na.Interface.Index
	}
	return mapping
}

func (dm *DeviceMappings) reconcileNetworkAttachments(wtx statedb.WriteTxn, network tables.PrivateNetwork) {
	for na := range dm.nodeAttachments.List(wtx, tables.NodeAttachmentsByNetworkName(network.Name)) {
		dm.reconcile(wtx, dm.forNetworkAttachment(network, na), true)
	}
}

func (dm *DeviceMappings) forLocalWorkload(lw *tables.LocalWorkload) tables.DeviceMapping {
	var network = tables.NetworkName(lw.Interface.Network)
	ipv4, _ := netip.ParseAddr(lw.Interface.Addressing.IPv4)
	ipv6, _ := netip.ParseAddr(lw.Interface.Addressing.IPv6)

	return tables.DeviceMapping{
		Owner:       tables.NewDeviceMappingOwner(ownerPrefixLocalWorkload, strconv.FormatUint(uint64(lw.EndpointID), 10)),
		DeviceIndex: lw.LXC.IfIndex,
		DeviceName:  lw.LXC.IfName,
		NetworkName: network,
		NetworkID:   dm.netIDs[network],
		NetworkIPv4: ipv4,
		NetworkIPv6: ipv6,
	}
}

func (dm *DeviceMappings) registerBPFReconciler(
	params reconciler.Params, bpfMap pnmaps.Map[*pnmaps.DeviceKeyVal],
	fence regeneration.Fence, registry *metrics.Registry,
) error {
	if !dm.cfg.Enabled {
		return nil
	}

	// Block regeneration until we populated the map.
	fence.Add("private-network-devices", NewWaitUntilReconciledFn(dm.db, dm.tbl,
		func(obj tables.DeviceMapping) reconciler.Status { return obj.Status }))

	bpf.TablePressureMetrics(
		dm.jg, registry, params.DB, dm.tbl, bpfMap,
	)

	var ops = deviceMappingsOps{bpfOps: bpfMap.Ops()}
	_, err := reconciler.Register(
		// params
		params,
		// table
		dm.tbl,
		// clone
		func(nim tables.DeviceMapping) tables.DeviceMapping {
			return nim
		},
		// setStatus
		func(nim tables.DeviceMapping, status reconciler.Status) tables.DeviceMapping {
			nim.Status = status
			return nim
		},
		// getStatus
		func(nim tables.DeviceMapping) reconciler.Status {
			return nim.Status
		},
		// ops
		&ops,
		// batchOps
		nil,

		reconciler.WithName("devmappings"),
	)
	return err
}

type deviceMappingsOps struct {
	bpfOps reconciler.Operations[*pnmaps.DeviceKeyVal]
}

// Update implements reconciler.Operations[tables.DeviceMapping]
func (ops *deviceMappingsOps) Update(ctx context.Context,
	txn statedb.ReadTxn, revision statedb.Revision, obj tables.DeviceMapping,
) error {
	return ops.bpfOps.Update(ctx, txn, revision, ops.KeyVal(obj))
}

// Delete implements reconciler.Operations[tables.DeviceMapping]
func (ops *deviceMappingsOps) Delete(ctx context.Context,
	txn statedb.ReadTxn, revision statedb.Revision, obj tables.DeviceMapping,
) error {
	return ops.bpfOps.Delete(ctx, txn, revision, ops.KeyVal(obj))
}

// Prune implements reconciler.Operations[tables.DeviceMapping]
func (ops *deviceMappingsOps) Prune(ctx context.Context,
	txn statedb.ReadTxn, iter iter.Seq2[tables.DeviceMapping, statedb.Revision],
) error {
	return ops.bpfOps.Prune(ctx, txn, statedb.Map(iter, ops.KeyVal))
}

func (ops *deviceMappingsOps) KeyVal(obj tables.DeviceMapping) *pnmaps.DeviceKeyVal {
	return &pnmaps.DeviceKeyVal{
		Key: pnmaps.NewDeviceKey(uint32(obj.DeviceIndex)),
		Val: pnmaps.NewDeviceVal(obj.NetworkID, ops.deviceMappingObjType(obj), obj.NetworkIPv4, obj.NetworkIPv6),
	}
}

// deviceMappingObjType returns the type of the device mapping object.
func (ops *deviceMappingsOps) deviceMappingObjType(obj tables.DeviceMapping) pnmaps.DeviceValType {
	if strings.HasPrefix(string(obj.Owner), ownerPrefixNodeAttachment) {
		return pnmaps.DeviceValTypeNetdev
	} else {
		return pnmaps.DeviceValTypeLxc
	}
}

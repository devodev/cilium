// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/YutaroHayakawa/go-ra"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/utils"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	osstypes "github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type LinkLocalReconcilerIn struct {
	cell.In
	JobGroup job.Group
	Logger   *slog.Logger

	Config    Config
	BGPConfig config.Config
	Signaler  *signaler.BGPCPSignaler
	RADaemon  RADaemon

	DB            *statedb.DB
	NeighborTable statedb.Table[*tables.Neighbor]
	DeviceTable   statedb.Table[*tables.Device]
}

type LinkLocalReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseConfigReconciler `group:"enterprise-bgp-config-reconciler"`
}

type LinkLocalReconciler struct {
	logger *slog.Logger

	config   Config
	signaler *signaler.BGPCPSignaler
	raDaemon RADaemon // provides router-side functionality of IPv6 Neighbor Discovery mechanism

	db            *statedb.DB
	neighborTable statedb.Table[*tables.Neighbor]
	deviceTable   statedb.Table[*tables.Device]

	metadata map[string]LinkLocalReconcilerMetadata

	// instancesWithUnnumberedPeers is used to count the instances with unnumbered peers.
	// Used to not trigger unnecessary reconciliation events upon neighbor table changes
	// if there is no unnumbered peer configured for this node.
	instancesWithUnnumberedPeers atomic.Int32
}

type LinkLocalReconcilerMetadata struct {
	hasUnnumberedPeers  bool              // used to mark if unnumbered peers are used for this instance
	linkLocalNeighbors  map[string]string // cache of interface to link-local neighbor addresses
	raEnabledInterfaces sets.Set[string]  // interfaces with RA enabled
}

func NewLinkLocalReconciler(params LinkLocalReconcilerIn) LinkLocalReconcilerOut {
	if !params.BGPConfig.Enabled {
		return LinkLocalReconcilerOut{}
	}

	r := &LinkLocalReconciler{
		logger:        params.Logger.With(osstypes.ReconcilerLogField, "LinkLocal"),
		config:        params.Config,
		signaler:      params.Signaler,
		raDaemon:      params.RADaemon,
		db:            params.DB,
		neighborTable: params.NeighborTable,
		deviceTable:   params.DeviceTable,
		metadata:      make(map[string]LinkLocalReconcilerMetadata),
	}

	params.JobGroup.Add(
		job.OneShot("neighbor-events", func(ctx context.Context, health cell.Health) (err error) {
			return r.processStateDBNeighborEvents(ctx)
		}),
	)

	params.JobGroup.Add(job.OneShot("ra-daemon", func(ctx context.Context, health cell.Health) error {
		r.raDaemon.Run(ctx)
		return nil
	}))

	return LinkLocalReconcilerOut{
		EnterpriseReconciler: r,
	}
}

func (r *LinkLocalReconciler) Name() string {
	return LinkLocalReconcilerName
}

func (r *LinkLocalReconciler) Priority() int {
	return LinkLocalReconcilerPriority
}

func (r *LinkLocalReconciler) Init(i *instance.EnterpriseBGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = LinkLocalReconcilerMetadata{
		hasUnnumberedPeers:  false,
		linkLocalNeighbors:  make(map[string]string),
		raEnabledInterfaces: sets.New[string](),
	}
	return nil
}

func (r *LinkLocalReconciler) Cleanup(i *instance.EnterpriseBGPInstance) {
	if i != nil {
		if r.metadata[i.Name].hasUnnumberedPeers {
			r.instancesWithUnnumberedPeers.Add(-1)
		}
		if len(r.metadata[i.Name].raEnabledInterfaces) > 0 {
			// If there are still some RA-enabled interfaces for this instance, remove them.
			// Since there is no context provided for Cleanup(), create a context with an arbitrary timeout.
			ctx, cancelTimeout := context.WithTimeout(context.Background(), time.Second*3)
			metadata := r.getMetadata(i)
			metadata.raEnabledInterfaces = nil
			err := r.reconcileRAInterfaces(ctx, i, &metadata)
			if err != nil {
				r.logger.Warn("Error by disabling RA interfaces during instance cleanup",
					osstypes.InstanceLogField, i.Name,
					logfields.Error, err,
				)
			}
			cancelTimeout()
		}
		delete(r.metadata, i.Name)
	}
}

func (r *LinkLocalReconciler) Reconcile(ctx context.Context, p EnterpriseReconcileParams) error {
	metadata := r.getMetadata(p.BGPInstance)

	// retrieve all configured unnumbered interfaces from the desired config
	unnumberedInterfaces := r.getUnnumberedInterfaces(p.DesiredConfig)

	if unnumberedInterfaces.Len() > 0 {
		// there are some unnumbered peers configured
		if !metadata.hasUnnumberedPeers {
			// if we are not yet processing statedb neighbor events, start from now
			r.instancesWithUnnumberedPeers.Add(1)
			metadata.hasUnnumberedPeers = true
		}
		// update peer address in BGPNodeInstance's DesiredConfig for unnumbered peers
		if err := r.updateUnnumberedPeerAddresses(p, &metadata); err != nil {
			return err
		}
	} else {
		// no unnumbered peers configured for this instance
		if metadata.hasUnnumberedPeers {
			// if we were processing statedb neighbor events, stop from now
			r.instancesWithUnnumberedPeers.Add(-1)
			metadata.hasUnnumberedPeers = false
		}
	}

	if !metadata.raEnabledInterfaces.Equal(unnumberedInterfaces) {
		// change in unnumbered interfaces, reconfigure RA
		metadata.raEnabledInterfaces = unnumberedInterfaces
		if err := r.reconcileRAInterfaces(ctx, p.BGPInstance, &metadata); err != nil {
			return err
		}
	}

	r.setMetadata(p.BGPInstance, metadata)
	return nil
}

func (r *LinkLocalReconciler) getMetadata(i *instance.EnterpriseBGPInstance) LinkLocalReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *LinkLocalReconciler) setMetadata(i *instance.EnterpriseBGPInstance, m LinkLocalReconcilerMetadata) {
	r.metadata[i.Name] = m
}

func (r *LinkLocalReconciler) getUnnumberedInterfaces(nodeInstance *v1.IsovalentBGPNodeInstance) sets.Set[string] {
	res := sets.Set[string]{}
	for _, peer := range nodeInstance.Peers {
		if peer.AutoDiscovery != nil && peer.AutoDiscovery.Mode == v1.BGPADUnnumbered && peer.AutoDiscovery.Unnumbered != nil {
			res.Insert(peer.AutoDiscovery.Unnumbered.Interface)
		}
	}
	return res
}

// updateUnnumberedPeerAddresses sets the peer address in BGPNodeInstance's DesiredConfig for unnumbered peers.
// PeerAddress is then referenced from various other reconcilers.
func (r *LinkLocalReconciler) updateUnnumberedPeerAddresses(iParams EnterpriseReconcileParams, metadata *LinkLocalReconcilerMetadata) error {
	l := r.logger.With(osstypes.InstanceLogField, iParams.DesiredConfig.Name)
	txn := r.db.ReadTxn()

	for i, peer := range iParams.DesiredConfig.Peers {
		if peer.AutoDiscovery != nil && peer.AutoDiscovery.Mode == v1.BGPADUnnumbered && peer.AutoDiscovery.Unnumbered != nil {
			peerInterface := peer.AutoDiscovery.Unnumbered.Interface
			peerLog := l.With(
				osstypes.PeerLogField, peer.Name,
				types.InterfaceLogField, peerInterface,
			)

			peerAddress, found, err := utils.GetIPv6LinkLocalNeighborAddress(r.deviceTable, r.neighborTable, txn, peerInterface)
			if err != nil {
				// The error is most likely due to non-existing interface or multiple link-local peers on the link.
				// As these are related to the host's state rather than the BGP CP, just emit a warning and skip
				// this peer. Whenever this situation is recovered on the host, we get a new reconcile thanks
				// to watching the host's neighbor table.
				peerLog.Warn("Failed to get link local address for the peer", logfields.Error, err)
				continue
			}
			if !found {
				// Try to look up the peer address in the reconciler's metadata cache.
				// If the LL peer address was known previously and the neighbor entry was deleted after it
				// (e.g. router/link went down temporarily, or neighbor table was flushed manually to debug an issue),
				// we keep the previously set peer address, so that the BGP peer remains configured.
				// We will leave it upto BGP keepalive mechanism to manage the peering state.
				// If the LL address changes, the peering will be reconfigured as soon as we get a new neighbor entry for it.
				peerAddress, found = metadata.linkLocalNeighbors[peerInterface]
				if !found {
					// The LL address is not in the neighbor table nor in the cache - we skip this peer
					// (it will not be configured on the underlying router instance by the neighbor reconciler).
					peerLog.Debug("Link-local address for the peer not found")
					continue
				}
			}
			peerLog.Debug("Setting peer address", osstypes.PeerLogField, peerAddress)

			// update address in the cache
			metadata.linkLocalNeighbors[peerInterface] = peerAddress

			// update the peer address in CEE desired config
			iParams.DesiredConfig.Peers[i].PeerAddress = &peerAddress
		}
	}

	return nil
}

// reconcileRAInterfaces reconciles the RA Daemon config with the desired set of unnumbered interfaces across all BGP instances.
func (r *LinkLocalReconciler) reconcileRAInterfaces(ctx context.Context, i *instance.EnterpriseBGPInstance, metadata *LinkLocalReconcilerMetadata) error {
	desiredRAInterfaces := sets.Set[string]{}
	for instanceName, instanceMeta := range r.metadata {
		if instanceName == i.Name {
			// for the current instance, used the passed metadata, as it was not persisted yet
			desiredRAInterfaces.Insert(metadata.raEnabledInterfaces.UnsortedList()...)
		} else {
			desiredRAInterfaces.Insert(instanceMeta.raEnabledInterfaces.UnsortedList()...)
		}
	}

	configuredRAInterfaces := sets.Set[string]{}
	status := r.raDaemon.Status()
	for _, raInterface := range status.Interfaces {
		configuredRAInterfaces.Insert(raInterface.Name)
	}

	if desiredRAInterfaces.Equal(configuredRAInterfaces) {
		return nil // no need to reconfigure anything
	}

	r.logger.Debug("Configuring RA interfaces", logfields.Interface, desiredRAInterfaces.UnsortedList())

	raInterfaces := make([]*ra.InterfaceConfig, 0, len(desiredRAInterfaces))
	for _, interfaceName := range desiredRAInterfaces.UnsortedList() {
		raInterfaces = append(raInterfaces, &ra.InterfaceConfig{
			Name:                   interfaceName,
			RAIntervalMilliseconds: int(r.config.RouterAdvertisementInterval.Milliseconds()),
			CurrentHopLimit:        64,
			RouterLifetimeSeconds:  30,
		})
	}

	err := r.raDaemon.Reload(ctx, &ra.Config{Interfaces: raInterfaces})
	if err != nil {
		return fmt.Errorf("failed to reload RA daemon config: %w", err)
	}

	return nil
}

// processStateDBNeighborEvents processes all statedb events in the "neighbor" table and triggers
// BGP reconciliation upon updates of link-local neighbor entries.
func (r *LinkLocalReconciler) processStateDBNeighborEvents(ctx context.Context) error {
	observable := statedb.Observable[*tables.Neighbor](r.db, r.neighborTable)
	ch := stream.ToChannel[statedb.Change[*tables.Neighbor]](ctx, observable)

	for ev := range ch {
		if r.instancesWithUnnumberedPeers.Load() < 1 {
			continue // do not process neighbor events if there is no unnumbered BGP peer config used on this node
		}
		neighbor := ev.Object
		if neighbor.IPAddr.Is6() && neighbor.IPAddr.IsLinkLocalUnicast() {
			r.logger.Debug("Link-local neighbor update, triggering BGP reconciliation",
				types.LinkIndexLogField, neighbor.LinkIndex,
				osstypes.PeerLogField, neighbor.IPAddr,
				types.IsDeletedLogField, ev.Deleted,
			)
			r.signaler.Event(struct{}{})
		}
	}
	return nil
}

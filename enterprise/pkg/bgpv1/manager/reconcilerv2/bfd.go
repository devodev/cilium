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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	bgptypes "github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type BFDStateReconcilerIn struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	BGPConfig config.Config
	BFDCfg    types.BFDConfig
	Signaler  *signaler.BGPCPSignaler

	DB                    *statedb.DB
	BFDPeersTable         statedb.Table[*types.BFDPeerStatus]
	BGPPeerConfigResource resource.Resource[*v1.IsovalentBGPPeerConfig]
}

type BFDStateReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseConfigReconciler `group:"enterprise-bgp-config-reconciler"`
}

// BFDStateReconciler reconciles BFD peers' state into BGP router state - if a BFD peer
// that was configured via BGP goes down, it hard-resets the BGP peering.
type BFDStateReconciler struct {
	log         *slog.Logger
	initialized atomic.Bool

	signaler *signaler.BGPCPSignaler

	db                 *statedb.DB
	bfdPeersTable      statedb.Table[*types.BFDPeerStatus]
	bgpPeerConfigStore resource.Store[*v1.IsovalentBGPPeerConfig]
	metadata           map[string]BFDStateReconcilerMetadata
}

type BFDStateReconcilerMetadata struct {
	lastRevision  statedb.Revision
	lastPeerState map[netip.Addr]types.BFDState
}

func NewBFDStateReconciler(p BFDStateReconcilerIn) BFDStateReconcilerOut {
	if !p.BGPConfig.Enabled || !p.BFDCfg.BFDEnabled {
		return BFDStateReconcilerOut{}
	}
	r := &BFDStateReconciler{
		db:            p.DB,
		bfdPeersTable: p.BFDPeersTable,
		signaler:      p.Signaler,
		metadata:      make(map[string]BFDStateReconcilerMetadata),
		log:           p.Logger.With(bgptypes.ReconcilerLogField, "BFDState"),
	}

	p.JobGroup.Add(
		job.OneShot("bfd-events", func(ctx context.Context, health cell.Health) (err error) {
			// init peer config store before processing any BFD events
			r.bgpPeerConfigStore, err = p.BGPPeerConfigResource.Store(ctx)
			if err != nil {
				return err
			}
			r.initialized.Store(true)
			return r.processStateDBEvents(ctx)
		}),
	)

	return BFDStateReconcilerOut{
		EnterpriseReconciler: r,
	}
}

func (r *BFDStateReconciler) Name() string {
	return BFDStateReconcilerName
}

func (r *BFDStateReconciler) Priority() int {
	return BFDStateReconcilerPriority
}

func (r *BFDStateReconciler) Init(i *instance.EnterpriseBGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = BFDStateReconcilerMetadata{
		lastPeerState: make(map[netip.Addr]types.BFDState),
	}
	return nil
}

func (r *BFDStateReconciler) Cleanup(i *instance.EnterpriseBGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

// Reconcile checks if a BFD peer that was configured for the router instance went down,
// and if yes, it hard-resets the BGP peering for that peer address on the router instance.
func (r *BFDStateReconciler) Reconcile(ctx context.Context, params EnterpriseReconcileParams) error {
	var err error
	logger := r.log.With(bgptypes.InstanceLogField, params.DesiredConfig.Name)
	if !r.initialized.Load() {
		logger.Debug("BFD state reconciler not yet initialized, reconciliation skipped")
		return nil
	}
	logger.Debug("BFD state reconciliation started")

	metadata := r.getMetadata(params.BGPInstance)

	// get BFD peers configured for this router instance
	configuredBFDPeers := r.getConfiguredBFDPeers(params.DesiredConfig)
	if len(configuredBFDPeers) == 0 {
		return nil // nothing to reconcile
	}

	// iterate over BFD peers with status changed since the last reconcile, in the revision order (oldest change first).
	startRev := statedb.Revision(0)
	if metadata.lastRevision > 0 {
		startRev = metadata.lastRevision + 1
	}
	txn := r.db.ReadTxn()
	iter := r.bfdPeersTable.LowerBound(txn, statedb.ByRevision[*types.BFDPeerStatus](startRev))
	for peer, rev := range iter {
		metadata.lastRevision = rev
		peerLogger := logger.With(bgptypes.PeerLogField, peer.PeerAddress)

		if !configuredBFDPeers.Has(peer.PeerAddress) {
			// this BFD peer is not configured for this router instance, skip
			continue
		}

		// RFC 5882, section 4.2.1
		//   When a BFD session transitions from Up to Down, action
		//   SHOULD be taken in the control protocol to signal the lack of
		//   connectivity for the path over which BFD is running. If the control
		//   protocol has an explicit mechanism for announcing path state, a
		//   system SHOULD use that mechanism rather than impacting the
		//   connectivity of the control protocol, particularly if the control
		//   protocol operates out-of-band from the failed data protocol.
		//   However, if such a mechanism is not available, a control protocol
		//   timeout SHOULD be emulated for the associated neighbor.

		// RFC 5882, section 3.2
		//   The AdminDown mechanism in BFD is intended to signal that the BFD
		//   session is being taken down for administrative purposes, and the
		//   session state is not indicative of the liveness of the data path.
		//
		//   Therefore, a system SHOULD NOT indicate a connectivity failure to a
		//   client if either the local session state or the remote session state
		//   (if known) transitions to AdminDown, so long as that client has
		//   independent means of liveness detection (typically, control
		//   protocols).

		if peer.Local.State == types.BFDStateDown && peer.Remote.State != types.BFDStateAdminDown {
			// if the current state is Down, and not because being AdministrativelyDown on the remote side

			if lastState, lastStateKnown := metadata.lastPeerState[peer.PeerAddress]; !lastStateKnown || lastState != types.BFDStateUp {
				// if the previous peer state was not Up, ignore
				continue
			}
			peerLogger.Info("BFD peer went down, resetting BGP peer")

			resetErr := params.BGPInstance.Router.ResetNeighbor(ctx, bgptypes.ResetNeighborRequest{
				PeerAddress:        peer.PeerAddress,
				Soft:               false,
				AdminCommunication: "BFD session down",
			})
			if resetErr != nil {
				peerLogger.Error("Error resetting BGP peer", logfields.Error, resetErr)
				err = errors.Join(err, resetErr)
			}
		}
	}

	// refresh lastPeerState map
	metadata.lastPeerState = make(map[netip.Addr]types.BFDState)
	for peer := range r.bfdPeersTable.All(txn) {
		metadata.lastPeerState[peer.PeerAddress] = peer.Local.State
	}
	r.setMetadata(params.BGPInstance, metadata)

	logger.Debug("BFD state reconciliation finished")

	return err
}

func (r *BFDStateReconciler) getMetadata(i *EnterpriseBGPInstance) BFDStateReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *BFDStateReconciler) setMetadata(i *EnterpriseBGPInstance, m BFDStateReconcilerMetadata) {
	r.metadata[i.Name] = m
}

// getConfiguredBFDPeers returns set of BFD peers configured in the provided router instance.
func (r *BFDStateReconciler) getConfiguredBFDPeers(ni *v1.IsovalentBGPNodeInstance) sets.Set[netip.Addr] {
	peers := sets.New(netip.Addr{})
	for _, peer := range ni.Peers {
		if peer.PeerAddress == nil {
			continue
		}
		peerAddr, err := netip.ParseAddr(*peer.PeerAddress)
		if err != nil {
			r.log.Warn("Error parsing BGP peer address, skipping the peer",
				bgptypes.PeerLogField, peer.PeerAddress,
				logfields.Error, err,
			)
			continue
		}
		if peer.PeerConfigRef == nil || peer.PeerConfigRef.Name == "" {
			continue
		}
		peerConfig, exists, err := r.bgpPeerConfigStore.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
		if err != nil {
			r.log.Warn("Error getting BGP peer config, skipping the peer",
				bgptypes.PeerLogField, peer.PeerAddress,
				logfields.Error, err,
			)
		}
		if !exists {
			continue
		}
		if peerConfig.Spec.BFDProfileRef != nil {
			peers.Insert(peerAddr)
		}
	}
	return peers
}

// processStateDBEvents processes all statedb events in the "bfd-peers" table and triggers
// BGP reconciliation if a BFD peer just went to Up or Down state.
func (r *BFDStateReconciler) processStateDBEvents(ctx context.Context) error {
	observable := statedb.Observable[*types.BFDPeerStatus](r.db, r.bfdPeersTable)
	ch := stream.ToChannel[statedb.Change[*types.BFDPeerStatus]](ctx, observable)

	prevPeerState := make(map[netip.Addr]types.BFDState)

	for ev := range ch {
		peerAddr := ev.Object.PeerAddress
		state := ev.Object.Local.State
		prevState, prevStateKnown := prevPeerState[peerAddr]

		if !ev.Deleted {
			// trigger reconcile if the state went to Up or Down. We don't really care about other state changes.
			if (state == types.BFDStateDown || state == types.BFDStateUp) && (!prevStateKnown || prevState != state) {
				r.log.Debug("BFD peer state changed, triggering BGP reconciliation",
					types.PeerAddressField, peerAddr,
					types.SessionStateField, state,
				)
				r.signaler.Event(struct{}{})
			}
			prevPeerState[peerAddr] = state
		} else {
			delete(prevPeerState, peerAddr)
		}
	}
	return nil
}

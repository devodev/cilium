//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/watchdog"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// settleTime is the time reconcilers wait before proceeding with the actual
// reconciliation, to batch work. It can be overridden for testing purposes.
var settleTime = 100 * time.Millisecond

// watchdogIDPrefix is the prefix prepended to watchdog IDs to prevent collisions
// with other subsystems.
const watchdogIDPrefix = "__srv/"

type health struct {
	api.UnimplementedHealthServer
	api.UnimplementedNetworksServer

	log *slog.Logger

	db          *statedb.DB
	networks    statedb.Table[tables.PrivateNetwork]
	attachments statedb.Table[*tables.NodeAttachment]
	tbl         statedb.RWTable[tables.ActiveNetwork]

	watchdog watchdog.Watchdog

	// hmu protects the access to [healthy]. It must be always acquired first
	// when acquiring a write transaction as well.
	hmu     lock.RWMutex
	healthy map[tables.WorkloadNode]wnEntry

	wg   sync.WaitGroup
	stop chan struct{}
}

type wnEntry struct {
	timeout   *time.Timer
	wdtimeout time.Duration
}

type healthParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	DB          *statedb.DB
	Networks    statedb.Table[tables.PrivateNetwork]
	Attachments statedb.Table[*tables.NodeAttachment]
	Table       statedb.RWTable[tables.ActiveNetwork]

	Watchdog watchdog.Watchdog
}

func newHealth(in healthParams) *health {
	h := &health{
		log: in.Logger,

		db:          in.DB,
		networks:    in.Networks,
		attachments: in.Attachments,
		tbl:         in.Table,

		healthy: make(map[tables.WorkloadNode]wnEntry),
		stop:    make(chan struct{}),

		watchdog: in.Watchdog,
	}
	in.Lifecycle.Append(cell.Hook{OnStop: h.stopHook})
	return h
}

func (s *health) stopHook(_ cell.HookContext) error {
	close(s.stop)
	s.wg.Wait()
	return nil
}

// registerGCer registers a job to GC entries from the active networks table
// when the given network can no longer be served.
func (s *health) registerGCer(jg job.Group, cfg pncfg.Config) {
	// No need to reconcile anything if we are not running as bridge.
	if !cfg.EnabledAsBridge() {
		return
	}

	jg.Add(
		job.OneShot("health-server-active-gc", s.gcLoop),
	)
}

func (s *health) gcLoop(ctx context.Context, health cell.Health) error {
	wtx := s.db.WriteTxn(s.networks, s.attachments)
	netIter, _ := s.networks.Changes(wtx)
	attachIter, _ := s.attachments.Changes(wtx)
	wtx.Commit()

	health.OK("Primed")
	for {
		var toGC = sets.New[tables.NetworkName]()

		wtx := s.db.WriteTxn(s.tbl)
		netChanges, netWatch := netIter.Next(wtx)
		attachChanges, attachWatch := attachIter.Next(wtx)

		for change := range netChanges {
			network := change.Object.Name
			if change.Deleted {
				// The network cannot be served, hence trigger GC.
				toGC.Insert(network)
			}
		}

		// check there is valid attachment associated with private-network.
		var nwProcessed = sets.New[tables.NetworkName]()
		for attach := range attachChanges {
			network := attach.Object.Network
			if nwProcessed.Has(network) {
				continue
			}

			if !s.validNetworkAttachment(wtx, network) {
				// no attachment associated with a network.
				toGC.Insert(network)
			}
			nwProcessed.Insert(network)
		}

		if len(toGC) > 0 {
			var cnt uint

			// We assume that this operation is rare enough that it is better to
			// simply iterate over all entries rather than adding a dedicated index.
			for entry := range s.tbl.All(wtx) {
				if toGC.Has(entry.Network) {
					s.tbl.Delete(wtx, entry)
					cnt++
				}
			}

			if cnt > 0 {
				wtx.Commit()
				health.OK(fmt.Sprintf("Reconciliation completed, GCed %d entries", cnt))
			}
		}

		wtx.Abort()

		select {
		case <-netWatch:
		case <-attachWatch:
		case <-ctx.Done():
			return nil
		}

		// Wait for a bit of time, to allow for possible other
		// changes to accumulate in the meanwhile.
		select {
		case <-time.After(settleTime):
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *health) Probe(stream grpc.BidiStreamingServer[api.ProbeRequest, api.ProbeResponse]) error {
	var known tables.WorkloadNode

	for {
		request, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("receiving: %w", err)
		}

		node, err := s.toWorkloadNode(request.GetSelf())
		if err != nil {
			return err
		}

		if known == (tables.WorkloadNode{}) {
			// We received the first message from the stream. Let's make sure that
			// all subsequent ones include the same node information.
			known = node
		} else if node != known {
			return status.Error(codes.InvalidArgument, "mismatching [Self] parameter")
		}

		timeout := request.GetTimeout().AsDuration()
		if timeout == 0 {
			return status.Error(codes.InvalidArgument, "invalid [Timeout] parameter")
		}

		interval := request.GetInterval().AsDuration()
		if interval == 0 {
			return status.Error(codes.InvalidArgument, "invalid [Interval] parameter")
		}

		// [Config.validate] enforces that timeout is at least 50% higher than
		// interval. We perform a loose validation here, to prevent surprises
		// in case of misbehaving clients, but without failing hard to avoid
		// breaking changes if we were to change the constraint in the future.
		if thresh := timeout * 2 / 3; interval > thresh {
			interval = timeout * 2 / 3
		}

		s.onProbe(node, interval, timeout)

		err = stream.Send(&api.ProbeResponse{Status: api.ProbeResponse_SERVING})
		if err != nil {
			return fmt.Errorf("sending: %w", err)
		}
	}
}

func (s *health) onProbe(node tables.WorkloadNode, interval, timeout time.Duration) {
	// We are conservative, and compute the watchdog timeout as timeout - interval.
	// This is to have a reasonable guarantee that it would always expire first,
	// regardless of the fact that intervals are different, and not synchronized.
	// The worst case, if we were to use the same timeout, is exemplified by the
	// following (hpr: health probe, hpt: health probe timeout, alp: agent liveness
	// probe, alt: agent liveness timeout):
	//
	//  alp  alp alp alp               alt
	//   v    v   v   v                 v
	// --|--|-|---|---|-|-------|~~~~~~~|
	//      ^           x down  ^
	//     hpr         hpr     hpt
	var wdtimeout = timeout - interval

	// Reduce a bit the timeout advertised by the node, to account for
	// possible latency, and speed up the detection on the INB side.
	// This is intended to reduce the likelihood of ending up with two
	// INBs thinking that they are both active at the same time.
	timeout = timeout / 10 * 8

	s.hmu.Lock()
	defer s.hmu.Unlock()

	entry, found := s.healthy[node]
	if found {
		if entry.wdtimeout != wdtimeout {
			entry.wdtimeout = wdtimeout
			s.healthy[node] = entry
			s.watchdog.RequestTimeout(watchdogIDPrefix+node.String(), wdtimeout)
		}

		// The node was already healthy: restart the timeout timer.
		entry.timeout.Reset(timeout)
		return
	}

	// The node just became healthy: start the timeout logic.
	entry = wnEntry{
		timeout:   time.NewTimer(timeout),
		wdtimeout: wdtimeout,
	}

	s.watchdog.RequestTimeout(watchdogIDPrefix+node.String(), wdtimeout)

	s.wg.Go(func() {
		select {
		case <-s.stop:
		case <-entry.timeout.C:
			s.onProbeTimeout(node)
		}
	})

	s.healthy[node] = entry
	s.log.Info("Registered new healthy workload node", logfields.Node, node)
}

func (s *health) onProbeTimeout(node tables.WorkloadNode) {
	s.hmu.Lock()
	defer s.hmu.Unlock()

	s.log.Info("Workload node is no longer healthy", logfields.Node, node)
	delete(s.healthy, node)

	s.watchdog.ReleaseTimeout(watchdogIDPrefix + node.String())

	wtx := s.db.WriteTxn(s.tbl)

	// The node is no longer considered healthy, hence drop all active networks.
	for active := range s.tbl.Prefix(wtx, tables.ActiveNetworkByNode(node)) {
		s.tbl.Delete(wtx, active)
	}

	wtx.Commit()
}

func (s *health) Watch(in *api.WatchRequest, stream grpc.ServerStreamingServer[api.NetworkEvents]) error {
	var incremental bool

	node, err := s.toWorkloadNode(in.GetSelf())
	if err != nil {
		return err
	}

	// Wait for networks table initialization, so that we only send the first
	// snapshot once everything settled down.
	_, watch := s.networks.Initialized(s.db.ReadTxn())
	select {
	case <-watch:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}

	wtx := s.db.WriteTxn(s.networks, s.tbl, s.attachments)
	networksIter, _ := s.networks.Changes(wtx)
	activeIter, _ := s.tbl.Changes(wtx)
	attachIter, _ := s.attachments.Changes(wtx)
	wtx.Commit()

	for {
		var (
			events  api.NetworkEvents
			changes = sets.New[tables.NetworkName]()
			txn     = s.db.ReadTxn()
		)

		networkChanges, networksWatch := networksIter.Next(txn)
		for change := range networkChanges {
			changes.Insert(change.Object.Name)
		}

		activeChanges, activeWatch := activeIter.Next(txn)
		for change := range activeChanges {
			if change.Object.Node == node {
				changes.Insert(change.Object.Network)
			}
		}

		attachmentChanges, attachWatch := attachIter.Next(txn)
		for change := range attachmentChanges {
			changes.Insert(change.Object.Network)
		}

		for network := range changes {
			var status = api.NetworkEvents_Event_NOT_SERVING

			_, _, found := s.networks.Get(txn, tables.PrivateNetworkByName(network))
			if found && s.validNetworkAttachment(txn, network) {
				status = api.NetworkEvents_Event_STANDBY

				_, _, active := s.tbl.Get(txn, tables.ActiveNetworkByKey(node, network))
				if active {
					status = api.NetworkEvents_Event_ACTIVE
				}
			}

			// No need to send an event for non served networks in the initial snapshot.
			if status != api.NetworkEvents_Event_NOT_SERVING || incremental {
				events.Events = append(events.Events, &api.NetworkEvents_Event{
					Network: &api.Network{Name: string(network)},
					Status:  status,
				})
			}
		}

		if cnt := len(events.Events); cnt > 0 || !incremental {
			err := stream.Send(&events)
			if err != nil {
				return fmt.Errorf("sending: %w", err)
			}

			s.log.Debug("Sent update of networks served to node",
				logfields.Node, node,
				logfields.Count, cnt,
				logfields.Incremental, incremental,
			)
		}

		incremental = true

		select {
		case <-networksWatch:
		case <-activeWatch:
		case <-attachWatch:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}

		// Wait for a bit of time, to allow for possible other changes to
		// accumulate in the meanwhile.
		select {
		case <-time.After(settleTime):
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *health) Activate(ctx context.Context, in *api.ActivationRequest) (*api.ActivationResponse, error) {
	node, err := s.toWorkloadNode(in.GetSelf())
	if err != nil {
		return &api.ActivationResponse{}, err
	}

	network := tables.NetworkName(in.GetNetwork().GetName())
	if network == "" {
		return &api.ActivationResponse{}, status.Error(codes.InvalidArgument, "invalid [Network] parameter")
	}

	if err := s.activate(node, network); err != nil {
		s.log.Info("Failed activating network for node",
			logfields.Error, err,
			logfields.Node, node,
			logfields.Network, network,
		)
		return &api.ActivationResponse{}, status.Error(codes.FailedPrecondition, err.Error())
	}

	s.log.Info("Successfully activated network for node",
		logfields.Network, network,
		logfields.Node, node,
	)

	return &api.ActivationResponse{}, nil
}

func (s *health) activate(node tables.WorkloadNode, network tables.NetworkName) error {
	s.hmu.RLock()
	defer s.hmu.RUnlock()

	if _, healthy := s.healthy[node]; !healthy {
		return errors.New("requesting node is not healthy")
	}

	wtx := s.db.WriteTxn(s.tbl)
	defer wtx.Abort()

	_, _, found := s.networks.Get(wtx, tables.PrivateNetworkByName(network))
	if !found {
		return errors.New("network is unknown")
	}

	if !s.validNetworkAttachment(wtx, network) {
		return errors.New("network cannot be served")
	}

	_, hasOld, _ := s.tbl.Insert(wtx, tables.ActiveNetwork{Node: node, Network: network})
	if hasOld {
		// No need to commit if the entry was already present, as that would wake the watchers.
		return nil
	}

	wtx.Commit()
	return nil
}

func (s *health) Deactivate(ctx context.Context, in *api.DeactivationRequest) (*api.DeactivationResponse, error) {
	node, err := s.toWorkloadNode(in.GetSelf())
	if err != nil {
		return &api.DeactivationResponse{}, err
	}

	network := tables.NetworkName(in.GetNetwork().GetName())
	if network == "" {
		return &api.DeactivationResponse{}, status.Error(codes.InvalidArgument, "invalid [Network] parameter")
	}

	wtx := s.db.WriteTxn(s.tbl)
	s.tbl.Delete(wtx, tables.ActiveNetwork{Node: node, Network: network})
	wtx.Commit()

	s.log.Info("Successfully deactivated network for node",
		logfields.Network, network,
		logfields.Node, node,
	)

	return &api.DeactivationResponse{}, nil
}

func (s *health) toWorkloadNode(in *api.Node) (tables.WorkloadNode, error) {
	out := tables.WorkloadNode{
		Cluster: tables.ClusterName(in.GetCluster()),
		Name:    tables.NodeName(in.GetName()),
	}

	if out.Cluster == "" || out.Name == "" {
		return tables.WorkloadNode{}, status.Error(codes.InvalidArgument, "invalid [Self] parameter")
	}

	return out, nil
}

// validNetworkAttachment checks there is at least one ready interface associated with the network.
func (s *health) validNetworkAttachment(txn statedb.ReadTxn, networkName tables.NetworkName) bool {
	for networkAttach := range s.attachments.List(txn, tables.NodeAttachmentsByNetworkName(networkName)) {
		if networkAttach.IsReady() {
			return true
		}
	}
	return false
}

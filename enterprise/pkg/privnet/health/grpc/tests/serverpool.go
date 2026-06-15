//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cslices "github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
)

var ServerPoolCell = cell.Group(
	cell.Provide(
		newServerPool,
		(*ServerPool).Commands,
	),
)

type ServerPool struct {
	jg      job.Group
	factory ConnFactory

	db     *statedb.DB
	served statedb.RWTable[InstanceNetwork]
	active statedb.RWTable[InstanceNetwork]

	started bool
	pool    map[Instance]*Server
}

func newServerPool(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Factory   ConnFactory

	DB *statedb.DB
}) (sp *ServerPool, err error) {
	sp = &ServerPool{
		jg:      in.JobGroup,
		factory: in.Factory,
		db:      in.DB,

		pool: make(map[Instance]*Server),
	}

	// Initialize the tables here, rather than through hive, for simplicity,
	// as they'd otherwise conflict given the usage of the same underlying type.
	sp.served, err = newTable(in.DB, "test-served-networks")
	if err != nil {
		return nil, err
	}

	sp.active, err = newTable(in.DB, "test-active-networks")
	if err != nil {
		return nil, err
	}

	sp.jg.Add(
		job.OneShot(
			"test-health-servers-reconcile",
			sp.reconcile,
		),
	)

	in.Lifecycle.Append(sp)
	return sp, nil
}

func (sp *ServerPool) Start(cell.HookContext) error {
	sp.started = true
	return nil
}

func (sp *ServerPool) Stop(cell.HookContext) error {
	for _, srv := range sp.pool {
		srv.Stop()
	}
	return nil
}

func (sp *ServerPool) Commands() hive.ScriptCmdsOut {
	return hive.NewScriptCmds(
		map[string]script.Cmd{
			"serverpool/new":   sp.instanceCmd("Create a new server", sp.new),
			"serverpool/start": sp.instanceCmd("Start a server", sp.start),
			"serverpool/stop":  sp.instanceCmd("Stop a server", sp.stop),
			"serverpool/block": sp.instanceCmd("Block a server", sp.block),

			"serverpool/serve":    sp.instanceNetworksCmd("Mark networks as served", sp.serve),
			"serverpool/withdraw": sp.instanceNetworksCmd("Unmark networks as served", sp.withdraw),

			"serverpool/streams": sp.instanceIntCmd(
				"Check if the count of open streams matches expected", sp.validateStreams),
		},
	)
}

func (sp *ServerPool) instanceCmd(usage string, do func(Instance) error) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: usage,
			Args:    "cluster/node",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected cluster/node", script.ErrUsage)
			}

			inst, err := NewInstance(args[0])
			if err != nil {
				return nil, fmt.Errorf("%w: %w", script.ErrUsage, err)
			}

			return nil, do(inst)
		},
	)
}

func (sp *ServerPool) instanceNetworksCmd(usage string, do func(Instance, ...tables.NetworkName)) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: usage,
			Args:    "cluster/node networks...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("%w: expected cluster/node, and at least a network", script.ErrUsage)
			}

			inst, err := NewInstance(args[0])
			if err != nil {
				return nil, fmt.Errorf("%w: %w", script.ErrUsage, err)
			}

			do(inst, cslices.Map(args[1:], func(in string) tables.NetworkName { return tables.NetworkName(in) })...)
			return nil, nil
		},
	)
}

func (sp *ServerPool) instanceIntCmd(usage string, do func(Instance, int32) error) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: usage,
			Args:    "cluster/node expected",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected cluster/node, and expected", script.ErrUsage)
			}

			inst, err := NewInstance(args[0])
			if err != nil {
				return nil, fmt.Errorf("%w: %w", script.ErrUsage, err)
			}

			expected, err := strconv.ParseInt(args[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: cannot parse expected: %w", script.ErrUsage, err)
			}

			return nil, do(inst, int32(expected))
		},
	)
}

func (sp *ServerPool) new(inst Instance) error {
	if sp.started {
		return errors.New("hive already started")
	}

	if _, found := sp.pool[inst]; found {
		return errors.New("already exists")
	}

	sp.pool[inst] = &Server{
		factory: sp.factory,
		self:    inst,

		db:     sp.db,
		served: sp.served,
		active: sp.active,
	}

	return nil
}

func (sp *ServerPool) start(inst Instance) error { return sp.do(inst, (*Server).Start) }
func (sp *ServerPool) stop(inst Instance) error  { return sp.do(inst, (*Server).Stop) }
func (sp *ServerPool) block(inst Instance) error { return sp.do(inst, (*Server).Block) }

func (sp *ServerPool) validateStreams(inst Instance, expected int32) error {
	return sp.do(inst, func(s *Server) error {
		got := s.streams.Load()
		if got != int32(expected) {
			return fmt.Errorf("invalid streams count, expected %d, got %d", expected, got)
		}

		return nil
	})
}

func (sp *ServerPool) do(inst Instance, fn func(*Server) error) error {
	srv, found := sp.pool[inst]
	if !found {
		return errors.New("not found")
	}

	return fn(srv)
}

func (sp *ServerPool) serve(inst Instance, networks ...tables.NetworkName) {
	wtx := sp.db.WriteTxn(sp.served)
	for _, net := range networks {
		sp.served.Insert(wtx, InstanceNetwork{Instance: inst, Network: net})
	}
	wtx.Commit()
}

func (sp *ServerPool) withdraw(inst Instance, networks ...tables.NetworkName) {
	wtx := sp.db.WriteTxn(sp.served)
	for _, net := range networks {
		sp.served.Delete(wtx, InstanceNetwork{Instance: inst, Network: net})
	}
	wtx.Commit()
}

// reconcile takes care of removing stale entries from the test-active-networks
// table if the corresponding network is no longer served by the given server.
func (sp *ServerPool) reconcile(ctx context.Context, _ cell.Health) error {
	wtx := sp.db.WriteTxn(sp.served)
	changeIter, _ := sp.served.Changes(wtx)
	wtx.Commit()

	for {
		wtx := sp.db.WriteTxn(sp.active)

		changes, watch := changeIter.Next(wtx)
		for change := range changes {
			if change.Deleted {
				sp.active.Delete(wtx, change.Object)
			}
		}

		wtx.Commit()

		select {
		case <-watch:
		case <-ctx.Done():
			return nil
		}
	}
}

type Server struct {
	api.UnimplementedHealthServer
	api.UnimplementedNetworksServer
	api.UnimplementedMigrationServer

	factory ConnFactory
	self    Instance

	db     *statedb.DB
	served statedb.Table[InstanceNetwork]
	active statedb.RWTable[InstanceNetwork]

	wg   sync.WaitGroup
	stop func()

	running bool
	streams atomic.Int32

	// block is used to simulate a blocked server.
	block   chan struct{}
	unblock chan struct{}
}

func (s *Server) Start() error {
	if s.running {
		return errors.New("already running")
	}

	lis, err := s.factory.NewListener(s.self)
	if err != nil {
		return err
	}

	srv := grpc.NewServer(grpc.WaitForHandlers(true))
	api.RegisterHealthServer(srv, s)
	api.RegisterNetworksServer(srv, s)
	api.RegisterMigrationServer(srv, s)
	s.stop = srv.Stop

	s.block = make(chan struct{})
	s.unblock = make(chan struct{})
	s.running = true

	s.wg.Go(func() { srv.Serve(lis) })
	return nil
}

func (s *Server) Stop() error {
	if !s.running {
		return nil
	}

	close(s.unblock)
	s.stop()
	s.wg.Wait()
	s.running = false

	// Stop simulates a restart, so we lost all state.
	s.deactivateAll()

	return nil
}

func (s *Server) Block() error {
	if !s.running {
		return errors.New("not running")
	}

	select {
	case <-s.block:
		return errors.New("already blocked")
	default:
		close(s.block)
		return nil
	}
}

func (s *Server) Probe(stream grpc.BidiStreamingServer[api.ProbeRequest, api.ProbeResponse]) error {
	s.streams.Add(1)
	defer func() { s.streams.Add(-1) }()

	var cancel = func() {}

	for {
		request, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("receiving: %w", err)
		}

		// Successfully received a probe, so stop the timeout function.
		cancel()

		timeout := request.GetTimeout().AsDuration()
		if timeout == 0 {
			return status.Error(codes.InvalidArgument, "invalid timeout value of 0")
		}

		timer := time.AfterFunc(timeout, s.deactivateAll)
		cancel = func() { timer.Stop() }

		select {
		case <-s.block:
			<-s.unblock
			return status.Error(codes.Aborted, "unblocked")
		default:
		}

		err = stream.Send(&api.ProbeResponse{Status: api.ProbeResponse_SERVING})
		if err != nil {
			return fmt.Errorf("sending: %w", err)
		}
	}
}

func (s *Server) Watch(_ *api.WatchRequest, stream grpc.ServerStreamingServer[api.NetworkEvents]) error {
	s.streams.Add(1)
	defer func() { s.streams.Add(-1) }()

	var (
		incremental bool
		extract     = func(in statedb.Change[InstanceNetwork]) InstanceNetwork { return in.Object }
		keep        = func(in InstanceNetwork) bool { return in.Instance == s.self }
	)

	wtx := s.db.WriteTxn(s.served, s.active)
	servedIter, _ := s.served.Changes(wtx)
	activeIter, _ := s.active.Changes(wtx)
	wtx.Commit()

	for {
		var events api.NetworkEvents

		select {
		case <-s.block:
			<-s.unblock
			return status.Error(codes.Aborted, "unblocked")
		default:
		}

		txn := s.db.ReadTxn()
		served, servedWatch := servedIter.Next(txn)
		active, activeWatch := activeIter.Next(txn)

		changes := cslices.Unique(slices.Concat(
			statedb.Collect(statedb.Filter(statedb.Map(served, extract), keep)),
			statedb.Collect(statedb.Filter(statedb.Map(active, extract), keep)),
		))

		for _, change := range changes {
			_, _, served := s.served.Get(txn, byObject(change))
			_, _, active := s.active.Get(txn, byObject(change))

			status := api.NetworkEvents_Event_NOT_SERVING
			if served && active {
				status = api.NetworkEvents_Event_ACTIVE
			} else if served {
				status = api.NetworkEvents_Event_STANDBY
			}

			events.Events = append(events.Events, &api.NetworkEvents_Event{
				Network: &api.Network{Name: string(change.Network)},
				Status:  status,
			})
		}

		if len(events.Events) > 0 || !incremental {
			err := stream.Send(&events)
			if err != nil {
				return fmt.Errorf("sending: %w", err)
			}
		}

		incremental = true

		select {
		case <-servedWatch:
		case <-activeWatch:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *Server) Activate(ctx context.Context, in *api.ActivationRequest) (*api.ActivationResponse, error) {
	select {
	case <-s.block:
		<-s.unblock
		return nil, status.Error(codes.Aborted, "unblocked")
	default:
	}

	wtx := s.db.WriteTxn(s.active)
	defer wtx.Abort()

	network := tables.NetworkName(in.GetNetwork().GetName())
	if network == "" {
		return nil, status.Error(codes.InvalidArgument, "empty network")
	}

	obj := InstanceNetwork{Instance: s.self, Network: network}
	_, _, found := s.served.Get(wtx, byObject(obj))
	if !found {
		return &api.ActivationResponse{}, status.Error(codes.FailedPrecondition, "network is not served")
	}

	s.active.Insert(wtx, obj)
	wtx.Commit()

	return &api.ActivationResponse{}, nil
}

func (s *Server) Deactivate(ctx context.Context, in *api.DeactivationRequest) (*api.DeactivationResponse, error) {
	select {
	case <-s.block:
		<-s.unblock
		return nil, status.Error(codes.Aborted, "unblocked")
	default:
	}

	wtx := s.db.WriteTxn(s.active)
	defer wtx.Abort()

	network := tables.NetworkName(in.GetNetwork().GetName())
	if network == "" {
		return nil, status.Error(codes.InvalidArgument, "empty network")
	}

	s.active.Delete(wtx, InstanceNetwork{Instance: s.self, Network: network})
	wtx.Commit()

	return &api.DeactivationResponse{}, nil
}

func (s *Server) deactivateAll() {
	wtx := s.db.WriteTxn(s.active)
	for entry := range s.active.Prefix(wtx, byINB(s.self)) {
		s.active.Delete(wtx, entry)
	}
	wtx.Commit()
}

func (s *Server) Migrate(stream grpc.BidiStreamingServer[api.MigrationRequest, api.MigrationBatch]) error {
	// Simulate a migration with some fake data.
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	start := req.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "expected start")
	}

	// tests/script_test.go sets time.Now to 2038-01-01. Use the same here.
	fakeNow := time.Date(2038, 1, 1, 0, 0, 0, 0, time.UTC)
	now := timestamppb.New(fakeNow)
	expire := timestamppb.New(fakeNow.Add(time.Hour))

	err = stream.Send(&api.MigrationBatch{
		Records: []*api.CTRecord{},
		DhcpLease: []*api.DHCPLease{{
			Ipv4:       netip.MustParseAddr("1.2.3.4").AsSlice(),
			ServerId:   "1.2.3.255",
			ObtainedAt: now,
			RenewAt:    expire,
			ExpireAt:   expire,
		}},
	})
	if err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}
	finalize := req.GetFinalize()
	if finalize == nil {
		return status.Error(codes.InvalidArgument, "expected finalize")
	}

	return nil
}

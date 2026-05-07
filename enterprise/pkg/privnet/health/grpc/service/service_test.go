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
	"log/slog"
	"maps"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

type (
	PN  = tables.PrivateNetwork
	NA  = tables.NodeAttachment
	NAI = tables.NodeAttachmentInterface
	AN  = tables.ActiveNetwork
	WN  = tables.WorkloadNode
)

const (
	// timeout is the timeout when waiting for an event to occur.
	timeout = 1 * time.Second

	// shortTimeout is a shorter timeout when checking that an event didn't occur.
	shortTimeout = 100 * time.Millisecond
)

var (
	TestValidNASelector = tables.NodeSelector{SelectorMatches: true}
)

type fakewd struct {
	m lock.Map[string, time.Duration]
}

func (fwd *fakewd) RequestTimeout(id string, timeout time.Duration) {
	fwd.m.Store(id, timeout)
}

func (fwd *fakewd) ReleaseTimeout(id string) {
	fwd.m.Delete(id)
}

func (fwd *fakewd) get(id string) time.Duration {
	timeout, _ := fwd.m.Load(id)
	return timeout
}

func fixture(t *testing.T) (*statedb.DB, statedb.RWTable[PN], statedb.RWTable[AN], statedb.RWTable[*NA], *fakewd, *health) {
	var (
		db  = statedb.New()
		fwd fakewd
	)

	networks, err := tables.NewPrivateNetworksTable(db)
	require.NoError(t, err, "tables.NewPrivateNetworksTable")

	actnets, err := tables.NewActiveNetworksTable(db)
	require.NoError(t, err, "tables.NewActiveNetworksTable")

	attachments, err := tables.NewNodeAttachmentsTable(db)
	require.NoError(t, err, "tables.NewNodeAttachmentsTable")

	return db, networks, actnets, attachments, &fwd, newHealth(healthParams{
		Logger:      hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		Lifecycle:   hivetest.Lifecycle(t),
		DB:          db,
		Networks:    networks,
		Attachments: attachments,
		Table:       actnets,
		Watchdog:    &fwd,
	})
}

type mockStream[Req, Res any] struct {
	ctx  context.Context
	recv chan mockStreamReq[Req]
	sent chan *Res
}

type mockStreamReq[Req any] struct {
	data *Req
	err  error
}

var _ grpc.ServerStreamingServer[string] = mockStream[int, string]{}
var _ grpc.BidiStreamingServer[int, string] = mockStream[int, string]{}

func newMockStream[Req, Res any](ctx context.Context) mockStream[Req, Res] {
	return mockStream[Req, Res]{
		ctx:  ctx,
		recv: make(chan mockStreamReq[Req], 10),
		sent: make(chan *Res, 10),
	}
}

func (m mockStream[Req, Res]) Recv() (*Req, error) {
	req := <-m.recv
	return req.data, req.err
}

func (m mockStream[Req, Res]) Send(res *Res) error {
	m.sent <- res
	return nil
}

func (m mockStream[Req, Res]) doSend(req *Req, err error) {
	m.recv <- mockStreamReq[Req]{data: req, err: err}
}

func (m mockStream[Req, Res]) getSent(t *testing.T) (got *Res) {
	select {
	case got = <-m.sent:
	case <-time.After(timeout):
		require.FailNow(t, "Expected update to have been sent")
	}
	return got
}

func (m mockStream[Req, Res]) syncGetSent(t *testing.T) (got *Res) {
	synctest.Wait()
	select {
	case got = <-m.sent:
	default:
		require.FailNow(t, "Expected update to have been sent")
	}
	return got
}

func (m mockStream[Req, Res]) noGetSent(t *testing.T) {
	select {
	case <-time.After(shortTimeout):
	case <-m.sent:
		require.FailNow(t, "No update should have been sent")
	}
}

func (m mockStream[Req, Res]) Context() context.Context     { return m.ctx }
func (m mockStream[Req, Res]) RecvMsg(any) error            { panic("unimplemented") }
func (m mockStream[Req, Res]) SendHeader(metadata.MD) error { panic("unimplemented") }
func (m mockStream[Req, Res]) SendMsg(any) error            { panic("unimplemented") }
func (m mockStream[Req, Res]) SetHeader(metadata.MD) error  { panic("unimplemented") }
func (m mockStream[Req, Res]) SetTrailer(metadata.MD)       { panic("unimplemented") }

func TestMain(m *testing.M) {
	testutils.GoleakVerifyTestMain(m)
}

func TestServiceProbe(t *testing.T) {
	var (
		sloth    = WN{Cluster: "local", Name: "sloth"}
		snail    = WN{Cluster: "local", Name: "snail"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
		apiSnail = &api.Node{Cluster: string(snail.Cluster), Name: string(snail.Name)}
		interval = 250 * time.Millisecond
		timeout  = time.Second
	)

	synctest.Test(t, func(t *testing.T) {
		db, _, actnets, _, fwd, srv := fixture(t)

		var (
			streamSloth = newMockStream[api.ProbeRequest, api.ProbeResponse](t.Context())
			streamSnail = newMockStream[api.ProbeRequest, api.ProbeResponse](t.Context())
		)

		defer func() {
			// Force both streams to terminate
			streamSloth.doSend(nil, context.Canceled)
			streamSnail.doSend(nil, context.Canceled)
		}()

		go func() { srv.Probe(streamSloth) }()
		go func() { srv.Probe(streamSnail) }()

		streamSloth.doSend(&api.ProbeRequest{Self: apiSloth, Interval: durationpb.New(interval), Timeout: durationpb.New(timeout)}, nil)
		streamSnail.doSend(&api.ProbeRequest{Self: apiSnail, Interval: durationpb.New(interval), Timeout: durationpb.New(timeout)}, nil)

		// A reply should have been received.
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSloth.syncGetSent(t))
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSnail.syncGetSent(t))

		// Both nodes should be healthy
		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})

		// The watchdog methods should have been invoked correctly.
		require.Equal(t, timeout-interval, fwd.get("__srv/local/sloth"))
		require.Equal(t, timeout-interval, fwd.get("__srv/local/snail"))

		// Pretend that a few networks have been activated.
		wtx := db.WriteTxn(actnets)
		actnets.Insert(wtx, AN{Node: sloth, Network: "green"})
		actnets.Insert(wtx, AN{Node: snail, Network: "yellow"})
		actnets.Insert(wtx, AN{Node: snail, Network: "blue"})
		wtx.Commit()

		// The timeout has not expired, so both nodes should still be healthy.
		time.Sleep(timeout/10*8 - 1*time.Millisecond)
		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})

		streamSloth.doSend(&api.ProbeRequest{Self: apiSloth, Interval: durationpb.New(interval * 2), Timeout: durationpb.New(timeout)}, nil)
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSloth.syncGetSent(t))
		time.Sleep(1 * time.Millisecond)

		// The snail node should no longer be healthy.
		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth})

		// The watchdog methods should have been invoked correctly.
		require.Equal(t, timeout-2*interval, fwd.get("__srv/local/sloth"))
		require.Empty(t, fwd.get("__srv/local/snail"))

		// The corresponding active network entries should have been dropped.
		require.ElementsMatch(t, statedb.Collect(actnets.All(db.ReadTxn())), []AN{{Node: sloth, Network: "green"}})

		// Healthy again.
		streamSnail.doSend(&api.ProbeRequest{Self: apiSnail, Interval: durationpb.New(interval), Timeout: durationpb.New(timeout)}, nil)
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSnail.syncGetSent(t))

		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})
		require.Equal(t, timeout-2*interval, fwd.get("__srv/local/sloth"))
		require.Equal(t, timeout-interval, fwd.get("__srv/local/snail"))

		// Break both streams, the nodes should still be healthy until timeout.
		streamSloth.doSend(nil, context.Canceled)
		streamSnail.doSend(nil, context.Canceled)

		time.Sleep(timeout/10*8 - 2*time.Millisecond)

		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})

		// Restart only one, and send a new probe.
		go func() { srv.Probe(streamSloth) }()
		streamSloth.doSend(&api.ProbeRequest{Self: apiSloth, Interval: durationpb.New(interval), Timeout: durationpb.New(timeout)}, nil)
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSloth.syncGetSent(t))

		// The snail node should no longer be healthy after timeout.
		time.Sleep(10 * time.Millisecond)

		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth})
		require.Equal(t, timeout-interval, fwd.get("__srv/local/sloth"))
		require.Empty(t, fwd.get("__srv/local/snail"))
	})
}

func TestServiceProbeErrors(t *testing.T) {
	var (
		apiSloth = &api.Node{Cluster: "local", Name: "sloth"}
		apiSnail = &api.Node{Cluster: "local", Name: "snail"}
		interval = durationpb.New(500 * time.Millisecond)
		timeout  = durationpb.New(time.Second)
	)

	tests := []struct {
		name string
		do   func(mockStream[api.ProbeRequest, api.ProbeResponse])
		err  string
	}{
		{
			name: "invalid Self",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Interval: interval, Timeout: timeout}, nil)
			},
			err: "invalid [Self] parameter",
		},
		{
			name: "mismatching Self",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Self: apiSloth, Interval: interval, Timeout: timeout}, nil)
				stream.doSend(&api.ProbeRequest{Self: apiSnail, Interval: interval, Timeout: timeout}, nil)
			},
			err: "mismatching [Self] parameter",
		},
		{
			name: "invalid Interval",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Self: apiSloth, Timeout: timeout}, nil)
			},
			err: "invalid [Interval] parameter",
		},
		{
			name: "invalid Timeout",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Self: apiSloth, Interval: interval}, nil)
			},
			err: "invalid [Timeout] parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, _, _, _, _, srv := fixture(t)

				var (
					errch  = make(chan error)
					stream = newMockStream[api.ProbeRequest, api.ProbeResponse](t.Context())
				)

				go func() { errch <- srv.Probe(stream) }()

				tt.do(stream)

				err := <-errch
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				require.ErrorContains(t, err, tt.err)
			})
		})
	}

}

func TestServiceWatch(t *testing.T) {
	// Ideally, we could use synctest here to not have to depend on timings.
	// However, that turned out not working well because [Table.Changes] makes
	// use of [runtime.SetFinalizer] to unregister the delete tracker. However,
	// finalizers run outside of any bubble [1], causing a fatal error as it
	// eventually closes a channel defined inside the bubble:
	//
	//     fatal error: close of synctest channel from outside bubble
	//
	// [1]: https://pkg.go.dev/testing/synctest#hdr-Isolation
	// > Cleanup functions and finalizers registered with runtime.AddCleanup
	// > and runtime.SetFinalizer run outside of any bubble.

	// Override the settleTime to make the test faster.
	settleTime = 0

	var (
		wg       sync.WaitGroup
		sloth    = WN{Cluster: "local", Name: "sloth"}
		snail    = WN{Cluster: "local", Name: "snail"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
	)

	db, networks, actnets, attachs, _, srv := fixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	stream := newMockStream[struct{}, api.NetworkEvents](ctx)
	defer func() { cancel(); wg.Wait() }()

	// Configure the initial state.
	wtx := db.WriteTxn(networks, actnets, attachs)
	networks.Insert(wtx, PN{Name: "blue"})
	networks.Insert(wtx, PN{Name: "green"})
	networks.Insert(wtx, PN{Name: "yellow"})
	networks.Insert(wtx, PN{Name: "purple"})

	actnets.Insert(wtx, AN{Node: sloth, Network: "green"})
	actnets.Insert(wtx, AN{Node: snail, Network: "yellow"})
	actnets.Insert(wtx, AN{Node: snail, Network: "blue"})

	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.blue", Index: 10}, Network: "blue", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.green", Index: 11}, Network: "green", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.yellow", Index: 12}, Network: "yellow", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.purple", Index: 0}, Network: "purple", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	wtx.Commit()

	// Invalid requests should return an InvalidArgument error.
	err := srv.Watch(&api.WatchRequest{}, stream)
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	wg.Go(func() { srv.Watch(&api.WatchRequest{Self: apiSloth}, stream) })

	require.ElementsMatch(t, stream.getSent(t).GetEvents(),
		[]*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "blue"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "green"}, Status: api.NetworkEvents_Event_ACTIVE},
			{Network: &api.Network{Name: "yellow"}, Status: api.NetworkEvents_Event_STANDBY},
		},
	)

	// Update network state, and assert that a correct update is sent.
	wtx = db.WriteTxn(networks, actnets, attachs)
	networks.Insert(wtx, PN{Name: "red"})
	networks.Insert(wtx, PN{Name: "brown"})
	networks.Delete(wtx, PN{Name: "blue"})
	wtx.Commit()

	require.ElementsMatch(t, stream.getSent(t).GetEvents(),
		[]*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "red"}, Status: api.NetworkEvents_Event_NOT_SERVING},
			{Network: &api.Network{Name: "brown"}, Status: api.NetworkEvents_Event_NOT_SERVING},
			{Network: &api.Network{Name: "blue"}, Status: api.NetworkEvents_Event_NOT_SERVING},
		},
	)

	// update attachment state and check change events
	wtx = db.WriteTxn(networks, actnets, attachs)
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.red", Index: 13}, Network: "red", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.brown", Index: 0}, Network: "brown", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.yellow", Index: 0}, Network: "magenta", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	wtx.Commit()

	require.ElementsMatch(t, stream.getSent(t).GetEvents(),
		[]*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "red"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "brown"}, Status: api.NetworkEvents_Event_NOT_SERVING},
			{Network: &api.Network{Name: "yellow"}, Status: api.NetworkEvents_Event_NOT_SERVING},
			{Network: &api.Network{Name: "magenta"}, Status: api.NetworkEvents_Event_NOT_SERVING},
		},
	)

	// Update the state again, and assert that a correct update is sent.
	wtx = db.WriteTxn(networks, actnets, attachs)
	actnets.Insert(wtx, AN{Node: sloth, Network: "red"})
	actnets.Delete(wtx, AN{Node: sloth, Network: "green"})
	wtx.Commit()

	require.ElementsMatch(t, stream.getSent(t).GetEvents(),
		[]*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "green"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "red"}, Status: api.NetworkEvents_Event_ACTIVE},
		},
	)

	// An unrelated update should not trigger an update.
	wtx = db.WriteTxn(networks, actnets, attachs)
	actnets.Insert(wtx, AN{Node: snail, Network: "green"})
	wtx.Commit()

	stream.noGetSent(t)
}

func TestServiceActivate(t *testing.T) {
	var (
		sloth    = WN{Cluster: "local", Name: "sloth"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
	)

	db, networks, actnets, attachs, _, srv := fixture(t)

	// Configure the initial state.
	wtx := db.WriteTxn(networks, attachs)
	networks.Insert(wtx, PN{Name: "blue"})
	networks.Insert(wtx, PN{Name: "purple"})

	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.blue", Index: 10}, Network: "blue", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.purple", Index: 0}, Network: "purple", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	wtx.Commit()

	// Pretend that the sloth node is healthy.
	srv.healthy[sloth] = wnEntry{}

	// Invalid requests should return an InvalidArgument error.
	_, err := srv.Activate(t.Context(), &api.ActivationRequest{Network: &api.Network{Name: "yellow"}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// Activating a network that is unknown should return a FailedPrecondition error.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "yellow"}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Activating a network that cannot be served should return a FailedPrecondition error.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "purple"}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Activating a network for an unhealthy node should return a FailedPrecondition error.
	other := &api.Node{Cluster: string(sloth.Cluster), Name: "snail"}
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: other, Network: &api.Network{Name: "blue"}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Activating a network that can be served should succeed.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Activate]")

	// The active networks table should be updated correctly.
	require.ElementsMatch(t, statedb.Collect(actnets.All(db.ReadTxn())), []AN{{Node: sloth, Network: "blue"}})

	// Activating the same network again should succeed.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Activate]")
}

func TestServiceDeactivate(t *testing.T) {
	var (
		sloth    = WN{Cluster: "local", Name: "sloth"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
	)

	db, networks, actnets, attachs, _, srv := fixture(t)

	// Configure the initial state.
	wtx := db.WriteTxn(networks, attachs)
	networks.Insert(wtx, PN{Name: "blue"})
	networks.Insert(wtx, PN{Name: "purple"})

	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.blue", Index: 10}, Network: "blue", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.purple", Index: 0}, Network: "purple", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	wtx.Commit()

	// Pretend that the sloth node is healthy.
	srv.healthy[sloth] = wnEntry{}

	// Activate one of the networks.
	_, err := srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Activate]")
	require.ElementsMatch(t, statedb.Collect(actnets.All(db.ReadTxn())), []AN{{Node: sloth, Network: "blue"}})

	// Invalid requests should return an InvalidArgument error.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Network: &api.Network{Name: "yellow"}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// Deactivating a network that is unknown should not return an error.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "yellow"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// Deactivating a network that cannot be served should not return an error.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "purple"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// Deactivating a network for an unhealthy node should not return an error.
	other := &api.Node{Cluster: string(sloth.Cluster), Name: "snail"}
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: other, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// Deactivating a network that was previously active should succeed.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// The active networks table should be updated correctly.
	require.Empty(t, statedb.Collect(actnets.All(db.ReadTxn())))

	// Deactivating a network that was already not active should succeed.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Deactivate]")
}

func TestServiceGCer(t *testing.T) {
	// Override the settleTime to make the test faster.
	settleTime = 0

	const interval = 10 * time.Millisecond

	var (
		wg        sync.WaitGroup
		sloth     = WN{Cluster: "local", Name: "sloth"}
		snail     = WN{Cluster: "local", Name: "snail"}
		health, _ = cell.NewSimpleHealth()
	)

	db, networks, actnets, attachs, _, srv := fixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); wg.Wait() }()

	// Configure the initial state.
	wtx := db.WriteTxn(networks, actnets, attachs)
	networks.Insert(wtx, PN{Name: "blue"})
	networks.Insert(wtx, PN{Name: "green"})
	networks.Insert(wtx, PN{Name: "yellow"})
	networks.Insert(wtx, PN{Name: "purple"})

	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.blue", Index: 10}, Network: "blue", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.green", Index: 11}, Network: "green", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.yellow", Index: 12}, Network: "yellow", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.purple", Index: 0}, Network: "purple", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})

	actnets.Insert(wtx, AN{Node: snail, Network: "blue"})
	actnets.Insert(wtx, AN{Node: sloth, Network: "green"})
	actnets.Insert(wtx, AN{Node: snail, Network: "green"})
	actnets.Insert(wtx, AN{Node: snail, Network: "yellow"})
	actnets.Insert(wtx, AN{Node: snail, Network: "purple"})
	actnets.Insert(wtx, AN{Node: sloth, Network: "purple"})

	// Simulate the case in which the corresponding network (or node attachment)
	// got deleted before that the GC logic started; the stale entry should be
	// eventually removed.
	actnets.Insert(wtx, AN{Node: snail, Network: "brown"})
	wtx.Commit()

	wg.Go(func() { srv.gcLoop(ctx, health) })

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, statedb.Collect(actnets.All(db.ReadTxn())), []AN{
			{Node: snail, Network: "blue"},
			{Node: sloth, Network: "green"},
			{Node: snail, Network: "green"},
			{Node: snail, Network: "yellow"},
		})
	}, timeout, interval)

	// Delete one of the networks, the corresponding entries should be removed.
	wtx = db.WriteTxn(networks)
	networks.Delete(wtx, PN{Name: "green"})
	wtx.Commit()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, statedb.Collect(actnets.All(db.ReadTxn())), []AN{
			{Node: snail, Network: "blue"},
			{Node: snail, Network: "yellow"},
		})
	}, timeout, interval)

	// One of the networks is no longer served, the corresponding entries should be removed.
	wtx = db.WriteTxn(attachs)
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.blue", Index: 0}, Network: "blue", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	wtx.Commit()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, statedb.Collect(actnets.All(db.ReadTxn())), []AN{
			{Node: snail, Network: "yellow"},
		})
	}, timeout, interval)

	// One of the networks is no longer served, as its attachment targets a different network,
	// the corresponding entries should be removed.
	wtx = db.WriteTxn(attachs)
	attachs.Insert(wtx, &NA{Interface: NAI{Name: "eth.yellow", Index: 12}, Network: "other", NodeSelector: TestValidNASelector, Conflict: tables.AttachmentConflictNone})
	wtx.Commit()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Empty(c, statedb.Collect(actnets.All(db.ReadTxn())))
	}, timeout, interval)
}

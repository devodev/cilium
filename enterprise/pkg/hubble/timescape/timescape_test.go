// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package timescape

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	rpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/timestamppb"

	tsv1alphapb "github.com/isovalent/hubble-timescape/api/timescape/v1alpha"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

func TestExporterRunReturnsOnCancelWithBufferedFlows(t *testing.T) {
	backoff := newSignalingBackoff()
	t.Cleanup(backoff.unblock)

	// Start and immediately stop a server so the exporter uses a predictable
	// target that will refuse connections while flows remain buffered.
	target, closeReservedServer := startIngesterServer(t, &testIngesterService{}, "127.0.0.1:0")
	require.NoError(t, closeReservedServer())

	exporter := newTestExporter(
		t,
		target,
		WithBackoff(backoff),
		WithMaxBufferSize(4),
	)

	cancel, errCh := runExporter(t, exporter)

	// Wait until the exporter is blocked in reconnect backoff before queuing
	// flows through the public Export API.
	require.Equal(t, 1, requireReceive(t, backoff.called, "exporter never entered retry backoff"))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	// Before the drain fix, canceling here would hang in Run after consuming the
	// buffered flows because the exporter never closes its buffer channel.
	cancel()
	backoff.unblock()

	requireRunResult(t, errCh, context.Canceled)
	require.Empty(t, exporter.buffer)
}

func TestExporterDropsFlowsWhenBufferFull(t *testing.T) {
	exporter := newTestExporter(
		t,
		"passthrough:///unused",
		WithMaxBufferSize(1),
	)

	// Fill the single-slot buffer, then verify the next export is dropped
	// instead of blocking the caller.
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	require.Len(t, exporter.buffer, 1)
	require.EqualValues(t, 1, exporter.droppedFlows.Load())
}

func TestExporterReconnectsAndResetsRetriesAfterSuccessfulSend(t *testing.T) {
	backoff := newSignalingBackoff()
	t.Cleanup(backoff.unblock)

	// Start and immediately stop a server so the exporter's first connection
	// attempt fails with connection refused on a predictable target.
	target, closeReservedServer := startIngesterServer(t, &testIngesterService{}, "127.0.0.1:0")
	require.NoError(t, closeReservedServer())

	started := make(chan struct{})
	service := newStartedBatchIngester(started)

	exporter := newTestExporter(
		t,
		target,
		WithBackoff(backoff),
		WithBatchSize(1),
		WithBatchFlushInterval(time.Hour),
	)

	cancel, errCh := runExporter(t, exporter)

	// Wait until the exporter has observed the failed dial and entered its retry
	// backoff path before starting the server.
	require.Equal(t, 1, requireReceive(t, backoff.called, "exporter never entered retry backoff"))

	// Bring the ingester up on the same target and release the blocked backoff so
	// the next connection attempt can succeed.
	startedTarget, _ := startIngesterServer(t, service, target)
	require.Equal(t, target, startedTarget)
	backoff.unblock()

	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))
	requireClosed(t, started, "exporter never reconnected")

	// The successful sends on the reconnected stream should reset the retry
	// counter back to zero.
	require.Eventually(t, func() bool {
		return batchNodeNamesEqual(service.batchNodeNames(), [][]string{
			{"flow-1"},
			{"flow-2"},
		})
	}, time.Second, 10*time.Millisecond)

	cancel()
	requireRunResult(t, errCh, context.Canceled)
	require.Zero(t, exporter.connectRetries)
}

func TestExporterFlushesBatchesBySize(t *testing.T) {
	started := make(chan struct{})
	service := newStartedBatchIngester(started)
	target, _ := startIngesterServer(t, service, "127.0.0.1:0")

	exporter := newTestExporter(
		t,
		target,
		WithBatchSize(2),
		WithBatchFlushInterval(time.Hour),
	)

	cancel, errCh := runExporter(t, exporter)
	requireClosed(t, started, "exporter never opened the batch stream")

	// Queue five flows. The first four should flush as two full batches, while
	// the fifth stays buffered until shutdown.
	for i := range 5 {
		require.NoError(t, exporter.Export(t.Context(), newFlowEvent(i+1)))
	}

	require.Eventually(t, func() bool {
		return batchNodeNamesEqual(service.batchNodeNames(), [][]string{
			{"flow-1", "flow-2"},
			{"flow-3", "flow-4"},
		})
	}, time.Second, 10*time.Millisecond)

	cancel()
	requireRunResult(t, errCh, context.Canceled)
	require.Eventually(t, func() bool {
		return batchNodeNamesEqual(service.batchNodeNames(), [][]string{
			{"flow-1", "flow-2"},
			{"flow-3", "flow-4"},
			{"flow-5"},
		})
	}, time.Second, 10*time.Millisecond)
}

func TestExporterFlushesPartialBatchByTimer(t *testing.T) {
	const flushInterval = time.Second

	started := make(chan struct{})
	service := newStartedBatchIngester(started)
	service.batchReceived = make(chan struct{}, 1)
	target, _ := startIngesterServer(t, service, "127.0.0.1:0")
	clock := clockwork.NewFakeClock()

	exporter := newTestExporter(
		t,
		target,
		WithBatchSize(8),
		WithBatchFlushInterval(flushInterval),
		withTestClock(clock),
	)

	cancel, errCh := runExporter(t, exporter)
	requireClosed(t, started, "exporter never opened the batch stream")

	// Queue a partial batch and confirm nothing has been sent before the flush
	// timer is advanced.
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	require.Empty(t, service.batchNodeNames())
	require.NoError(t, clock.BlockUntilContext(t.Context(), 1))
	clock.Advance(flushInterval)

	// After the fake clock advances, the batch should flush without needing a
	// size threshold or shutdown.
	requireReceive(t, service.batchReceived, "server never received the timer-flushed batch")
	require.True(t, batchNodeNamesEqual(service.batchNodeNames(), [][]string{
		{"flow-1", "flow-2"},
	}))

	cancel()
	requireRunResult(t, errCh, context.Canceled)
}

func TestExporterReturnsFailedBatchForRetryAndResendsItFirst(t *testing.T) {
	exporter := newTestExporter(
		t,
		"passthrough:///unused",
		WithBatchSize(2),
		WithBatchFlushInterval(time.Hour),
	)

	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	// Drive the send loop with a stream that fails the batch send. The exporter
	// should keep that batch for retry.
	firstStream := &fakeBatchStream{
		ctx:     t.Context(),
		sendErr: errors.New("send failed"),
	}
	err := exporter.sendLoop(t.Context(), firstStream)
	require.ErrorContains(t, err, "failed to send flow batch to stream")
	require.Equal(t, []string{"flow-1", "flow-2"}, flowNodeNames(exporter.retryBatch))

	exporter.connectRetries = 2
	shutdownCtx, cancel := context.WithCancel(t.Context())
	cancel()

	// Run the loop again with a canceled context. It should send the saved retry
	// batch first, then observe shutdown and return.
	secondStream := &fakeBatchStream{ctx: t.Context()}
	err = exporter.sendLoop(shutdownCtx, secondStream)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, exporter.retryBatch)
	require.Zero(t, exporter.connectRetries)
	require.True(t, batchNodeNamesEqual(secondStream.sentBatchNodeNames(), [][]string{
		{"flow-1", "flow-2"},
	}))
}

func TestExporterFlushesPartialBatchOnShutdown(t *testing.T) {
	started := make(chan struct{})
	service := newStartedBatchIngester(started)
	target, _ := startIngesterServer(t, service, "127.0.0.1:0")

	exporter := newTestExporter(
		t,
		target,
		WithBatchSize(8),
		WithBatchFlushInterval(time.Hour),
	)

	cancel, errCh := runExporter(t, exporter)
	requireClosed(t, started, "exporter never opened the batch stream")

	// Queue a partial batch, then cancel the exporter. Shutdown should flush the
	// remaining buffered flows before the stream closes.
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	cancel()
	requireRunResult(t, errCh, context.Canceled)
	require.Eventually(t, func() bool {
		return batchNodeNamesEqual(service.batchNodeNames(), [][]string{
			{"flow-1", "flow-2"},
		})
	}, time.Second, 10*time.Millisecond)
}

func TestExporterAutoModeFallsBackToSingleIngestWhenBatchMethodIsMissing(t *testing.T) {
	started := make(chan struct{})
	service := newStartedSingleIngester(started)
	target, _ := startLegacyIngesterServer(t, service, "127.0.0.1:0")

	exporter := newTestExporter(
		t,
		target,
		WithBatchSize(2),
		WithBatchFlushInterval(time.Hour),
	)

	cancel, errCh := runExporter(t, exporter)

	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))
	requireClosed(t, started, "exporter never fell back to the single-flow stream")

	require.Eventually(t, func() bool {
		return slices.Equal(service.singleNodeNames(), []string{"flow-1", "flow-2"})
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, 0, service.getBatchStreamCount())
	require.Equal(t, 1, service.getSingleStreamCount())
	require.Equal(t, ingestModeSingle, exporter.options.ingestMode)
	require.Zero(t, exporter.connectRetries)

	cancel()
	requireRunResult(t, errCh, context.Canceled)
}

func TestExporterSingleModeUsesSingleIngestOnly(t *testing.T) {
	started := make(chan struct{})
	service := newStartedSingleIngester(started)
	service.onIngestBatch = func(_ int, _ grpc.ClientStreamingServer[tsv1alphapb.IngestBatchRequest, tsv1alphapb.IngestBatchResponse]) error {
		return errors.New("single mode should not open IngestBatch")
	}
	target, _ := startIngesterServer(t, service, "127.0.0.1:0")

	exporter := newTestExporter(
		t,
		target,
		WithIngestMode("single"),
		WithBatchSize(8),
		WithBatchFlushInterval(time.Hour),
	)

	cancel, errCh := runExporter(t, exporter)
	requireClosed(t, started, "exporter never opened the single-flow stream")

	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.Eventually(t, func() bool {
		return slices.Equal(service.singleNodeNames(), []string{"flow-1"})
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, 0, service.getBatchStreamCount())
	require.Equal(t, 1, service.getSingleStreamCount())

	cancel()
	requireRunResult(t, errCh, context.Canceled)
}

func TestExporterBatchModeUsesBatchIngestOnly(t *testing.T) {
	started := make(chan struct{})
	service := newStartedBatchIngester(started)
	target, _ := startIngesterServer(t, service, "127.0.0.1:0")

	exporter := newTestExporter(
		t,
		target,
		WithIngestMode("batch"),
		WithBatchSize(2),
		WithBatchFlushInterval(time.Hour),
	)

	cancel, errCh := runExporter(t, exporter)
	requireClosed(t, started, "exporter never opened the batch stream")

	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	require.Eventually(t, func() bool {
		return batchNodeNamesEqual(service.batchNodeNames(), [][]string{
			{"flow-1", "flow-2"},
		})
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, 1, service.getBatchStreamCount())
	require.Empty(t, service.singleNodeNames())
	require.Equal(t, ingestModeBatch, exporter.options.ingestMode)
	require.Nil(t, exporter.retryBatch)

	cancel()
	requireRunResult(t, errCh, context.Canceled)
}

func TestNewExporterValidatesIngestMode(t *testing.T) {
	for _, mode := range []string{"auto", "batch", "single"} {
		_, err := NewExporter(hivetest.Logger(t), "passthrough:///unused", WithIngestMode(mode))
		require.NoError(t, err)
	}

	_, err := NewExporter(hivetest.Logger(t), "passthrough:///unused", WithIngestMode("legacy"))
	require.ErrorContains(t, err, "invalid ingest mode")
}

type testIngesterService struct {
	tsv1alphapb.UnimplementedIngesterServiceServer

	mu                 lock.Mutex
	batchStreamCount   int
	singleStreamCount  int
	receivedBatches    [][]*flowpb.Flow
	receivedSingle     []*flowpb.Flow
	batchReceived      chan struct{}
	singleFlowReceived chan struct{}

	onIngest      func(int, grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error
	onIngestBatch func(int, grpc.ClientStreamingServer[tsv1alphapb.IngestBatchRequest, tsv1alphapb.IngestBatchResponse]) error
}

func newStartedBatchIngester(started chan struct{}) *testIngesterService {
	service := &testIngesterService{}
	var once sync.Once
	service.onIngestBatch = func(_ int, stream grpc.ClientStreamingServer[tsv1alphapb.IngestBatchRequest, tsv1alphapb.IngestBatchResponse]) error {
		once.Do(func() { close(started) })
		return service.receiveAllBatches(stream)
	}
	return service
}

func newStartedSingleIngester(started chan struct{}) *testIngesterService {
	service := &testIngesterService{}
	var once sync.Once
	service.onIngest = func(_ int, stream grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error {
		once.Do(func() { close(started) })
		return service.receiveAllSingle(stream)
	}
	return service
}

func (s *testIngesterService) Ingest(stream grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error {
	s.mu.Lock()
	s.singleStreamCount++
	streamNum := s.singleStreamCount
	s.mu.Unlock()

	if s.onIngest != nil {
		return s.onIngest(streamNum, stream)
	}

	return s.receiveAllSingle(stream)
}

func (s *testIngesterService) IngestBatch(stream grpc.ClientStreamingServer[tsv1alphapb.IngestBatchRequest, tsv1alphapb.IngestBatchResponse]) error {
	s.mu.Lock()
	s.batchStreamCount++
	streamNum := s.batchStreamCount
	s.mu.Unlock()

	if s.onIngestBatch != nil {
		return s.onIngestBatch(streamNum, stream)
	}

	return s.receiveAllBatches(stream)
}

func (s *testIngesterService) receiveAllSingle(stream grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&tsv1alphapb.IngestResponse{})
		}
		if err != nil {
			return err
		}
		if flow := req.GetFlow(); flow != nil {
			s.recordSingle(flow)
		}
	}
}

func (s *testIngesterService) receiveAllBatches(stream grpc.ClientStreamingServer[tsv1alphapb.IngestBatchRequest, tsv1alphapb.IngestBatchResponse]) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&tsv1alphapb.IngestBatchResponse{})
		}
		if err != nil {
			return err
		}
		if batch := req.GetFlowBatch(); batch != nil {
			s.recordBatch(batch.GetFlows())
		}
	}
}

func (s *testIngesterService) recordSingle(flow *flowpb.Flow) {
	s.mu.Lock()
	s.receivedSingle = append(s.receivedSingle, flow)
	singleFlowReceived := s.singleFlowReceived
	s.mu.Unlock()

	if singleFlowReceived != nil {
		select {
		case singleFlowReceived <- struct{}{}:
		default:
		}
	}
}

func (s *testIngesterService) recordBatch(flows []*flowpb.Flow) {
	copiedFlows := slices.Clone(flows)

	s.mu.Lock()
	s.receivedBatches = append(s.receivedBatches, copiedFlows)
	batchReceived := s.batchReceived
	s.mu.Unlock()

	if batchReceived != nil {
		select {
		case batchReceived <- struct{}{}:
		default:
		}
	}
}

func (s *testIngesterService) singleNodeNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	names := make([]string, 0, len(s.receivedSingle))
	for _, flow := range s.receivedSingle {
		names = append(names, flow.GetNodeName())
	}
	return names
}

func (s *testIngesterService) batchNodeNames() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	names := make([][]string, 0, len(s.receivedBatches))
	for _, batch := range s.receivedBatches {
		batchNames := make([]string, 0, len(batch))
		for _, flow := range batch {
			batchNames = append(batchNames, flow.GetNodeName())
		}
		names = append(names, batchNames)
	}
	return names
}

func (s *testIngesterService) getBatchStreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.batchStreamCount
}

func (s *testIngesterService) getSingleStreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.singleStreamCount
}

func startIngesterServer(t *testing.T, service *testIngesterService, target string) (string, func() error) {
	t.Helper()

	listener, err := net.Listen("tcp", target)
	require.NoError(t, err)

	server := grpc.NewServer()
	tsv1alphapb.RegisterIngesterServiceServer(server, service)
	reflection.Register(server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	var (
		closeOnce sync.Once
		closeErr  error
	)
	closeServer := func() error {
		closeOnce.Do(func() {
			server.Stop()
			_ = listener.Close()
			if err := <-errCh; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				closeErr = err
			}
		})
		return closeErr
	}
	t.Cleanup(func() {
		if err := closeServer(); err != nil {
			t.Errorf("ingester server exited with error: %v", err)
		}
	})

	return listener.Addr().String(), closeServer
}

// legacyIngesterServiceServer is a copy of the generated gRPC server interface for the
// IngesterService without the IngestBatch method. This allows testing the exporter's fallback to
// single ingest when the batch method is missing from the server.
type legacyIngesterServiceServer interface {
	Ingest(grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error
}

func registerLegacyIngesterServiceServer(s grpc.ServiceRegistrar, srv legacyIngesterServiceServer) {
	ingestHandler := func(srv any, stream grpc.ServerStream) error {
		return srv.(legacyIngesterServiceServer).Ingest(&grpc.GenericServerStream[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]{ServerStream: stream})
	}
	var legacyIngesterServiceDesc = grpc.ServiceDesc{
		ServiceName: "timescape.v1alpha.IngesterService",
		HandlerType: (*legacyIngesterServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Ingest",
				Handler:       ingestHandler,
				ClientStreams: true,
			},
		},
		Metadata: "timescape/v1alpha/ingester.proto",
	}
	s.RegisterService(&legacyIngesterServiceDesc, srv)
}

func registerLegacyIngesterReflection(t *testing.T, server *grpc.Server) {
	t.Helper()

	fileProto := protodesc.ToFileDescriptorProto(tsv1alphapb.File_timescape_v1alpha_ingester_proto)
	removedIngestBatch := false
	for _, service := range fileProto.GetService() {
		if service.GetName() != "IngesterService" {
			continue
		}
		methods := service.Method[:0]
		for _, method := range service.GetMethod() {
			if method.GetName() == ingestBatchMethodName {
				removedIngestBatch = true
				continue
			}
			methods = append(methods, method)
		}
		service.Method = methods
	}
	require.True(t, removedIngestBatch, "test descriptor did not include IngestBatch")

	file, err := protodesc.NewFile(fileProto, protoregistry.GlobalFiles)
	require.NoError(t, err)

	files := new(protoregistry.Files)
	require.NoError(t, files.RegisterFile(file))

	rpb.RegisterServerReflectionServer(server, reflection.NewServerV1(reflection.ServerOptions{
		Services:           server,
		DescriptorResolver: files,
	}))
}

func startLegacyIngesterServer(t *testing.T, service legacyIngesterServiceServer, target string) (string, func() error) {
	t.Helper()

	listener, err := net.Listen("tcp", target)
	require.NoError(t, err)

	server := grpc.NewServer()
	registerLegacyIngesterServiceServer(server, service)
	registerLegacyIngesterReflection(t, server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	var (
		closeOnce sync.Once
		closeErr  error
	)
	closeServer := func() error {
		closeOnce.Do(func() {
			server.Stop()
			_ = listener.Close()
			if err := <-errCh; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				closeErr = err
			}
		})
		return closeErr
	}
	t.Cleanup(func() {
		if err := closeServer(); err != nil {
			t.Errorf("legacy ingester server exited with error: %v", err)
		}
	})

	return listener.Addr().String(), closeServer
}

type fakeBatchStream struct {
	ingestBatchStream
	ctx         context.Context
	sendErr     error
	sentBatches [][]*flowpb.Flow
}

func (s *fakeBatchStream) Send(req *tsv1alphapb.IngestBatchRequest) error {
	if batch := req.GetFlowBatch(); batch != nil {
		s.sentBatches = append(s.sentBatches, append([]*flowpb.Flow(nil), batch.GetFlows()...))
	}
	return s.sendErr
}

func (s *fakeBatchStream) CloseAndRecv() (*tsv1alphapb.IngestBatchResponse, error) {
	return &tsv1alphapb.IngestBatchResponse{}, nil
}

func (s *fakeBatchStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *fakeBatchStream) sentBatchNodeNames() [][]string {
	names := make([][]string, 0, len(s.sentBatches))
	for _, batch := range s.sentBatches {
		names = append(names, flowNodeNames(batch))
	}
	return names
}

func newTestExporter(t *testing.T, target string, opts ...Option) *Exporter {
	t.Helper()

	baseOpts := []Option{
		WithReportDroppedFlowsInterval(0),
	}

	exporter, err := NewExporter(
		hivetest.Logger(t),
		target,
		append(baseOpts, opts...)...,
	)
	require.NoError(t, err)

	return exporter
}

func runExporter(t *testing.T, exporter *Exporter) (context.CancelFunc, <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- exporter.Run(ctx)
	}()
	return cancel, errCh
}

type signalingBackoff struct {
	called      chan int
	release     chan struct{}
	releaseOnce sync.Once
}

func newSignalingBackoff() *signalingBackoff {
	return &signalingBackoff{
		called:  make(chan int, 1),
		release: make(chan struct{}),
	}
}

func (b *signalingBackoff) Duration(attempt int) time.Duration {
	select {
	case b.called <- attempt:
	default:
	}

	<-b.release
	return 0
}

func (b *signalingBackoff) unblock() {
	b.releaseOnce.Do(func() {
		close(b.release)
	})
}

func requireClosed(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
	}
}

func requireRunResult(t *testing.T, errCh <-chan error, want error) {
	t.Helper()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, want)
	case <-time.After(2 * time.Second):
		t.Fatalf("exporter did not stop within timeout, want %v", want)
	}
}

func requireReceive[T any](t *testing.T, ch <-chan T, msg string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
	}

	var zero T
	return zero
}

func batchNodeNamesEqual(got, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if !slices.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

func flowNodeNames(flows []*flowpb.Flow) []string {
	names := make([]string, 0, len(flows))
	for _, flow := range flows {
		names = append(names, flow.GetNodeName())
	}
	return names
}

func newFlowEvent(id int) *v1.Event {
	return &v1.Event{
		Event: &flowpb.Flow{
			NodeName: fmt.Sprintf("flow-%d", id),
			Time:     timestamppb.New(time.Unix(int64(id), 0)),
		},
	}
}

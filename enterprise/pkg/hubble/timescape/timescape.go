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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	rpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	tsv1alphapb "github.com/isovalent/hubble-timescape/api/timescape/v1alpha"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/dial"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var _ exporter.FlowLogExporter = (*Exporter)(nil)

// shutdownFlushTimeout is the duration that the exporter will wait for flushing flows to the stream
// after the main context is canceled and before forcefully closing the stream context.
const shutdownFlushTimeout = 2 * time.Second

type ingestBatchStream = grpc.ClientStreamingClient[tsv1alphapb.IngestBatchRequest, tsv1alphapb.IngestBatchResponse]
type ingestSingleStream = grpc.ClientStreamingClient[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]

const ingestBatchMethodName = "IngestBatch"

// OnExportEvent is a hook that can be registered on a timescape exporter and is invoked for each
// event.
//
// Returning false will stop the export pipeline for the current event, meaning the default export
// logic as well as the following hooks will not run.
type OnExportEvent interface {
	OnExportEvent(ctx context.Context, ev *v1.Event) (stop bool, err error)
}

// OnExportEventFunc implements OnExportEvent for a single function.
type OnExportEventFunc func(ctx context.Context, ev *v1.Event) (stop bool, err error)

// OnExportEvent implements OnExportEvent.
func (f OnExportEventFunc) OnExportEvent(ctx context.Context, ev *v1.Event) (bool, error) {
	return f(ctx, ev)
}

// Exporter is a Hubble FlowLogExporter that exports flow logs via gRPC to a remote Timescape server
// supporting the IngesterService.
type Exporter struct {
	log     *slog.Logger
	target  string
	options options

	// This channel is closed when Run returns and is used to signal the Exporter to stop processing
	// events from the Export method.
	stopped chan struct{}

	// tlsConfigBuilder is obtained from resolving options.tlsConfigPromise in Run().
	tlsConfigBuilder certloader.ClientConfigBuilder

	// NOTE: buffer is never closed to avoid possible panic trying to write to a closed channel
	// from the Export method, which is part of our API and can be called concurrently with Run.
	buffer         chan *flowpb.Flow
	retryBatch     []*flowpb.Flow
	connectRetries int

	droppedFlows atomic.Uint64
}

// NewExporter creates a new Exporter with the provided options. You must call Run to start the
// exporter, which will establish a connection to the remote server and begin exporting flow logs.
// The exporter will retry on connection failures using the configured backoff strategy.
func NewExporter(log *slog.Logger, target string, opts ...Option) (*Exporter, error) {
	if target == "" {
		return nil, errors.New("target is empty")
	}

	options := options{
		clock:                      realTimerClock{},
		ingestMode:                 ingestModeAuto,
		batchSize:                  256,
		batchFlushInterval:         250 * time.Millisecond,
		backoff:                    exponentialBackoff(),
		maxBufferSize:              4096, // Use a similar value as the observer ring buffer size
		reportDroppedFlowsInterval: 1 * time.Minute,
	}
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	scopedLog := log.With(
		logfields.LogSubsys, "hubble-timescape-exporter",
		logfields.Target, target,
	)
	return &Exporter{
		log:     scopedLog,
		target:  target,
		options: options,
		stopped: make(chan struct{}),
		buffer:  make(chan *flowpb.Flow, options.maxBufferSize),
	}, nil
}

// Export implements exporter.FlowLogExporter.
func (s *Exporter) Export(ctx context.Context, ev *v1.Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopped:
		return nil
	default:
	}

	// Filter the event using the configured allow and deny filters.
	if !filters.Apply(s.options.allowFilters, s.options.denyFilters, ev) {
		return nil
	}

	// Process OnExportEvent hooks.
	for _, f := range s.options.onExportEvent {
		stop, err := f.OnExportEvent(ctx, ev)
		if err != nil {
			s.log.Warn("OnExportEvent hook failed", logfields.Error, err)
		}
		if stop {
			return nil
		}
	}

	// Process the event based on its type.
	switch event := ev.Event.(type) {
	case *flowpb.Flow:
		if s.options.fieldMask.Active() {
			s.options.fieldMask.Copy(s.options.fieldMaskFlow.ProtoReflect(), event.ProtoReflect())
			event = s.options.fieldMaskFlow
		}
		if s.options.nodeName != "" {
			event.NodeName = s.options.nodeName
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopped:
			return nil
		case s.buffer <- event:
		default:
			// buffer is full, drop the flow.
			s.droppedFlows.Add(1)
		}
	}

	return nil
}

// Stop implements exporter.FlowLogExporter.
//
// This is a no-op, as the Run method is responsible for handling stopping the exporter when its
// context is canceled.
func (s *Exporter) Stop() error {
	return nil
}

// Run establishes a connection to the remote server and starts exporting flow logs. On failure to
// connect, it retries using the configured backoff strategy. The method blocks until the context is
// canceled.
//
// When the context is canceled, the exporter will stop processing events from the Export method and
// will close any open connections.
func (s *Exporter) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Go(func() {
		<-ctx.Done()
		s.log.Debug("context canceled, stopping timescape exporter")
		close(s.stopped)
	})

	if s.options.reportDroppedFlowsInterval > 0 {
		wg.Go(func() {
			log := s.log.With(logfields.Duration, s.options.reportDroppedFlowsInterval)
			log.Debug("starting dropped flows reporting")
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(s.options.reportDroppedFlowsInterval):
					if count := s.droppedFlows.Swap(0); count > 0 {
						log.Warn("dropped flows in the last period",
							logfields.Count, count,
							logfields.Reason, "buffer full",
						)
					}
				}
			}
		})
	}

	err := s.run(ctx)
	cancel()
	wg.Wait()
	s.drainBuffer()
	return err
}

// drainBuffer is a best effort attempt to clear any remaining flows from the buffer channel when
// the exporter is stopped. There is no guarantee that all flows will be drained, as new flows may
// be added to the buffer by an ongoing Export call.
func (s *Exporter) drainBuffer() {
	for {
		select {
		case <-s.buffer:
		default:
			return
		}
	}
}

// run is the main loop of the exporter that manages the connection to the remote server and handles
// streaming flow logs.
func (s *Exporter) run(ctx context.Context) error {
	if s.options.tlsConfigPromise != nil {
		tlsConfigBuilder, err := s.options.tlsConfigPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to get TLS config: %w", err)
		}
		s.tlsConfigBuilder = tlsConfigBuilder
	}

	for {
		s.log.Info("start streaming flow logs")
		err := s.connectAndStream(ctx)
		if err == nil {
			continue
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		s.log.Error("failed to stream flow logs", logfields.Error, err)
		s.connectRetries++
		backoffDuration := s.options.backoff.Duration(s.connectRetries)
		s.log.Info("retrying export after backoff",
			logfields.Duration, backoffDuration,
			logfields.Retries, s.connectRetries,
		)
		select {
		case <-time.After(backoffDuration):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// connectAndStream establishes a gRPC stream to the remote server and sends flows from the buffer.
func (s *Exporter) connectAndStream(ctx context.Context) error {
	s.log.Debug("creating grpc client")
	client, err := s.buildClient()
	if err != nil {
		return fmt.Errorf("failed to build client: %w", err)
	}
	defer func() {
		s.log.Debug("closing grpc client")
		if err := client.Close(); err != nil {
			s.log.Error("failed to close connection", logfields.Error, err)
		}
	}()

	err = func() error {
		switch s.options.ingestMode {
		case ingestModeAuto:
			// In auto mode, check whether server reflection reports the IngestBatch RPC. If
			// the RPC is absent, fall back to the single-flow Ingest RPC.
			supportsIngestBatch, err := checkIngestBatchSupport(ctx, s.log, client)
			if err != nil {
				return err
			}
			if !supportsIngestBatch {
				s.log.Info("Timescape IngestBatch RPC is unavailable, falling back to single-flow Ingest RPC")
				s.options.ingestMode = ingestModeSingle
				return s.connectAndStreamSingle(ctx, client)
			}
			return s.connectAndStreamBatch(ctx, client)
		case ingestModeBatch:
			return s.connectAndStreamBatch(ctx, client)
		case ingestModeSingle:
			return s.connectAndStreamSingle(ctx, client)
		default:
			return fmt.Errorf("invalid ingest mode: %q", s.options.ingestMode)
		}
	}()
	if ctx.Err() != nil {
		// Prefer the shutdown cause over transport/send errors that may race with context
		// cancellation, so run exits cleanly instead of treating shutdown as a stream failure
		// to retry.
		return ctx.Err()
	}
	return err
}

// connectAndStreamBatch establishes an IngestBatch gRPC stream to the remote server and sends flow
// batches from the buffer.
func (s *Exporter) connectAndStreamBatch(ctx context.Context, client *grpc.ClientConn) error {
	// create a new context scoped to the stream that will be canceled after a
	// grace period when the main context is canceled. This allows us to attempt
	// to flush any remaining flows to the stream before forcefully closing it.
	streamCtx, cancel := newGracefulStreamContext(ctx, shutdownFlushTimeout)
	defer cancel()

	s.log.Debug("opening stream", logfields.Service, tsv1alphapb.IngesterService_IngestBatch_FullMethodName)
	stream, err := tsv1alphapb.NewIngesterServiceClient(client).IngestBatch(streamCtx)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	s.log.Debug("stream opened, writing flow batches from buffer to stream")
	err = s.sendLoop(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to stream batched flows: %w", err)
	}

	return nil
}

// connectAndStreamSingle establishes a legacy Ingest gRPC stream to the remote server and sends
// flows one at a time from the buffer.
func (s *Exporter) connectAndStreamSingle(ctx context.Context, client *grpc.ClientConn) error {
	// create a new context scoped to the stream that will be canceled after a
	// grace period when the main context is canceled. This allows us to attempt
	// to flush any remaining flows to the stream before forcefully closing it.
	streamCtx, cancel := newGracefulStreamContext(ctx, shutdownFlushTimeout)
	defer cancel()

	s.log.Debug("opening stream", logfields.Service, tsv1alphapb.IngesterService_Ingest_FullMethodName)
	stream, err := tsv1alphapb.NewIngesterServiceClient(client).Ingest(streamCtx)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	s.log.Debug("stream opened, writing flows from buffer to stream")
	err = s.sendLoopSingle(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to stream single flows: %w", err)
	}

	return nil
}

// sendLoop reads flow batches from the buffer and sends them to the stream until the context is
// canceled. When the context is canceled, it attempts to flush any remaining flows to the stream
// before returning.
func (s *Exporter) sendLoop(ctx context.Context, stream ingestBatchStream) error {
	batcher := newFlowBatcher(s.options.clock, s.options.batchSize, s.options.batchFlushInterval)
	defer batcher.Stop()

	// Send any flows that failed to send in the previous attempt before
	// processing new flows from the buffer.
	if err := s.sendBatch(stream, s.retryBatch); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			if err := s.flushOnShutdown(stream, batcher); err != nil {
				s.log.Warn("failed to flush on shutdown", logfields.Error, err)
			}
			s.log.Debug("shutdown requested, closing the stream and waiting for the server response")
			if _, err := stream.CloseAndRecv(); err != nil {
				s.log.Warn("failed to close stream", logfields.Error, err)
			}
			return ctx.Err()
		case flow := <-s.buffer:
			if err := s.sendBatch(stream, batcher.Add(flow)); err != nil {
				return err
			}
		case <-batcher.FlushC():
			// Flush the current batch when the flush timer expires.
			// NOTE: This branch is disabled when the batcher is empty.
			if err := s.sendBatch(stream, batcher.Take()); err != nil {
				return err
			}
		}
	}
}

// sendLoopSingle reads flows from the buffer and sends them to the stream until the context is
// canceled. When the context is canceled, it attempts to flush any remaining flows to the stream
// before returning.
func (s *Exporter) sendLoopSingle(ctx context.Context, stream ingestSingleStream) error {
	// Send any flows that failed to send in the previous attempt before
	// processing new flows from the buffer.
	if err := s.sendBatchSingle(stream, s.retryBatch); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			if err := s.flushOnShutdownSingle(stream); err != nil {
				s.log.Warn("failed to flush on shutdown", logfields.Error, err)
			}
			s.log.Debug("shutdown requested, closing the stream and waiting for the server response")
			if _, err := stream.CloseAndRecv(); err != nil {
				s.log.Warn("failed to close stream", logfields.Error, err)
			}
			return ctx.Err()
		case flow := <-s.buffer:
			if err := s.sendBatchSingle(stream, []*flowpb.Flow{flow}); err != nil {
				return err
			}
		}
	}
}

// flushOnShutdown attempts to flush any remaining flows from the buffer to the stream.
func (s *Exporter) flushOnShutdown(stream ingestBatchStream, batcher *flowBatcher) error {
	for {
		select {
		case flow := <-s.buffer:
			if err := s.sendBatch(stream, batcher.Add(flow)); err != nil {
				return fmt.Errorf("flushing batched flows: %w", err)
			}
		default:
			if err := s.sendBatch(stream, batcher.Take()); err != nil {
				return fmt.Errorf("flushing batched flows: %w", err)
			}
			return nil
		}
	}
}

// flushOnShutdownSingle attempts to flush any remaining flows from the buffer to the stream.
func (s *Exporter) flushOnShutdownSingle(stream ingestSingleStream) error {
	for {
		select {
		case flow := <-s.buffer:
			if err := s.sendBatchSingle(stream, []*flowpb.Flow{flow}); err != nil {
				return fmt.Errorf("flushing single flow: %w", err)
			}
		default:
			return nil
		}
	}
}

// sendBatch sends a batch of flows to the stream. If the batch is empty, it is a no-op.
func (s *Exporter) sendBatch(stream ingestBatchStream, batch []*flowpb.Flow) error {
	if len(batch) == 0 {
		return nil
	}

	err := stream.Send(&tsv1alphapb.IngestBatchRequest{
		Data: &tsv1alphapb.IngestBatchRequest_FlowBatch{
			FlowBatch: &tsv1alphapb.FlowBatch{Flows: batch},
		},
	})
	if err != nil {
		// If sending the batch fails, we save it to retry on the next
		// successful connection.
		s.retryBatch = batch
		return fmt.Errorf("failed to send flow batch to stream: %w", err)
	}

	// Reset the batch now that it has been successfully sent.
	s.retryBatch = nil
	// Reset the connect retries counter now that we know the stream is open and working.
	s.connectRetries = 0
	return nil
}

// sendBatchSingle sends a batch of flows to the legacy Ingest stream one flow at a time.
func (s *Exporter) sendBatchSingle(stream ingestSingleStream, batch []*flowpb.Flow) error {
	if len(batch) == 0 {
		return nil
	}

	for i, flow := range batch {
		err := stream.Send(&tsv1alphapb.IngestRequest{
			Data: &tsv1alphapb.IngestRequest_Flow{Flow: flow},
		})
		if err != nil {
			s.retryBatch = batch[i:]
			return fmt.Errorf("failed to send flow to stream: %w", err)
		}
		s.connectRetries = 0
	}

	s.retryBatch = nil
	return nil
}

// buildClient creates a gRPC client connection to the target server using the configured options.
func (s *Exporter) buildClient() (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	opts = append(opts, s.options.dialOptions...)
	opts = append(opts, grpc.WithContextDialer(dial.NewContextDialer(s.log, s.options.resolvers...)))
	if s.tlsConfigBuilder == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// NOTE: gosec is unable to resolve the constant and warns about "TLS
		// MinVersion too low".
		baseConf := &tls.Config{ //nolint:gosec
			MinVersion: minTLSVersion,
		}
		opts = append(opts, grpc.WithTransportCredentials(
			&grpcTLSCredentialsWrapper{
				TransportCredentials: credentials.NewTLS(s.tlsConfigBuilder.ClientConfig(baseConf)),
				baseConf:             baseConf,
				TLSConfig:            s.tlsConfigBuilder,
			},
		))
	}
	// We don't want the grpc client to perform DNS resolution when we use
	// resolvers. As per documentation on `grpc.WithContextDialer`:
	//  Note that gRPC by default performs name resolution on the target passed to
	//  NewClient. To bypass name resolution and cause the target string to be
	//  passed directly to the dialer here instead, use the "passthrough" resolver
	//  by specifying it in the target string, e.g. "passthrough:target".
	target := s.target
	if len(s.options.resolvers) > 0 {
		target = "passthrough:" + strings.TrimPrefix(target, "passthrough:")
	}
	return grpc.NewClient(target, opts...)
}

// newGracefulStreamContext returns a context for the stream that is canceled after the provided
// grace period when the parent context is canceled.
func newGracefulStreamContext(ctx context.Context, gracePeriod time.Duration) (context.Context, func()) {
	streamCtx, cancelStream := context.WithCancel(context.Background())
	stopShutdownCancel := context.AfterFunc(ctx, func() {
		time.AfterFunc(gracePeriod, cancelStream)
	})

	return streamCtx, func() {
		stopShutdownCancel()
		cancelStream()
	}
}

// checkIngestBatchSupport uses gRPC reflection to check whether the remote server exposes the
// IngestBatch RPC.
func checkIngestBatchSupport(ctx context.Context, log *slog.Logger, client *grpc.ClientConn) (bool, error) {
	serviceName := tsv1alphapb.IngesterService_ServiceDesc.ServiceName
	log.Debug("checking stream batch support",
		logfields.Service, serviceName,
		logfields.Method, ingestBatchMethodName,
	)

	stream, err := rpb.NewServerReflectionClient(client).ServerReflectionInfo(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to create reflection stream: %w", err)
	}
	defer func() {
		if err := stream.CloseSend(); err != nil {
			log.Debug("failed to close reflection stream", logfields.Error, err)
		}
	}()

	if err := stream.Send(&rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_FileContainingSymbol{
			FileContainingSymbol: serviceName,
		},
	}); err != nil {
		return false, fmt.Errorf("failed to request Timescape ingester descriptor: %w", err)
	}

	res, err := stream.Recv()
	if err != nil {
		return false, fmt.Errorf("failed to receive Timescape ingester descriptor: %w", err)
	}
	switch msg := res.GetMessageResponse().(type) {
	case *rpb.ServerReflectionResponse_FileDescriptorResponse:
		return serviceSupportsMethod(msg.FileDescriptorResponse.GetFileDescriptorProto(), serviceName, ingestBatchMethodName)
	case *rpb.ServerReflectionResponse_ErrorResponse:
		return false, fmt.Errorf("failed to reflect Timescape ingester descriptor: code=%d message=%q",
			msg.ErrorResponse.GetErrorCode(),
			msg.ErrorResponse.GetErrorMessage(),
		)
	default:
		return false, fmt.Errorf("unexpected reflection response: %T", msg)
	}
}

// serviceSupportsMethod checks whether the reflected file descriptors for the provided
// service include the provided method.
func serviceSupportsMethod(fileDescriptorProtos [][]byte, serviceName, methodName string) (bool, error) {
	fullServiceName := func(pkg, service string) string {
		if pkg == "" {
			return service
		}
		return pkg + "." + service
	}

	for _, raw := range fileDescriptorProtos {
		var file descriptorpb.FileDescriptorProto
		if err := proto.Unmarshal(raw, &file); err != nil {
			return false, fmt.Errorf("failed to unmarshal reflected descriptor: %w", err)
		}
		for _, service := range file.GetService() {
			if fullServiceName(file.GetPackage(), service.GetName()) != serviceName {
				continue
			}
			for _, method := range service.GetMethod() {
				if method.GetName() == methodName {
					return true, nil
				}
			}
			return false, nil
		}
	}
	return false, fmt.Errorf("reflected descriptors did not include service %q", serviceName)
}

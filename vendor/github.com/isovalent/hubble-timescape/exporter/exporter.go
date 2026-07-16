// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

package exporter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	timescapepb "github.com/isovalent/hubble-timescape/api/timescape/v1alpha"
)

type ingestBatchStream = grpc.ClientStreamingClient[timescapepb.IngestBatchRequest, timescapepb.IngestBatchResponse]
type ingestSingleStream = grpc.ClientStreamingClient[timescapepb.IngestRequest, timescapepb.IngestResponse]

// Exporter admits completed typed batches and streams them to Timescape.
//
// Export may be called concurrently and before Run. Run must be called exactly
// once. The exporter retries failed connections and always retries an in-flight
// batch before processing newer batches.
type Exporter struct {
	log     *slog.Logger
	target  string
	options options

	lifecycleMu sync.RWMutex
	accepting   bool
	running     atomic.Bool

	admission *admission
	queue     chan *Batch
	retry     *Batch
	retries   int

	droppedEvents     atomic.Uint64
	unsupportedEvents atomic.Uint64
}

// NewExporter creates an exporter for completed typed batches.
func NewExporter(log *slog.Logger, target string, opts ...Option) (*Exporter, error) {
	if target == "" {
		return nil, errors.New("target is empty")
	}
	if log == nil {
		log = slog.Default()
	}

	options := defaultOptions()
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("option is nil")
		}
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}
	if options.transportCredentials != nil && options.transportCredentialsProvider != nil {
		return nil, errors.New("static transport credentials and a credentials provider are mutually exclusive")
	}

	return &Exporter{
		log:       log.With("subsystem", "timescape-exporter", "target", target),
		target:    target,
		options:   options,
		accepting: true,
		admission: newAdmission(options.maxBufferSize),
		queue:     make(chan *Batch, options.maxBufferSize),
	}, nil
}

// Export atomically admits batch. A successful call consumes batch. If Export
// returns ErrBufferFull, ErrStopped, or a context error, batch remains reusable.
func (e *Exporter) Export(ctx context.Context, batch *Batch) error {
	if err := validateBatch(batch); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !batch.claim() {
		return ErrBatchAlreadyExported
	}

	e.lifecycleMu.RLock()
	defer e.lifecycleMu.RUnlock()
	if !e.accepting {
		batch.releaseClaim()
		return ErrStopped
	}
	if err := ctx.Err(); err != nil {
		batch.releaseClaim()
		return err
	}
	if !e.admission.acquire(batch.Len()) {
		batch.releaseClaim()
		e.recordDropped(batch.Len(), false)
		return ErrBufferFull
	}

	select {
	case e.queue <- batch:
		batch.consume()
		return nil
	default:
		// Weighted admission guarantees enough channel slots because every
		// queued batch contains at least one admitted event. Keep this guard so
		// a future queue implementation cannot turn Export into a blocking call.
		e.admission.release(batch.Len())
		batch.releaseClaim()
		e.recordDropped(batch.Len(), false)
		return ErrBufferFull
	}
}

// Run connects to Timescape and drains admitted batches until ctx is canceled.
func (e *Exporter) Run(ctx context.Context) error {
	if !e.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}

	stopOnCancel := context.AfterFunc(ctx, e.stopAdmission)
	reporterCtx, stopReporter := context.WithCancel(context.WithoutCancel(ctx))
	var reporterWG sync.WaitGroup
	if e.options.reportDroppedEventInterval > 0 {
		reporterWG.Go(func() {
			e.reportDrops(reporterCtx)
		})
	}
	defer func() {
		stopOnCancel()
		e.stopAdmission()
		e.discardRemaining()
		stopReporter()
		reporterWG.Wait()
	}()

	transportCredentials, err := e.resolveTransportCredentials(ctx)
	if err != nil {
		return fmt.Errorf("resolve transport credentials: %w", err)
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := e.connectAndStream(ctx, transportCredentials)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			continue
		}

		e.retries++
		delay := e.options.backoff.Duration(e.retries)
		e.log.Error("failed to stream events", "error", err)
		e.log.Info("retrying export after backoff", "duration", delay, "retries", e.retries)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (e *Exporter) reserve(count int) error {
	e.lifecycleMu.RLock()
	defer e.lifecycleMu.RUnlock()
	if !e.accepting {
		return ErrStopped
	}
	if !e.admission.acquire(count) {
		e.recordDropped(count, false)
		return ErrBufferFull
	}
	return nil
}

// submitReserved transfers an already-reserved batch to the transport queue.
// It releases the reservation itself if submission fails.
func (e *Exporter) submitReserved(batch *Batch) error {
	if err := validateBatch(batch); err != nil {
		if batch != nil {
			e.admission.release(batch.Len())
		}
		return err
	}
	if !batch.claim() {
		e.admission.release(batch.Len())
		return ErrBatchAlreadyExported
	}

	e.lifecycleMu.RLock()
	defer e.lifecycleMu.RUnlock()
	if !e.accepting {
		e.admission.release(batch.Len())
		batch.releaseClaim()
		return ErrStopped
	}
	select {
	case e.queue <- batch:
		batch.consume()
		return nil
	default:
		count := batch.Len()
		e.admission.release(count)
		batch.releaseClaim()
		e.recordDropped(count, false)
		return ErrBufferFull
	}
}

func (e *Exporter) stopAdmission() {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if !e.accepting {
		return
	}
	e.accepting = false
}

func (e *Exporter) resolveTransportCredentials(ctx context.Context) (credentials.TransportCredentials, error) {
	if e.options.transportCredentialsProvider != nil {
		transportCredentials, err := e.options.transportCredentialsProvider(ctx)
		if err != nil {
			return nil, err
		}
		if transportCredentials == nil {
			return nil, errors.New("transport credentials provider returned nil credentials")
		}
		return transportCredentials, nil
	}
	if e.options.transportCredentials != nil {
		return e.options.transportCredentials, nil
	}
	return insecure.NewCredentials(), nil
}

func (e *Exporter) connectAndStream(ctx context.Context, transportCredentials credentials.TransportCredentials) error {
	dialOptions := make([]grpc.DialOption, 0, len(e.options.dialOptions)+1)
	dialOptions = append(dialOptions, e.options.dialOptions...)
	dialOptions = append(dialOptions, grpc.WithTransportCredentials(transportCredentials))
	client, err := grpc.NewClient(e.target, dialOptions...)
	if err != nil {
		return fmt.Errorf("create gRPC client: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			e.log.Debug("failed to close gRPC client", "error", err)
		}
	}()

	switch e.options.ingestMode {
	case IngestModeAuto:
		capabilities, batchAvailable, err := reflectIngestCapabilities(ctx, client)
		if err != nil {
			return err
		}
		if !batchAvailable {
			e.log.Info("IngestBatch is unavailable; using deprecated single-event ingestion")
			return e.streamSingle(ctx, client)
		}
		return e.streamBatch(ctx, client, capabilities)
	case IngestModeBatch:
		return e.streamBatch(ctx, client, ingestCapabilities{flow: true})
	case IngestModeSingle:
		return e.streamSingle(ctx, client)
	default:
		return fmt.Errorf("invalid ingest mode %q", e.options.ingestMode)
	}
}

func (e *Exporter) streamBatch(ctx context.Context, client grpc.ClientConnInterface, capabilities ingestCapabilities) error {
	streamCtx, cancel := newGracefulStreamContext(ctx, e.options.shutdownFlushTimeout)
	defer cancel()
	stream, err := timescapepb.NewIngesterServiceClient(client).IngestBatch(streamCtx)
	if err != nil {
		return fmt.Errorf("open IngestBatch stream: %w", err)
	}
	if err := e.sendBatchLoop(ctx, stream, capabilities); err != nil {
		return fmt.Errorf("stream batches: %w", err)
	}
	return nil
}

func (e *Exporter) streamSingle(ctx context.Context, client grpc.ClientConnInterface) error {
	streamCtx, cancel := newGracefulStreamContext(ctx, e.options.shutdownFlushTimeout)
	defer cancel()
	// Keep the legacy endpoint functional while IngestModeSingle is supported.
	stream, err := timescapepb.NewIngesterServiceClient(client).Ingest(streamCtx) //nolint:staticcheck
	if err != nil {
		return fmt.Errorf("open Ingest stream: %w", err)
	}
	if err := e.sendSingleLoop(ctx, stream); err != nil {
		return fmt.Errorf("stream single events: %w", err)
	}
	return nil
}

func (e *Exporter) sendBatchLoop(ctx context.Context, stream ingestBatchStream, capabilities ingestCapabilities) error {
	if err := e.sendBatch(stream, e.retry, capabilities); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			// Wait for in-flight Export calls to finish enqueueing before the
			// shutdown drain takes its final queue snapshot.
			e.stopAdmission()
			e.flushBatchQueue(stream, capabilities)
			if _, err := stream.CloseAndRecv(); err != nil {
				e.log.Debug("failed to close IngestBatch stream", "error", err)
			}
			return ctx.Err()
		case batch := <-e.queue:
			if err := e.sendBatch(stream, batch, capabilities); err != nil {
				return err
			}
		}
	}
}

func (e *Exporter) sendSingleLoop(ctx context.Context, stream ingestSingleStream) error {
	if err := e.sendSingleBatch(stream, e.retry); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			// See sendBatchLoop. Single mode shares the same admission barrier.
			e.stopAdmission()
			e.flushSingleQueue(stream)
			if _, err := stream.CloseAndRecv(); err != nil {
				e.log.Debug("failed to close Ingest stream", "error", err)
			}
			return ctx.Err()
		case batch := <-e.queue:
			if err := e.sendSingleBatch(stream, batch); err != nil {
				return err
			}
		}
	}
}

func (e *Exporter) sendBatch(stream ingestBatchStream, batch *Batch, capabilities ingestCapabilities) error {
	if batch == nil {
		return nil
	}
	if batch.kind != batchKindFlow || !capabilities.flow {
		count := batch.Len()
		e.retry = nil
		e.admission.release(count)
		e.recordDropped(count, true)
		return nil
	}

	request := &timescapepb.IngestBatchRequest{
		Data: &timescapepb.IngestBatchRequest_FlowBatch{
			FlowBatch: &timescapepb.FlowBatch{Flows: batch.flows},
		},
	}
	if err := stream.Send(request); err != nil {
		e.retry = batch
		return fmt.Errorf("send flow batch: %w", err)
	}

	e.retry = nil
	e.retries = 0
	e.admission.release(batch.Len())
	return nil
}

func (e *Exporter) sendSingleBatch(stream ingestSingleStream, batch *Batch) error {
	if batch == nil {
		return nil
	}
	if batch.kind != batchKindFlow {
		count := batch.Len()
		e.retry = nil
		e.admission.release(count)
		e.recordDropped(count, true)
		return nil
	}

	for index, flow := range batch.flows {
		request := &timescapepb.IngestRequest{
			Data: &timescapepb.IngestRequest_Flow{Flow: flow},
		}
		if err := stream.Send(request); err != nil {
			batch.flows = batch.flows[index:]
			e.retry = batch
			return fmt.Errorf("send flow: %w", err)
		}
		e.admission.release(1)
		e.retries = 0
	}
	e.retry = nil
	return nil
}

func (e *Exporter) flushBatchQueue(stream ingestBatchStream, capabilities ingestCapabilities) {
	if err := e.sendBatch(stream, e.retry, capabilities); err != nil {
		e.log.Warn("failed to retry batch during shutdown", "error", err)
		return
	}
	for {
		select {
		case batch := <-e.queue:
			if err := e.sendBatch(stream, batch, capabilities); err != nil {
				e.log.Warn("failed to flush batch during shutdown", "error", err)
				return
			}
		default:
			return
		}
	}
}

func (e *Exporter) flushSingleQueue(stream ingestSingleStream) {
	if err := e.sendSingleBatch(stream, e.retry); err != nil {
		e.log.Warn("failed to retry events during shutdown", "error", err)
		return
	}
	for {
		select {
		case batch := <-e.queue:
			if err := e.sendSingleBatch(stream, batch); err != nil {
				e.log.Warn("failed to flush events during shutdown", "error", err)
				return
			}
		default:
			return
		}
	}
}

func (e *Exporter) discardRemaining() {
	if e.retry != nil {
		count := e.retry.Len()
		e.admission.release(count)
		e.recordDropped(count, false)
		e.retry = nil
	}
	for {
		select {
		case batch := <-e.queue:
			count := batch.Len()
			e.admission.release(count)
			e.recordDropped(count, false)
		default:
			return
		}
	}
}

func (e *Exporter) recordDropped(count int, unsupported bool) {
	if count <= 0 {
		return
	}
	e.droppedEvents.Add(uint64(count))
	if unsupported {
		e.unsupportedEvents.Add(uint64(count))
	}
}

func (e *Exporter) reportDrops(ctx context.Context) {
	ticker := time.NewTicker(e.options.reportDroppedEventInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			total := e.droppedEvents.Swap(0)
			unsupported := e.unsupportedEvents.Swap(0)
			if total == 0 {
				continue
			}
			e.log.Warn("dropped events", "count", total, "unsupported-event-count", unsupported)
		}
	}
}

func validateBatch(batch *Batch) error {
	if batch == nil || batch.Len() == 0 {
		return ErrInvalidBatch
	}
	if batch.kind != batchKindFlow {
		return ErrInvalidBatch
	}
	return nil
}

func newGracefulStreamContext(ctx context.Context, gracePeriod time.Duration) (context.Context, context.CancelFunc) {
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopAfterFunc := context.AfterFunc(ctx, func() {
		if gracePeriod == 0 {
			cancel()
			return
		}
		time.AfterFunc(gracePeriod, cancel)
	})
	return streamCtx, func() {
		stopAfterFunc()
		cancel()
	}
}

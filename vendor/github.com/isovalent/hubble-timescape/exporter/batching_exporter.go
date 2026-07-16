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

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

const (
	defaultBatchSize     = 256
	defaultFlushInterval = 250 * time.Millisecond
)

// BatchingConfig controls typed event accumulation.
type BatchingConfig struct {
	BatchSize     int
	FlushInterval time.Duration
}

// DefaultBatchingConfig returns the recommended batching configuration.
func DefaultBatchingConfig() BatchingConfig {
	return BatchingConfig{
		BatchSize:     defaultBatchSize,
		FlushInterval: defaultFlushInterval,
	}
}

// BatchingExporter accumulates events into per-family typed batches before
// handing them to an internal [Exporter]. FIFO ordering is preserved within an
// event family. No total ordering is promised across independent families.
type BatchingExporter struct {
	exporter *Exporter
	config   BatchingConfig

	lifecycleMu sync.RWMutex
	accepting   bool
	running     atomic.Bool

	flowEvents chan *flowpb.Flow
}

// NewBatchingExporter creates an exporter that accumulates typed events.
func NewBatchingExporter(
	log *slog.Logger,
	target string,
	batching BatchingConfig,
	opts ...Option,
) (*BatchingExporter, error) {
	if batching.BatchSize <= 0 {
		return nil, fmt.Errorf("invalid batch size %d: must be greater than zero", batching.BatchSize)
	}
	if batching.FlushInterval <= 0 {
		return nil, fmt.Errorf("invalid flush interval %s: must be greater than zero", batching.FlushInterval)
	}

	exporter, err := NewExporter(log, target, opts...)
	if err != nil {
		return nil, err
	}
	return &BatchingExporter{
		exporter:   exporter,
		config:     batching,
		accepting:  true,
		flowEvents: make(chan *flowpb.Flow, exporter.options.maxBufferSize),
	}, nil
}

// Export admits event into its typed accumulator. Event remains reusable and
// may be passed to other batching exporters after a successful call.
func (e *BatchingExporter) Export(ctx context.Context, event Event) error {
	if event.len() == 0 {
		return ErrInvalidEvent
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	e.lifecycleMu.RLock()
	defer e.lifecycleMu.RUnlock()
	if !e.accepting {
		return ErrStopped
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.exporter.reserve(1); err != nil {
		return err
	}

	if e.exporter.options.ingestMode == IngestModeSingle {
		batch := NewFlowBatch([]*flowpb.Flow{event.flow})
		if err := e.submitDetached(batch); err != nil {
			return err
		}
		return nil
	}

	select {
	case e.flowEvents <- event.flow:
		return nil
	default:
		// Weighted admission makes this unreachable while the typed queue
		// accounts for at least one event per slot. Retain the guard to keep
		// the public path non-blocking if the implementation changes.
		e.exporter.admission.release(1)
		e.exporter.recordDropped(1, false)
		return ErrBufferFull
	}
}

// Run starts the internal completed-batch exporter and blocks until ctx is
// canceled. Run must be called exactly once.
func (e *BatchingExporter) Run(ctx context.Context) error {
	if !e.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}

	coreCtx, cancelCore := context.WithCancel(context.WithoutCancel(ctx))
	coreResult := make(chan error, 1)
	go func() {
		coreResult <- e.exporter.Run(coreCtx)
	}()
	accumulatorStop := make(chan bool, 1)
	accumulatorDone := make(chan struct{})
	go func() {
		defer close(accumulatorDone)
		e.runFlowAccumulator(accumulatorStop)
	}()

	select {
	case <-ctx.Done():
		e.stopAdmission()
		accumulatorStop <- true
		<-accumulatorDone
		cancelCore()
		coreErr := <-coreResult
		if coreErr != nil && !errors.Is(coreErr, context.Canceled) {
			return coreErr
		}
		return ctx.Err()
	case coreErr := <-coreResult:
		e.stopAdmission()
		accumulatorStop <- false
		<-accumulatorDone
		cancelCore()
		return coreErr
	}
}

func (e *BatchingExporter) stopAdmission() {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.accepting = false
}

func (e *BatchingExporter) submitDetached(batch *Batch) error {
	count := batch.Len()
	err := e.exporter.submitReserved(batch)
	if err != nil && !errors.Is(err, ErrBufferFull) {
		e.exporter.recordDropped(count, false)
	}
	return err
}

func (e *BatchingExporter) runFlowAccumulator(stop <-chan bool) {
	e.runFlowAccumulatorWithReady(stop, nil)
}

func (e *BatchingExporter) runFlowAccumulatorWithReady(stop <-chan bool, ready chan<- struct{}) {
	flows := e.takeFlowSlice()
	if ready != nil {
		close(ready)
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	startTimer := func() {
		if timer == nil {
			timer = time.NewTimer(e.config.FlushInterval)
		} else {
			timer.Reset(e.config.FlushInterval)
		}
		timerC = timer.C
	}
	submit := func(replaceAccumulator bool) {
		if len(flows) == 0 {
			return
		}
		batch := NewFlowBatch(flows)
		if err := e.submitDetached(batch); err != nil {
			e.exporter.log.Debug("failed to submit accumulated batch", "error", err)
		}
		if replaceAccumulator {
			flows = e.takeFlowSlice()
		} else {
			flows = nil
		}
	}
	appendFlow := func(flow *flowpb.Flow) {
		flows = append(flows, flow)
		if len(flows) == 1 {
			startTimer()
		}
		if len(flows) == e.config.BatchSize {
			stopTimer()
			submit(true)
		}
	}

	for {
		select {
		case flow := <-e.flowEvents:
			appendFlow(flow)
		case <-timerC:
			timerC = nil
			submit(true)
		case flush := <-stop:
			stopTimer()
			if !flush {
				e.discardAccumulated(flows)
				return
			}
			for {
				select {
				case flow := <-e.flowEvents:
					if flows == nil {
						flows = e.takeFlowSlice()
					}
					flows = append(flows, flow)
					if len(flows) == e.config.BatchSize {
						submit(false)
					}
				default:
					submit(false)
					return
				}
			}
		}
	}
}

func (e *BatchingExporter) takeFlowSlice() []*flowpb.Flow {
	return make([]*flowpb.Flow, 0, e.config.BatchSize)
}

func (e *BatchingExporter) discardAccumulated(flows []*flowpb.Flow) {
	count := len(flows)
	for {
		select {
		case <-e.flowEvents:
			count++
		default:
			e.exporter.admission.release(count)
			e.exporter.recordDropped(count, false)
			return
		}
	}
}

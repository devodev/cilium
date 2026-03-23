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
	"github.com/jonboulle/clockwork"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/time"
)

// timerClock is an interface that abstracts the creation of timers. It is used to allow the use of
// a real timer clock by default and a fake clock in tests.
type timerClock interface {
	NewTimer(d time.Duration) clockwork.Timer
}

// flowBatcher is a helper for batching flows before sending them to the stream. It maintains an
// internal buffer of flows and starts a timer using the configured flushInterval when the first
// flow is added with [flowBatcher.Add]. Callers can use [flowBatcher.FlushC] to receive a
// notification when the flush timer expires, at which point they can call [flowBatcher.Take] to
// retrieve the current batch of flows and reset the batcher. Additionally, [flowBatcher.Add]
// returns a batch when the configured batch size has been reached.
//
// When the batcher is no longer needed, [flowBatcher.Stop] should be called to stop the flush timer. Any
// remaining flows can be retrieved by calling [flowBatcher.Take] after Stop.
type flowBatcher struct {
	clock         timerClock
	size          int
	flushInterval time.Duration

	flows      []*flowpb.Flow
	flushTimer clockwork.Timer
	flushC     <-chan time.Time
}

// newFlowBatcher creates a new flowBatcher with the given batch size and flush interval.
func newFlowBatcher(clock timerClock, size int, flushInterval time.Duration) *flowBatcher {
	if clock == nil {
		clock = realTimerClock{}
	}
	return &flowBatcher{
		clock:         clock,
		size:          size,
		flushInterval: flushInterval,
	}
}

// Add adds a flow to the batcher and returns a batch of flows if the batch size is reached.
func (b *flowBatcher) Add(flow *flowpb.Flow) []*flowpb.Flow {
	b.flows = append(b.flows, flow)
	if len(b.flows) == 1 {
		b.startFlushTimer()
	}
	if len(b.flows) < b.size {
		return nil
	}
	return b.Take()
}

// Take returns the current batch of flows and resets the batcher.
func (b *flowBatcher) Take() []*flowpb.Flow {
	if len(b.flows) == 0 {
		return nil
	}

	b.stopFlushTimer()
	flows := b.flows
	b.flows = nil
	return flows
}

// FlushC returns a channel that will receive a time when the flush timer expires.
func (b *flowBatcher) FlushC() <-chan time.Time {
	return b.flushC
}

// Stop stops the flush timer. Note that this does not reset the batcher. Call [flowBatcher.Take]
// to reset the batcher and retrieve any remaining flows after calling Stop.
func (b *flowBatcher) Stop() {
	b.stopFlushTimer()
}

func (b *flowBatcher) startFlushTimer() {
	if b.flushTimer == nil {
		b.flushTimer = b.clock.NewTimer(b.flushInterval)
	} else {
		b.flushTimer.Reset(b.flushInterval)
	}
	b.flushC = b.flushTimer.Chan()
}

func (b *flowBatcher) stopFlushTimer() {
	if b.flushTimer == nil {
		return
	}
	// Stop the timer and drain the channel if it has already fired to prevent
	// stale values from being received when we reset the timer.
	if !b.flushTimer.Stop() {
		select {
		case <-b.flushTimer.Chan():
		default:
		}
	}
	b.flushC = nil
}

type realTimerClock struct{}

func (realTimerClock) NewTimer(d time.Duration) clockwork.Timer {
	return realTimer{Timer: time.NewTimer(d)}
}

type realTimer struct {
	*time.Timer
}

func (t realTimer) Chan() <-chan time.Time {
	return t.C
}

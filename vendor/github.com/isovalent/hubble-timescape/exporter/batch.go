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
	"sync/atomic"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type batchKind uint8

const (
	batchKindUnknown batchKind = iota
	batchKindFlow
)

const (
	batchStateReady uint32 = iota
	batchStateClaimed
	batchStateExported
)

// Batch is an opaque, homogeneous batch accepted by [Exporter].
//
// Batch must not be copied. A successful call to [Exporter.Export] consumes the
// batch. The batch and its underlying slice and protobuf messages must not be
// accessed or modified after that point.
type Batch struct {
	kind  batchKind
	flows []*flowpb.Flow
	state atomic.Uint32
}

// NewFlowBatch wraps flows without copying, boxing, or validating the slice or
// its elements. The caller must provide non-nil flows and may retain or reuse
// the batch only when Export rejects it.
func NewFlowBatch(flows []*flowpb.Flow) *Batch {
	return &Batch{kind: batchKindFlow, flows: flows}
}

// Len returns the number of events in the batch.
func (b *Batch) Len() int {
	if b == nil {
		return 0
	}
	return len(b.flows)
}

func (b *Batch) claim() bool {
	return b.state.CompareAndSwap(batchStateReady, batchStateClaimed)
}

func (b *Batch) releaseClaim() {
	b.state.CompareAndSwap(batchStateClaimed, batchStateReady)
}

func (b *Batch) consume() {
	b.state.Store(batchStateExported)
}

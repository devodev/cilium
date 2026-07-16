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

import flowpb "github.com/cilium/cilium/api/v1/flow"

type eventKind uint8

const (
	eventKindUnknown eventKind = iota
	eventKindFlow
)

// Event is an opaque event accepted by [BatchingExporter].
//
// Event is a small copyable value. It may be submitted to multiple batching
// exporters, but its underlying protobuf message must not be modified after the
// first successful [BatchingExporter.Export] call.
type Event struct {
	kind eventKind
	flow *flowpb.Flow
}

// NewFlowEvent wraps flow without copying or validating it. A nil flow produces
// an invalid event. The caller retains ownership until Export succeeds.
func NewFlowEvent(flow *flowpb.Flow) Event {
	return Event{kind: eventKindFlow, flow: flow}
}

func (e Event) len() int {
	if e.kind != eventKindFlow || e.flow == nil {
		return 0
	}
	return 1
}

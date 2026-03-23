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
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/time"
)

func TestFlowBatcherFlushesOnSize(t *testing.T) {
	batcher := newFlowBatcher(nil, 2, time.Hour)
	t.Cleanup(batcher.Stop)

	// The first flow only starts the batch. The second flow reaches the size
	// limit and returns the batch immediately.
	require.Nil(t, batcher.Add(&flowpb.Flow{NodeName: "flow-1"}))
	batch := batcher.Add(&flowpb.Flow{NodeName: "flow-2"})
	require.Equal(t, []string{"flow-1", "flow-2"}, flowNodeNames(batch))
	require.Nil(t, batcher.Take())
}

func TestFlowBatcherFlushesOnTimer(t *testing.T) {
	clock := clockwork.NewFakeClock()
	batcher := newFlowBatcher(clock, 4, time.Second)
	t.Cleanup(batcher.Stop)

	// Adding the first flow arms the timer. Advance the fake clock only after
	// the timer waiter is registered so the flush is deterministic.
	require.Nil(t, batcher.Add(&flowpb.Flow{NodeName: "flow-1"}))
	require.NoError(t, clock.BlockUntilContext(t.Context(), 1))
	clock.Advance(time.Second)

	// Once the timer fires, FlushC becomes readable and Take returns the
	// partial batch.
	requireReceive(t, batcher.FlushC(), "batcher never triggered its flush timer")
	require.Equal(t, []string{"flow-1"}, flowNodeNames(batcher.Take()))
	require.Nil(t, batcher.FlushC())
}

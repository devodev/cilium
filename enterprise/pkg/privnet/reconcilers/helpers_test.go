// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"slices"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
)

func TestWatchesTracker(t *testing.T) {
	var (
		chs     []<-chan struct{}
		tracker = newWatchesTracker[int]()
	)

	// Initialize a bunch of channels for testing purposes
	for range 10 {
		chs = append(chs, make(<-chan struct{}))
	}

	// Register a few associations
	tracker.Register(chs[0], 0x01)
	tracker.Register(chs[1], 0x11)
	tracker.Register(chs[1], 0x12)
	tracker.Register(chs[1], 0x13)
	tracker.Register(chs[2], 0x21)
	tracker.Register(chs[3], 0x31)

	// Registering the same associations again should not lead to duplicate entries
	tracker.Register(chs[1], 0x13)
	tracker.Register(chs[2], 0x21)

	// Assert that [Iter] returns the expected elements
	got := tracker.Iter([]<-chan struct{}{chs[1], chs[3], chs[9]})
	require.ElementsMatch(t, slices.Collect(got), []int{0x11, 0x12, 0x13, 0x31})

	// Register a few more associations
	tracker.Register(chs[2], 0x21)
	tracker.Register(chs[2], 0x22)
	tracker.Register(chs[4], 0x41)
	tracker.Register(chs[4], 0x42)

	// Assert that [Iter] returns the expected elements
	got = tracker.Iter([]<-chan struct{}{chs[1], chs[2], chs[4], chs[0]})
	require.ElementsMatch(t, slices.Collect(got), []int{0x01, 0x21, 0x22, 0x41, 0x42})
}

func TestPropertyTracker(t *testing.T) {
	type dummy struct{ key, value string }

	var (
		tracker = NewPropertyTracker(
			func(d dummy) string { return d.key },
			func(d dummy) string { return d.value },
		)

		change = func(key, value string, deleted bool) statedb.Change[dummy] {
			return statedb.Change[dummy]{
				Object:  dummy{key: key, value: value},
				Deleted: deleted,
			}
		}
	)

	prev, changed := tracker.Track(change("foo", "foo1", false))
	require.False(t, changed, "No existing association")
	require.Empty(t, prev, "No existing association")

	prev, changed = tracker.Track(change("foo", "foo1", false))
	require.False(t, changed, "No change occurred")
	require.Equal(t, "foo1", prev, "An association existed")

	prev, changed = tracker.Track(change("foo", "foo2", false))
	require.True(t, changed, "A change occurred")
	require.Equal(t, "foo1", prev, "An association existed")

	prev, changed = tracker.Track(change("foo", "foo3", false))
	require.True(t, changed, "A change occurred")
	require.Equal(t, "foo2", prev, "An association existed")

	prev, changed = tracker.Track(change("foo", "foo3", true))
	require.False(t, changed, "No change occurred")
	require.Equal(t, "foo3", prev, "An association existed")

	prev, changed = tracker.Track(change("bar", "bar1", true))
	require.False(t, changed, "No existing association")
	require.Empty(t, prev, "No existing association")

	_, _ = tracker.Track(change("qux", "qux1", false))
	prev, changed = tracker.Track(change("qux", "qux2", true))
	require.True(t, changed, "A change occurred")
	require.Equal(t, "qux1", prev, "An association existed")
}

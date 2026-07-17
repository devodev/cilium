// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package idpool

import (
	"fmt"
	"log/slog"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/wal"
)

func TestIDPool(t *testing.T) {
	log := slog.Default()

	pool := NewIDPool[tables.NetworkName, tables.NetworkID](log, 3, 5)

	nameFn := func(id tables.NetworkID) tables.NetworkName {
		return tables.NetworkName(fmt.Sprintf("net-%d", id))
	}

	acquireAssertValue := func(expected tables.NetworkID) {
		actual, err := pool.Acquire(nameFn(expected))
		require.NoError(t, err, "acquire unexpectedly failed")
		require.Equal(t, expected, actual)
	}

	acquireAssertError := func() {
		_, err := pool.Acquire("error")
		require.Error(t, err, "acquire should have failed")
	}

	acquireAssertValue(3)
	acquireAssertValue(4)
	acquireAssertValue(5)
	require.Equal(t, 3, pool.Allocated())
	acquireAssertValue(1)
	acquireAssertValue(2)
	require.Equal(t, 5, pool.Allocated())

	// No more IDs should be available
	acquireAssertError()

	pool.Release(4)
	pool.Release(0) // No-op
	pool.Release(4) // No-op, as already released
	pool.Release(2)
	require.Equal(t, 3, pool.Allocated())

	acquireAssertValue(4)
	acquireAssertValue(2)

	// No more IDs should be available
	acquireAssertError()

	// The zero value can correctly acquire and release an ID
	pool.Release(2)
	actual, err := pool.Acquire("")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)
	pool.Release(actual)
	acquireAssertValue(2)

	// Checking the boundaries
	pool = NewIDPool[tables.NetworkName, tables.NetworkID](log, 0, 5)
	acquireAssertValue(1)
	acquireAssertValue(2)
	require.Equal(t, 2, pool.Allocated())

	pool = NewIDPool[tables.NetworkName, tables.NetworkID](log, 5, 5)
	acquireAssertValue(5)
	require.Equal(t, 1, pool.Allocated())
	acquireAssertValue(1)

	pool = NewIDPool[tables.NetworkName, tables.NetworkID](log, tables.NetworkIDMax-1, tables.NetworkIDMax)
	acquireAssertValue(tables.NetworkIDMax - 1)
	acquireAssertValue(tables.NetworkIDMax)
	require.Equal(t, 2, pool.Allocated())
	acquireAssertValue(1)

	// Checking re requesting the ID
	pool = NewIDPool[tables.NetworkName, tables.NetworkID](log, 0, 5)
	actual, err = pool.Acquire("foobar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)

	actual, err = pool.Acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)
	require.Equal(t, 2, pool.Allocated())

	actual, err = pool.Acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)
	require.Equal(t, 2, pool.Allocated())

	actual, err = pool.Acquire("foobar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)
	require.Equal(t, 2, pool.Allocated())

	pool.Release(1)
	require.Equal(t, 1, pool.Allocated())
	// Acquire new id after release
	actual, err = pool.Acquire("foobar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(3), actual)
	actual, err = pool.Acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)
	require.Equal(t, 2, pool.Allocated())
}

func TestIDPool_restore(t *testing.T) {
	log := slog.Default()
	walFile := path.Join(t.TempDir(), PrivnetIDWALFile)
	var err error

	pool := NewIDPool[tables.NetworkName, tables.NetworkID](log, 0, 5)
	pool.walWriter, err = wal.NewWriter[allocationWALEntry[tables.NetworkName, tables.NetworkID]](walFile)
	require.NoError(t, err)

	actual, err := pool.Acquire("foo")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)

	actual, err = pool.Acquire("bar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)

	actual, err = pool.Acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(3), actual)

	actual, err = pool.Acquire("other")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(4), actual)

	pool.Release(tables.NetworkID(4))

	pool = NewIDPool[tables.NetworkName, tables.NetworkID](log, 3, 6)
	require.NoError(t, pool.restore(walFile))
	pool.walWriter, err = wal.NewWriter[allocationWALEntry[tables.NetworkName, tables.NetworkID]](walFile)
	require.NoError(t, err)

	actual, err = pool.Acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(3), actual)

	actual, err = pool.Acquire("foo")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)

	actual, err = pool.Acquire("not_other")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(4), actual)

	actual, err = pool.Acquire("other")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(5), actual)

	pool.Initialized()

	actual, err = pool.Acquire("bar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(6), actual)
}

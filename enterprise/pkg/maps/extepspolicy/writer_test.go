//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extepspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/testutils"
)

func newPolicyMap(t *testing.T, log *slog.Logger, id uint16) *policymap.UnderlyingPolicyMap {
	t.Helper()

	pm := &policymap.UnderlyingPolicyMap{
		Map: bpf.NewMap(
			bpf.LocalMapPath(log, "cilium_test", id),
			ebpf.LPMTrie,
			&policymap.PolicyKey{},
			&policymap.PolicyEntry{},
			16,
			bpf.GetMapMemoryFlags(ebpf.LPMTrie)|unix.BPF_F_RDONLY_PROG,
		),
	}

	require.NoError(t, pm.CreateUnpinned(), "pm.CreateUnpinned")
	t.Cleanup(func() { pm.Close() })

	return pm
}

func TestPrivilegedWriter(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		ctx = t.Context()
		log = hivetest.Logger(t)

		writer Writer
		theMap *extEpsPolMap

		pm1 = newPolicyMap(t, log, 10)
		pm2 = newPolicyMap(t, log, 20)

		dump = make(map[string][]string)
	)

	t.Cleanup(func() {
		if theMap != nil {
			require.NoError(t, theMap.m.Unpin())
		}
	})

	h := hive.New(
		Cell,

		Enable(func(Config) bool { return true }),

		cell.Config(policymap.DefaultPolicyConfig),

		cell.Invoke(func(w Writer, m *extEpsPolMap) {
			writer, theMap = w, m
		}),
	)

	require.NoError(t, h.Start(log, ctx), "h.Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "h.Stop")
	})

	// Create a couple of pre-existing entries
	key := &Key{bpf.NewEndpointKey(netip.MustParseAddr("10.0.0.1"), 0)}
	require.NoError(t, theMap.m.Update(key, &Value{uint32(pm1.FD())}), "map.Update")

	v, err := theMap.m.Lookup(key)
	require.NoError(t, err, "map.Lookup")
	pm1ID := v.(*Value).Fd

	key = &Key{bpf.NewEndpointKey(netip.MustParseAddr("10.0.0.6"), 0)}
	require.NoError(t, theMap.m.Update(key, &Value{uint32(pm2.FD())}), "map.Update")

	v, err = theMap.m.Lookup(key)
	require.NoError(t, err, "map.Lookup")
	pm2ID := v.(*Value).Fd

	// Upsert a bunch of entries, and assert that they are correctly present in the map
	require.NoError(t, writer.Upsert(netip.MustParseAddr("10.0.0.1"), pm1), "writer.Upsert")
	require.NoError(t, writer.Upsert(netip.MustParseAddr("10.0.0.2"), pm2), "writer.Upsert")
	require.NoError(t, writer.Upsert(netip.MustParseAddr("fd00::1"), pm2), "writer.Upsert")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		clear(dump)
		assert.NoError(c, theMap.m.Dump(dump), "map.Dump")
		assert.Equal(c, map[string][]string{
			"10.0.0.1:0": {fmt.Sprintf("fd=%d", pm1ID)},
			"10.0.0.2:0": {fmt.Sprintf("fd=%d", pm2ID)},
			"10.0.0.6:0": {fmt.Sprintf("fd=%d", pm2ID)},
			"fd00::1:0":  {fmt.Sprintf("fd=%d", pm2ID)},
		}, dump)
	}, 5*time.Second, 10*time.Millisecond)

	// Mark the writer as initialized, stale entries should be removed
	writer.MarkInitialized()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		clear(dump)
		assert.NoError(c, theMap.m.Dump(dump), "map.Dump")
		assert.Equal(c, map[string][]string{
			"10.0.0.1:0": {fmt.Sprintf("fd=%d", pm1ID)},
			"10.0.0.2:0": {fmt.Sprintf("fd=%d", pm2ID)},
			"fd00::1:0":  {fmt.Sprintf("fd=%d", pm2ID)},
		}, dump)
	}, 5*time.Second, 10*time.Millisecond)

	// Perform a few more operations, and assert that they are reflected into the map
	require.NoError(t, writer.Upsert(netip.MustParseAddr("fd00::1"), pm1), "writer.Upsert")
	require.NoError(t, writer.Delete(netip.MustParseAddr("10.0.0.1")), "writer.Delete")
	require.NoError(t, writer.Upsert(netip.MustParseAddr("10.0.0.4"), pm2), "writer.Upsert")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		clear(dump)
		assert.NoError(c, theMap.m.Dump(dump), "map.Dump")
		assert.Equal(c, map[string][]string{
			"10.0.0.2:0": {fmt.Sprintf("fd=%d", pm2ID)},
			"10.0.0.4:0": {fmt.Sprintf("fd=%d", pm2ID)},
			"fd00::1:0":  {fmt.Sprintf("fd=%d", pm1ID)},
		}, dump)
	}, 5*time.Second, 10*time.Millisecond)

	// When disabled, the map should be deleted
	path, err := theMap.m.Path()
	require.NoError(t, err, "map.Path")

	require.NoError(t, h.Stop(log, ctx), "h.Stop")
	require.FileExists(t, path, "Map pin should still exist")

	h = hive.New(Cell, cell.Config(policymap.DefaultPolicyConfig))
	require.NoError(t, h.Start(log, ctx), "h.Start")
	require.NoFileExists(t, path, "Map pin should not exist")
}

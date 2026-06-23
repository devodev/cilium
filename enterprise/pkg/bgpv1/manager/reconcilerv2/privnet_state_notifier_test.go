// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
)

type mockStateChangeNotifier struct {
	count atomic.Int64
}

func (m *mockStateChangeNotifier) NotifyStateChange() {
	m.count.Add(1)
}

func TestPrivnetStateNotifier(t *testing.T) {
	// This simple test ensures that the update to the private network table
	// triggers a state change notification.
	var (
		notifier     = &mockStateChangeNotifier{}
		db           *statedb.DB
		privnetTable statedb.RWTable[privnetTables.PrivateNetwork]
	)
	h := hive.New(
		cell.Module(
			"test",
			"test module",
			evpnConfig.Cell,
			privnetConfig.Cell,
			cell.Config(config.DefaultConfig),
			cell.Provide(
				tunnel.NewTestConfig,
				func() tunnel.EncapProtocol {
					return tunnel.VXLAN
				},
				privnetTables.NewPrivateNetworksTable,
				statedb.RWTable[privnetTables.PrivateNetwork].ToTable,
				func() StateChangeNotifier {
					return notifier
				},
			),
			cell.Invoke(
				registerPrivnetStatusNotifier,
				func(
					d *statedb.DB,
					t statedb.RWTable[privnetTables.PrivateNetwork],
				) {
					db = d
					privnetTable = t
				},
			),
		),
	)

	hive.AddConfigOverride(h, func(c *evpnConfig.Config) {
		c.Enabled = true
	})
	hive.AddConfigOverride(h, func(c *config.Config) {
		c.Enabled = true
	})
	hive.AddConfigOverride(h, func(c *privnetConfig.Flags) {
		c.Enabled = true
	})

	err := h.Start(hivetest.Logger(t), t.Context())
	require.NoError(t, err)
	t.Cleanup(func() {
		h.Stop(hivetest.Logger(t), t.Context())
	})

	// Insert a private network to trigger the notifier
	wtxn := db.WriteTxn(privnetTable)
	_, _, err = privnetTable.Insert(wtxn, privnetTables.PrivateNetwork{
		Name: "test",
	})
	wtxn.Commit()
	require.NoError(t, err)

	// The update to the private network should trigger a state change
	// notification.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Equal(ct, int64(1), notifier.count.Load())
	}, time.Second*3, time.Millisecond*100)
}

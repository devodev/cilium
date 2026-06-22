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
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bgp/agent"
	ossFake "github.com/cilium/cilium/pkg/bgp/fake"
	"github.com/cilium/cilium/pkg/bgp/manager"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
)

func TestPrivnetStateNotifier(t *testing.T) {
	// This simple test ensures that the update to the private network
	// table triggers the state reconciliation of all BGP instances.
	var (
		sr           *mockStatusReconciler
		mgr          agent.BGPRouterManager
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
				newMockStatusReconciler,
				privnetTables.NewPrivateNetworksTable,
				statedb.RWTable[privnetTables.PrivateNetwork].ToTable,
				manager.NewBGPRouterManager,
				manager.NewBGPManagerMetrics,
				ossFake.NewFakeRouterProvider,
				bgpTables.NewBGPReconcileErrorTable,
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableBGPControlPlane: true,
					}
				},
				func(m agent.BGPRouterManager) StateChangeNotifier {
					// We only test OSS RouterManager here
					// as we soon delete this
					// StateChangeNotifier logic. Avoid
					// getting rid of the import cycle.
					return m.(*manager.BGPRouterManager)
				},
			),
			cell.Invoke(
				registerPrivnetStatusNotifier,
				func(
					s *mockStatusReconciler,
					m agent.BGPRouterManager,
					d *statedb.DB,
					t statedb.RWTable[privnetTables.PrivateNetwork],
				) {
					sr = s
					mgr = m
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

	// Create BGP instances
	err = mgr.ReconcileInstances(
		t.Context(),
		&v2.CiliumBGPNodeConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
			Spec: v2.CiliumBGPNodeSpec{
				BGPInstances: []v2.CiliumBGPNodeInstance{
					{
						Name:     "instance0",
						LocalASN: ptr.To[int64](65000),
						RouterID: ptr.To("10.0.0.1"),
					},
					{
						Name:     "instance1",
						LocalASN: ptr.To[int64](65001),
						RouterID: ptr.To("10.0.0.2"),
					},
				},
			},
		},
		&v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
		},
	)
	require.NoError(t, err)

	// Insert a private network to trigger the notifier
	wtxn := db.WriteTxn(privnetTable)
	_, _, err = privnetTable.Insert(wtxn, privnetTables.PrivateNetwork{
		Name: "test",
	})
	wtxn.Commit()
	require.NoError(t, err)

	// The update to the private network should trigger the reconciliation
	// for all instances.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		sr.Lock()
		defer sr.Unlock()
		if !assert.Equal(ct, 1, sr.countPerInstance["instance0"]) {
			return
		}
		if !assert.Equal(ct, 1, sr.countPerInstance["instance1"]) {
			return
		}
	}, time.Second*3, time.Millisecond*100)
}

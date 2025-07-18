// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// TestCell checks that 'Cell' can be instantiated with the defaults and it
// also shows what are the minimal dependencies to it for testing.
func TestCell(t *testing.T) {

	h := hive.New(
		k8sClient.FakeClientCell(),
		daemonk8s.ResourcesCell,
		daemonk8s.TablesCell,
		maglev.Cell,
		node.LocalNodeStoreCell,
		metrics.Cell,
		kpr.Cell,
		Cell,
		cell.Provide(source.NewSources),
		cell.Provide(
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{}
			},
		),
		cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
	)
	require.NoError(t, h.Populate(hivetest.Logger(t)))
}

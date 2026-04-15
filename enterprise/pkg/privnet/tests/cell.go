//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"log/slog"
	"net"
	"path"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers/idpool"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

func NewTestHive(t testing.TB) *hive.Hive {
	return hive.New(
		k8sClient.FakeClientCell(),
		metrics.Cell,

		cell.Config(cmtypes.DefaultClusterInfo),

		daemonk8s.ResourcesCell,
		daemonk8s.TablesCell,
		node.LocalNodeStoreTestCell,

		mockEndpointCell(t),
		mockLocalCiliumNodeCell(t),
		mockGneigh(t),
		mockBPFMapCell(t),
		mockK8sCell(t),
		mockPolicyCell(t),
		mockDeviceManagerCell(t),
		mockIPAMCell(t),
		mockExtEPPolicyCell(t),

		cell.Provide(
			dptables.NewDeviceTable,
			statedb.RWTable[*dptables.Device].ToTable,

			func() promise.Promise[synced.CRDSync] {
				r, p := promise.New[synced.CRDSync]()
				r.Resolve(synced.CRDSync{})
				return p
			},

			func() tunnel.Config {
				return tunnel.NewTestConfig(tunnel.VXLAN)
			},

			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					// Set StateDir to match the script test directory.
					StateDir: path.Join(path.Dir(t.TempDir()), "001"),

					EnableIPv4: true,
					EnableIPv6: true,
				}
			},
		),

		cell.Invoke(func(localNodeStore *node.LocalNodeStore) {
			// Prepopulate local node name and labels for nodeattachment test which
			// requires modifying the local node labels.
			localNodeStore.Update(func(n *node.LocalNode) {
				n.Labels["node"] = "node1"
				n.SetNodeInternalIP(net.ParseIP("172.18.0.3"))
				n.SetNodeInternalIP(net.ParseIP("fc00:18::3"))
			})
		}),

		// Make privnet ID predictable
		withOverride(idpool.NewIDPool[tables.NetworkName, tables.NetworkID](slog.Default(), 1, tables.NetworkIDMax)),
		// Make subnet ID predictable
		withOverride(reconcilers.SubnetIDPoolFactory(func() *idpool.SubnetIDPool {
			return idpool.NewIDPool[tables.SubnetName, tables.SubnetID](slog.Default(), 1, tables.SubnetIDMax)
		})),

		ClusterMeshObservers,
		Health(t.TempDir()),

		dhcpScriptCmdsCell(t),

		privnet.Cell,
	)
}

func withOverride[T any](override T) cell.Cell {
	return cell.DecorateAll(func(T) T {
		return override
	})
}

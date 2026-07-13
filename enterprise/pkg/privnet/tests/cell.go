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
	"net"
	"path"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	cni "github.com/cilium/cilium/daemon/cmd/cni/config"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	clustermesh "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
	"github.com/cilium/cilium/enterprise/pkg/privnet"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipsecfake "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	dpopt "github.com/cilium/cilium/pkg/datapath/option"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	ipamopt "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	wgfake "github.com/cilium/cilium/pkg/wireguard/fake"
	wireguard "github.com/cilium/cilium/pkg/wireguard/types"
	ztunnel "github.com/cilium/cilium/pkg/ztunnel/config"
)

func NewTestHive(t testing.TB) *hive.Hive {
	return hive.New(
		k8sClient.FakeClientCell(),
		metrics.Cell,

		diagnostics.NewCell("test", "v0.0.0"),

		cell.Config(cmtypes.DefaultClusterInfo),

		daemonk8s.ResourcesCell,
		k8sTables.TablesCell,
		node.LocalNodeStoreTestCell,

		mockEndpointCell(t),
		mockLocalCiliumNodeCell(t),
		mockGneigh(t),
		mockBPFMapCell(t),
		mockCTMaps(t),
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

					DatapathMode:         dpopt.DatapathModeVeth,
					IPAM:                 ipamopt.IPAMKubernetes,
					NodePortAcceleration: option.NodePortAccelerationDisabled,
					RoutingMode:          option.RoutingModeTunnel,
				}
			},

			// Satisfy the config validation.
			func() kpr.KPRConfig { return kpr.KPRConfig{KubeProxyReplacement: true} },
			func() clustermesh.Config { return clustermesh.Config{} },
			func() cni.Config { return cni.Config{CNIChainingMode: "none"} },
			func() ipsec.Config { return ipsecfake.Config{} },
			func() wireguard.Config { return wgfake.Config{} },
			func() ztunnel.Config { return ztunnel.Config{} },
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

		ClusterMeshObservers,
		Health(t.TempDir()),

		dhcpScriptCmdsCell(t),

		privnet.Cell,
	)
}

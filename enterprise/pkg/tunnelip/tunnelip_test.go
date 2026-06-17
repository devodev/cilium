//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tunnelip

import (
	"maps"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"unsafe"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcmap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type fakeTunnelIPMap struct {
	updates []ipcmap.RemoteEndpointInfo
	deletes int
}

func (f *fakeTunnelIPMap) Update(_ bpf.MapKey, value bpf.MapValue) error {
	f.updates = append(f.updates, *value.(*ipcmap.RemoteEndpointInfo))
	return nil
}

func (f *fakeTunnelIPMap) Delete(bpf.MapKey) error {
	f.deletes++
	return nil
}

type fakeTunnelIPNodes struct {
	nodes map[nodeTypes.Identity]nodeTypes.Node
}

func (f *fakeTunnelIPNodes) GetNodes() map[nodeTypes.Identity]nodeTypes.Node {
	return maps.Clone(f.nodes)
}

type fakeTunnelIPCache struct {
	refreshed []net.IP
}

func (f *fakeTunnelIPCache) RefreshByHost(_ ipcache.IPIdentityMappingListener, hostIP net.IP) int {
	f.refreshed = append(f.refreshed, hostIP)
	return 1
}

func newTestManager(t *testing.T, underlay tunnel.UnderlayProtocol) (*manager, *fakeTunnelIPMap, *fakeTunnelIPCache, *fakeTunnelIPNodes, *node.LocalNode, statedb.RWTable[*dptables.Device]) {
	t.Helper()

	db := statedb.New()
	devices, err := dptables.NewDeviceTable(db)
	require.NoError(t, err)
	insertTestDevice(t, db, devices, &dptables.Device{
		Index:    1,
		Name:     "eth0",
		Selected: true,
	})

	ipc := &fakeTunnelIPCache{}
	nodes := &fakeTunnelIPNodes{nodes: map[nodeTypes.Identity]nodeTypes.Node{}}
	next := &fakeTunnelIPMap{}
	ln := &node.LocalNode{
		Node: nodeTypes.Node{
			IPAddresses: []nodeTypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
			},
		},
		Local: &node.LocalNodeInfo{},
	}

	mgr := &manager{
		logger:     hivetest.Logger(t),
		ipc:        ipc,
		nodes:      nodes,
		tunnelConf: newTestTunnelConfig(underlay),
		db:         db,
		devices:    devices,
		devFilter:  dptables.DeviceFilter([]string{"eth+"}),
		next:       next,

		nodeToTunnelEndpoint: make(map[netip.Addr]netip.Addr),
	}

	return mgr, next, ipc, nodes, ln, devices
}

func newTestTunnelConfig(underlay tunnel.UnderlayProtocol) tunnel.Config {
	cfg := tunnel.NewTestConfig(tunnel.VXLAN)
	field := reflect.ValueOf(&cfg).Elem().FieldByName("underlay")
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().SetString(string(underlay))
	return cfg
}

func newRemoteNode() nodeTypes.Node {
	return nodeTypes.Node{
		Name: "remote",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.10")},
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("172.16.0.10")},
			{Type: addressing.NodeCiliumTunnelIP, IP: net.ParseIP("172.16.0.10")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::10")},
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("fd00::10")},
			{Type: addressing.NodeCiliumTunnelIP, IP: net.ParseIP("fd00::10")},
		},
	}
}

func mustAddrFromIP(t *testing.T, ip net.IP) netip.Addr {
	t.Helper()

	addr, ok := netip.AddrFromSlice(ip)
	require.True(t, ok)
	return addr.Unmap()
}

func overrideGetNextHops(t *testing.T, fn func(dev *dptables.Device, ip netip.Addr) ([]netlink.Route, error)) {
	t.Helper()

	old := getNextHops
	getNextHops = fn
	t.Cleanup(func() {
		getNextHops = old
	})
}

func TestTunnelIPSkipsUnknownHostUpdates(t *testing.T) {
	mgr, next, _, _, _, _ := newTestManager(t, "")

	value := ipcmap.NewValue(123, netip.MustParseAddr("192.0.2.10"), 5, 0)
	require.NoError(t, mgr.Update(nil, &value))
	require.Empty(t, next.updates)
}

func TestTunnelIPRefreshesWhenMappingResolves(t *testing.T) {
	mgr, next, ipc, _, _, _ := newTestManager(t, "")
	overrideGetNextHops(t, func(dev *dptables.Device, ip netip.Addr) ([]netlink.Route, error) {
		if ip == netip.MustParseAddr("172.16.0.10") {
			return []netlink.Route{{LinkIndex: dev.Index}}, nil
		}
		return nil, nil
	})

	value := ipcmap.NewValue(123, netip.MustParseAddr("192.0.2.10"), 5, 0)
	require.NoError(t, mgr.Update(nil, &value))
	require.Empty(t, next.updates)

	require.NoError(t, mgr.NodeAdd(newRemoteNode()))
	require.ElementsMatch(t, []net.IP{
		net.ParseIP("192.0.2.10"),
		net.ParseIP("2001:db8::10"),
	}, ipc.refreshed)
}

func TestTunnelIPNodeAddUsesExpectedTunnelEndpoint(t *testing.T) {
	overrideGetNextHops(t, func(dev *dptables.Device, ip netip.Addr) ([]netlink.Route, error) {
		switch ip {
		case netip.MustParseAddr("172.16.0.10"):
			return []netlink.Route{{LinkIndex: dev.Index}}, nil
		case netip.MustParseAddr("fd00::10"):
			return []netlink.Route{{LinkIndex: dev.Index}}, nil
		default:
			return nil, nil
		}
	})

	tests := []struct {
		name     string
		underlay tunnel.UnderlayProtocol
		wantIPv4 netip.Addr
		wantIPv6 netip.Addr
	}{
		{name: "dual stack", underlay: "", wantIPv4: netip.MustParseAddr("172.16.0.10"), wantIPv6: netip.MustParseAddr("fd00::10")},
		{name: "ipv4", underlay: tunnel.IPv4, wantIPv4: netip.MustParseAddr("172.16.0.10"), wantIPv6: netip.MustParseAddr("172.16.0.10")},
		{name: "ipv6", underlay: tunnel.IPv6, wantIPv4: netip.MustParseAddr("fd00::10"), wantIPv6: netip.MustParseAddr("fd00::10")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, next, _, _, _, _ := newTestManager(t, tt.underlay)
			node := newRemoteNode()

			require.NoError(t, mgr.NodeAdd(node))

			ipv4Value := ipcmap.NewValue(123, netip.MustParseAddr("192.0.2.10"), 5, 0)
			require.NoError(t, mgr.Update(nil, &ipv4Value))
			ipv6Value := ipcmap.NewValue(124, netip.MustParseAddr("2001:db8::10"), 5, 0)
			require.NoError(t, mgr.Update(nil, &ipv6Value))

			require.Len(t, next.updates, 2)
			require.Equal(t, tt.wantIPv4.Unmap(), next.updates[0].GetTunnelEndpoint().Unmap())
			require.Equal(t, tt.wantIPv6.Unmap(), next.updates[1].GetTunnelEndpoint().Unmap())
		})
	}
}

func TestTunnelIPReconcileTunnelEndpointsRefreshesChangedHosts(t *testing.T) {
	mgr, _, ipc, nodes, _, _ := newTestManager(t, tunnel.IPv4)

	node := nodeTypes.Node{
		Name: "remote",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.10")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::10")},
			{Type: addressing.NodeCiliumTunnelIP, IP: net.ParseIP("172.16.0.10")},
			{Type: addressing.NodeCiliumTunnelIP, IP: net.ParseIP("172.16.0.20")},
		},
	}
	nodes.nodes[nodeTypes.Identity{Name: node.Name, Cluster: node.Cluster}] = node

	preferSecond := false
	overrideGetNextHops(t, func(dev *dptables.Device, ip netip.Addr) ([]netlink.Route, error) {
		switch ip {
		case netip.MustParseAddr("172.16.0.10"):
			if preferSecond {
				return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_UNIVERSE}}, nil
			}
			return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_LINK}}, nil
		case netip.MustParseAddr("172.16.0.20"):
			if preferSecond {
				return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_LINK}}, nil
			}
			return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_UNIVERSE}}, nil
		default:
			return nil, nil
		}
	})

	require.NoError(t, mgr.NodeAdd(node))
	require.Equal(t, netip.MustParseAddr("172.16.0.10").Unmap(), mgr.nodeToTunnelEndpoint[mustAddrFromIP(t, node.GetNodeIP(false))].Unmap())
	require.Equal(t, netip.MustParseAddr("172.16.0.10").Unmap(), mgr.nodeToTunnelEndpoint[mustAddrFromIP(t, node.GetNodeIP(true))].Unmap())

	ipc.refreshed = nil
	preferSecond = true
	mgr.reconcileTunnelEndpoints(statedb.ToSeq(mgr.devices.List(mgr.db.ReadTxn(), dptables.DevicesBySelected(true))))

	require.Equal(t, netip.MustParseAddr("172.16.0.20").Unmap(), mgr.nodeToTunnelEndpoint[mustAddrFromIP(t, node.GetNodeIP(false))].Unmap())
	require.Equal(t, netip.MustParseAddr("172.16.0.20").Unmap(), mgr.nodeToTunnelEndpoint[mustAddrFromIP(t, node.GetNodeIP(true))].Unmap())
	require.ElementsMatch(t, []net.IP{node.GetNodeIP(false), node.GetNodeIP(true)}, ipc.refreshed)
}

func TestTunnelIPNodeAddRefreshesChangedHosts(t *testing.T) {
	mgr, _, ipc, _, _, _ := newTestManager(t, tunnel.IPv4)

	node := nodeTypes.Node{
		Name: "remote",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.10")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::10")},
			{Type: addressing.NodeCiliumTunnelIP, IP: net.ParseIP("172.16.0.10")},
			{Type: addressing.NodeCiliumTunnelIP, IP: net.ParseIP("172.16.0.20")},
		},
	}

	preferSecond := false
	overrideGetNextHops(t, func(dev *dptables.Device, ip netip.Addr) ([]netlink.Route, error) {
		switch ip {
		case netip.MustParseAddr("172.16.0.10"):
			if preferSecond {
				return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_UNIVERSE}}, nil
			}
			return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_LINK}}, nil
		case netip.MustParseAddr("172.16.0.20"):
			if preferSecond {
				return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_LINK}}, nil
			}
			return []netlink.Route{{LinkIndex: dev.Index, Scope: netlink.SCOPE_UNIVERSE}}, nil
		default:
			return nil, nil
		}
	})

	require.NoError(t, mgr.NodeAdd(node))
	require.ElementsMatch(t, []net.IP{node.GetNodeIP(false), node.GetNodeIP(true)}, ipc.refreshed)

	ipc.refreshed = nil
	preferSecond = true
	require.NoError(t, mgr.NodeUpdate(node, node))

	require.Equal(t, netip.MustParseAddr("172.16.0.20").Unmap(), mgr.nodeToTunnelEndpoint[mustAddrFromIP(t, node.GetNodeIP(false))].Unmap())
	require.Equal(t, netip.MustParseAddr("172.16.0.20").Unmap(), mgr.nodeToTunnelEndpoint[mustAddrFromIP(t, node.GetNodeIP(true))].Unmap())
	require.ElementsMatch(t, []net.IP{node.GetNodeIP(false), node.GetNodeIP(true)}, ipc.refreshed)
}

func TestSyncLocalNodeTunnelIPs(t *testing.T) {
	mgr, _, _, _, ln, devices := newTestManager(t, "")

	insertTestDevice(t, mgr.db, devices, &dptables.Device{
		Index:    1,
		Name:     "eth0",
		Selected: true,
		Addrs: []dptables.DeviceAddress{
			{Addr: netip.MustParseAddr("198.51.100.10")},
			{Addr: netip.MustParseAddr("10.0.0.8")},
			{Addr: netip.MustParseAddr("10.0.0.2")},
			{Addr: netip.MustParseAddr("fe80::1")},
		},
	})
	insertTestDevice(t, mgr.db, devices, &dptables.Device{
		Index:    2,
		Name:     "eth1",
		Selected: false,
		Addrs:    []dptables.DeviceAddress{{Addr: netip.MustParseAddr("10.0.0.4")}},
	})
	insertTestDevice(t, mgr.db, devices, &dptables.Device{
		Index:    3,
		Name:     "ens3",
		Selected: true,
		Addrs:    []dptables.DeviceAddress{{Addr: netip.MustParseAddr("10.0.0.42")}},
	})

	lni := localNodeInit{
		db:      mgr.db,
		devices: devices,
		filter:  mgr.devFilter,
	}
	lni.initFunc(t.Context(), ln)
	require.Equal(t, []string{"192.0.2.1", "10.0.0.2", "10.0.0.8", "198.51.100.10"}, addressStrings(ln.IPAddresses))

	syncLocalNodeTunnelIPs(mgr.devFilter, statedb.ToSeq(mgr.devices.List(mgr.db.ReadTxn(), dptables.DevicesBySelected(true))), ln)
	require.Equal(t, []string{"192.0.2.1", "10.0.0.2", "10.0.0.8", "198.51.100.10"}, addressStrings(ln.IPAddresses))

	insertTestDevice(t, mgr.db, devices, &dptables.Device{
		Index:    1,
		Name:     "eth0",
		Selected: true,
		Addrs: []dptables.DeviceAddress{
			{Addr: netip.MustParseAddr("10.0.0.9")},
			{Addr: netip.MustParseAddr("10.0.0.4")},
		},
	})

	syncLocalNodeTunnelIPs(mgr.devFilter, statedb.ToSeq(mgr.devices.List(mgr.db.ReadTxn(), dptables.DevicesBySelected(true))), ln)
	require.Equal(t, []string{"192.0.2.1", "10.0.0.4", "10.0.0.9"}, addressStrings(ln.IPAddresses))
}

func insertTestDevice(t *testing.T, db *statedb.DB, devices statedb.RWTable[*dptables.Device], dev *dptables.Device) {
	t.Helper()

	wtxn := db.WriteTxn(devices)
	_, _, err := devices.Insert(wtxn, dev)
	require.NoError(t, err)
	wtxn.Commit()
}

func addressStrings(addrs []nodeTypes.Address) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.IP.String())
	}
	return out
}

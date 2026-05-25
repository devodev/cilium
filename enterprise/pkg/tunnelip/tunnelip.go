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
	"cmp"
	"context"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/container/set"
	dpipc "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcmap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

const deviceReconciliationMinInterval = time.Minute

// getNextHops is a wrapper around RouteGetWithOptions that the unit test can override.
var getNextHops = func(dev *dptables.Device, ip netip.Addr) ([]netlink.Route, error) {
	return safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		return netlink.RouteGetWithOptions(ip.AsSlice(), &netlink.RouteGetOptions{
			OifIndex: dev.Index,
			FIBMatch: true,
		})
	})
}

type params struct {
	cell.In

	Logger     *slog.Logger
	Config     Config
	TunnelConf tunnel.Config
	IPCache    *ipcache.IPCache
	Nodes      nodemanager.NodeManager
	DB         *statedb.DB
	Devices    statedb.Table[*dptables.Device]
}

type refreshingIPCache interface {
	RefreshByHost(ipcache.IPIdentityMappingListener, net.IP) int
}

type tunnelIPNodes interface {
	GetNodes() map[nodeTypes.Identity]nodeTypes.Node
}

type manager struct {
	logger      *slog.Logger
	ipc         refreshingIPCache
	bpfListener ipcache.IPIdentityMappingListener
	nodes       tunnelIPNodes
	tunnelConf  tunnel.Config
	db          *statedb.DB
	devices     statedb.Table[*dptables.Device]
	devFilter   dptables.DeviceFilter

	next dpipc.Map

	mu                   lock.Mutex
	nodeToTunnelEndpoint map[netip.Addr]netip.Addr
}

func newManager(in params, bpfListener ipcache.IPIdentityMappingListener) *manager {
	if len(in.Config.PreferredTunnelEndpointDevices) == 0 {
		return nil
	}

	return &manager{
		logger:      in.Logger,
		ipc:         in.IPCache,
		bpfListener: bpfListener,
		nodes:       in.Nodes,
		tunnelConf:  in.TunnelConf,
		db:          in.DB,
		devices:     in.Devices,
		devFilter:   dptables.DeviceFilter(in.Config.PreferredTunnelEndpointDevices),

		nodeToTunnelEndpoint: make(map[netip.Addr]netip.Addr),
	}
}

func (m *manager) SetNext(next dpipc.Map) {
	m.next = next
}

func (m *manager) Update(key bpf.MapKey, value bpf.MapValue) error {
	rei := value.(*ipcmap.RemoteEndpointInfo)
	if rei.Flags&ipcmap.FlagHasTunnelEndpoint == 0 {
		return m.next.Update(key, value)
	}

	hostAddr := rei.GetTunnelEndpoint().Unmap()
	tunnelAddr, ok := m.lookupMapping(hostAddr)
	if !ok {
		m.logger.Debug("Tunnel mapping not known for host, skipping IPCache update until refresh",
			logfields.HostIP, hostAddr,
		)
		return nil
	}

	// Since we might go from a IPv4 to IPv6 tunnel endpoint or vice versa, clear
	// the tunnel endpoint flags and let [ipcache.NewValue] set the right one.
	flags := rei.Flags &^ (ipcmap.FlagHasTunnelEndpoint | ipcmap.FlagIPv6TunnelEndpoint)
	*rei = ipcmap.NewValue(rei.SecurityIdentity, tunnelAddr, rei.Key, flags)

	return m.next.Update(key, value)
}

func (m *manager) Delete(key bpf.MapKey) error {
	return m.next.Delete(key)
}

func (m *manager) lookupMapping(hostAddr netip.Addr) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mappedAddr, ok := m.nodeToTunnelEndpoint[hostAddr]
	return mappedAddr, ok
}

func (m *manager) deleteMappingLocked(nodeIP net.IP) {
	if nodeIP == nil {
		return
	}
	nodeAddr, ok := netip.AddrFromSlice(nodeIP)
	if !ok {
		return
	}
	delete(m.nodeToTunnelEndpoint, nodeAddr.Unmap())
}

func (m *manager) lookupTunnelIP(devices iter.Seq[*dptables.Device], n nodeTypes.Node, ipv6 bool) netip.Addr {
	type result struct {
		addr  netip.Addr
		route netlink.Route
	}

	var (
		results    []result
		candidates []netip.Addr
	)

	for _, ip := range n.IPAddresses {
		if ip.Type == addressing.NodeCiliumTunnelIP {
			if addr, ok := netip.AddrFromSlice(ip.IP); ok {
				candidates = append(candidates, addr.Unmap())
			}
		}
	}

	for dev := range devices {
		match, excluded := m.devFilter.Match(dev.Name)
		if !match || excluded {
			continue
		}
		for _, ip := range candidates {
			if ip.Is6() != ipv6 {
				continue
			}
			routes, err := getNextHops(dev, ip)
			if err != nil {
				m.logger.Warn("Failed to resolve next hop",
					logfields.IPAddr, ip,
					logfields.Error, err)
				continue
			}
			for _, route := range routes {
				results = append(results, result{addr: ip, route: route})
			}
		}
	}

	// Sort the candidates first by scope (narrower first), then by
	// link index (links added later win) and finally by address to break
	// ties.
	slices.SortStableFunc(results, func(a, b result) int {
		return cmp.Or(
			cmp.Compare(b.route.Scope, a.route.Scope),
			cmp.Compare(b.route.LinkIndex, a.route.LinkIndex),
			a.addr.Compare(b.addr),
		)
	})

	if len(results) > 0 {
		return results[0].addr
	}

	if len(candidates) > 0 {
		m.logger.Warn("Failed to find suitable tunnel endpoint. Falling back to node IP.",
			logfields.Node, n.Name,
			logfields.Candidates, candidates,
		)
	}
	addr, _ := netip.AddrFromSlice(n.GetNodeIP(ipv6))
	return addr
}

// NodeAdd implements [node.Handler]
func (m *manager) NodeAdd(newNode nodeTypes.Node) error {
	m.mu.Lock()
	devices := statedb.ToSeq(m.devices.List(m.db.ReadTxn(), dptables.DeviceSelectedIndex.Query(true)))
	hostsToRefresh := m.syncNodeLocked(devices, newNode)
	m.mu.Unlock()

	for _, hostIP := range hostsToRefresh {
		m.ipc.RefreshByHost(m.bpfListener, hostIP)
	}
	return nil
}

// NodeDelete implements [node.Handler]
func (m *manager) NodeDelete(node nodeTypes.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deleteMappingLocked(node.GetNodeIP(true))
	m.deleteMappingLocked(node.GetNodeIP(false))
	return nil
}

// NodeUpdate implements [node.Handler]
func (m *manager) NodeUpdate(oldNode nodeTypes.Node, newNode nodeTypes.Node) error {
	m.mu.Lock()
	if !oldNode.GetNodeIP(true).Equal(newNode.GetNodeIP(true)) {
		m.deleteMappingLocked(oldNode.GetNodeIP(true))
	}
	if !oldNode.GetNodeIP(false).Equal(newNode.GetNodeIP(false)) {
		m.deleteMappingLocked(oldNode.GetNodeIP(false))
	}
	m.mu.Unlock()
	return m.NodeAdd(newNode)
}

func (m *manager) reconcileTunnelEndpoints(devices iter.Seq[*dptables.Device]) {
	nodes := m.nodes.GetNodes()
	hostsToRefresh := set.NewSet[netip.Addr]()

	m.mu.Lock()
	for _, n := range nodes {
		for _, hostIP := range m.syncNodeLocked(devices, n) {
			hostAddr, ok := netip.AddrFromSlice(hostIP)
			if !ok {
				continue
			}
			hostsToRefresh.Insert(hostAddr.Unmap())
		}
	}
	m.mu.Unlock()

	for hostAddr := range hostsToRefresh.Members() {
		ip := hostAddr.As16()
		m.ipc.RefreshByHost(m.bpfListener, ip[:])
	}
}

// AllNodeValidateImplementation implements [node.Handler]
func (m *manager) AllNodeValidateImplementation() {}

// Name implements [node.Handler]
func (m *manager) Name() string {
	return "tunnelip"
}

// NodeValidateImplementation implements [node.Handler]
func (m *manager) NodeValidateImplementation(node nodeTypes.Node) error {
	return nil
}

func (m *manager) syncNodeLocked(devices iter.Seq[*dptables.Device], n nodeTypes.Node) []net.IP {
	hostsToRefresh := make([]net.IP, 0, 2)

	switch m.tunnelConf.UnderlayProtocol() {
	case tunnel.IPv4:
		internalIP := m.lookupTunnelIP(devices, n, false)
		hostsToRefresh = m.reconcileMappingLocked(hostsToRefresh, n.GetNodeIP(false), internalIP)
		hostsToRefresh = m.reconcileMappingLocked(hostsToRefresh, n.GetNodeIP(true), internalIP)
	case tunnel.IPv6:
		internalIP := m.lookupTunnelIP(devices, n, true)
		hostsToRefresh = m.reconcileMappingLocked(hostsToRefresh, n.GetNodeIP(false), internalIP)
		hostsToRefresh = m.reconcileMappingLocked(hostsToRefresh, n.GetNodeIP(true), internalIP)
	default:
		hostsToRefresh = m.reconcileMappingLocked(hostsToRefresh, n.GetNodeIP(false), m.lookupTunnelIP(devices, n, false))
		hostsToRefresh = m.reconcileMappingLocked(hostsToRefresh, n.GetNodeIP(true), m.lookupTunnelIP(devices, n, true))
	}

	return hostsToRefresh
}

func (m *manager) reconcileMappingLocked(hostsToRefresh []net.IP, nodeIP net.IP, tunnelAddr netip.Addr) []net.IP {
	if nodeIP == nil || !tunnelAddr.IsValid() {
		return hostsToRefresh
	}

	nodeAddr, ok := netip.AddrFromSlice(nodeIP)
	if !ok {
		return hostsToRefresh
	}

	nodeAddr = nodeAddr.Unmap()
	tunnelAddr = tunnelAddr.Unmap()
	if m.nodeToTunnelEndpoint[nodeAddr] == tunnelAddr {
		return hostsToRefresh
	}

	prevTunnelAddr := m.nodeToTunnelEndpoint[nodeAddr]
	m.nodeToTunnelEndpoint[nodeAddr] = tunnelAddr

	if tunnelAddr != prevTunnelAddr {
		m.logger.Info("Tunnel mapping updated",
			logfields.HostIP, nodeIP,
			logfields.Previous, prevTunnelAddr,
			logfields.TunnelPeer, tunnelAddr,
		)
	}

	return append(hostsToRefresh, nodeIP)
}

func (m *manager) runDeviceSync(ctx context.Context, store *node.LocalNodeStore) error {
	for {
		ws, devs := getDevicesToSync(m.db.ReadTxn(), m.devices)
		m.reconcileTunnelEndpoints(devs)
		store.Update(func(node *node.LocalNode) {
			syncLocalNodeTunnelIPs(m.devFilter, devs, node)
		})

		if _, err := ws.Wait(ctx, deviceReconciliationMinInterval); err != nil {
			return err
		}
	}
}

func getDevicesToSync(rxn statedb.ReadTxn, devices statedb.Table[*dptables.Device]) (*statedb.WatchSet, iter.Seq[*dptables.Device]) {
	ws := statedb.NewWatchSet()

	selectedDevices, watchSelected := devices.ListWatch(rxn, dptables.DeviceSelectedIndex.Query(true))
	ws.Add(watchSelected)

	hostDev, _, watchHost, found := devices.GetWatch(rxn, tables.DeviceNameIndex.Query(defaults.HostDevice))
	ws.Add(watchHost)

	return ws,
		func(yield func(*dptables.Device) bool) {
			for dev := range selectedDevices {
				if !yield(dev) {
					return
				}
			}
			if found {
				yield(hostDev)
			}
		}
}

func syncLocalNodeTunnelIPs(devFilter dptables.DeviceFilter, devices iter.Seq[*dptables.Device], localNode *node.LocalNode) {
	var newTunnelIPs []netip.Addr

	for dev := range devices {
		match, exclude := devFilter.Match(dev.Name)
		if !match || exclude {
			continue
		}

		for _, addr := range dev.Addrs {
			if addr.Addr.IsGlobalUnicast() {
				newTunnelIPs = append(newTunnelIPs, addr.Addr)
			}
		}
	}
	slices.SortFunc(newTunnelIPs, netip.Addr.Compare)

	addrs := make([]nodeTypes.Address, 0, len(localNode.IPAddresses))
	for _, addr := range localNode.IPAddresses {
		if addr.Type != addressing.NodeCiliumTunnelIP {
			addrs = append(addrs, addr)
		}
	}
	for _, addr := range newTunnelIPs {
		addrs = append(addrs, nodeTypes.Address{
			Type: addressing.NodeCiliumTunnelIP,
			IP:   addr.AsSlice(),
		})
	}

	localNode.IPAddresses = addrs
}

type localNodeInit struct {
	db      *statedb.DB
	devices statedb.Table[*dptables.Device]
	filter  dptables.DeviceFilter
}

// initFunc is called by [sync.LocalNodeSynchronizer] to fill in the tunnel IP
// before the node object is advertised to other nodes.
func (lni localNodeInit) initFunc(ctx context.Context, localNode *node.LocalNode) error {
	_, devs := getDevicesToSync(lni.db.ReadTxn(), lni.devices)
	syncLocalNodeTunnelIPs(
		lni.filter,
		devs,
		localNode,
	)
	return nil
}

var _ dpipc.ChainableMap = (*manager)(nil)
var _ node.Handler = (*manager)(nil)

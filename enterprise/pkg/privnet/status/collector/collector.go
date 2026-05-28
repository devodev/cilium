//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package collector

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/status"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
	nomgr "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	cslices "github.com/cilium/cilium/pkg/slices"

	"github.com/cilium/statedb"
)

type statusCollector struct {
	config      config.Config
	clusterInfo cmtypes.ClusterInfo

	db              *statedb.DB
	privateNetworks statedb.Table[tables.PrivateNetwork]
	attachments     statedb.Table[*tables.NodeAttachment]
	endpoints       statedb.Table[tables.Endpoint]
	mapEntries      statedb.Table[*tables.MapEntry]
	activeNetworks  statedb.Table[tables.ActiveNetwork]
	inbs            statedb.Table[tables.INB]

	nm nomgr.NodeManager
}

func (sc *statusCollector) collectNodeStatus() status.NodeStatus {
	tx := sc.db.ReadTxn()

	stat := status.NodeStatus{
		Name:              tables.NodeName(nodeTypes.GetName()),
		Cluster:           tables.ClusterName(sc.clusterInfo.Name),
		Enabled:           sc.config.Enabled,
		Mode:              sc.config.Mode,
		ConnectedClusters: sc.collectConnectedClusters(),
	}

	if !sc.config.Enabled {
		return stat
	}

	activeWorkloadNodesByNet := sc.collectActiveWorkloadNodesByNet(tx)
	inbsByNet := sc.collectINBsByNet(tx)

	for pn := range sc.privateNetworks.All(tx) {
		errs := []string{}
		pns := status.NetworkStatus{
			Name: pn.Name,
			Subnets: cslices.Map(pn.Subnets, func(s tables.PrivateNetworkSubnet) status.Subnet {
				return status.Subnet{
					Name:   s.Name,
					CIDRv4: s.CIDRv4,
					CIDRv6: s.CIDRv6,
				}
			}),
			Errors: errs,
		}

		for _, subnet := range pn.Subnets {
			for _, route := range subnet.Routes {
				pns.Routes = append(pns.Routes, status.Route{
					Destination: route.Destination,
					Gateway:     route.Gateway,
				})
			}
		}

		var ok bool
		inbs := inbsByNet[pn.Name]
		activeINB, ok := findActiveINB(inbs)
		inbs = addUnknownINBs(inbs, pn.INBs.Selectors)
		pns.WorkerStatus = status.WorkerStatus{
			ActiveINB:            activeINB,
			ConnectedINBClusters: inbs,
		}
		if !ok && len(inbs) > 0 {
			pns.Errors = append(pns.Errors, "No Active INB")
		}

		inbInterfaces := sc.collectNetworkNodeAttachments(tx, pn.Name)
		pns.INBStatus = status.INBStatus{
			Interfaces: inbInterfaces,
			Serving: slices.ContainsFunc(inbInterfaces, func(intf status.Interface) bool {
				return intf.Index > 0 // at least one interface is active
			}),
			ActiveWorkloadNodes: activeWorkloadNodesByNet[pn.Name],
		}

		for _, intf := range inbInterfaces {
			if intf.Error != "" {
				pns.Errors = append(pns.Errors, intf.Error)
			}
		}

		pns.Endpoints = sc.collectEndpointsForNet(tx, pns.Name)

		stat.Networks = append(stat.Networks, pns)
	}

	return stat
}

func (sc *statusCollector) collectActiveWorkloadNodesByNet(tx statedb.ReadTxn) map[tables.NetworkName][]status.WorkloadNode {
	activeWorkloadNodesByNet := map[tables.NetworkName][]status.WorkloadNode{}
	for cnet := range sc.activeNetworks.All(tx) {
		activeWorkloadNodesByNet[cnet.Network] = append(activeWorkloadNodesByNet[cnet.Network], status.WorkloadNode{
			Name:    cnet.Node.Name,
			Cluster: cnet.Node.Cluster,
		})
	}
	return activeWorkloadNodesByNet
}

func (sc *statusCollector) collectINBsByNet(tx statedb.ReadTxn) map[tables.NetworkName][]status.INBCluster {
	inbsByNetAndCluster := map[tables.NetworkName]map[tables.ClusterName]status.INBCluster{}

	for inb := range sc.inbs.All(tx) {
		inbsByCluster, ok := inbsByNetAndCluster[inb.Network]
		if !ok {
			inbsByCluster = map[tables.ClusterName]status.INBCluster{}
		}
		inbs := inbsByCluster[inb.Node.Cluster]
		inbs.Name = inb.Node.Cluster
		inbs.INBs = append(inbs.INBs, status.ConnectedINB{
			Cluster: inb.Node.Cluster,
			Name:    inb.Node.Name,
			Active:  inb.Role == tables.INBRoleActive,
			Healthy: inb.Health.Node == tables.INBNodeStateHealthy &&
				inb.Health.Network == tables.INBNetworkStateConfirmed,
		})
		inbsByCluster[inb.Node.Cluster] = inbs
		inbsByNetAndCluster[inb.Network] = inbsByCluster

	}

	inbByNet := map[tables.NetworkName][]status.INBCluster{}
	for net, clusters := range inbsByNetAndCluster {
		inbs := slices.SortedFunc(maps.Values(clusters), func(a, b status.INBCluster) int {
			return cmp.Compare(a.Name, b.Name)
		})
		inbByNet[net] = inbs
	}

	return inbByNet
}

func findActiveINB(clusters []status.INBCluster) (string, bool) {
	for _, cl := range clusters {
		for _, inb := range cl.INBs {
			if inb.Active {
				return fmt.Sprintf("%s/%s", inb.Cluster, inb.Name), true
			}
		}
	}
	return "", false
}

func addUnknownINBs(clusters []status.INBCluster, selectors map[tables.ClusterName]tables.Selector) []status.INBCluster {
	for _, cluster := range slices.Sorted(maps.Keys(selectors)) {
		if !slices.ContainsFunc(clusters, func(inb status.INBCluster) bool {
			return inb.Name == cluster
		}) {
			clusters = append(clusters, status.INBCluster{
				Name: cluster,
			})
		}
	}
	return clusters
}

func (sc *statusCollector) collectConnectedClusters() []status.ConnectedCluster {
	knownNodesByCluster := map[string][]tables.NodeName{}
	for _, node := range sc.nm.GetNodes() {
		knownNodesByCluster[node.Cluster] = append(knownNodesByCluster[node.Cluster], tables.NodeName(node.Name))
	}

	cc := []status.ConnectedCluster{}

	for _, cluster := range slices.Sorted(maps.Keys(knownNodesByCluster)) {
		nodes := knownNodesByCluster[cluster]
		slices.Sort(nodes)
		cc = append(cc, status.ConnectedCluster{
			Name:      tables.ClusterName(cluster),
			NodeNames: nodes,
		})
	}
	return cc
}

func (sc *statusCollector) collectEndpointsForNet(tx statedb.ReadTxn, net tables.NetworkName) []status.EndpointStatus {
	epsByName := map[string]status.EndpointStatus{}

	activePIPs := set.Set[netip.Addr]{}
	if sc.config.EnabledAsBridge() {
		for activeEP := range sc.mapEntries.Prefix(tx, tables.MapEntriesByNetworkAndType(net, tables.MapEntryTypeEndpoint)) {
			if activeEP.Routing.L2Announce {
				activePIPs.Insert(activeEP.Routing.NextHop)
			}
		}
	}

	for ep := range sc.endpoints.Prefix(tx, tables.EndpointsByNetwork(net)) {
		epStatus := epsByName[ep.Source.String()+"|"+ep.Name]
		epStatus.Name = ep.Name
		epStatus.Node = tables.NodeName(ep.NodeName)
		epStatus.Cluster = tables.ClusterName(ep.Source.Cluster)
		if ep.IP.Is4() {
			epStatus.IPv4 = ep.IP
			epStatus.NetIPv4 = ep.Network.IP
		}
		if ep.IP.Is6() {
			epStatus.IPv6 = ep.IP
			epStatus.NetIPv6 = ep.Network.IP
		}
		epStatus.External = ep.Flags.External
		epStatus.Active = epStatus.Active || activePIPs.Has(ep.IP)

		epsByName[ep.Source.String()+"|"+ep.Name] = epStatus
	}

	return slices.SortedFunc(maps.Values(epsByName), func(a, b status.EndpointStatus) int {
		return cmp.Or(cmp.Compare(a.Cluster, b.Cluster), cmp.Compare(a.Name, b.Name))
	})
}

func (sc *statusCollector) collectNetworkNodeAttachments(tx statedb.ReadTxn, net tables.NetworkName) []status.Interface {
	var networkNodeAttachments []status.Interface
	for attach := range sc.attachments.List(tx, tables.NodeAttachmentsByNetworkName(net)) {
		if attach.NodeSelector.SelectorMatches {
			var subnets []string
			for _, subnet := range attach.Subnets {
				subnets = append(subnets, string(subnet))
			}
			networkNodeAttachments = append(networkNodeAttachments, status.Interface{
				Name:    string(attach.Interface.Name),
				Index:   attach.Interface.Index,
				Error:   attach.Interface.Error,
				Subnets: subnets,
			})
		}
	}
	return networkNodeAttachments
}

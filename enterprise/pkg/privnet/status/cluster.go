//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cslices "github.com/cilium/cilium/pkg/slices"
)

// ClusterStatus is a summary of the state of the privnet subsystem for all
// nodes in the cluster
type ClusterStatus struct {
	// Name is the cluster name
	Name tables.ClusterName

	Nodes []NodeStatus
}

type nodeNetworkStatus struct {
	NetworkStatus
	nodeName tables.NodeName
}

type mergedNetworkStatus struct {
	Name tables.NetworkName
	// Nodes is a list of nodenames, where this network is available
	nodes []tables.NodeName

	// Errors are any critical error related to the network
	errors []merged[string]

	// warnings are non fatal issues. These are generally unexpected differences
	// between the status reported by different nodes.
	warnings []merged[string]

	// The set of subnets (that is, L2 domains) associated with, and directly
	// reachable, from this private network.
	subnets []merged[Subnet]
	// The set of routes configured for this private network.
	routes []merged[Route]
	// The list of known endpoint in this network
	endpoints []merged[EndpointStatus]

	// The list of configured INBs and they're status for every node.
	inbs []merged[ConnectedINB]
}

func (cs ClusterStatus) networks() []mergedNetworkStatus {
	netsByName := map[tables.NetworkName][]nodeNetworkStatus{}
	for _, ns := range cs.Nodes {
		for _, net := range ns.Networks {
			netsByName[net.Name] = append(netsByName[net.Name], nodeNetworkStatus{
				NetworkStatus: net,
				nodeName:      ns.Name,
			})
		}
	}

	netStatuses := []mergedNetworkStatus{}
	for name, nets := range netsByName {
		netStatus := mergedNetworkStatus{
			Name:   name,
			errors: mergeErrors(nets),
			inbs:   mergeINBs(nets),
		}

		nodesWNet, nodesWoNet := nodesWithNetwork(nets, cs.nodeNames())
		netStatus.nodes = nodesWNet
		if len(nodesWoNet) > 0 {
			netStatus.errors = append(netStatus.errors, merged[string]{
				nodes: nodesWoNet,
				entry: "network not configured",
			})
		}

		var warnings []merged[string]
		netStatus.subnets, warnings = mergeSubnets(nets, cs.nodeNames())
		netStatus.warnings = append(netStatus.warnings, warnings...)
		netStatus.routes, warnings = mergeRoutes(nets, cs.nodeNames())
		netStatus.warnings = append(netStatus.warnings, warnings...)
		netStatus.endpoints, warnings = mergeEndpoints(nets, cs.nodeNames())
		netStatus.warnings = append(netStatus.warnings, warnings...)

		netStatuses = append(netStatuses, netStatus)

	}

	slices.SortFunc(netStatuses, func(a, b mergedNetworkStatus) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return netStatuses
}

func (cs ClusterStatus) nodeNames() []tables.NodeName {
	res := []tables.NodeName{}
	for _, n := range cs.Nodes {
		res = append(res, n.Name)
	}
	return res
}

func mergeErrors(networks []nodeNetworkStatus) []merged[string] {
	return mergeSorted(networks, func(n NetworkStatus) []string {
		return n.Errors
	})
}

func mergeSubnets(networks []nodeNetworkStatus, allNodes []tables.NodeName) ([]merged[Subnet], []merged[string]) {
	subnets := mergeSortedFunc(networks,
		func(n NetworkStatus) []Subnet {
			return n.Subnets
		},
		func(a, b Subnet) int {
			return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.CIDRv4.String(), b.CIDRv4.String()), cmp.Compare(a.CIDRv6.String(), b.CIDRv6.String()))
		},
	)

	warnings := []merged[string]{}
	for _, subnet := range subnets {
		if len(subnet.nodes) < len(allNodes) {
			warnings = append(warnings, merged[string]{
				nodes: cslices.Diff(allNodes, subnet.nodes),
				entry: fmt.Sprintf("subnet %s not configured", subnet.unwrap().CIDRv4),
			})
		}
	}
	return subnets, warnings
}

func mergeRoutes(networks []nodeNetworkStatus, allNodes []tables.NodeName) ([]merged[Route], []merged[string]) {
	routes := mergeSortedFunc(networks,
		func(n NetworkStatus) []Route {
			return n.Routes
		},
		func(a, b Route) int {
			return cmp.Or(
				cmp.Compare(a.Destination.String(), b.Destination.String()),
				cmp.Compare(a.Gateway.String(), b.Gateway.String()),
			)
		},
	)
	warnings := []merged[string]{}
	for _, route := range routes {
		if len(route.nodes) < len(allNodes) {
			warnings = append(warnings, merged[string]{
				nodes: cslices.Diff(allNodes, route.nodes),
				entry: fmt.Sprintf("route %s via %s not configured", route.unwrap().Destination, route.unwrap().Gateway),
			})
		}
	}
	return routes, warnings
}

func mergeEndpoints(networks []nodeNetworkStatus, allNodes []tables.NodeName) ([]merged[EndpointStatus], []merged[string]) {
	eps := mergeSortedFunc(networks,
		func(n NetworkStatus) []EndpointStatus {
			return n.Endpoints
		},
		func(a, b EndpointStatus) int {
			// Make order deteminisitc, mostly for tests
			return cmp.Or(
				cmp.Compare(a.Cluster, b.Cluster),
				cmp.Compare(a.Name, b.Name),
				cmp.Compare(a.IPv4.String(), b.IPv4.String()),
				cmp.Compare(a.NetIPv4.String(), b.NetIPv4.String()),
				cmp.Compare(a.IPv6.String(), b.IPv6.String()),
				cmp.Compare(a.NetIPv6.String(), b.NetIPv6.String()),
			)
		},
	)
	warnings := []merged[string]{}
	for _, ep := range eps {
		if len(ep.nodes) < len(allNodes) {
			warnings = append(warnings, merged[string]{
				nodes: cslices.Diff(allNodes, ep.nodes),
				entry: fmt.Sprintf("endpoint %s unknown", ep.unwrap().Name),
			})
		}
	}
	return eps, warnings
}

func mergeINBs(networks []nodeNetworkStatus) []merged[ConnectedINB] {
	return mergeSortedFunc(networks,
		func(n NetworkStatus) []ConnectedINB {
			res := []ConnectedINB{}
			for _, cluster := range n.WorkerStatus.ConnectedINBClusters {
				res = append(res, cluster.INBs...)
				if len(cluster.INBs) == 0 {
					// Append a sentinel INB indicating that this node does not know anything about the INB cluster
					res = append(res, ConnectedINB{
						Name:    "",
						Cluster: cluster.Name,
						Active:  false,
						Healthy: false,
					})
				}
			}
			return res
		},
		func(a, b ConnectedINB) int {
			cmpBool := func(x, y bool) int {
				switch {
				case x && !y:
					return 1
				case !x && y:
					return -1
				default:
					return 0
				}

			}
			// Make order deteminisitc, mostly for tests
			return cmp.Or(
				cmp.Compare(a.Cluster, b.Cluster),
				cmp.Compare(a.Name, b.Name),
				cmpBool(a.Active, b.Active),
				cmpBool(a.Healthy, b.Healthy),
			)
		},
	)
}

type connectedClusterBrief struct {
	name      tables.ClusterName
	nodeCount int
}

func mergeConnectedClusters(nstatus []NodeStatus, allNodes []tables.NodeName) []merged[connectedClusterBrief] {

	CCPerNode := map[connectedClusterBrief][]tables.NodeName{}
	for _, node := range nstatus {
		for _, cc := range node.ConnectedClusters {
			b := connectedClusterBrief{
				name:      cc.Name,
				nodeCount: len(cc.NodeNames),
			}
			CCPerNode[b] = append(CCPerNode[b], node.Name)
		}
	}
	mergedCC := []merged[connectedClusterBrief]{}
	for r, ns := range CCPerNode {
		mergedCC = append(mergedCC, merged[connectedClusterBrief]{
			nodes: ns,
			entry: r,
		})
	}
	slices.SortFunc(mergedCC, func(a, b merged[connectedClusterBrief]) int {
		return cmp.Compare(a.unwrap().name, b.unwrap().name)
	})

	return mergedCC
}

func nodesWithNetwork(networks []nodeNetworkStatus, totalNodes []tables.NodeName) (nodesWithNetwork []tables.NodeName, nodesWithoutNetwork []tables.NodeName) {
	for _, n := range totalNodes {
		if slices.ContainsFunc(networks, func(ns nodeNetworkStatus) bool {
			return ns.nodeName == n
		}) {
			nodesWithNetwork = append(nodesWithNetwork, n)
		} else {
			nodesWithoutNetwork = append(nodesWithoutNetwork, n)
		}
	}
	return nodesWithNetwork, nodesWithoutNetwork
}

type merged[T comparable] struct {
	nodes []tables.NodeName
	entry T
}

func (m merged[T]) unwrap() T {
	return m.entry
}

func (m merged[T]) on(allNodes []tables.NodeName) string {
	nodeStr := fmt.Sprintf("%d/%d Nodes", len(m.nodes), len(allNodes))
	switch len(m.nodes) {
	case 1:
		return string(m.nodes[0])
	case 2:
		return fmt.Sprintf("%s, %s", m.nodes[0], m.nodes[1])
	}
	return nodeStr
}

func merge[T comparable](networks []nodeNetworkStatus, fn func(n NetworkStatus) []T) []merged[T] {
	nodes := map[T][]tables.NodeName{}
	for _, net := range networks {
		for _, r := range fn(net.NetworkStatus) {
			nodes[r] = append(nodes[r], net.nodeName)
		}
	}
	rs := []merged[T]{}
	for r, ns := range nodes {
		rs = append(rs, merged[T]{
			nodes: ns,
			entry: r,
		})
	}
	return rs
}

func mergeSortedFunc[T comparable](networks []nodeNetworkStatus, fn func(n NetworkStatus) []T, sort func(a, b T) int) []merged[T] {
	res := merge(networks, fn)
	slices.SortFunc(res, func(a, b merged[T]) int {
		return sort(a.unwrap(), b.unwrap())
	})
	return res
}

func mergeSorted[T cmp.Ordered](networks []nodeNetworkStatus, fn func(n NetworkStatus) []T) []merged[T] {
	return mergeSortedFunc(networks, fn, cmp.Compare)
}

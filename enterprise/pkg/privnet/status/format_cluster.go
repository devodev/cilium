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
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cslices "github.com/cilium/cilium/pkg/slices"
)

func (ps ClusterStatus) Format(color bool) string {
	sb := strings.Builder{}
	nodes := ps.nodeNames()

	sb.WriteString(fmtBar("Cluster", fmtHghlt(ps.Name), ps.clusterStatus(), 100))

	for _, net := range ps.networks() {
		sb.WriteString("\n")
		errStr := ""
		wrnStr := ""
		if len(net.errors) > 0 {
			errStr = fmtIndent(fmtErr(strings.Join(cslices.Map(net.errors, func(in merged[string]) string {
				return fmt.Sprintf("%s on %s", in.unwrap(), in.on(nodes))
			}), "\n")), 6) + "\n"
		}
		if len(net.warnings) > 0 {
			wrnStr = fmtIndent(fmtWrn(strings.Join(cslices.Map(net.warnings, func(in merged[string]) string {
				return fmt.Sprintf("%s on %s", in.unwrap(), in.on(nodes))
			}), "\n")), 6) + "\n"
		}

		sb.WriteString(fmtIndent(fmtBar(
			fmt.Sprintf("Network %s", fmtHghlt(net.Name)), "", networkStatus(errStr),
			98,
		)+errStr+wrnStr, 2))
		sb.WriteString(
			fmtIndent(net.formatSubnets(96, len(nodes)), 4),
		)
		sb.WriteString(
			fmtIndent(net.formatRoutes(96, len(nodes)), 4),
		)
		sb.WriteString("\n")
		sb.WriteString(
			fmtIndent(net.formatEndpoints(96, ps.Name), 4),
		)
		sb.WriteString("\n")
		sb.WriteString(
			fmtIndent(net.formatConnectedINBs(nodes), 4),
		)
	}

	if len(ps.networks()) == 0 {
		sb.WriteString(fmtInfo("No Private Networks configured"))
		sb.WriteString("\n")
	}
	sb.WriteString(
		ps.formatConnectedClusters(100),
	)

	out := sb.String()

	if !color {
		out = FmtReset(out)
	}
	return out
}

func (ps ClusterStatus) clusterStatus() string {
	if slices.ContainsFunc(ps.Nodes, func(node NodeStatus) bool {
		return slices.ContainsFunc(node.Networks, func(net NetworkStatus) bool {
			return len(net.Errors) > 0
		})
	}) {
		return "Status  " + fmtErr("DEGRADED")
	}
	return "Status  " + fmtOk("OK")
}

func networkStatus(errs string) string {
	if errs == "" {
		return fmtOk("OK")
	} else {
		return fmtErr("DEGRADED")
	}
}

func (s mergedNetworkStatus) formatSubnets(width int, totalNodes int) string {
	if len(s.subnets) == 0 {
		return "Subnets    " + fmtErr("No subnets defined for network") + "\n"
	}
	subnetStr := []string{}
	for _, subnet := range s.subnets {
		fmtAndAppend := func(cidr netip.Prefix) {
			if !cidr.IsValid() {
				return
			}
			cidrStr := cidr.String()
			if len(subnet.nodes) < totalNodes {
				cidrStr = fmtWrn(cidrStr)
			}
			subnetStr = append(subnetStr, cidrStr)
		}
		fmtAndAppend(subnet.unwrap().CIDRv4)
		fmtAndAppend(subnet.unwrap().CIDRv6)
	}
	return fmtWrapLineItemsTitle("Subnets", subnetStr, 10, width)
}

func (s mergedNetworkStatus) formatRoutes(width int, totalNodes int) string {
	if len(s.routes) == 0 {
		return "Routes    " + fmtInfo("No routes defined for network") + "\n"
	}
	routesStr := []string{}
	for _, route := range s.routes {
		str := fmt.Sprintf("%s via %s", route.unwrap().Destination.String(), route.unwrap().Gateway.String())
		if len(route.nodes) < totalNodes {
			str = fmtWrn(str)
		}
		routesStr = append(routesStr, str)
	}
	return fmtWrapLineItemsTitle("Routes", routesStr, 10, width)
}

func (s mergedNetworkStatus) formatEndpoints(width int, localCluster tables.ClusterName) string {
	if len(s.endpoints) == 0 {
		return fmtWrn("No Endpoints in Network") + "\n"
	}

	epsByCluster := map[tables.ClusterName][]merged[EndpointStatus]{}
	for _, ep := range s.endpoints {
		epsByCluster[ep.entry.Cluster] = append(epsByCluster[ep.entry.Cluster], ep)
	}

	const title = "Endpoints"

	sb := strings.Builder{}
	w := tabwriter.NewWriter(&sb, 30, 20, 2, ' ', 0)

	for _, cluster := range slices.SortedFunc(maps.Keys(epsByCluster), sortWithPin(localCluster)) {
		eps := epsByCluster[cluster]
		if cluster == localCluster {
			cluster = cluster + " (local)"
		}

		fmt.Fprintf(w, "%s\t%d Endpoints\n", cluster, len(eps))
	}
	w.Flush()
	return fmtIndentTitle(title, sb.String(), 20)
}

func (s mergedNetworkStatus) formatConnectedINBs(allNodes []tables.NodeName) string {
	if len(s.inbs) == 0 {
		return fmtInfo("No INBs configured") + "\n"
	}
	totalNodes := len(allNodes)

	inbsByCluster := map[tables.ClusterName]struct {
		healthy   int
		total     int
		serving   []tables.NodeName
		unhealthy []merged[ConnectedINB]
	}{}

	for _, inb := range s.inbs {
		inbSum := inbsByCluster[inb.unwrap().Cluster]
		inbSum.total++
		if inb.unwrap().Active {
			inbSum.serving = append(inbSum.serving, inb.nodes...)
		}
		if !inb.unwrap().Healthy {
			inbSum.unhealthy = append(inbSum.unhealthy, inb)
		} else {
			inbSum.healthy++
		}
		inbsByCluster[inb.unwrap().Cluster] = inbSum
	}

	const title = "Connected INBs"

	sb := strings.Builder{}

	for _, cluster := range slices.Sorted(maps.Keys(inbsByCluster)) {
		inbsByNode := inbsByCluster[cluster]

		switch {
		case len(inbsByNode.serving) > 0:
			sb.WriteString(fmtBar(fmtOk(cluster), "", fmtOk(fmt.Sprintf("SERVING %d/%d Nodes", len(inbsByNode.serving), totalNodes)), 45))
		case inbsByNode.healthy > 0:
			sb.WriteString(fmtBar(fmtInfo(cluster), "", fmtInfo("STANDBY"), 45))
		default:
			sb.WriteString(fmtBar(fmtErr(cluster), "", fmtErr("DEGRADED"), 45))
		}

		for _, unhealthy := range inbsByNode.unhealthy {
			errStr := fmt.Sprintf("  %s unhealthy for %s", unhealthy.unwrap().Name, unhealthy.on(allNodes))
			if unhealthy.unwrap().Name == "" {
				// sentinel node, meaning the cluster is not these nodes at all
				errStr = fmt.Sprintf("  cluster unknown to %s", unhealthy.on(allNodes))
			}
			if inbsByNode.healthy == 0 {
				errStr = fmtErr(errStr)
			} else {
				errStr = fmtWrn(errStr)
			}
			fmt.Fprint(&sb, errStr, "\n")
		}
	}
	return fmtIndentTitle(title, sb.String(), 20)
}

func (s ClusterStatus) formatConnectedClusters(width int) string {
	nodes := s.nodeNames()
	ccSum := mergeConnectedClusters(s.Nodes, nodes)

	if len(ccSum) < 2 {
		// Only the local cluster. Don't add a line for it
		return ""
	}
	ccStrings := []string{}
	for _, cc := range ccSum {
		if cc.unwrap().name == s.Name {
			continue
		}
		str := fmt.Sprintf("%s (%d Nodes)", cc.unwrap().name, cc.unwrap().nodeCount)
		if len(cc.nodes) < len(nodes) {
			str = fmtWrn(str)
		} else {
			str = fmtInfo(str)
		}
		ccStrings = append(ccStrings, str)
	}
	return "\n" + fmtWrapLineItemsTitle("Connected Clusters/INBs", ccStrings, 25, width) + "\n"
}

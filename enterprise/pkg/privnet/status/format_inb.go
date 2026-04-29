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
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

func (s NodeStatus) formatINBNode() string {
	sb := strings.Builder{}

	sb.WriteString(fmtBar("Network Bridge", fmtHghlt(s.Name), s.nodeStatus(), 100))
	sb.WriteString("\n")

	for _, net := range s.Networks {
		sb.WriteString(net.formatINBNetwork(s.ConnectedClusters, s.Cluster, s.Name))
		sb.WriteString("\n")
	}
	if len(s.Networks) == 0 {
		sb.WriteString(fmtInfo("No Private Networks configured"))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(s.formatConnectedClusters())

	return sb.String()
}

func (s NodeStatus) formatConnectedClusters() string {
	clusterStrs := []string{}
	for _, cc := range s.ConnectedClusters {
		if cc.Name == s.Cluster {
			continue
		}
		clusterStrs = append(clusterStrs, fmtHghlt(fmt.Sprintf("%s (%d Nodes)", cc.Name, len(cc.NodeNames))))
	}
	if len(clusterStrs) == 0 {
		return fmtWrn("No clusters connected") + "\n"
	}
	return fmtWrapLineItemsTitle("Connected Clusters", clusterStrs, 24, 100)
}

func (pn NetworkStatus) formatINBNetwork(connectedClusters []ConnectedCluster, localCluster tables.ClusterName, localNode tables.NodeName) string {
	sum := summarizeConnectedCluster(pn, connectedClusters, localCluster, localNode)

	sb := strings.Builder{}

	sb.WriteString(fmtIndent(pn.inbNetworkStatusLine(sum, 98), 2))

	sb.WriteString(fmtIndent(pn.INBStatus.formatInterfaces(96), 4))
	sb.WriteString(fmtIndent(pn.formatSubnets(96), 4))
	sb.WriteString(fmtIndent(pn.formatRoutes(96), 4))

	sb.WriteString(fmtIndent(sum.formatINBEndpointBar(96), 4))
	sb.WriteString("\n")
	sb.WriteString(fmtIndent(sum.formatINBServedNodes(localCluster), 4))

	return sb.String()
}

func (pn NetworkStatus) inbNetworkStatusLine(sum connectedEndpointsSummary, width int) string {
	errStr := ""
	if len(pn.Errors) > 0 {
		errStr = fmtIndent(fmtErr(strings.Join(pn.Errors, "\n"))+"\n", 4)
	}
	activeInterfaces := 0
	for _, intf := range pn.INBStatus.Interfaces {
		if intf.Index > 0 {
			activeInterfaces += 1
		}
	}

	return fmtBar(
		fmt.Sprintf("Network %s", fmtHghlt(pn.Name)),
		fmt.Sprintf("Active Interfaces %d", activeInterfaces),
		pn.inbNetworkStatus(sum),
		width,
	) + errStr
}
func (pn NetworkStatus) inbNetworkStatus(sum connectedEndpointsSummary) string {
	switch {
	case pn.INBStatus.Serving && sum.activeNodes() > 0:
		return fmtOk("SERVING")
	case pn.INBStatus.Serving:
		return fmtInfo("STANDBY")
	case len(pn.Errors) == 0:
		return fmtWrn("NOT SERVING")
	default:
		return fmtErr("DEGRADED")
	}
}

func (inb INBStatus) formatInterfaces(width int) string {
	if len(inb.Interfaces) == 0 {
		return "Interfaces    " + fmtErr("No interfaces attached for network") + "\n"
	}

	var interfacesStr []string
	for _, iface := range inb.Interfaces {
		var sb strings.Builder
		sb.WriteString(iface.String())
		sb.WriteString(", State")

		if iface.Index > 0 {
			sb.WriteString(fmtOk(" UP"))
		} else {
			sb.WriteString(fmtWrn(" DOWN"))
		}

		sb.WriteString(", Subnets")
		if len(iface.Subnets) == 0 { // when no subnet is specified, all subnets are served via the device
			sb.WriteString(fmtOk(" (<all>)"))
		} else {
			sb.WriteString(fmtOk(fmt.Sprintf(" (%s)", strings.Join(iface.Subnets, ", "))))
		}

		interfacesStr = append(interfacesStr, sb.String())
	}

	return fmtWrapLineItemsTitle("Interfaces", interfacesStr, 10, width)
}

func (sum connectedEndpointsSummary) formatINBEndpointBar(width int) string {
	return fmtBar(
		fmt.Sprintf("External Endpoints %d", sum.localExtEPs),
		func() string {
			if sum.activeEps > 0 {
				return fmt.Sprintf("Served Endpoints %d", sum.activeEps)
			} else {
				return fmtInfo(fmt.Sprintf("Served Endpoints %d", sum.activeEps))
			}
		}(),
		fmt.Sprintf("Total Endpoints %d", sum.totalEps),
		width)
}

func (sum connectedEndpointsSummary) formatINBServedNodes(localCluster tables.ClusterName) string {
	if len(sum.clusters) < 2 {
		return fmtInfo("Not severing any cluster")
	}

	const title = "Served Nodes"
	sb := strings.Builder{}
	w := tabwriter.NewWriter(&sb, 20, 20, 2, ' ', 0)

	for _, cluster := range slices.Sorted(maps.Keys(sum.clusters)) {
		info := sum.clusters[cluster]
		if cluster == localCluster {
			// Don't show the local cluster. We currently don't serve the local
			// cluster for the INB. Maybe revisit once we have local breakout
			continue
		}

		activeNodeStr := fmt.Sprintf("%s\t%d/%d (%d/%d endpoints)", cluster, info.activeNodes, info.totalNodes, info.activeEps, info.totalEps-info.extEps)
		if info.activeNodes > 0 {
			activeNodeStr = fmtOk(activeNodeStr)
		} else {
			activeNodeStr = fmtInfo(activeNodeStr)
		}
		fmt.Fprint(w, activeNodeStr, "\n")
	}
	w.Flush()
	return fmtIndentTitle(title, sb.String(), 20)
}

func (sum connectedEndpointsSummary) activeNodes() int {
	activeNodes := 0
	for _, cluster := range sum.clusters {
		activeNodes += cluster.activeNodes
	}
	return activeNodes
}

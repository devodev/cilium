//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"cmp"
	"net/netip"
	"strconv"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/node/types"
)

type (
	// ClusterName is the name of a cluster.
	ClusterName string

	// NodeName is the name of a node.
	NodeName string
)

// Node is a slim version of [types.Node] with only the fields required
// by the private networks reconcilers.
type Node struct {
	// Cluster is the name of the cluster the node lives in.
	Cluster ClusterName

	// Name is the name of the node.
	Name NodeName

	// IP is the tunnel endpoint address of the given node.
	IP netip.Addr

	// APIPort is the TCP port the privnet API server is listening to.
	APIPort uint16

	// labels are the labels associated with the node. This field is unexported
	// to enforce the usage of the [ValidAndSelectedBy] helper.
	labels labels.Set
}

// NewNode creates a new Node from a [types.Node] instance, appropriately selecting
// the tunnel endpoint address based on whether IPv6 underlay is preferred.
func NewNode(node types.Node, ipv6Underlay bool, defAPIPort uint16) *Node {
	ip, _ := netip.AddrFromSlice(node.GetNodeIP(ipv6Underlay))
	port, _ := strconv.ParseUint(node.Annotations[PrivateNetworkINBAPIServerPortAnnotation], 10, 16)

	return &Node{
		Cluster: ClusterName(node.Cluster),
		Name:    NodeName(node.Name),
		labels:  node.Labels,

		IP:      ip.Unmap(),
		APIPort: cmp.Or(uint16(port), defAPIPort),
	}
}

// ValidAndSelectedBy returns whether the node is selected by the given selector,
// and it is valid (i.e., its tunnel endpoint address is valid).
func (no *Node) ValidAndSelectedBy(selector labels.Selector) bool {
	return no.IP.IsValid() && !no.IP.IsUnspecified() && selector.Matches(no.labels)
}

func (no *Node) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(no.IP, no.APIPort)
}

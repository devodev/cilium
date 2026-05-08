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
	"net"

	"github.com/cilium/cilium/pkg/node/addressing"
)

// GetCiliumTunnelIP returns the Cilium tunnel IP for the node, or nil if not found.
func (n *Node) GetCiliumTunnelIP() net.IP {
	for _, addr := range n.IPAddresses {
		if addr.Type == addressing.NodeCiliumTunnelIP {
			return addr.IP
		}
	}

	return nil
}

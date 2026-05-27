// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"bytes"
	"maps"
	"net/netip"

	"github.com/cilium/cilium/pkg/mac"
)

const (
	// PropertyPrivNetNetwork is the name of the network this endpoint is attached to. If unset, then the endpoint is
	// not attached to a custom private network.
	PropertyPrivNetNetwork = "isovalent-privnet-network"

	// PropertyPrivNetSubnet is the name of the subnet this endpoint is attached to.
	PropertyPrivNetSubnet = "isovalent-privnet-subnet"

	// PropertyPrivNetIPv4 contains the IPv4 address of the endpoint within the network.
	PropertyPrivNetIPv4 = "isovalent-privnet-ipv4-addr"

	// PropertyPrivNetIPv4UsesDHCP records whether the endpoint was configured to
	// obtain its IPv4 address via DHCP rather than from an explicit annotation.
	PropertyPrivNetIPv4UsesDHCP = "isovalent-privnet-ipv4-uses-dhcp"

	// PropertyPrivNetIPv6 contains the IPv6 address of the endpoint within the network.
	PropertyPrivNetIPv6 = "isovalent-privnet-ipv6-addr"

	// PropertyPrivNetActivatedAt contains the timestamp when the endpoint became active.
	PropertyPrivNetActivatedAt = "isovalent-privnet-activated-at"

	// PropertyPrivNetNICIndex contains the index of the NIC of the workload.
	PropertyPrivNetNICIndex = "isovalent-privnet-nic-index"
)

type EndpointProperties struct {
	Network    string
	MAC        mac.MAC
	IPv4, IPv6 netip.Addr
	Labels     map[string]string
}

func (e *EndpointProperties) Equal(other *EndpointProperties) bool {
	return e.Network == other.Network &&
		e.IPv4 == other.IPv4 &&
		e.IPv6 == other.IPv6 &&
		bytes.Equal(e.MAC, other.MAC) &&
		maps.Equal(e.Labels, other.Labels)
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func mustIPAddrPrefixNLRI(prefix string) bgp.NLRI {
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	if err != nil {
		panic(err)
	}
	return nlri
}

func mustPathAttributeNextHop(addr string) *bgp.PathAttributeNextHop {
	attr, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(addr))
	if err != nil {
		panic(err)
	}
	return attr
}

func mustPathAttributeMpReachNLRI(family bgp.Family, nextHop string, nlris ...bgp.NLRI) *bgp.PathAttributeMpReachNLRI {
	pathNLRIs := make([]bgp.PathNLRI, 0, len(nlris))
	for _, nlri := range nlris {
		pathNLRIs = append(pathNLRIs, bgp.PathNLRI{NLRI: nlri})
	}

	attr, err := bgp.NewPathAttributeMpReachNLRI(family, pathNLRIs, netip.MustParseAddr(nextHop))
	if err != nil {
		panic(err)
	}
	return attr
}

func mustLabeledVPNIPAddrPrefix(prefix netip.Prefix, labelStack bgp.MPLSLabelStack, rd bgp.RouteDistinguisherInterface) *bgp.LabeledVPNIPAddrPrefix {
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, labelStack, rd)
	if err != nil {
		panic(err)
	}
	return nlri
}

func mustEVPNIPPrefixRoute(rd bgp.RouteDistinguisherInterface, esi bgp.EthernetSegmentIdentifier, etag uint32, prefixLen uint8, ipPrefix string, gateway string, label uint32) *bgp.EVPNNLRI {
	prefixAddr := netip.MustParseAddr(ipPrefix)
	gatewayAddr := zeroAddrForFamily(prefixAddr)
	if gateway != "" {
		gatewayAddr = netip.MustParseAddr(gateway)
	}

	nlri, err := bgp.NewEVPNIPPrefixRoute(rd, esi, etag, prefixLen, prefixAddr, gatewayAddr, label)
	if err != nil {
		panic(err)
	}
	return nlri
}

func mustEVPNMacIPAdvertisementRoute(rd bgp.RouteDistinguisherInterface, esi bgp.EthernetSegmentIdentifier, etag uint32, macAddress string, ipAddress string, labels []uint32) *bgp.EVPNNLRI {
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(rd, esi, etag, macAddress, netip.MustParseAddr(ipAddress), labels)
	if err != nil {
		panic(err)
	}
	return nlri
}

func zeroAddrForFamily(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

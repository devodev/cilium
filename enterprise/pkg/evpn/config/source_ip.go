// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

// SourceIPs holds IP addresses usable as EVPN source IP addresses.
type SourceIPs struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// SourceIPsFromDevice detects IP addresses usable as EVPN source IP addresses on a device.
func SourceIPsFromDevice(dev *tables.Device) (SourceIPs, error) {
	var res SourceIPs
	for _, addr := range dev.Addrs {
		if !isUsableSourceAddr(addr.Addr) {
			continue
		}
		switch {
		case addr.Addr.Is4():
			if res.IPv4.IsValid() {
				return res, fmt.Errorf("multiple usable IPv4 source addresses found")
			}
			res.IPv4 = addr.Addr
		case addr.Addr.Is6():
			if res.IPv6.IsValid() {
				return res, fmt.Errorf("multiple usable IPv6 source addresses found")
			}
			res.IPv6 = addr.Addr
		}
	}
	return res, nil
}

func isUsableSourceAddr(addr netip.Addr) bool {
	if addr.Is4In6() {
		return false
	}
	if addr.Is6() {
		return addr.IsGlobalUnicast()
	}
	if addr.Is4() {
		return addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast()
	}
	return false
}

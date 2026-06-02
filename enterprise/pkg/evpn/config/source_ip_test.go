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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

func TestSourceIPsFromDevice(t *testing.T) {
	tests := []struct {
		name      string
		addrs     []tables.DeviceAddress
		want      SourceIPs
		wantError string
	}{
		{
			name: "no addresses",
		},
		{
			name: "usable IPv4 and IPv6 addresses",
			addrs: []tables.DeviceAddress{
				deviceAddr("10.0.0.1"),
				deviceAddr("2001:db8::1"),
			},
			want: SourceIPs{
				IPv4: netip.MustParseAddr("10.0.0.1"),
				IPv6: netip.MustParseAddr("2001:db8::1"),
			},
		},
		{
			name: "IPv4 link-local address is usable",
			addrs: []tables.DeviceAddress{
				deviceAddr("169.254.1.1"),
			},
			want: SourceIPs{
				IPv4: netip.MustParseAddr("169.254.1.1"),
			},
		},
		{
			name: "unusable addresses are ignored",
			addrs: []tables.DeviceAddress{
				{},
				deviceAddr("0.0.0.0"),
				deviceAddr("127.0.0.1"),
				deviceAddr("224.0.0.1"),
				deviceAddr("::"),
				deviceAddr("::1"),
				deviceAddr("ff00::1"),
				deviceAddr("fe80::1"),
				deviceAddr("::ffff:192.0.2.1"),
			},
		},
		{
			name: "multiple usable IPv4 addresses fail",
			addrs: []tables.DeviceAddress{
				deviceAddr("10.0.0.1"),
				deviceAddr("192.0.2.1"),
			},
			wantError: "multiple usable IPv4 source addresses found",
		},
		{
			name: "multiple usable IPv6 addresses fail",
			addrs: []tables.DeviceAddress{
				deviceAddr("2001:db8::1"),
				deviceAddr("2001:db8::2"),
			},
			wantError: "multiple usable IPv6 source addresses found",
		},
		{
			name: "duplicate unusable addresses do not fail",
			addrs: []tables.DeviceAddress{
				deviceAddr("127.0.0.1"),
				deviceAddr("127.0.0.2"),
				deviceAddr("fe80::1"),
				deviceAddr("fe80::2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SourceIPsFromDevice(&tables.Device{
				Name:  "eth0",
				Index: 1,
				Addrs: tt.addrs,
			})

			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func deviceAddr(addr string) tables.DeviceAddress {
	return tables.DeviceAddress{Addr: netip.MustParseAddr(addr)}
}

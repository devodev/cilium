//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

func TestAllocateEgressIPsForGroup(t *testing.T) {
	testCases := []struct {
		name              string
		cidrs             []netip.Prefix
		gatewaysByAZ      map[string][]netip.Addr
		prevAllocs        map[netip.Addr]netip.Addr
		healthyGatewayIPs []netip.Addr
		expected          map[netip.Addr]netip.Addr
		expectedError     bool
	}{
		{
			name: "no previous allocations",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			prevAllocs: nil,
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.10"),
			},
		},
		{
			name: "with previous allocations",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
		},
		{
			name: "with in-active gateways, 10.0.0.2 and 10.0.0.3 are in-active but healthy",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
			},
			// should not release the egress IPs of 10.0.0.2 and 10.0.0.3
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
		},
		{
			name: "no enough address with in-active gateways",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
			},
			// It should release the egress IPs 10.0.0.5: 192.168.0.11 and allocate it to an active gateway 10.0.0.1
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
			},
			expectedError: true,
		},
		{
			name: "with affinity zones",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
			},
		},
		{
			name: "in-active gateways with affinity zones, 10.0.0.4, 10.0.0.5 and 10.0.0.6 are in-active but healthy",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			// should not release the egress IPs of 10.0.0.4, 10.0.0.5 and 10.0.0.6
			// The allocation priority is in the order of zone2(the number of alloc is 0),
			// then zone1(the number of alloc is 1(10.0.0.2: 192.168.0.12 from provAllocs)).
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
			},
		},
		{
			name: "not enough addresses",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
			},
			expectedError: true,
		},
		{
			name: "rebalanced allocations",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			// zone-1 should give up an address in favor of zone-3
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.9"),
			},
			expectedError: true,
		},
		{
			name: "rebalanced allocations using egress IPs of inactive gateways",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.8"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
				netip.MustParseAddr("10.0.0.7"),
				netip.MustParseAddr("10.0.0.8"),
			},
			// It should release egress IPs for inactive gateways(10.0.0.7: 192.168.0.10, 10.0.0.8: 192.168.0.11)
			// and allocates them to zone-2 and zone-3
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
			},
			expectedError: true,
		},
		{
			name: "allocations not rebalanced",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/31"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			// not enough addresses to cover all zones, thus no rebalance
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			pool, err := newPool(tc.cidrs...)
			require.NoErrorf(t, err, "unexpected error while creating pool for CIDRs %v", tc.cidrs)

			allocs, err := allocateEgressIPsForGroup(logger, pool, tc.gatewaysByAZ, tc.prevAllocs, tc.healthyGatewayIPs)
			if !tc.expectedError {
				require.NoErrorf(t, err, "unexpected error while allocating egress IPs")
			} else {
				require.Errorf(t, err, "expected error while allocating egress IPs, got nil")
			}

			require.Equal(t, tc.expected, allocs)
		})
	}
}

type expectedValues struct {
	allocsByAZ                  map[string]map[netip.Addr]netip.Addr
	egressIPsOfInactiveGateways map[netip.Addr]netip.Addr
}

func TestEnsureZonesCoverage(t *testing.T) {
	testCases := []struct {
		name                        string
		gatewaysByAZ                map[string][]netip.Addr
		egressIPsByAZ               map[string]map[netip.Addr]netip.Addr
		egressIPsOfInactiveGateways map[netip.Addr]netip.Addr
		expected                    expectedValues
	}{
		{
			name: "one zone to cover",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
				},
				"zone-3": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
						netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.12"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			},
		},
		{
			name: "one zone to cover using an egressIP of inactive gateway",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
				},
				"zone-3": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.12"): netip.MustParseAddr("192.168.0.14"),
			},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
						netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
						netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{
					netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.13"),
				},
			},
		},
		{
			name: "multiple zones to cover",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
				"zone-4": {
					netip.MustParseAddr("10.0.0.11"),
					netip.MustParseAddr("10.0.0.12"),
				},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"),
					netip.MustParseAddr("10.0.0.14"),
				},
				"zone-6": {
					netip.MustParseAddr("10.0.0.15"),
					netip.MustParseAddr("10.0.0.16"),
					netip.MustParseAddr("10.0.0.17"),
					netip.MustParseAddr("10.0.0.18"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
					netip.MustParseAddr("10.0.0.8"): netip.MustParseAddr("192.168.0.13"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
				},
				"zone-4": {},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
				},
				"zone-6": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.13"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
					},
					"zone-4": {
						netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.12"),
					},
					"zone-5": {
						netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
					},
					"zone-6": {
						netip.MustParseAddr("10.0.0.15"): netip.MustParseAddr("192.168.0.11"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			},
		},
		{
			name: "multiple zones to cover using egressIPs of inactive gateway",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
				"zone-4": {
					netip.MustParseAddr("10.0.0.11"),
					netip.MustParseAddr("10.0.0.12"),
				},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"),
					netip.MustParseAddr("10.0.0.14"),
				},
				"zone-6": {
					netip.MustParseAddr("10.0.0.15"),
					netip.MustParseAddr("10.0.0.16"),
					netip.MustParseAddr("10.0.0.17"),
					netip.MustParseAddr("10.0.0.18"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
					netip.MustParseAddr("10.0.0.8"): netip.MustParseAddr("192.168.0.13"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
				},
				"zone-4": {},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
				},
				"zone-6": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.19"): netip.MustParseAddr("192.168.0.16"),
			},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.16"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
						netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
					},
					"zone-4": {
						netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.13"),
					},
					"zone-5": {
						netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
					},
					"zone-6": {
						netip.MustParseAddr("10.0.0.15"): netip.MustParseAddr("192.168.0.12"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allocsByAZ, egressIPsOfInactiveGateways := ensureZonesCoverage(tc.gatewaysByAZ, tc.egressIPsByAZ, tc.egressIPsOfInactiveGateways)
			require.Equal(t, tc.expected.allocsByAZ, allocsByAZ)
			require.Equal(t, tc.expected.egressIPsOfInactiveGateways, egressIPsOfInactiveGateways)
		})
	}
}

// TestGetIEGPForStatusUpdateConditions verifies that getIEGPForStatusUpdate seeds
// the returned policy's Conditions with the existing ones from the cached IEGP, so
// that meta.SetStatusCondition can preserve LastTransitionTime across no-op
// reconciliations. Without this, every reconcile would write a fresh timestamp,
// defeating the status-equality short-circuit in updateGroupStatuses and causing
// an endless UpdateStatus -> informer -> reconcile loop for IPAM IEGPs.
func TestGetIEGPForStatusUpdateConditions(t *testing.T) {
	const generation int64 = 3
	prior := meta_v1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))

	newSatisfied := func(status meta_v1.ConditionStatus) meta_v1.Condition {
		return meta_v1.Condition{
			Type:               egwIPAMRequestSatisfied,
			Status:             status,
			ObservedGeneration: generation,
			LastTransitionTime: meta_v1.Now(),
			Reason:             "noreason",
			Message:            "allocation requests satisfied",
		}
	}

	existingSatisfied := meta_v1.Condition{
		Type:               egwIPAMRequestSatisfied,
		Status:             meta_v1.ConditionTrue,
		ObservedGeneration: generation,
		LastTransitionTime: prior,
		Reason:             "noreason",
		Message:            "allocation requests satisfied",
	}

	t.Run("no-op reconcile short-circuits updateGroupStatuses", func(t *testing.T) {
		iegp := &v1.IsovalentEgressGatewayPolicy{
			Status: v1.IsovalentEgressGatewayPolicyStatus{
				Conditions: []meta_v1.Condition{existingSatisfied},
			},
		}

		out := getIEGPForStatusUpdate(iegp, nil, []meta_v1.Condition{newSatisfied(meta_v1.ConditionTrue)})

		// The cached and newly-built Conditions must be equal so that the early
		// return in updateGroupStatuses fires. If this is false, the operator
		// will call UpdateStatus on the IEGP every reconciliation and loop
		// forever via the informer callback.
		require.Equal(t, iegp.Status.Conditions, out.Status.Conditions,
			"cached vs new conditions must be equal so updateGroupStatuses short-circuits")

		// verify the cached IEGP still holds the original condition untouched.
		// Otherwise the equality check above would pass simply because both sides
		// alias the same backing array.
		require.Equal(t, []meta_v1.Condition{existingSatisfied}, iegp.Status.Conditions,
			"cached IEGP must not be mutated by getIEGPForStatusUpdate")
	})

	t.Run("status transition produces a distinct conditions slice", func(t *testing.T) {
		iegp := &v1.IsovalentEgressGatewayPolicy{
			Status: v1.IsovalentEgressGatewayPolicyStatus{
				Conditions: []meta_v1.Condition{existingSatisfied},
			},
		}

		out := getIEGPForStatusUpdate(iegp, nil, []meta_v1.Condition{newSatisfied(meta_v1.ConditionFalse)})

		// When the status actually transitions the new conditions must differ
		// from the cached ones, otherwise the short-circuit in
		// updateGroupStatuses would swallow legitimate updates.
		require.NotEqual(t, iegp.Status.Conditions, out.Status.Conditions,
			"cached vs new conditions must differ on transition")
		require.Len(t, out.Status.Conditions, 1)
		require.Equal(t, meta_v1.ConditionFalse, out.Status.Conditions[0].Status)
		require.False(t, out.Status.Conditions[0].LastTransitionTime.Equal(&prior),
			"LastTransitionTime should be refreshed when Status transitions")

		// Cached IEGP must still be untouched so the next reconcile can compare
		// against the pre-update state.
		require.Equal(t, []meta_v1.Condition{existingSatisfied}, iegp.Status.Conditions)
	})

	t.Run("appends new condition when none exists", func(t *testing.T) {
		iegp := &v1.IsovalentEgressGatewayPolicy{}
		cond := newSatisfied(meta_v1.ConditionTrue)

		out := getIEGPForStatusUpdate(iegp, nil, []meta_v1.Condition{cond})
		require.Equal(t, []meta_v1.Condition{cond}, out.Status.Conditions)
	})

	t.Run("drops stale conditions not in the new set", func(t *testing.T) {
		// Simulate a recovery reconcile: the cached IEGP carries a failure
		// condition plus an auxiliary egwIPAMPoolExhausted, then the allocation
		// recovers and the new set only contains IPAMRequestSatisfied=True.
		// The auxiliary condition must be pruned so callers asserting on a
		// single-entry Conditions slice (e.g. TestEgressCIDRAllocation) keep
		// working, and so stale status is not reported to users.
		iegp := &v1.IsovalentEgressGatewayPolicy{
			Status: v1.IsovalentEgressGatewayPolicyStatus{
				Conditions: []meta_v1.Condition{
					{
						Type:               egwIPAMRequestSatisfied,
						Status:             meta_v1.ConditionFalse,
						ObservedGeneration: generation,
						LastTransitionTime: prior,
						Reason:             "noreason",
						Message:            "allocation requests not satisfied",
					},
					{
						Type:               egwIPAMPoolExhausted,
						Status:             meta_v1.ConditionUnknown,
						ObservedGeneration: generation,
						LastTransitionTime: prior,
						Reason:             "noreason",
						Message:            "unable to fulfill allocations",
					},
				},
			},
		}

		satisfied := newSatisfied(meta_v1.ConditionTrue)
		out := getIEGPForStatusUpdate(iegp, nil, []meta_v1.Condition{satisfied})

		require.Equal(t, []meta_v1.Condition{satisfied}, out.Status.Conditions)
	})
}

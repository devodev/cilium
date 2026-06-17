//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"fmt"
	"net/netip"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/lock"
)

func mockIPAMCell(t testing.TB) cell.Cell {
	t.Helper()
	return cell.Group(
		cell.ProvidePrivate(newFakeIPAMAllocator),
		cell.Provide(
			func(f *fakeIPAMAllocator) uhive.ScriptCmdsOut { return uhive.NewScriptCmds(f.cmds()) },
		),
		cell.DecorateAll(func(f *fakeIPAMAllocator) endpoints.IPAM { return f }),
	)
}

type ipPair struct {
	ipv4 netip.Addr
	ipv6 netip.Addr
}

type fakeIPAMAllocator struct {
	mu           lock.Mutex
	reservedIPs  map[ipamOwner]ipPair
	allocatedIPs map[netip.Addr]ipamOwner
}

type ipamOwner = string

func newFakeIPAMAllocator() *fakeIPAMAllocator {
	return &fakeIPAMAllocator{
		reservedIPs:  make(map[ipamOwner]ipPair),
		allocatedIPs: make(map[netip.Addr]ipamOwner),
	}
}

// AllocateNext implements endpoints.IPAM
func (f *fakeIPAMAllocator) AllocateNext(family, owner string, pool ipam.Pool) (ipv4Result, ipv6Result *ipam.AllocationResult, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	pair, ok := f.reservedIPs[owner]
	if !ok {
		return nil, nil, fmt.Errorf("no reserved IP for owner %q. Use privnet/ipam-reserve to reserve an IP first", owner)
	}

	if ipv4 := pair.ipv4; (family == "" || family == "ipv4") && ipv4.IsValid() {
		if other, ok := f.allocatedIPs[ipv4]; ok {
			return nil, nil, fmt.Errorf("IPv4 already allocated for owner: %q", other)
		}
		ipv4Result = &ipam.AllocationResult{
			IP: ipv4,
		}
		f.allocatedIPs[ipv4] = owner
	}
	if ipv6 := pair.ipv6; (family == "" || family == "ipv6") && ipv6.IsValid() {
		if other, ok := f.allocatedIPs[ipv6]; ok {
			return nil, nil, fmt.Errorf("IPv6 already allocated for owner: %q", other)
		}
		ipv6Result = &ipam.AllocationResult{
			IP: ipv6,
		}
		f.allocatedIPs[ipv6] = owner
	}

	return ipv4Result, ipv6Result, nil
}

// AllocateIPWithoutSyncUpstream implements endpoints.IPAM
func (f *fakeIPAMAllocator) AllocateIPWithoutSyncUpstream(addr netip.Addr, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	pair, ok := f.reservedIPs[owner]
	if !ok {
		return nil, fmt.Errorf("no reserved IP for owner %q. Use privnet/ipam-reserve to reserve an IP first", owner)
	}

	reserved := pair.ipv4
	if addr.Is6() {
		reserved = pair.ipv6
	}
	if addr != reserved {
		return nil, fmt.Errorf("requested IP %s does not match reserved IP %s for owner %q", addr, reserved, owner)
	}

	if other, ok := f.allocatedIPs[addr]; ok {
		return nil, fmt.Errorf("IP already allocated for owner: %q", other)
	}

	f.allocatedIPs[addr] = owner
	return &ipam.AllocationResult{
		IP: addr,
	}, nil
}

// ReleaseIP implements endpoints.IPAM
func (f *fakeIPAMAllocator) ReleaseIP(addr netip.Addr, pool ipam.Pool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.allocatedIPs, addr)
	return nil
}

func (f *fakeIPAMAllocator) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		"privnet/ipam-reserve": f.reserveCmd(),
	}
}

func (f *fakeIPAMAllocator) reserveCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Reserve an IP pair for allocation to a given owner",
			Args:    "owner ipv4-addr ipv6-addr",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 3 {
				return nil, fmt.Errorf("%w: expected number of arguments", script.ErrUsage)
			}

			owner := args[0]
			ipv4, err := netip.ParseAddr(args[1])
			if err != nil || !ipv4.Is4() {
				return nil, fmt.Errorf("invalid IPv4 address: %s", args[1])
			}
			ipv6, err := netip.ParseAddr(args[2])
			if err != nil || !ipv6.Is6() {
				return nil, fmt.Errorf("invalid IPv6 address: %s", args[1])
			}

			f.mu.Lock()
			f.reservedIPs[owner] = ipPair{
				ipv4: ipv4,
				ipv6: ipv6,
			}
			f.mu.Unlock()

			return nil, nil
		},
	)
}

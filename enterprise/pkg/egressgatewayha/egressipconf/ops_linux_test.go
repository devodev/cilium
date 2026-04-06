//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build linux

package egressipconf

import (
	"context"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

const (
	egressIP1 = "192.168.1.50"
)

func filterEgressIPs(nlAddrs []netlink.Addr, label string) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		if label != "" && nlAddr.Label != label {
			continue
		}

		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}

	return addrs
}

func runTest(t *testing.T, prepareLink func(*netlink.Handle, netlink.Link, string)) {
	testutils.PrivilegedTest(t)

	var (
		nlh *netlink.Handle
		err error
	)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = netlink.NewHandle()
		return err
	}))
	t.Cleanup(func() {
		ns.Close()
	})

	// Create a dummy device to test with
	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("dummy0")
	})
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link))
	ifName := link.Attrs().Name

	egressIP := netip.MustParseAddr(egressIP1)

	prepareLink(nlh, link, egressIP1)

	ops := newOps(slog.New(slog.DiscardHandler), newMockGNeighSender())

	// Initial Update()
	entry := &tables.EgressIPEntry{
		Addr:      egressIP,
		Interface: ifName,
		Status:    reconciler.StatusPending(),
	}

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, entry)
	})
	require.NoError(t, err, "expected no error from initial update")

	// Egress IP should have been added to device
	nlAddrs, err := safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")

	addrs := make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.Containsf(t, addrs, egressIP, "egress IP %s not found in %s device", egressIP, ifName)

	// Further Update() with the same entry should not do anything
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, entry)
	})
	require.NoError(t, err, "expected no error from second update")

	// Non-existing devices return an error
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "non-existent",
		})
	})
	require.Error(t, err, "expected error from update of non-existing device")

	// Delete()
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: ifName,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from delete")

	// Egress IP should have been removed from device
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")

	addrs = make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.NotContainsf(t, addrs, egressIP, "egress IP %s found in %s device after deletion", egressIP, ifName)

	// Further Delete() should not do anything
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: ifName,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from delete")

	// Non-existing devices return an error
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "non-existent",
		})
	})
	require.Error(t, err, "expected error from delete of non-existing device")

	// *** Virtual Egress IP

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "",
			Status:    reconciler.StatusPending(),
		})

	})
	require.NoError(t, err, "expected no error from initial update")

	// Virtual Egress IP should not be set on the node
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(nil, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")

	addrs = make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.NotContainsf(t, addrs, egressIP, "found virtual egress IP %s on the node", egressIP)

	// Delete() should not do anything
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "",
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from delete")
}

func TestPrivilegedClean(t *testing.T) {
	prepare := func(nlh *netlink.Handle, link netlink.Link, egressIP string) {}

	runTest(t, prepare)
}

// Tolerate that the egressIP is already set on the interface. Reconcile the
// other pieces.
func TestPrivilegedRestart(t *testing.T) {
	prepare := func(nlh *netlink.Handle, link netlink.Link, egressIP string) {
		addr := addrForEgressIP(netip.MustParseAddr(egressIP), egressIPLabel)
		if err := nlh.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}

	runTest(t, prepare)
}

// Tolerate that an unlabeled egressIP is already set on the interface. Reconcile the
// other pieces.
func TestPrivilegedRestartWithoutLabel(t *testing.T) {
	prepare := func(nlh *netlink.Handle, link netlink.Link, egressIP string) {
		addr := addrForEgressIP(netip.MustParseAddr(egressIP), "")
		if err := nlh.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}

	runTest(t, prepare)
}

func TestPrivilegedPrune(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		nlh *netlink.Handle
		err error
	)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = netlink.NewHandle()
		return err
	}))
	t.Cleanup(func() {
		ns.Close()
	})

	// Create dummy devices to test with
	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("dummy0")
	})
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link))
	ifName := link.Attrs().Name

	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy1",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link1, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("dummy1")
	})
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link1))
	ifName1 := link1.Attrs().Name

	ops := newOps(slog.New(slog.DiscardHandler), newMockGNeighSender())

	egressIP_1 := netip.MustParseAddr("192.168.1.50")
	egressIP_2 := netip.MustParseAddr("192.168.1.100")

	entries := []*tables.EgressIPEntry{
		{
			Addr:      egressIP_1,
			Interface: ifName,
		},
		{
			Addr:      egressIP_2,
			Interface: ifName,
		},
	}

	// call Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, 0, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake iterator containing entries for:
	//
	// <egressIP_2>
	//
	// then call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator(&tables.EgressIPEntry{
			Addr:      egressIP_2,
			Interface: ifName,
		}))
	})
	require.NoError(t, err, "ops.Prune")

	// egressIP_1 should have been deleted
	nlAddrs, err := safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs := filterEgressIPs(nlAddrs, "")
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_2})

	// call again Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, 0, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake iterator containing an entry for:
	//
	// <egressIP_1>
	//
	// then call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator(
			&tables.EgressIPEntry{
				Addr:      egressIP_1,
				Interface: ifName,
			}))
	})
	require.NoError(t, err, "ops.Prune")

	// egressIP_2 should have been deleted
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs = filterEgressIPs(nlAddrs, "")
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_1})

	// build a fake empty iterator and call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator())
	})
	require.NoError(t, err, "ops.Prune")

	// egress IPs should have been deleted
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs = filterEgressIPs(nlAddrs, "")
	require.Empty(t, addrs)

	// *** Addrs should also be deleted when not associated with any interface

	// call again Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, 0, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake iterator containing an entry for:
	//
	// <egressIP_1>
	// <egressIP_2>
	//
	// then call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator(
			// Virtual IP, not bound to any interface
			&tables.EgressIPEntry{
				Addr:      egressIP_1,
				Interface: "",
			},
			// IP has magically moved to another interface
			&tables.EgressIPEntry{
				Addr:      egressIP_2,
				Interface: ifName1,
			},
		))
	})
	require.NoError(t, err, "ops.Prune")

	// egress IPs should have been deleted
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs = filterEgressIPs(nlAddrs, "")
	require.Empty(t, addrs)

	// *** Now validate that we don't prune old-style IPs:

	// Add an unlabeled IP, and reconcile the rest:
	addr := addrForEgressIP(egressIP_2, "")
	if err = nlh.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}

	// call again Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, 0, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake empty iterator and call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator())
	})
	require.NoError(t, err, "ops.Prune")

	// egressIP_2 should still be there
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs = filterEgressIPs(nlAddrs, "")
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_2})
}

func newFakeIterator(objs ...*tables.EgressIPEntry) iter.Seq2[*tables.EgressIPEntry, statedb.Revision] {
	return func(yield func(*tables.EgressIPEntry, statedb.Revision) bool) {
		for _, obj := range objs {
			if !yield(obj, 0) {
				return
			}
		}
	}
}

func newMockGNeighSender() gneigh.Sender {
	return &mockGNeighSender{}
}

type mockGNeighSender struct{}

func (gs *mockGNeighSender) SendArp(iface gneigh.Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (gs *mockGNeighSender) SendNd(iface gneigh.Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (gs *mockGNeighSender) NewArpSender(iface gneigh.Interface) (gneigh.ArpSender, error) {
	return &mockArpSender{}, nil
}

func (gs *mockGNeighSender) NewNdSender(iface gneigh.Interface) (gneigh.NdSender, error) {
	return &mockNdSender{}, nil
}

func (gs *mockGNeighSender) InterfaceByIndex(idx int) (gneigh.Interface, error) {
	return gneigh.InterfaceFromNetInterface(&net.Interface{}), nil
}

type mockArpSender struct{}

func (as *mockArpSender) Send(ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (as *mockArpSender) Close() error {
	return nil
}

type mockNdSender struct{}

func (ns *mockNdSender) Send(ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (ns *mockNdSender) Close() error {
	return nil
}

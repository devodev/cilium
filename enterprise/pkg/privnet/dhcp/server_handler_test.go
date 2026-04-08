// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dhcp

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type fakeRelay struct {
	calls int
	resp  *dhcpv4.DHCPv4
}

func (f *fakeRelay) Relay(_ context.Context, _ time.Duration, _ *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	f.calls++
	if f.resp == nil {
		return nil, nil
	}
	return []*dhcpv4.DHCPv4{f.resp}, nil
}

type fakeRelayFactory struct {
	relay Relayer
}

func (f *fakeRelayFactory) RelayFor(*tables.LocalWorkload) (Relayer, error) {
	return f.relay, nil
}

func setupHandlerTestState(t *testing.T) (*statedb.DB, statedb.RWTable[*tables.LocalWorkload], *tables.DHCPLeaseWriter, statedb.Table[tables.DHCPLease], statedb.RWTable[tables.Subnet], *tables.LocalWorkload, *dhcpv4.DHCPv4, net.HardwareAddr) {
	t.Helper()
	log := hivetest.Logger(t)

	db := statedb.New()
	workloads, err := tables.NewLocalWorkloadsTable(db)
	require.NoError(t, err)

	leaseWriter, leases, err := tables.NewDHCPLeaseWriter(log, db, &option.DaemonConfig{
		StateDir: t.TempDir(),
	}, hivetest.Lifecycle(t))
	require.NoError(t, err)

	subnets, err := tables.NewSubnetTable(db)
	require.NoError(t, err)

	reqMAC := net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	req, err := dhcpv4.NewDiscovery(reqMAC)
	require.NoError(t, err)

	lw := &tables.LocalWorkload{
		EndpointID: 10,
		Namespace:  "ns",
		Subnet:     "default-v4",
		UsesDHCPv4: true,
		Endpoint: iso_v1alpha1.PrivateNetworkEndpointSliceEndpoint{
			Name: "pod",
		},
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: "blue",
			MAC:     reqMAC.String(),
		},
		LXC: tables.LocalWorkloadLXC{
			IfName:  "lxc123",
			IfIndex: 10,
		},
	}

	wtxn := db.WriteTxn(workloads)
	workloads.Insert(wtxn, lw)
	wtxn.Commit()

	wtxn = db.WriteTxn(subnets)
	subnets.Insert(wtxn, tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network: "blue",
			Name:    "default-v4",
			CIDRv4:  netip.MustParsePrefix("192.168.1.0/24"),
		},
		DHCP: iso_v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: iso_v1alpha1.PrivateNetworkDHCPModeBroadcast,
		},
	})
	wtxn.Commit()

	return db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC
}

func TestHandlerWritesLeaseOnAck(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.YourIPAddr = net.IPv4(192, 168, 1, 10)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	resp.UpdateOption(dhcpv4.OptServerIdentifier(net.IPv4(192, 168, 1, 1)))
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(120 * time.Second))
	resp.UpdateOption(dhcpv4.OptRenewTimeValue(60 * time.Second))
	factory := &fakeRelayFactory{relay: &fakeRelay{resp: resp}}

	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, factory, 500*time.Millisecond)
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	h.now = func() time.Time { return now }

	// Process the DHCP request and the returning ack via the [fakeRelay].
	handler := h.serverHandler()
	_, resps, err := handler(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)
	require.Len(t, resps, 1)

	txn := db.ReadTxn()

	// The DHCP lease table should now contain the allocated IP
	m, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.True(t, found)
	require.Equal(t, netip.MustParseAddr("192.168.1.10"), m.IPv4)
	require.Equal(t, netip.MustParseAddr("192.168.1.1"), m.ServerID)
	require.Equal(t, now, m.ObtainedAt)
	require.Equal(t, now.Add(60*time.Second), m.RenewAt)
	require.Equal(t, now.Add(120*time.Second), m.ExpireAt)

}

func TestHandlerRenewsLeaseOnAckSameIP(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)

	oldNow := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	newNow := oldNow.Add(10 * time.Minute)
	oldRenew := oldNow.Add(60 * time.Second)
	oldExpire := oldNow.Add(120 * time.Second)

	wtxn := db.WriteTxn(workloads, leases)
	workloads.Insert(wtxn, &tables.LocalWorkload{
		EndpointID: lw.EndpointID,
		Namespace:  lw.Namespace,
		Subnet:     lw.Subnet,
		UsesDHCPv4: lw.UsesDHCPv4,
		Endpoint:   lw.Endpoint,
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: lw.Interface.Network,
			MAC:     lw.Interface.MAC,
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
		LXC: lw.LXC,
	})
	leaseWriter.Insert(wtxn, tables.DHCPLease{
		Network:    "blue",
		EndpointID: lw.EndpointID,
		MAC:        mac.MAC(reqMAC),
		IPv4:       netip.MustParseAddr("192.168.1.10"),
		ObtainedAt: oldNow,
		RenewAt:    oldRenew,
		ExpireAt:   oldExpire,
	})
	wtxn.Commit()

	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.YourIPAddr = net.IPv4(192, 168, 1, 10)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	resp.UpdateOption(dhcpv4.OptServerIdentifier(net.IPv4(192, 168, 1, 1)))
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(300 * time.Second))
	resp.UpdateOption(dhcpv4.OptRenewTimeValue(150 * time.Second))
	factory := &fakeRelayFactory{relay: &fakeRelay{resp: resp}}

	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, factory, 500*time.Millisecond)
	h.now = func() time.Time { return newNow }
	_, _, err = h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)

	txn := db.ReadTxn()
	lease, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.True(t, found)
	require.Equal(t, newNow, lease.ObtainedAt)
	require.Equal(t, newNow.Add(150*time.Second), lease.RenewAt)
	require.Equal(t, newNow.Add(300*time.Second), lease.ExpireAt)
}

func TestHandlerClearsLeaseOnNak(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	wtxn := db.WriteTxn(workloads, leases)
	workloads.Insert(wtxn, &tables.LocalWorkload{
		EndpointID: lw.EndpointID,
		Namespace:  lw.Namespace,
		Subnet:     lw.Subnet,
		UsesDHCPv4: lw.UsesDHCPv4,
		Endpoint:   lw.Endpoint,
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: lw.Interface.Network,
			MAC:     lw.Interface.MAC,
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
		LXC: lw.LXC,
	})
	leaseWriter.Insert(wtxn, tables.DHCPLease{
		Network:    "blue",
		EndpointID: lw.EndpointID,
		MAC:        mac.MAC(reqMAC),
		IPv4:       netip.MustParseAddr("192.168.1.10"),
		ObtainedAt: now,
	})
	wtxn.Commit()

	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
	factory := &fakeRelayFactory{relay: &fakeRelay{resp: resp}}

	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, factory, 500*time.Millisecond)
	_, _, err = h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)

	txn := db.ReadTxn()
	_, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.False(t, found)
}

func TestHandlerClearsLeaseOnReleaseRequest(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)

	wtxn := db.WriteTxn(workloads, leases)
	workloads.Insert(wtxn, &tables.LocalWorkload{
		EndpointID: lw.EndpointID,
		Namespace:  lw.Namespace,
		Subnet:     lw.Subnet,
		UsesDHCPv4: lw.UsesDHCPv4,
		Endpoint:   lw.Endpoint,
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: lw.Interface.Network,
			MAC:     lw.Interface.MAC,
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
		LXC: lw.LXC,
	})
	leaseWriter.Insert(wtxn, tables.DHCPLease{
		Network:    "blue",
		EndpointID: lw.EndpointID,
		MAC:        mac.MAC(reqMAC),
		IPv4:       netip.MustParseAddr("192.168.1.10"),
	})
	wtxn.Commit()

	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))
	req.ClientIPAddr = net.IPv4(192, 168, 1, 10)
	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, &fakeRelayFactory{relay: &fakeRelay{}}, 500*time.Millisecond)

	_, _, err := h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)

	txn := db.ReadTxn()
	_, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.False(t, found)
}

func TestHandlerClearsLeaseOnDeclineRequest(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)

	wtxn := db.WriteTxn(workloads, leases)
	workloads.Insert(wtxn, &tables.LocalWorkload{
		EndpointID: lw.EndpointID,
		Namespace:  lw.Namespace,
		Subnet:     lw.Subnet,
		UsesDHCPv4: lw.UsesDHCPv4,
		Endpoint:   lw.Endpoint,
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: lw.Interface.Network,
			MAC:     lw.Interface.MAC,
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
		LXC: lw.LXC,
	})
	leaseWriter.Insert(wtxn, tables.DHCPLease{
		Network:    "blue",
		EndpointID: lw.EndpointID,
		MAC:        mac.MAC(reqMAC),
		IPv4:       netip.MustParseAddr("192.168.1.10"),
	})
	wtxn.Commit()

	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	req.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IPv4(192, 168, 1, 10)))
	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, &fakeRelayFactory{relay: &fakeRelay{}}, 500*time.Millisecond)

	_, _, err := h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)

	txn := db.ReadTxn()
	_, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.False(t, found)
}

func TestHandlerIgnoresAckOutsideConfiguredSubnets(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.YourIPAddr = net.IPv4(10, 10, 10, 10)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	factory := &fakeRelayFactory{relay: &fakeRelay{resp: resp}}

	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, factory, 500*time.Millisecond)
	_, resps, err := h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)
	require.Empty(t, resps)

	txn := db.ReadTxn()
	_, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.False(t, found)
}

func TestHandlerSkipsRelayForStaticIPv4Workload(t *testing.T) {
	db, workloads, leaseWriter, _, subnets, lw, req, _ := setupHandlerTestState(t)

	staticLW := *lw
	staticLW.UsesDHCPv4 = false
	staticLW.Interface.Addressing.IPv4 = "192.168.1.10"

	wtxn := db.WriteTxn(workloads)
	_, _, err := workloads.Insert(wtxn, &staticLW)
	require.NoError(t, err)
	wtxn.Commit()

	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.YourIPAddr = net.IPv4(192, 168, 1, 10)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	relay := &fakeRelay{resp: resp}

	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, &fakeRelayFactory{relay: relay}, 500*time.Millisecond)
	_, resps, err := h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)
	require.Empty(t, resps)
	require.Zero(t, relay.calls)
}

func TestHandlerIgnoresAckOutsideWorkloadSubnet(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)

	wtxn := db.WriteTxn(subnets)
	subnets.Insert(wtxn, tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network: "blue",
			Name:    "other-v4",
			CIDRv4:  netip.MustParsePrefix("192.168.2.0/24"),
		},
	})
	wtxn.Commit()

	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.YourIPAddr = net.IPv4(192, 168, 2, 10)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	factory := &fakeRelayFactory{relay: &fakeRelay{resp: resp}}

	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, factory, 500*time.Millisecond)
	_, resps, err := h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)
	require.Empty(t, resps)

	txn := db.ReadTxn()
	_, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.False(t, found)
}

func TestHandlerIgnoresOfferOutsideWorkloadSubnet(t *testing.T) {
	db, workloads, leaseWriter, leases, subnets, lw, req, reqMAC := setupHandlerTestState(t)

	wtxn := db.WriteTxn(subnets)
	subnets.Insert(wtxn, tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network: "blue",
			Name:    "other-v4",
			CIDRv4:  netip.MustParsePrefix("192.168.2.0/24"),
		},
	})
	wtxn.Commit()

	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.YourIPAddr = net.IPv4(192, 168, 2, 10)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	factory := &fakeRelayFactory{relay: &fakeRelay{resp: resp}}

	h := newServerHandler(slog.Default(), db, workloads, leaseWriter, subnets, factory, 500*time.Millisecond)
	_, resps, err := h.serverHandler()(t.Context(), nil, lw.EndpointID, req)
	require.NoError(t, err)
	require.Empty(t, resps)

	txn := db.ReadTxn()
	_, _, found := leases.Get(txn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(reqMAC)))
	require.False(t, found)
}

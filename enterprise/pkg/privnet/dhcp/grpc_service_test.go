//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dhcp

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

func TestServiceRelayValidation(t *testing.T) {
	discover := newDHCPDiscover(t)
	svc := newServiceWithSubnet(t, nil)
	ctx := t.Context()

	t.Run("nil-request", func(t *testing.T) {
		_, err := svc.Relay(ctx, nil)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("empty-network", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{Subnet: "subnet-a", Request: discover.ToBytes(), WaitTime: durationpb.New(time.Second)})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("empty-subnet", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{Network: "blue", Request: discover.ToBytes(), WaitTime: durationpb.New(time.Second)})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("empty-payload", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{Network: "blue", Subnet: "subnet-a", WaitTime: durationpb.New(time.Second)})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("missing-wait-time", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{Network: "blue", Subnet: "subnet-a", Request: discover.ToBytes()})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("invalid-dhcp", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{
			Network:  "blue",
			Subnet:   "subnet-a",
			Request:  []byte{1, 2, 3},
			WaitTime: durationpb.New(time.Second),
		})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("relay-unavailable", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{
			Network:  "blue",
			Subnet:   "subnet-a",
			Request:  discover.ToBytes(),
			WaitTime: durationpb.New(time.Second),
		})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("subnet-not-found", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{
			Network:  "blue",
			Subnet:   "missing",
			Request:  discover.ToBytes(),
			WaitTime: durationpb.New(time.Second),
		})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("subnet-not-found-unknown-mode", func(t *testing.T) {
		_, err := svc.Relay(ctx, &api.RelayRequest{
			Network:  "blue",
			Subnet:   "missing",
			Request:  discover.ToBytes(),
			WaitTime: durationpb.New(time.Second),
			Mode:     api.RelayRequest_UNKNOWN,
		})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("network-not-inb-servable", func(t *testing.T) {
		fake := &grpcFakeRelay{}
		svc := newServiceWithSubnetAndINBSupport(t, func(mode api.RelayRequest_Mode, relayCfg *api.DHCPRelayModeConfig, iface string) (Relayer, error) {
			return fake, nil
		}, false)

		_, err := svc.Relay(ctx, &api.RelayRequest{
			Network:  "blue",
			Subnet:   "subnet-a",
			Request:  discover.ToBytes(),
			WaitTime: durationpb.New(time.Second),
			Mode:     api.RelayRequest_RELAY,
			Relay: &api.DHCPRelayModeConfig{
				ServerAddress: "192.0.2.10:67",
			},
		})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Equal(t, 0, fake.called)
	})
}

func TestServiceRelayUsesFactory(t *testing.T) {
	req := newDHCPDiscover(t)
	reqBytes := req.ToBytes()

	waitTime := 500 * time.Millisecond
	fake := &grpcFakeRelay{}
	var gotIface string
	var gotMode api.RelayRequest_Mode
	var gotRelayCfg *api.DHCPRelayModeConfig
	svc := newServiceWithSubnet(t, func(mode api.RelayRequest_Mode, relayCfg *api.DHCPRelayModeConfig, iface string) (Relayer, error) {
		gotIface = iface
		gotMode = mode
		gotRelayCfg = relayCfg
		return fake, nil
	})

	ctx := t.Context()
	resp, err := svc.Relay(ctx, &api.RelayRequest{
		Network:  "blue",
		Subnet:   "subnet-a",
		Request:  reqBytes,
		WaitTime: durationpb.New(waitTime),
		Mode:     api.RelayRequest_RELAY,
		Relay: &api.DHCPRelayModeConfig{
			ServerAddress:     "192.0.2.10:67",
			Option82CircuitId: "circuit-a",
			Option82RemoteId:  "remote-a",
		},
	})
	require.NoError(t, err)
	require.Equal(t, "eth99", gotIface)
	require.Equal(t, api.RelayRequest_RELAY, gotMode)
	require.NotNil(t, gotRelayCfg)
	require.Equal(t, "192.0.2.10:67", gotRelayCfg.GetServerAddress())
	require.Equal(t, "circuit-a", gotRelayCfg.GetOption82CircuitId())
	require.Equal(t, "remote-a", gotRelayCfg.GetOption82RemoteId())
	require.Equal(t, 1, fake.called)
	require.Equal(t, req.TransactionID, fake.lastReq.TransactionID)
	require.Equal(t, waitTime, fake.lastWait)
	require.Len(t, resp.GetResponses(), 2)
}

type grpcFakeRelay struct {
	called   int
	lastReq  *dhcpv4.DHCPv4
	lastWait time.Duration
}

func (f *grpcFakeRelay) Relay(_ context.Context, waitTime time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	f.called++
	f.lastReq = req
	f.lastWait = waitTime
	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, err
	}
	resp2, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, err
	}
	return []*dhcpv4.DHCPv4{resp, resp2}, nil
}

func TestNewRelayForServiceBroadcastModeReturnsBroadcastRelay(t *testing.T) {
	factory := newRelayForService(relayForServiceParams{
		Log:             slog.Default(),
		ReplyDispatcher: newReplyDispatcher(),
	})

	relay, err := factory(api.RelayRequest_BROADCAST, nil, "eth0")
	require.NoError(t, err)
	broadcast, ok := relay.(*broadcastRelay)
	require.True(t, ok)
	require.Equal(t, "eth0", broadcast.ifname)
}

func TestNewRelayForServiceUnknownModeReturnsError(t *testing.T) {
	factory := newRelayForService(relayForServiceParams{Log: slog.Default()})

	relay, err := factory(api.RelayRequest_UNKNOWN, nil, "eth0")
	require.Error(t, err)
	require.Nil(t, relay)
}

func TestServiceRelayUnknownModeReturnsFailedPrecondition(t *testing.T) {
	req := newDHCPDiscover(t)

	svc := newServiceWithSubnet(t, newRelayForService(relayForServiceParams{Log: slog.Default()}))

	_, err := svc.Relay(t.Context(), &api.RelayRequest{
		Network:  "blue",
		Subnet:   "subnet-a",
		Request:  req.ToBytes(),
		WaitTime: durationpb.New(500 * time.Millisecond),
		Mode:     api.RelayRequest_UNKNOWN,
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func newServiceWithSubnet(t *testing.T, factory serviceRelayFactoryFunc) *service {
	t.Helper()
	return newServiceWithSubnetAndINBSupport(t, factory, true)
}

func newServiceWithSubnetAndINBSupport(t *testing.T, factory serviceRelayFactoryFunc, inbServed bool) *service {
	t.Helper()

	db := statedb.New()
	privnets, err := tables.NewPrivateNetworksTable(db)
	require.NoError(t, err)
	subnets, err := tables.NewSubnetTable(db)
	require.NoError(t, err)

	ifindex := 0
	if inbServed {
		ifindex = 1
	}

	wtxn := db.WriteTxn(privnets, subnets)
	_, _, err = privnets.Insert(wtxn, tables.PrivateNetwork{
		Name: "blue",
	})
	require.NoError(t, err)

	_, _, err = subnets.Insert(wtxn, tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network:       "blue",
			Name:          "subnet-a",
			EgressIfIndex: ifindex,
			EgressIfName:  "eth99",
		},
	})
	require.NoError(t, err)
	wtxn.Commit()

	return newService(serviceParams{
		DB:      db,
		Subnets: subnets,
		Logger:  slog.Default(),
		Factory: factory,
	})
}

func newDHCPDiscover(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()

	hw := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	req, err := dhcpv4.NewDiscovery(hw)
	require.NoError(t, err)
	return req
}

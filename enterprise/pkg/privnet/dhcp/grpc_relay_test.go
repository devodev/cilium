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
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestGRPCRelay(t *testing.T) {
	db := statedb.New()
	inbs, err := tables.NewINBsTable(db)
	require.NoError(t, err)

	wtx := db.WriteTxn(inbs)
	inbs.Insert(wtx, tables.INB{
		Network: "blue",
		Node: tables.INBNode{
			Cluster: "local",
			Name:    "inb-0",
			IP:      netip.MustParseAddr("10.0.0.1"),
			APIPort: 4242,
		},
		Role: tables.INBRoleActive,
	})
	wtx.Commit()

	hw := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	req, err := dhcpv4.NewDiscovery(hw)
	require.NoError(t, err)

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	waitTime := 250 * time.Millisecond
	handler := &testDhcpServer{t: t, req: req, waitTime: waitTime}
	api.RegisterDHCPRelayServer(srv, handler)

	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(srv.Stop)

	relay := &grpcRelay{
		log:     slog.Default(),
		db:      db,
		inbs:    inbs,
		network: "blue",
		subnet:  "subnet-a",
		cfg: v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: v1alpha1.PrivateNetworkDHCPModeRelay,
			Relay: &v1alpha1.PrivateNetworkDHCPRelaySpec{
				ServerAddress: "192.0.2.10:67",
				Option82: &v1alpha1.PrivateNetworkDHCPOption82Spec{
					CircuitID: "circuit-a",
					RemoteID:  "remote-a",
				},
			},
		},
		factory: func(_ context.Context, cluster tables.ClusterName, node tables.NodeName, addrPort netip.AddrPort) (*grpc.ClientConn, error) {
			require.Equal(t, "local", string(cluster))
			require.Equal(t, "inb-0", string(node))
			require.Equal(t, uint16(4242), addrPort.Port())
			return grpc.NewClient(
				"passthrough:///bufnet",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return lis.Dial()
				}),
				grpc.WithDefaultCallOptions(grpc.CallContentSubtype("proto")),
			)
		},
	}

	resps, err := relay.Relay(t.Context(), waitTime, req)
	require.NoError(t, err)
	require.Len(t, resps, 2)
	require.Equal(t, req.TransactionID, resps[0].TransactionID)
}

type testDhcpServer struct {
	api.UnimplementedDHCPRelayServer
	t        *testing.T
	req      *dhcpv4.DHCPv4
	waitTime time.Duration
}

func (s *testDhcpServer) Relay(_ context.Context, r *api.RelayRequest) (*api.RelayResponse, error) {
	require.NotNil(s.t, r)
	require.Equal(s.t, "blue", r.Network)
	require.Equal(s.t, "subnet-a", r.Subnet)
	require.NotNil(s.t, r.GetWaitTime())
	require.Equal(s.t, s.waitTime, r.GetWaitTime().AsDuration())
	require.Equal(s.t, api.RelayRequest_RELAY, r.GetMode())
	require.NotNil(s.t, r.GetRelay())
	require.Equal(s.t, "192.0.2.10:67", r.GetRelay().GetServerAddress())
	require.Equal(s.t, "circuit-a", r.GetRelay().GetOption82CircuitId())
	require.Equal(s.t, "remote-a", r.GetRelay().GetOption82RemoteId())
	got, err := dhcpv4.FromBytes(r.Request)
	require.NoError(s.t, err)
	require.Equal(s.t, s.req.TransactionID, got.TransactionID)

	resp, err := dhcpv4.NewReplyFromRequest(s.req)
	require.NoError(s.t, err)
	resp2, err := dhcpv4.NewReplyFromRequest(s.req)
	require.NoError(s.t, err)
	return &api.RelayResponse{Responses: [][]byte{resp.ToBytes(), resp2.ToBytes()}}, nil
}

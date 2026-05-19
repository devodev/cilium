// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package migration

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/mac"
)

func TestClientServer(t *testing.T) {
	srv := grpc.NewServer()
	db := statedb.New()
	leases, err := tables.NewDHCPLeasesTable(db)
	require.NoError(t, err)

	network := tables.NetworkName("blue")
	mac := mac.MustParseMAC("02:00:01:e6:bb:ff")

	// Insert a lease that we can migrate
	wtxn := db.WriteTxn(leases)
	lease := tables.DHCPLease{
		Network:    network,
		EndpointID: 0,
		MAC:        mac,
		IPv4:       netip.MustParseAddr("1.2.3.4"),
		ServerID:   netip.MustParseAddr("1.2.3.255"),
		ObtainedAt: time.Unix(1, 0).UTC(),
		RenewAt:    time.Unix(2, 0).UTC(),
		ExpireAt:   time.Unix(3, 0).UTC(),
	}
	leases.Insert(wtxn, lease)
	wtxn.Commit()

	apiService := &service{
		log:    hivetest.Logger(t),
		db:     db,
		leases: leases,
	}
	api.RegisterMigrationServer(srv, apiService)
	t.Cleanup(srv.Stop)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	go func() {
		_ = srv.Serve(lis)
	}()

	factory := func(_ context.Context, cluster tables.ClusterName, node tables.NodeName, addrPort netip.AddrPort) (*grpc.ClientConn, error) {
		return grpc.NewClient(addrPort.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	stream, err := StartMigration(
		t.Context(),
		factory,
		types.Node{
			Cluster: "default",
			Name:    "worker-a",
			IP:      netip.MustParseAddr("127.0.0.1"),
			APIPort: uint16(lis.Addr().(*net.TCPAddr).Port),
		},
		network,
		mac.String(),
	)
	require.NoError(t, err)

	// Should receive the DHCP lease
	batch, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.NotEmpty(t, batch.GetDhcpLease())
	require.Equal(t, lease.ObtainedAt, batch.GetDhcpLease()[0].GetObtainedAt().AsTime())

	// Modify the DHCP lease
	wtxn = db.WriteTxn(leases)
	lease.ObtainedAt = time.Unix(4, 0).UTC()
	leases.Insert(wtxn, lease)
	wtxn.Commit()

	// After finalizing should receive the updated DHCP lease
	err = stream.Finalize()
	require.NoError(t, err)

	batch, err = stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.NotEmpty(t, batch.GetDhcpLease())
	require.Equal(t, lease.ObtainedAt, batch.GetDhcpLease()[0].GetObtainedAt().AsTime())

	batch, err = stream.Recv()
	require.ErrorIs(t, err, io.EOF)
	require.Nil(t, batch)
}

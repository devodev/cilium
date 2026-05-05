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

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

func TestClientServer(t *testing.T) {
	srv := grpc.NewServer()
	apiService := &service{
		log: hivetest.Logger(t),
	}
	api.RegisterMigrationServer(srv, apiService)
	t.Cleanup(srv.Stop)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	go func() {
		_ = srv.Serve(lis)
	}()

	factory := func(_ context.Context, target tables.INBNode) (*grpc.ClientConn, error) {
		return grpc.NewClient(target.APIAddress(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	stream, err := StartMigration(
		t.Context(),
		factory,
		tables.INBNode{
			Cluster: "default",
			Name:    "worker-a",
			IP:      netip.MustParseAddr("127.0.0.1"),
			APIPort: uint16(lis.Addr().(*net.TCPAddr).Port),
		},
		"blue", "02:00:01:e6:bb:ff",
	)
	require.NoError(t, err)

	// Should receive an empty batch with the placeholder service
	batch, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, batch)

	// After finalizing should receive one more batch after which the
	// stream closes.
	err = stream.Finalize()
	require.NoError(t, err)

	batch, err = stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, batch)

	batch, err = stream.Recv()
	require.ErrorIs(t, err, io.EOF)
	require.Nil(t, batch)
}

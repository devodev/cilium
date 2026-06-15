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
	"fmt"

	"google.golang.org/grpc"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	grpcclient "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
)

func StartMigration(ctx context.Context, factory grpcclient.ConnFactoryFn, sourceNode types.Node, network tables.NetworkName, workloadMAC string) (*Stream, error) {
	conn, err := factory(ctx, sourceNode.Cluster, sourceNode.Name, sourceNode.AddrPort())
	if err != nil {
		return nil, fmt.Errorf("dial migration target %s/%s (%s): %w", sourceNode.Cluster, sourceNode.Name, sourceNode.AddrPort(), err)
	}
	stream, err := api.NewMigrationClient(conn).Migrate(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open migration transfer stream: %w", err)
	}
	err = stream.Send(&api.MigrationRequest{
		Event: &api.MigrationRequest_Start{
			Start: &api.MigrationStart{
				Network: string(network),
				Mac:     workloadMAC,
			},
		}})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Stream{conn, stream}, nil
}

type Stream struct {
	conn   *grpc.ClientConn
	client api.Migration_MigrateClient
}

func (s *Stream) Recv() (*api.MigrationBatch, error) {
	return s.client.Recv()
}

// Finalize requests the final batch to finish the migration.
// [Stream.Recv] should be called to drain the last batches.
func (s *Stream) Finalize() error {
	return s.client.Send(&api.MigrationRequest{
		Event: &api.MigrationRequest_Finalize{}})
}

// Close the stream and the connection.
func (s *Stream) Close() {
	s.conn.Close()
}

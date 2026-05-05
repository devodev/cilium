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
	"errors"
	"io"
	"log/slog"

	"github.com/cilium/hive/cell"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
)

type service struct {
	api.UnimplementedMigrationServer

	log *slog.Logger
}

func newService(in struct {
	cell.In

	Log *slog.Logger
}) *service {
	return &service{
		log: in.Log,
	}
}

func (s *service) Migrate(stream api.Migration_MigrateServer) error {
	req, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}

	start := req.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "Start expected")
	}

	// TODO stream batch per CT map
	// TODO stream batch for DHCP leases
	stream.Send(&api.MigrationBatch{})

	req, err = stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}

	if req.GetFinalize() == nil {
		return status.Error(codes.InvalidArgument, "Finalize expected")
	}

	// TODO stream final delta for CT entries
	return stream.Send(&api.MigrationBatch{})
}

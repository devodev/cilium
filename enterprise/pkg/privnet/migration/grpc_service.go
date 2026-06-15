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
	"github.com/cilium/statedb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/mac"
)

type service struct {
	api.UnimplementedMigrationServer

	log    *slog.Logger
	db     *statedb.DB
	leases statedb.Table[tables.DHCPLease]
}

func newService(in struct {
	cell.In

	Log    *slog.Logger
	DB     *statedb.DB
	Leases statedb.Table[tables.DHCPLease]
}) *service {
	return &service{
		log:    in.Log,
		db:     in.DB,
		leases: in.Leases,
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

	// Send DHCP leases if any.
	leaseWatch, err := s.sendLease(start, stream)
	if err != nil {
		return err
	}

	// Wait for the target node to ask for final delta.
	req, err = stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	if req.GetFinalize() == nil {
		return status.Error(codes.InvalidArgument, "Finalize expected")
	}

	// Check if DHCP leases have changed.
	select {
	case <-leaseWatch:
		// Lease has changed while we waited for the target node to finalize.
		// Send the latest version.
		_, err = s.sendLease(start, stream)
		if err != nil {
			return err
		}
	default:
	}

	return nil
}

func (s *service) sendLease(start *api.MigrationStart, stream api.Migration_MigrateServer) (<-chan struct{}, error) {
	mac, err := mac.ParseMAC(start.GetMac())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	lease, _, watch, found := s.leases.GetWatch(s.db.ReadTxn(), tables.DHCPLeaseByNetworkMAC(tables.NetworkName(start.GetNetwork()), mac))
	if found {
		return watch, stream.Send(&api.MigrationBatch{
			DhcpLease: []*api.DHCPLease{
				{
					Ipv4:       lease.IPv4.AsSlice(),
					ServerId:   lease.ServerID.String(),
					ObtainedAt: timestamppb.New(lease.ObtainedAt),
					RenewAt:    timestamppb.New(lease.RenewAt),
					ExpireAt:   timestamppb.New(lease.ExpireAt),
				},
			},
		})
	}
	return watch, nil
}

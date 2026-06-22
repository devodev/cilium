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
	"bytes"
	"errors"
	"io"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

type service struct {
	api.UnimplementedMigrationServer

	log       *slog.Logger
	db        *statedb.DB
	leases    statedb.Table[tables.DHCPLease]
	endpoints endpoints.EndpointGetter
}

func newService(in struct {
	cell.In

	Log       *slog.Logger
	DB        *statedb.DB
	Leases    statedb.Table[tables.DHCPLease]
	Endpoints endpoints.EndpointGetter
}) *service {
	return &service{
		log:       in.Log,
		db:        in.DB,
		leases:    in.Leases,
		endpoints: in.Endpoints,
	}
}

func (s *service) Migrate(stream api.Migration_MigrateServer) error {
	req, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}

	// Parse migration request
	start := req.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "Start expected")
	}

	network := tables.NetworkName(start.GetNetwork())
	if network == "" {
		return status.Error(codes.InvalidArgument, "network expected")
	}
	mac, err := mac.ParseMAC(start.GetMac())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	// Extract source endpoint (identified by MAC address)
	var ep endpoints.Endpoint
	for e := range s.endpoints.GetEndpoints() {
		if bytes.Equal(mac, e.LXCMac()) {
			ep = e
			break
		}
	}
	if ep == nil {
		return status.Errorf(codes.NotFound, "no endpoint found for MAC %s", mac)
	}

	// Send old endpoint addressing first. This is static information that
	// doesn't have to be updated later, and the target endpoint needs to
	// have it before it is activated.
	err = s.sendEndpointAddresses(ep, stream)
	if err != nil {
		return err
	}

	// Send DHCP leases if any.
	leaseWatch, err := s.sendLease(network, ep, stream)
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
		_, err = s.sendLease(network, ep, stream)
		if err != nil {
			return err
		}
	default:
	}

	return nil
}

func (s *service) sendEndpointAddresses(ep endpoints.Endpoint, stream api.Migration_MigrateServer) error {
	// If the source endpoint was already migrated recently, we want to preserve
	// the previous addressing for the target endpoint.
	prop, ok := endpoints.ExtractEndpointProperties(ep)
	if !ok {
		return status.Error(codes.InvalidArgument, "source endpoint is not in a private-network")
	}
	prevAddrs, err := prop.PreviousAddressing()
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	// Prepend current addressing
	result := []*api.EndpointAddressing{
		{
			Ipv4:     ep.IPv4Address().AsSlice(),
			Ipv6:     ep.IPv6Address().AsSlice(),
			LastSeen: timestamppb.Now(),
		},
	}

	// Append previous addressing, but ignore any addressing that is older than 15 minutes
	threshold := time.Now().Add(-15 * time.Minute)
	for _, prevAddr := range prevAddrs {
		if prevAddr.LastSeen.Before(threshold) {
			continue
		}
		result = append(result, &api.EndpointAddressing{
			Ipv4:     prevAddr.IPv4.AsSlice(),
			Ipv6:     prevAddr.IPv6.AsSlice(),
			LastSeen: timestamppb.New(prevAddr.LastSeen),
		})
	}

	return stream.Send(&api.MigrationBatch{
		EndpointAddressing: result,
	})
}

func (s *service) sendLease(network tables.NetworkName, ep endpoints.Endpoint, stream api.Migration_MigrateServer) (<-chan struct{}, error) {
	lease, _, watch, found := s.leases.GetWatch(s.db.ReadTxn(), tables.DHCPLeaseByNetworkMAC(network, ep.LXCMac()))
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

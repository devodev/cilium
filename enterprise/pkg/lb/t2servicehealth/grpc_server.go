// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package t2servicehealth

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/cilium/cilium/enterprise/pkg/lb/t2servicehealth/api/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

type grpcServerParams struct {
	cell.In

	Config             t2ServiceHealthConfig
	Lifecycle          cell.Lifecycle
	LocalNodeStore     *node.LocalNodeStore
	DB                 *statedb.DB
	ServiceHealthTable statedb.RWTable[*serviceHealth]
}

func registerGRPCServer(params grpcServerParams) {
	if !option.Config.EnableL7Proxy || !params.Config.Enabled {
		return
	}

	server := &serviceHealthGRPCServer{
		db:    params.DB,
		table: params.ServiceHealthTable,
	}

	var grpcServer *grpc.Server
	var listeners []net.Listener

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			ln, err := params.LocalNodeStore.Get(ctx)
			if err != nil {
				return fmt.Errorf("failed to retrieve local node: %w", err)
			}

			for _, ip := range []net.IP{ln.GetNodeIP(false), ln.GetNodeIP(true)} {
				if ip == nil {
					continue
				}
				lis, err := net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(params.Config.Port), 10)))
				if err != nil {
					return fmt.Errorf("failed to create gRPC listener: %w", err)
				}
				listeners = append(listeners, lis)
			}
			if len(listeners) == 0 {
				return fmt.Errorf("no valid node IP address found")
			}

			grpcServer = grpc.NewServer(grpc.WaitForHandlers(true))
			api.RegisterServiceHealthServer(grpcServer, server)

			for _, lis := range listeners {
				go grpcServer.Serve(lis)
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			if grpcServer != nil {
				grpcServer.Stop()
			}
			for _, lis := range listeners {
				_ = lis.Close()
			}
			return nil
		},
	})
}

type serviceHealthGRPCServer struct {
	api.UnimplementedServiceHealthServer

	db    *statedb.DB
	table statedb.RWTable[*serviceHealth]
}

func (s *serviceHealthGRPCServer) Watch(_ *api.WatchRequest, stream grpc.ServerStreamingServer[api.WatchResponse]) error {
	snapshot := []*api.WatchResponse_Event{}
	for row := range s.table.All(s.db.ReadTxn()) {
		snapshot = append(snapshot, toWatchEvent(row, false))
	}
	if err := stream.Send(&api.WatchResponse{
		FullSnapshot: true,
		Events:       snapshot,
	}); err != nil {
		return err
	}

	wtxn := s.db.WriteTxn(s.table)
	iter, err := s.table.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}
	defer iter.Close()

	for {
		changes, watch := iter.Next(s.db.ReadTxn())
		events := []*api.WatchResponse_Event{}
		for change := range changes {
			events = append(events, toWatchEvent(change.Object, change.Deleted))
		}
		if len(events) > 0 {
			if err := stream.Send(&api.WatchResponse{Events: events}); err != nil {
				return err
			}
		}

		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-watch:
		}
	}
}

func toWatchEvent(row *serviceHealth, deleted bool) *api.WatchResponse_Event {
	event := &api.WatchResponse_Event{
		Namespace: row.Namespace,
		Name:      row.Name,
		Deleted:   deleted,
	}
	if deleted {
		return event
	}

	event.Healthy = row.Healthy
	event.HealthyBackends = int32(row.HealthyBackends)
	event.TotalBackends = int32(row.TotalBackends)
	event.MinHealthyPct = row.MinHealthyPct
	event.UpdatedAt = timestamppb.New(row.UpdatedAt)
	event.ExpiresAt = timestamppb.New(row.ExpiresAt)

	return event
}

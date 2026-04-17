//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/cilium/hive/cell"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	envoycache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoylog "github.com/envoyproxy/go-control-plane/pkg/log"
	envoyresource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	envoysotw "github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	envoyserver "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type xdsServer struct {
	logger        *slog.Logger
	bindAddress   string
	listener      net.Listener
	grpcServer    *grpc.Server
	snapshotCache envoycache.SnapshotCache
	versionsMu    lock.Mutex
	versions      map[string]uint64
}

type controlplaneNodeHash struct{}

type XDSResources struct {
	Listeners []*envoy_config_listener_v3.Listener
	Routes    []*envoy_config_route_v3.RouteConfiguration
	Clusters  []*envoy_config_cluster_v3.Cluster
	Endpoints []*envoy_config_endpoint_v3.ClusterLoadAssignment
	Secrets   []*envoy_extensions_transport_sockets_tls_v3.Secret
}

type XDSResourceMutator interface {
	UpdateSnapshot(ctx context.Context, snapshotKey string, resources XDSResources) error
	ClearSnapshot(ctx context.Context, snapshotKey string) error
}

func (controlplaneNodeHash) ID(node *envoy_config_core_v3.Node) string {
	return node.GetCluster()
}

func newXDSServer(logger *slog.Logger, config Config) (*xdsServer, error) {
	snapshotCache := envoycache.NewSnapshotCache(true, controlplaneNodeHash{}, envoylog.NewDefaultLogger())

	return &xdsServer{
		logger:        logger,
		bindAddress:   config.XDSBindAddress,
		snapshotCache: snapshotCache,
		versions:      make(map[string]uint64),
	}, nil
}

func (s *xdsServer) UpdateSnapshot(ctx context.Context, snapshotKey string, resources XDSResources) error {
	snapshot, err := envoycache.NewSnapshot(s.nextSnapshotVersion(snapshotKey), map[envoyresource.Type][]types.Resource{
		envoyresource.EndpointType: sliceToResources(resources.Endpoints),
		envoyresource.ClusterType:  sliceToResources(resources.Clusters),
		envoyresource.RouteType:    sliceToResources(resources.Routes),
		envoyresource.ListenerType: sliceToResources(resources.Listeners),
		envoyresource.SecretType:   sliceToResources(resources.Secrets),
	})
	if err != nil {
		return fmt.Errorf("failed to create xDS snapshot: %w", err)
	}

	if err := s.snapshotCache.SetSnapshot(ctx, snapshotKey, snapshot); err != nil {
		return fmt.Errorf("failed to publish xDS snapshot: %w", err)
	}

	return nil
}

func (s *xdsServer) ClearSnapshot(ctx context.Context, snapshotKey string) error {
	return s.UpdateSnapshot(ctx, snapshotKey, XDSResources{})
}

func (s *xdsServer) Serve(ctx context.Context, health cell.Health) error {
	listener, err := net.Listen("tcp", s.bindAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on xDS address %q: %w", s.bindAddress, err)
	}
	s.listener = listener

	s.grpcServer = grpc.NewServer()

	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(
		s.grpcServer,
		envoyserver.NewServer(ctx, s.snapshotCache, nil, envoysotw.WithOrderedADS()),
	)

	s.logger.Info("Starting xDS server", logfields.Address, s.bindAddress)
	health.OK("xDS server is running")

	return s.grpcServer.Serve(s.listener)
}

func (s *xdsServer) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func sliceToResources[T types.Resource](items []T) []types.Resource {
	if len(items) == 0 {
		return nil
	}

	resources := make([]types.Resource, 0, len(items))
	for _, item := range items {
		resources = append(resources, item)
	}

	return resources
}

func (s *xdsServer) nextSnapshotVersion(snapshotKey string) string {
	s.versionsMu.Lock()
	defer s.versionsMu.Unlock()

	s.versions[snapshotKey]++
	return strconv.FormatUint(s.versions[snapshotKey], 10)
}

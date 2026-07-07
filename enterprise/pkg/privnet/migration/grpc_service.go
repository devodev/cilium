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
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/time"
)

type service struct {
	api.UnimplementedMigrationServer

	log       *slog.Logger
	db        *statedb.DB
	leases    statedb.Table[tables.DHCPLease]
	ctTime    *ctTimestampConverter
	globalCT  ctmap.CTMaps
	privnetCT pnmaps.CTMaps

	endpoints endpoints.EndpointGetter
}

func newService(in struct {
	cell.In

	Log    *slog.Logger
	DB     *statedb.DB
	Leases statedb.Table[tables.DHCPLease]

	GlobalCT  ctmap.CTMaps
	PrivnetCT pnmaps.CTMaps
	CTTime    *ctTimestampConverter

	Endpoints endpoints.EndpointGetter
}) *service {
	return &service{
		log:       in.Log,
		db:        in.DB,
		leases:    in.Leases,
		globalCT:  in.GlobalCT,
		privnetCT: in.PrivnetCT,
		ctTime:    in.CTTime,
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

	// Send CT state
	err = s.sendCT(network, ep, stream)
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

func (s *service) sendCT(network tables.NetworkName, ep endpoints.Endpoint, stream api.Migration_MigrateServer) error {
	scopedLog := s.log.With(
		logfields.Hint, "Expect dropped connections for migrated endpoint",
		logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
	)

	prop, ok := endpoints.ExtractEndpointProperties(ep)
	if !ok {
		return status.Error(codes.InvalidArgument, "source endpoint is not in a private-network")
	}
	netIPv4, err := prop.NetworkIPv4()
	if err != nil {
		scopedLog.Warn("Unable to extract private network IPv4 address", logfields.Error, err)
	}
	netIPv6, err := prop.NetworkIPv6()
	if err != nil {
		scopedLog.Warn("Unable to extract private network IPv6 address", logfields.Error, err)
	}

	// Dump global CT maps. We collect all entries matching the endpoints P-IP of the migrating endpoint.
	ctx := stream.Context()
	for _, ctMap := range s.globalCT.ActiveMaps() {
		records, err := s.collectGlobalCT(ctx, ctMap, ep)
		if err != nil {
			// Log error, but send any collected records downstream anyway
			scopedLog.Warn("Failed to collect global CT entries", logfields.Error, err)
		}
		// Send any collected entries downstream
		if len(records) > 0 {
			err = stream.Send(&api.MigrationBatch{
				Records: records,
			})
			if err != nil {
				return err
			}
		}
	}

	// Dump privnet CT maps. We collect all entries matching the endpoints Net-IP of the migrating endpoint.
	for _, ctMap := range s.privnetCT.ActiveMapsForNetwork(string(network)) {
		records, err := s.collectPrivnetCT(ctx, ctMap, netIPv4, netIPv6)
		if err != nil {
			// Log error, but send any collected records downstream anyway
			scopedLog.Warn("Failed to collect private network CT entries", logfields.Error, err)
		}
		// Send any collected entries downstream
		if len(records) > 0 {
			err = stream.Send(&api.MigrationBatch{
				Records: records,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *service) collectGlobalCT(ctx context.Context, ctMap *ctmap.Map, ep endpoints.Endpoint) (records []*api.CTRecord, err error) {
	switch ctMap.Name() {
	case ctmap.MapNameTCP4Global:
		records, err = collectCTEntries[ctmap.CtKey4Global, *ctmap.CtKey4Global](
			ctx, api.CTMapKind_CT_MAP_KIND_GLOBAL_TCP4, s.ctTime, ctMap, ep.IPv4Address(),
		)
	case ctmap.MapNameAny4Global:
		records, err = collectCTEntries[ctmap.CtKey4Global, *ctmap.CtKey4Global](
			ctx, api.CTMapKind_CT_MAP_KIND_GLOBAL_ANY4, s.ctTime, ctMap, ep.IPv4Address(),
		)
	case ctmap.MapNameTCP6Global:
		records, err = collectCTEntries[ctmap.CtKey6Global, *ctmap.CtKey6Global](
			ctx, api.CTMapKind_CT_MAP_KIND_GLOBAL_TCP6, s.ctTime, ctMap, ep.IPv6Address(),
		)
	case ctmap.MapNameAny6Global:
		records, err = collectCTEntries[ctmap.CtKey6Global, *ctmap.CtKey6Global](
			ctx, api.CTMapKind_CT_MAP_KIND_GLOBAL_ANY6, s.ctTime, ctMap, ep.IPv6Address(),
		)
	}
	return records, err
}

func (s *service) collectPrivnetCT(ctx context.Context, ctMap pnmaps.CTMapWithConfig, netIPv4 netip.Addr, netIPv6 netip.Addr) (records []*api.CTRecord, err error) {
	var kind api.CTMapKind
	var cfg = ctMap.Config
	if !cfg.IPv6 && netIPv4.IsValid() {
		if cfg.TCP {
			kind = api.CTMapKind_CT_MAP_KIND_PRIVNET_TCP4
		} else {
			kind = api.CTMapKind_CT_MAP_KIND_PRIVNET_ANY4
		}
		records, err = collectCTEntries[ctmap.CtKey4Global, *ctmap.CtKey4Global](
			ctx, kind, s.ctTime, ctMap.Map, netIPv4,
		)
	} else if cfg.IPv6 && netIPv6.IsValid() {
		if cfg.TCP {
			kind = api.CTMapKind_CT_MAP_KIND_PRIVNET_TCP6
		} else {
			kind = api.CTMapKind_CT_MAP_KIND_PRIVNET_ANY6
		}
		records, err = collectCTEntries[ctmap.CtKey6Global, *ctmap.CtKey6Global](
			ctx, kind, s.ctTime, ctMap.Map, netIPv6,
		)
	}
	return records, err
}

func collectCTEntries[T any, PT ctKey[T]](ctx context.Context,
	kind api.CTMapKind,
	ctTime *ctTimestampConverter,
	ctMap pnmaps.CTMap,
	pip netip.Addr,
) ([]*api.CTRecord, error) {
	ctNow, err := ctTime.ctNow()
	if err != nil {
		return nil, err
	}

	var records []*api.CTRecord
	iter := bpf.NewBatchIterator[T, ctmap.CtEntry, PT, *ctmap.CtEntry](ctMap)
	for k, v := range iter.IterateAll(ctx) {
		if k.GetSourceAddr() == pip || k.GetDestAddr() == pip {
			lifetime := ctTime.toDuration(ctNow, v.Lifetime)
			if lifetime.Seconds <= 0 {
				continue // skip already expired entries
			}

			records = append(records, &api.CTRecord{
				Kind: kind,
				Key: &api.CTKey{
					SourceIp:   k.GetSourceAddr().AsSlice(),
					DestIp:     k.GetDestAddr().AsSlice(),
					SourcePort: uint32(k.GetSourcePort()),
					DestPort:   uint32(k.GetDestPort()),
					NextHeader: uint32(k.GetNextHeader()),
					Flags:      uint32(k.GetFlags()),
				},
				Value: &api.CTValue{
					Lifetime:    lifetime,
					Flags:       uint32(v.Flags),
					TxFlagsSeen: uint32(v.TxFlagsSeen),
					RxFlagsSeen: uint32(v.RxFlagsSeen),
				},
			})
		}
	}
	return records, iter.Err()
}

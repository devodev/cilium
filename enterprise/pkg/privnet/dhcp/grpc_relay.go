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
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"google.golang.org/protobuf/types/known/durationpb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// GRPCRelayFactory provides gRPC-backed DHCP relays for workloads.
type GRPCRelayFactory struct {
	Log     *slog.Logger
	DB      *statedb.DB
	INBs    statedb.Table[tables.INB]
	Subnets statedb.Table[tables.Subnet]
	Factory client.ConnFactoryFn
}

// RelayFor implements RelayFactory.
func (f *GRPCRelayFactory) RelayFor(lw *tables.LocalWorkload) (Relayer, error) {
	if lw == nil {
		return nil, errors.New("local workload is nil")
	}
	network := tables.NetworkName(lw.Interface.Network)
	if network == "" {
		return nil, fmt.Errorf("network missing on local workload %d", lw.EndpointID)
	}
	if lw.Subnet == "" {
		return nil, fmt.Errorf("subnet missing on local workload %d", lw.EndpointID)
	}
	subnet, _, found := f.Subnets.Get(f.DB.ReadTxn(), tables.SubnetsByNetworkAndName(network, lw.Subnet))
	if !found {
		return nil, fmt.Errorf("subnet %q not found for network %q", lw.Subnet, network)
	}
	return &grpcRelay{
		log:     f.Log,
		db:      f.DB,
		inbs:    f.INBs,
		factory: f.Factory,
		network: network,
		subnet:  lw.Subnet,
		cfg:     subnet.DHCP,
	}, nil
}

type grpcRelay struct {
	log     *slog.Logger
	db      *statedb.DB
	inbs    statedb.Table[tables.INB]
	factory client.ConnFactoryFn
	network tables.NetworkName
	subnet  tables.SubnetName
	cfg     iso_v1alpha1.PrivateNetworkSubnetDHCPSpec
}

// Relay forwards the DHCP request to the active INB via gRPC.
func (r *grpcRelay) Relay(ctx context.Context, waitTime time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	if req == nil {
		return nil, errors.New("dhcp request is nil")
	}
	if waitTime <= 0 {
		return nil, errors.New("wait time is required")
	}
	mode, err := relayDHCPModeToProto(r.cfg)
	if err != nil {
		return nil, err
	}
	log := r.log.With(
		logfields.Network, r.network,
		logfields.PrivateNetworkSubnet, r.subnet,
	)
	log.Info("Relaying DHCP request via gRPC",
		logfields.Type, req.MessageType(),
		logfields.Xid, req.TransactionID,
		logfields.Chaddr, req.ClientHWAddr,
	)

	txn := r.db.ReadTxn()
	inb, _, found := r.inbs.Get(txn, tables.INBsByNetworkAndRole(r.network, tables.INBRoleActive))
	if !found {
		log.Info("Active INB not found for DHCP relay")
		return nil, fmt.Errorf("active INB not found for network %q", r.network)
	}

	conn, err := r.factory(ctx, inb.Node.Cluster, inb.Node.Name, inb.Node.AddrPort())
	if err != nil {
		log.Info("Failed to dial INB for DHCP relay",
			logfields.Target, inb.Node,
			logfields.Error, err,
		)
		return nil, fmt.Errorf("dial INB %s: %w", inb.Node.String(), err)
	}
	defer conn.Close()

	client := api.NewDHCPRelayClient(conn)
	resp, err := client.Relay(ctx, &api.RelayRequest{
		Network:  string(r.network),
		Subnet:   string(r.subnet),
		Request:  req.ToBytes(),
		WaitTime: durationpb.New(waitTime),
		Mode:     mode,
		Relay:    relayDHCPRelayModeConfigToProto(r.cfg),
	})
	if err != nil {
		log.Info("DHCP gRPC relay request failed",
			logfields.Target, inb.Node,
			logfields.Error, err,
		)
		return nil, err
	}
	if resp == nil || len(resp.Responses) == 0 {
		log.Info("DHCP gRPC relay returned empty response",
			logfields.Target, inb.Node,
		)
		return nil, errors.New("empty DHCP response")
	}

	responses := make([]*dhcpv4.DHCPv4, 0, len(resp.Responses))
	for _, payload := range resp.Responses {
		if len(payload) == 0 {
			continue
		}
		parsed, err := dhcpv4.FromBytes(payload)
		if err != nil {
			log.Info("Failed to parse DHCP gRPC response",
				logfields.Target, inb.Node,
				logfields.Error, err,
			)
			return nil, fmt.Errorf("parse DHCP response: %w", err)
		}
		log.Info("Received DHCP response via gRPC",
			logfields.Type, parsed.MessageType(),
			logfields.Xid, parsed.TransactionID,
			logfields.IPv4, parsed.YourIPAddr,
		)
		responses = append(responses, parsed)
	}

	if len(responses) == 0 {
		return nil, errors.New("empty DHCP response")
	}
	return responses, nil
}

func relayDHCPModeToProto(cfg iso_v1alpha1.PrivateNetworkSubnetDHCPSpec) (api.RelayRequest_Mode, error) {
	switch cfg.Mode {
	case iso_v1alpha1.PrivateNetworkDHCPModeRelay:
		return api.RelayRequest_RELAY, nil
	case iso_v1alpha1.PrivateNetworkDHCPModeBroadcast:
		return api.RelayRequest_BROADCAST, nil
	case iso_v1alpha1.PrivateNetworkDHCPModeNone:
		return api.RelayRequest_UNKNOWN, fmt.Errorf("dhcp is disabled for subnet")
	default:
		return api.RelayRequest_UNKNOWN, fmt.Errorf("unknown dhcp mode %q", cfg.Mode)
	}
}

func relayDHCPRelayModeConfigToProto(cfg iso_v1alpha1.PrivateNetworkSubnetDHCPSpec) *api.DHCPRelayModeConfig {
	if cfg.Relay == nil {
		return nil
	}

	out := &api.DHCPRelayModeConfig{
		ServerAddress: cfg.Relay.ServerAddress,
	}
	if cfg.Relay.Option82 != nil {
		out.Option82CircuitId = cfg.Relay.Option82.CircuitID
		out.Option82RemoteId = cfg.Relay.Option82.RemoteID
	}
	return out
}

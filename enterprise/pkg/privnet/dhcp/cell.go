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
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	grpcclient "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	grpcserver "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/server"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides DHCP support for private networks.
//
// Flow overview:
//  1. BPF redirects DHCP packets (UDP 67/68) into the dummy device
//     named by [pncfg.DHCPInterfaceName]
//     and encodes the endpoint ID into the source MAC.
//  2. A single DHCP server in the host netns listens on [pncfg.DHCPInterfaceName]
//     via a raw socket.
//  3. The server decodes the endpoint ID, looks up the local workload to figure out how
//     to relay for this subnet and passes to the relay implementation.
//  4. The handler records leases in `privnet-dhcp-leases` table.
//  5. The DHCP lease reconciler projects leases into local workloads, endpoint properties,
//     device mappings, and endpoint slices.
//
// For more details on operation see e.g. `tests/testdata/dhcp-grpc.txtar` or the other test files.
//
// DHCP relaying is configured per subnet via ClusterwidePrivateNetwork
// `spec.subnets[].dhcp`. If omitted, DHCP relaying is disabled (`mode=none`).

var Cell = cell.Module(
	"private-network-dhcp",
	"DHCP support for Private Networks",

	cell.Config(DefaultConfig),
	cell.Provide(
		newRelayFactory,
	),
	cell.Invoke(
		registerServer,
	),
	serviceCell,
)

var serviceCell = cell.Group(
	cell.ProvidePrivate(
		newReplyDispatcher,
		newRelayForService,
		newService,
	),
	cell.Provide(
		func(cfg pncfg.Config, svc *service) grpcserver.RegistrarOut {
			if !cfg.EnabledAsBridge() {
				return grpcserver.RegistrarOut{}
			}
			return grpcserver.RegistrarOut{Registrar: func(gsrv *grpc.Server) {
				api.RegisterDHCPRelayServer(gsrv, svc)
			}}
		},
	),
)

type relayParams struct {
	cell.In

	Log             *slog.Logger
	DB              *statedb.DB
	INBs            statedb.Table[tables.INB]
	Subnets         statedb.Table[tables.Subnet]
	ConnFn          grpcclient.ConnFactoryFn `optional:"true"`
	TestCfg         *TestConfig              `optional:"true"`
	PrivnetConfig   pncfg.Config
	ReplyDispatcher *replyDispatcher
}

func newRelayFactory(p relayParams) (RelayFactory, error) {
	if !p.PrivnetConfig.Enabled {
		return nil, nil
	}

	var relayNetNS *netns.NetNS
	if p.TestCfg != nil {
		relayNetNS = p.TestCfg.NetNS
	}

	return &localRelayFactory{
		log:             p.Log,
		netns:           relayNetNS,
		db:              p.DB,
		subnets:         p.Subnets,
		replyDispatcher: p.ReplyDispatcher,
		grpc: GRPCRelayFactory{
			Log:     p.Log,
			DB:      p.DB,
			INBs:    p.INBs,
			Subnets: p.Subnets,
			Factory: p.ConnFn,
		},
	}, nil
}

type localRelayFactory struct {
	log             *slog.Logger
	netns           *netns.NetNS
	db              *statedb.DB
	subnets         statedb.Table[tables.Subnet]
	replyDispatcher *replyDispatcher
	grpc            GRPCRelayFactory
}

func (l *localRelayFactory) relayForSubnet(subnet tables.Subnet) (Relayer, error) {
	switch subnet.DHCP.Mode {
	case v1alpha1.PrivateNetworkDHCPModeNone:
		return nil, fmt.Errorf("DHCP disabled")
	case v1alpha1.PrivateNetworkDHCPModeBroadcast:
		return &broadcastRelay{log: l.log, netns: l.netns, ifname: subnet.EgressIfName, responses: l.replyDispatcher}, nil
	case v1alpha1.PrivateNetworkDHCPModeRelay:
		if subnet.DHCP.Relay == nil {
			return nil, fmt.Errorf("DHCP relay mode specified but target server unset")
		}
		addr, err := resolveServerAddr(subnet.DHCP.Relay.ServerAddress)
		if err != nil {
			return nil, err
		}
		return &unicastRelay{
			serverAddr: addr,
			option82:   subnet.DHCP.Relay.Option82,
			log:        l.log,
			netns:      l.netns,
		}, nil
	default:
		return nil, fmt.Errorf("unknown DHCP mode %q", subnet.DHCP.Mode)
	}
}

func (l *localRelayFactory) RelayFor(lw *tables.LocalWorkload) (Relayer, error) {
	if lw == nil {
		return nil, fmt.Errorf("local workload is nil")
	}

	subnet, _, found := l.subnets.Get(l.db.ReadTxn(), tables.SubnetsByNetworkAndName(tables.NetworkName(lw.Interface.Network), lw.Subnet))
	if !found {
		return nil, fmt.Errorf("subnet %q not found for network %q", lw.Subnet, lw.Interface.Network)
	}

	if subnet.EgressIfIndex != 0 {
		if subnet.EgressIfName == "" {
			return nil, fmt.Errorf("subnet %q in network %q has egress ifindex %d but no egress interface name",
				lw.Subnet,
				lw.Interface.Network,
				subnet.EgressIfIndex,
			)
		}
		return l.relayForSubnet(subnet)
	}

	return l.grpc.RelayFor(lw)
}

type registerServerParams struct {
	cell.In

	Config          Config
	PrivnetConfig   pncfg.Config
	Log             *slog.Logger
	JG              job.Group
	DB              *statedb.DB
	Workloads       statedb.RWTable[*tables.LocalWorkload]
	LeaseWriter     *tables.DHCPLeaseWriter
	Subnets         statedb.Table[tables.Subnet]
	RelayFactory    RelayFactory
	ReplyDispatcher *replyDispatcher
	TestCfg         *TestConfig `optional:"true"`
}

func registerServer(p registerServerParams) error {
	if !p.PrivnetConfig.Enabled {
		return nil
	}

	if os.Getuid() != 0 {
		// To make this cell usable in non-privileged tests we bail out if we're not
		// running as root.
		p.Log.Info("Not starting DHCP server as not running as root")
		return nil
	}

	if p.RelayFactory == nil {
		return fmt.Errorf("DHCP relay factory is required")
	}

	var relayNetNS *netns.NetNS
	if p.TestCfg != nil {
		relayNetNS = p.TestCfg.NetNS
	}

	handler := newServerHandler(p.Log, p.DB, p.Workloads, p.LeaseWriter, p.Subnets, p.RelayFactory, p.Config.WaitTime)
	srv, err := NewServer(p.Log, p.Config, relayNetNS, pncfg.DHCPInterfaceName, handler.serverHandler(), p.ReplyDispatcher)
	if err != nil {
		p.Log.Error("Failed to create DHCP server",
			logfields.Interface, pncfg.DHCPInterfaceName,
			logfields.Error, err,
		)
		return err
	}

	p.JG.Add(
		job.OneShot("dhcp-server",
			func(ctx context.Context, health cell.Health) error {
				p.Log.Info("Starting DHCP server")
				err := srv.Serve(ctx, health)
				if err != nil {
					p.Log.Error("DHCP server error occurred. Restarting", logfields.Error, err)
					health.Degraded("Error while serving", err)
					return err
				}
				p.Log.Info("DHCP server stopped")
				return nil
			},
			job.WithRetry(-1, &job.ExponentialBackoff{
				Min: time.Second,
				Max: time.Minute,
			})))

	return nil
}

type relayForServiceParams struct {
	cell.In

	Log             *slog.Logger
	ReplyDispatcher *replyDispatcher
	TestCfg         *TestConfig `optional:"true"`
}

func newRelayForService(p relayForServiceParams) serviceRelayFactoryFunc {
	var relayNetNS *netns.NetNS
	if p.TestCfg != nil {
		relayNetNS = p.TestCfg.NetNS
	}

	return func(mode api.RelayRequest_Mode, relayCfg *api.DHCPRelayModeConfig, iface string) (Relayer, error) {
		switch mode {
		case api.RelayRequest_RELAY:
			if relayCfg == nil || relayCfg.GetServerAddress() == "" {
				return nil, fmt.Errorf("DHCP server address required in relay mode")
			}
			addr, err := resolveServerAddr(relayCfg.GetServerAddress())
			if err != nil {
				return nil, err
			}

			var option82 *v1alpha1.PrivateNetworkDHCPOption82Spec
			if relayCfg.GetOption82CircuitId() != "" || relayCfg.GetOption82RemoteId() != "" {
				option82 = &v1alpha1.PrivateNetworkDHCPOption82Spec{
					CircuitID: relayCfg.GetOption82CircuitId(),
					RemoteID:  relayCfg.GetOption82RemoteId(),
				}
			}

			return &unicastRelay{
				serverAddr: addr,
				option82:   option82,
				log:        p.Log,
				netns:      relayNetNS,
			}, nil
		case api.RelayRequest_BROADCAST:
			ifName := iface
			if ifName == "" {
				return nil, fmt.Errorf("DHCP broadcast interface required in broadcast mode")
			}
			return &broadcastRelay{log: p.Log, netns: relayNetNS, responses: p.ReplyDispatcher, ifname: ifName}, nil
		default:
			return nil, fmt.Errorf("unknown mode %s", mode.String())
		}
	}
}

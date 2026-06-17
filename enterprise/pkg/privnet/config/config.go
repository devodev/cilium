//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	cni "github.com/cilium/cilium/daemon/cmd/cni/config"
	clustermesh "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	dpopt "github.com/cilium/cilium/pkg/datapath/option"
	ipamopt "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	wireguard "github.com/cilium/cilium/pkg/wireguard/types"
	ztunnel "github.com/cilium/cilium/pkg/ztunnel/config"
)

const (
	// FlagEnable is the flag to enable private networking.
	FlagEnable = option.PrivateNetworksEnabled

	// DHCPInterfaceName is the name of the host dummy interface used to
	// receive DHCP packets redirected from BPF.
	DHCPInterfaceName = "cilium_dhcp"

	// FlagMode is the flag to configure the private networking mode.
	FlagMode = "private-networks-mode"

	// FlagBridgeGneighInterval is the flag to configure the interval at which workload cluster
	// endpoints are announced via gratuitous ARP/ND in bridge mode.
	FlagBridgeGneighInterval = "private-networks-bridge-gneigh-interval"

	// FlagExternalEndpoints is the flag to enable support for PrivateNetworkExternalEndpoints
	FlagExternalEndpoints = "private-networks-external-endpoints-enabled"

	// FlagHostReachability is the flag to allow (remote) host traffic into privnet.
	FlagHostReachability = "private-networks-host-reachability"

	// FlagHostSNATIPv4 is the flag to configure the link-local IPv4 address used
	// to SNAT host traffic destined to PrivNet workloads.
	FlagHostSNATIPv4 = "private-networks-host-snat-ipv4"

	// FlagHostSNATIPv6 is the flag to configure the link-local IPv6 address used
	// to SNAT host traffic destined to PrivNet workloads.
	FlagHostSNATIPv6 = "private-networks-host-snat-ipv6"

	// FlagLiveMigration is the flag to enable support for KubeVirt live migration
	FlagLiveMigration = "private-networks-live-migration-enabled"

	// ModeDefault configures private networks to operate in default mode.
	ModeDefault = "default"

	// ModeLocalAccess configures the private network to operate in local access mode.
	ModeLocalAccess = "local-access"

	// ModeBridge configures private networks to operate in bridge mode,
	// that is providing connectivity between cilium-managed endpoints and
	// external endpoints that belong to the same private network.
	ModeBridge = "bridge"
)

var (
	// Cell registers the private networking configuration, without performing validation.
	Cell = cell.Group(
		cell.Config(defaultFlags),
		cell.Provide(NewConfig),
	)

	// Cell registers the private networking configuration, and performs validation.
	ValidatingCell = cell.Group(
		Cell,
		cell.Invoke(Config.validate),
	)

	DefaultCommon = Common{
		Enabled: false,
	}

	defaultFlags = Flags{
		Common:               DefaultCommon,
		Mode:                 ModeDefault,
		ExternalEndpoints:    false,
		BridgeGneighInterval: 1 * time.Minute,
		HostReachability:     true,
		HostSNATIPv4:         "169.254.7.1",
		HostSNATIPv6:         "fe80::a9fe:701",
		LiveMigration:        true,
	}
)

// Common represents the basic configuration to enable private networking. It is
// extracted into a separate type so that it can be reused by other components,
// such as the Cilium operator or the clustermesh-apiserver.
type Common struct {
	Enabled bool `mapstructure:"private-networks-enabled"`
}

func (def Common) Flags(flags *pflag.FlagSet) {
	flags.Bool(FlagEnable, def.Enabled, "Enable support for private networks")
}

// Flags groups the private networking agent flags.
type Flags struct {
	Common `mapstructure:",squash"`

	Mode                 string        `mapstructure:"private-networks-mode"`
	BridgeGneighInterval time.Duration `mapstructure:"private-networks-bridge-gneigh-interval"`
	ExternalEndpoints    bool          `mapstructure:"private-networks-external-endpoints-enabled"`
	HostReachability     bool          `mapstructure:"private-networks-host-reachability"`
	HostSNATIPv4         string        `mapstructure:"private-networks-host-snat-ipv4"`
	HostSNATIPv6         string        `mapstructure:"private-networks-host-snat-ipv6"`
	LiveMigration        bool          `mapstructure:"private-networks-live-migration-enabled"`
}

func (def Flags) Flags(flags *pflag.FlagSet) {
	def.Common.Flags(flags)

	flags.String(FlagMode, def.Mode, fmt.Sprintf("The private networks mode (%q, %q or %q)", ModeDefault, ModeLocalAccess, ModeBridge))

	flags.Duration(FlagBridgeGneighInterval, def.BridgeGneighInterval,
		fmt.Sprintf("Interval at which workload cluster endpoints are announced using gratuitous ARP/ND in %s or %s mode. Ignored in %s mode.", ModeBridge, ModeLocalAccess, ModeDefault))

	flags.Bool(FlagExternalEndpoints, def.ExternalEndpoints, "Enable support for private network external endpoints")

	flags.Bool(FlagHostReachability, def.HostReachability, "Allow (remote) host traffic into private networks")
	flags.MarkHidden(FlagHostReachability)

	flags.String(FlagHostSNATIPv4, def.HostSNATIPv4, "Link-local IPv4 address used to SNAT host traffic to private networks")
	flags.MarkHidden(FlagHostSNATIPv4)
	flags.String(FlagHostSNATIPv6, def.HostSNATIPv6, "Link-local IPv6 address used to SNAT host traffic to private networks")
	flags.MarkHidden(FlagHostSNATIPv6)

	flags.Bool(FlagLiveMigration, def.LiveMigration, "Enable support for private network endpoint live migration")
	flags.MarkHidden(FlagLiveMigration)
}

// Config is the parsed private networking configuration.
type Config struct {
	Enabled              bool
	Mode                 string
	BridgeGneighInterval time.Duration
	ExternalEndpoints    bool
	HostReachability     bool
	HostSNATIPv4         netip.Addr
	HostSNATIPv6         netip.Addr
	LiveMigration        bool
}

// NewConfig creates a Config from the parsed Flags.
func NewConfig(f Flags) (Config, error) {
	snatIPv4, err := netip.ParseAddr(f.HostSNATIPv4)
	if err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", FlagHostSNATIPv4, err)
	}
	if !snatIPv4.Is4() {
		return Config{}, fmt.Errorf("invalid %s: expected an IPv4 address", FlagHostSNATIPv4)
	}
	if !snatIPv4.IsLinkLocalUnicast() {
		return Config{}, fmt.Errorf("invalid %s: expected to be a link-local address", FlagHostSNATIPv4)
	}

	snatIPv6, err := netip.ParseAddr(f.HostSNATIPv6)
	if err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", FlagHostSNATIPv6, err)
	}
	if !snatIPv6.Is6() {
		return Config{}, fmt.Errorf("invalid %s: expected an IPv6 address", FlagHostSNATIPv6)
	}
	if !snatIPv6.IsLinkLocalUnicast() {
		return Config{}, fmt.Errorf("invalid %s: expected to be a link-local address", FlagHostSNATIPv6)
	}

	return Config{
		Enabled:              f.Enabled,
		Mode:                 f.Mode,
		BridgeGneighInterval: f.BridgeGneighInterval,
		ExternalEndpoints:    f.ExternalEndpoints,
		HostReachability:     f.HostReachability,
		HostSNATIPv4:         snatIPv4,
		HostSNATIPv6:         snatIPv6,
		LiveMigration:        f.LiveMigration,
	}, nil
}

func (cfg Config) validate(in struct {
	cell.In

	ClusterMesh clustermesh.Config
	CNI         cni.Config
	Daemon      *option.DaemonConfig
	KPR         kpr.KPRConfig
	IPSec       ipsec.Config
	WireGuard   wireguard.Config
	ZTunnel     ztunnel.Config
}) error {
	if !cfg.Enabled {
		return nil
	}

	switch cfg.Mode {
	case ModeDefault, ModeBridge, ModeLocalAccess:
	default:
		return fmt.Errorf("invalid private networks mode %q, should be one of: %q, %q, %q",
			cfg.Mode, ModeDefault, ModeBridge, ModeLocalAccess)
	}

	var (
		incompatible = func(opt string) error {
			return fmt.Errorf("currently, --%s is not compatible with --%s", FlagEnable, opt)
		}
		requires = func(opt string) error {
			return fmt.Errorf("currently, --%s requires --%s", FlagEnable, opt)
		}
	)

	for _, incompatibility := range []struct {
		has bool
		err error
	}{
		// EndpointRoutes introduce the cil_to_container BPF program, which is currently not supported.
		{has: in.Daemon.EnableEndpointRoutes, err: incompatible(option.EnableEndpointRoutes)},
		// At least host reachability requires KPR to work. More testing would be also needed to claim support with KPR off.
		{has: !in.KPR.KubeProxyReplacement, err: requires("kube-proxy-replacement")},
		// HostFirewall needs more testing to validate the interaction with local access and INB traffic.
		{has: in.Daemon.EnableHostFirewall, err: incompatible(option.EnableHostFirewall)},

		// KubeVirt VMs don't seem to work in combination with netkit, and more testing would be needed anyways.
		{has: in.Daemon.DatapathMode != dpopt.DatapathModeVeth, err: requires(option.DatapathMode + "=" + dpopt.DatapathModeVeth)},

		// Miscellaneous options that may or may not work, but are unlikely to be of interest soon anyways.
		{has: in.Daemon.EnableNat46X64Gateway, err: incompatible(option.EnableNat46X64Gateway)},
		{has: in.Daemon.EnableVTEP, err: incompatible(option.EnableVTEP)},

		// IPSec and WireGuard may work out of the box, as all traffic is either pod to pod or goes
		// through the tunnel, but we need better testing to validate that we actually treat it
		// correctly in all cases, and we don't unexpectedly leak unencrypted packets onto the wire.
		{has: in.IPSec.Enabled(), err: incompatible(option.EnableIPSec)},
		{has: in.WireGuard.Enabled(), err: incompatible(wireguard.EnableWireguard)},
		{has: in.ZTunnel.EnableZTunnel, err: incompatible("enable-ztunnel")},

		// Forbid CNI chaining, to ensure that Cilium is in full control to handle the pod interconnection.
		{has: in.CNI.CNIChainingMode != "none", err: incompatible(option.CNIChainingMode + "=" + in.CNI.CNIChainingMode)},

		// The support for Overlapping Pod CIDR comes with many limitations, and definitely requires more testing.
		{has: in.ClusterMesh.EnableClusterAwareAddressing, err: incompatible(clustermesh.EnableClusterAwareAddressing)},
		{has: in.ClusterMesh.EnableInterClusterSNAT, err: incompatible(clustermesh.EnableInterClusterSNAT)},

		// Forbid cloud-provider related IPAM modes, which are typically associated with specific
		// quirks, and would require additional testing to validate that they work correctly.
		{
			has: !slices.Contains([]string{ipamopt.IPAMKubernetes, ipamopt.IPAMClusterPool, ipamopt.IPAMMultiPool}, in.Daemon.IPAM),
			err: incompatible(option.IPAM + "=" + in.Daemon.IPAM),
		},

		// Forbid XDP acceleration, as it is not possible to attach XDP programs to VLAN interfaces,
		// and more testing is required to validate the interaction with local access and INB traffic.
		{
			has: in.Daemon.NodePortAcceleration != option.NodePortAccelerationDisabled,
			err: incompatible(option.LoadBalancerAcceleration + "=" + in.Daemon.NodePortAcceleration),
		},

		// Enforce that INBs run in tunnel mode, so that they can forward unknown flow traffic
		// through the tunnel. The workload clusters may either run in native routing mode with
		// mixed routing mode support, or tunnel mode.
		{
			has: cfg.Mode == ModeBridge && in.Daemon.RoutingMode != option.RoutingModeTunnel,
			err: fmt.Errorf("currently, --%s=%s requires %s=%s", FlagMode, ModeBridge, option.RoutingMode, option.RoutingModeTunnel),
		},
	} {
		if incompatibility.has {
			return incompatibility.err
		}
	}

	return nil
}

// EnabledAsBridge returns whether private networking is enabled, and configured in bridge mode.
func (cfg Config) EnabledAsBridge() bool {
	return cfg.Enabled && cfg.Mode == ModeBridge
}

// EnabledAsLocalAccess returns whether private networking is enabled, and configured in local access mode.
func (cfg Config) EnabledAsLocalAccess() bool {
	return cfg.Enabled && cfg.Mode == ModeLocalAccess
}

func (cfg Config) EnabledWithLiveMigration() bool {
	return cfg.Enabled && cfg.LiveMigration
}

// IsLocallyConnected returns whether private networking is enabled, and configured in local access or
// bridge mode. It signifies that the private network can egress via a local device configured on
// the node. Currently, INB or a K8s cluster in local access mode can egress via local device.
func (cfg Config) IsLocallyConnected() bool {
	return cfg.Enabled && (cfg.Mode == ModeBridge || cfg.Mode == ModeLocalAccess)
}

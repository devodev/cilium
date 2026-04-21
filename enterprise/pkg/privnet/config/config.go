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

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const (
	// FlagEnable is the flag to enable private networking.
	FlagEnable = "private-networks-enabled"

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
	// Cell registers the private networking configuration, and performs validation.
	Cell = cell.Group(
		cell.Config(defaultFlags),
		cell.Provide(NewConfig),
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
}

// NewConfig creates a Config from the parsed Flags.
func NewConfig(f Flags) (Config, error) {
	switch f.Mode {
	case ModeDefault, ModeBridge, ModeLocalAccess:
	default:
		return Config{}, fmt.Errorf("invalid private networks mode %q, should be one of: %q, %q, %q",
			f.Mode, ModeDefault, ModeBridge, ModeLocalAccess)
	}

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
	}, nil
}

// EnabledAsBridge returns whether private networking is enabled, and configured in bridge mode.
func (cfg Config) EnabledAsBridge() bool {
	return cfg.Enabled && cfg.Mode == ModeBridge
}

// EnabledAsLocalAccess returns whether private networking is enabled, and configured in local access mode.
func (cfg Config) EnabledAsLocalAccess() bool {
	return cfg.Enabled && cfg.Mode == ModeLocalAccess
}

// IsLocallyConnected returns whether private networking is enabled, and configured in local access or
// bridge mode. It signifies that the private network can egress via a local device configured on
// the node. Currently, INB or a K8s cluster in local access mode can egress via local device.
func (cfg Config) IsLocallyConnected() bool {
	return cfg.Enabled && (cfg.Mode == ModeBridge || cfg.Mode == ModeLocalAccess)
}

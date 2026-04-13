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

	"github.com/spf13/pflag"

	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// EnableClusterAwareAddressing enables cluster-aware addressing
	EnableClusterAwareAddressing = "enable-cluster-aware-addressing"

	// EnableInterClusterSNAT enables inter-cluster SNAT
	EnableInterClusterSNAT = "enable-inter-cluster-snat"

	// EnablePhantomServices enables phantom service handling
	EnablePhantomServices = "enable-phantom-services"
)

type Config struct {
	// EnableClusterAwareAddressing enables cluster-aware addressing
	EnableClusterAwareAddressing bool

	// EnableInterClusterSNAT enables inter-cluster SNAT
	EnableInterClusterSNAT bool

	// EnablePhantomServices enables phantom services support
	EnablePhantomServices bool
}

// IsPhantomServicesEnabled returns whether phantom services are enabled
func (cfg Config) IsPhantomServicesEnabled() bool {
	return cfg.EnablePhantomServices
}

// IsOverlappingPodCIDREnabled returns whether overlapping PodCIDR support is enabled
func (cfg Config) IsOverlappingPodCIDREnabled() bool {
	return cfg.EnableClusterAwareAddressing && cfg.EnableInterClusterSNAT
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableClusterAwareAddressing, def.EnableClusterAwareAddressing, "Enable cluster-aware addressing, to support overlapping PodCIDRs")
	flags.Bool(EnableInterClusterSNAT, def.EnableInterClusterSNAT, "Enable inter-cluster SNAT, to support overlapping PodCIDRs")
	flags.Bool(EnablePhantomServices, def.EnablePhantomServices, "Enable phantom services handling")
}

func (cfg Config) Validate(dcfg *option.DaemonConfig, kprConfig kpr.KPRConfig, wgConfig wgTypes.Config, ipsecConfig ipsecTypes.Config) error {
	if !cfg.EnableClusterAwareAddressing {
		if cfg.EnableInterClusterSNAT {
			return fmt.Errorf("%s depends on %s", EnableInterClusterSNAT, EnableClusterAwareAddressing)
		}

		return nil
	}

	if !dcfg.TunnelingEnabled() {
		return fmt.Errorf("--%s depends on tunnel=%s|%s", EnableClusterAwareAddressing, tunnel.VXLAN, tunnel.Geneve)
	}

	// We cannot rely on the EnableNodePort value only because it may be
	// mutated depending on the KPR settings. Hence, check them both.
	if !kprConfig.KubeProxyReplacement {
		return fmt.Errorf("--%s depends on BPF NodePort", EnableClusterAwareAddressing)
	}

	incompatibilities := map[string]bool{
		option.EnableEndpointRoutes:         dcfg.EnableEndpointRoutes,
		option.EnableEndpointHealthChecking: dcfg.EnableEndpointHealthChecking,
		option.EnableIPSec:                  ipsecConfig.Enabled(),
		wgTypes.EnableWireguard:             wgConfig.Enabled(),
	}

	for cfgname, enabled := range incompatibilities {
		if enabled {
			return fmt.Errorf("Currently, --%s can't be used with --%s", EnableClusterAwareAddressing, cfgname)
		}
	}

	return nil
}

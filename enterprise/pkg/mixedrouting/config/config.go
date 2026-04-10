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

	"github.com/cilium/cilium/daemon/cmd/cni"
	ipsectypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	dpopt "github.com/cilium/cilium/pkg/datapath/option"
	ipamopt "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

// FallbackType is the type of the possible values for the --fallback-routing-mode flag
type FallbackType string

const (
	// FallbackDisabled: mixed routing modes support is disabled.
	FallbackDisabled = FallbackType("")
	// FallbackNative: mixed routing mode support is enabled, and configured
	// to fallback to native routing in case of a mismatch.
	FallbackNative = FallbackType(option.RoutingModeNative)
	// FallbackTunnel: mixed routing mode support is enabled, and configured
	// to fallback to tunnel routing in case of a mismatch.
	FallbackTunnel = FallbackType(option.RoutingModeTunnel)

	fallbackRoutingModeFlag = "fallback-routing-mode"
)

// Config represents the mixed routing mode configuration.
type Config struct {
	FallbackRoutingMode FallbackType
}

// Flags implements the cell.Flagger interface, to register the given flags.
func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(fallbackRoutingModeFlag, string(def.FallbackRoutingMode),
		fmt.Sprintf("Enable fallback routing mode, used in case of mismatch between "+
			"source and destination node (supported: %s)", FallbackTunnel))
}

func (cfg Config) Validate(dcfg *option.DaemonConfig, cmcfg cecmcfg.Config, cnicfg cni.CNIConfigManager, lbcfg loadbalancer.Config, ipsecCfg ipsectypes.Config) error {
	switch cfg.FallbackRoutingMode {
	case FallbackDisabled:
		return nil
	case FallbackTunnel:
	case FallbackNative:
		return fmt.Errorf("currently, %s=%s is not supported", fallbackRoutingModeFlag, FallbackNative)
	default:
		return fmt.Errorf("invalid %s value %q, valid fallback modes are {%s}",
			fallbackRoutingModeFlag, cfg.FallbackRoutingMode, FallbackTunnel)
	}

	for cfgname, enabled := range map[string]bool{
		option.EnableEncryptionStrictModeEgress: dcfg.EnableEncryptionStrictModeEgress,
		option.EnableIPSec:                      ipsecCfg.Enabled(),
		option.EnableEgressGateway:              dcfg.EnableEgressGateway,
		option.EnableIPv4EgressGatewayHA:        dcfg.EnableIPv4EgressGatewayHA,
		option.EnableNat46X64Gateway:            dcfg.EnableNat46X64Gateway,
		option.EnableVTEP:                       dcfg.EnableVTEP,
		option.EncryptNode:                      dcfg.EncryptNode,
		option.InstallNoConntrackIptRules:       dcfg.InstallNoConntrackIptRules,

		cecmcfg.EnableClusterAwareAddressing: cmcfg.EnableClusterAwareAddressing,
		cecmcfg.EnableInterClusterSNAT:       cmcfg.EnableInterClusterSNAT,
	} {
		if enabled {
			return fmt.Errorf("currently, --%s is not compatible with --%s", fallbackRoutingModeFlag, cfgname)
		}
	}

	switch dcfg.IPAM {
	case ipamopt.IPAMKubernetes, ipamopt.IPAMClusterPool:
	default:
		return fmt.Errorf("currently, %s is not compatible with %s=%s",
			fallbackRoutingModeFlag, option.IPAM, dcfg.IPAM)
	}

	if lbcfg.LBMode != loadbalancer.LBModeSNAT {
		return fmt.Errorf("currently, %s requires %s=%s", fallbackRoutingModeFlag, lbcfg.LBMode, loadbalancer.LBModeSNAT)
	}

	if dcfg.DatapathMode != dpopt.DatapathModeVeth {
		return fmt.Errorf("currently, %s requires %s=%s",
			fallbackRoutingModeFlag, option.DatapathMode, dpopt.DatapathModeVeth)
	}

	if cnicfg.GetChainingMode() != "none" {
		return fmt.Errorf("currently, %s requires %s=%s",
			fallbackRoutingModeFlag, option.CNIChainingMode, "none")
	}

	return nil
}

func (def Config) IsMixedRoutingEnabled() bool {
	return def.FallbackRoutingMode != FallbackDisabled
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"github.com/vishvananda/netlink"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// EvpnBase returns a [BPFEvpnBase].
func EvpnBase(lnc *Config, link netlink.Link) any {
	cfg := NewBPFEvpnBase(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)
	cfg.InterfaceMAC.Addr = mac.MAC(link.Attrs().HardwareAddr).As6()

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6FragmentsTracking

	return cfg
}

// EvpnEnterprise returns a [BPFEvpnEnterprise].
func EvpnEnterprise(lnc *Config, evpnCfg evpnConfig.Config, privnetCfg privnetConfig.Config) any {
	cfg := NewBPFEvpnEnterprise()

	cfg.EVPNEnable = evpnCfg.Enabled

	cfg.PrivnetEnable = privnetCfg.Enabled
	cfg.PrivnetBridgeEnable = privnetCfg.EnabledAsBridge()
	cfg.PrivnetLocalAccessEnable = privnetCfg.EnabledAsLocalAccess()
	cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules
	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

	return cfg
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package loader

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	encryptionPolicyTypes "github.com/cilium/cilium/enterprise/pkg/encryption/policy/types"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	pnconfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	pnendpoints "github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// EnterpriseCell provides the enterprise-specific loader config hooks.
var EnterpriseCell = cell.Module(
	"enterprise-loader",
	"Enterprise Loader",

	cell.Provide(
		newEnterpriseLoader,
		newPrivnetDHCPDevice,
	),

	cell.Invoke(
		(*EnterpriseLoader).registerEndpointConfig,
		(*EnterpriseLoader).registerOverlayConfig,
		(*EnterpriseLoader).registerNetdevConfig,
		(*EnterpriseLoader).registerWireguardConfig,
	),
)

type EnterpriseLoader struct {
	privnetConfig       pnconfig.Config
	evpnConfig          evpnConfig.Config
	inspectionConfig    inspectionConfig.Config
	encryptionPolicyCfg encryptionPolicyTypes.Config
	db                  *statedb.DB
	deviceTable         statedb.Table[*tables.Device]
}

func newEnterpriseLoader(in struct {
	cell.In

	PrivnetConfig       pnconfig.Config
	EvpnConfig          evpnConfig.Config
	InspectionConfig    inspectionConfig.Config
	EncryptionPolicyCfg encryptionPolicyTypes.Config
	DB                  *statedb.DB
	DeviceTable         statedb.Table[*tables.Device]
}) *EnterpriseLoader {
	return &EnterpriseLoader{
		privnetConfig:       in.PrivnetConfig,
		evpnConfig:          in.EvpnConfig,
		inspectionConfig:    in.InspectionConfig,
		encryptionPolicyCfg: in.EncryptionPolicyCfg,
		db:                  in.DB,
		deviceTable:         in.DeviceTable,
	}
}

func (l *EnterpriseLoader) registerEndpointConfig(pd *privnetDHCPDevice) {
	epConfigs.register(func(ep endpoint.Config, lnc *config.Config) any {
		cfg := config.NewBPFLXCEnterprise()

		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		if l.privnetConfig.Enabled {
			_, ok := pnendpoints.ExtractEndpointProperties(ep)
			if ok {
				cfg.PrivnetEnable = true
				cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
				cfg.PrivnetLocalAccessEnable = l.privnetConfig.EnabledAsLocalAccess()
				cfg.PrivnetHostReachability = l.privnetConfig.HostReachability
				cfg.PrivnetHostSNATIPv4.Addr = l.privnetConfig.HostSNATIPv4.As4()
				cfg.PrivnetHostSNATIPv6.Addr = l.privnetConfig.HostSNATIPv6.As16()

				cfg.CiliumDhcpIfIndex = uint32(pd.getIfindex())
			}
		}

		if l.evpnConfig.Enabled {
			cfg.EVPNEnable = true
			dev, _, found := l.deviceTable.Get(l.db.ReadTxn(), tables.DeviceNameIndex.Query(l.evpnConfig.VxlanDevice))
			if found {
				cfg.EVPNDeviceIfIndex = uint32(dev.Index)
				cfg.EVPNDeviceMAC.Addr = mac.MAC(dev.HardwareAddr).As6()
			}
		}

		if l.inspectionConfig.Enabled {
			dev, _, found := l.deviceTable.Get(l.db.ReadTxn(), tables.DeviceNameIndex.Query(inspectionConfig.InterfaceName))
			if found {
				cfg.PassiveInspectionEnable = true
				cfg.PassiveInspectionIfIndex = uint32(dev.Index)
			}
		}

		return cfg
	})
}

func (l *EnterpriseLoader) registerOverlayConfig() {
	overlayConfigs.register(func(lnc *config.Config, link netlink.Link) any {
		cfg := config.NewBPFOverlayEnterprise()

		cfg.PrivnetEnable = l.privnetConfig.Enabled
		cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
		cfg.PrivnetLocalAccessEnable = l.privnetConfig.EnabledAsLocalAccess()
		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
		cfg.EnableICMPRule = option.Config.EnableICMPRules
		cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

		return cfg
	})
}

func (l *EnterpriseLoader) registerNetdevConfig() {
	netdevConfigs.register(func(ep endpoint.Config, lnc *config.Config, link netlink.Link, _ netip.Addr, _ netip.Addr) any {
		cfg := config.NewBPFHostEnterprise()

		cfg.EncryptionPolicyFallbackEncrypt = l.encryptionPolicyCfg.FallbackEncrypt()

		cfg.PrivnetEnable = l.privnetConfig.Enabled
		cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
		cfg.PrivnetLocalAccessEnable = l.privnetConfig.EnabledAsLocalAccess()
		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		return cfg
	})
}

func (l *EnterpriseLoader) registerWireguardConfig() {
	wireguardConfigs.register(func(lnc *config.Config, link netlink.Link) any {
		cfg := config.NewBPFWireguardEnterprise()

		cfg.PrivnetEnable = l.privnetConfig.Enabled
		cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
		cfg.PrivnetLocalAccessEnable = l.privnetConfig.EnabledAsLocalAccess()
		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		return cfg
	})
}

// newPrivnetDHCPDevice registers lifecycle hook to create [pnconfig.DHCPInterfaceName]
// and provides access to its ifindex. This is used in bpf/lib/enterprise_privnet.h
// to redirect DHCP packets for processing by the agent.
func newPrivnetDHCPDevice(lc cell.Lifecycle, fence regeneration.Fence, cfg pnconfig.Config) *privnetDHCPDevice {
	p := &privnetDHCPDevice{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
	// Register an endpoint regeneration fence to force regeneration to wait for the cilium_dhcp
	// device to be ready.
	fence.Add("privnet-dhcp", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.ready:
			return nil
		}
	})
	lc.Append(p)
	return p
}

type privnetDHCPDevice struct {
	cfg     pnconfig.Config
	ifindex atomic.Uint32
	ready   chan struct{}
}

func (p *privnetDHCPDevice) getIfindex() uint32 {
	return p.ifindex.Load()
}

// Start implements [cell.HookInterface].
func (p *privnetDHCPDevice) Start(ctx cell.HookContext) error {
	defer close(p.ready)
	if !p.cfg.Enabled {
		return p.deleteDevice()
	}

	link, err := safenetlink.LinkByName(pnconfig.DHCPInterfaceName)
	if err != nil {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: pnconfig.DHCPInterfaceName}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return err
		}
		link = dummy
	}

	p.ifindex.Store(uint32(link.Attrs().Index))
	return netlink.LinkSetUp(link)
}

// Stop implements [cell.HookInterface].
func (p *privnetDHCPDevice) Stop(cell.HookContext) error {
	return nil
}

func (p *privnetDHCPDevice) deleteDevice() error {
	link, _ := safenetlink.LinkByName(pnconfig.DHCPInterfaceName)
	if link != nil {
		return netlink.LinkDel(link)
	}
	return nil
}

var _ cell.HookInterface = &privnetDHCPDevice{}

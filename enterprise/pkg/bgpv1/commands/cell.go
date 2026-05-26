// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package commands

import (
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	ossCommands "github.com/cilium/cilium/pkg/bgp/commands"
	"github.com/cilium/cilium/pkg/option"
)

// Override the OSS BGP commands with the enterprise-extended versions
var Cell = cell.Group(
	cell.DecorateAll(
		func(
			dc *option.DaemonConfig,
			config config.Config,
			bgpMgr agent.EnterpriseBGPRouterManager,
			errorPathStore *reconcilerv2.ErrorPathStore,
			ossCmds ossCommands.BGPCommands,
		) ossCommands.BGPCommands {
			if dc.BGPControlPlaneEnabled() && config.Enabled {
				// Override the OSS BGP commands with the
				// enterprise-extended versions when both OSS and
				// enterprise BGP Control Plane are enabled.
				ossCmds["bgp/routes"] = BGPRoutesCmd(bgpMgr, errorPathStore)
				ossCmds["bgp/route-policies"] = BGPPRoutePolicies(bgpMgr)
			}
			return ossCmds
		},
	),
	cell.Provide(
		func(
			dc *option.DaemonConfig,
			config config.Config,
			bgpMgr agent.EnterpriseBGPRouterManager,
			errorPathStore *reconcilerv2.ErrorPathStore,
		) hive.ScriptCmdsOut {
			if !config.Enabled {
				// If enterprise BGP Control Plane is disabled,
				// do not provide any commands.
				return hive.ScriptCmdsOut{}
			}

			if dc.BGPControlPlaneEnabled() {
				// If both OSS and enterprise BGP Control Plane
				// are enabled, the enterprise-extended BGP
				// commands will be provided by the decorator
				// above, so no need to provide them here.
				return hive.ScriptCmdsOut{}
			}

			// If only enterprise BGP Control Plane is enabled,
			// provide the enterprise-extended BGP commands
			// directly.
			return hive.NewScriptCmds(map[string]script.Cmd{
				"bgp/routes":         BGPRoutesCmd(bgpMgr, errorPathStore),
				"bgp/route-policies": BGPPRoutePolicies(bgpMgr),
			})
		},
	),
)

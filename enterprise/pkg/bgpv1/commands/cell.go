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
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	ossCommands "github.com/cilium/cilium/pkg/bgp/commands"
)

// Override the OSS BGP commands with the enterprise-extended versions
var Cell = cell.Group(
	cell.DecorateAll(
		func(
			config config.Config,
			bgpMgr agent.EnterpriseBGPRouterManager,
			errorPathStore *reconcilerv2.ErrorPathStore,
			ossCmds ossCommands.BGPCommands,
		) ossCommands.BGPCommands {
			if config.Enabled {
				// Override the OSS BGP commands with the
				// enterprise-extended versions when the enterprise
				// BGP Control Plane is enabled.
				ossCmds["bgp/globals"] = BGPGlobalsCmd(bgpMgr)
				ossCmds["bgp/peers"] = BGPPeersCmd(bgpMgr)
				ossCmds["bgp/routes"] = BGPRoutesCmd(bgpMgr, errorPathStore)
				ossCmds["bgp/route-policies"] = BGPPRoutePolicies(bgpMgr)
			}
			return ossCmds
		},
	),
)

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv1

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/api"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/commands"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/metrics"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/option"
)

// Cell is module with Enterprise BGP Control Plane components
var Cell = cell.Module(
	"enterprise-bgp-control-plane",
	"Enterprise BGP Control Plane",

	// BGP resources
	cell.Provide(
		k8s.IsovalentBGPPeerConfigResource,
		k8s.IsovalentBGPAdvertisementResource,
		k8s.IsovalentBGPNodeConfigResource,
		k8s.IsovalentBGPPolicyResource,
		k8s.IsovalentBGPVRFConfigResource,
	),

	// enterprise-only reconcilers
	reconcilerv2.ConfigReconcilers,

	// set enterprise BGP config object in agent
	cell.Config(config.DefaultConfig),

	// enterprise-specific commands
	commands.Cell,

	// enterprise-specific API handlers
	api.Cell,

	// enterprise BGP agent components
	cell.Provide(
		agent.NewController,
		manager.NewBGPRouterManager,
	),

	cell.ProvidePrivate(
		gobgp.NewEnterpriseRouterProvider,
	),

	// override GoBGP router provider with the enterprise version
	cell.DecorateAll(
		func(_ types.RouterProvider) types.RouterProvider {
			return gobgp.NewEnterpriseRouterProviderAsOSS()
		},
	),

	cell.Invoke(
		// Invoke enterprise bgp controller to trigger the constructor.
		func(*agent.Controller) {},

		// Register metrics collector
		metrics.RegisterCollector,

		// Raise error when OSS and enterprise BGP CPlane are both enabled
		func(cfg config.Config, dc *option.DaemonConfig) error {
			if cfg.Enabled && dc.BGPControlPlaneEnabled() {
				return fmt.Errorf("OSS and Enterprise BGP Control Plane cannot be enabled at the same time")
			}
			return nil
		},
	),
)

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"bgp-enterprise-operator",
	"BGP Control Plane Operator",

	cell.Provide(
		k8s.IsovalentBGPClusterConfigResource,
		k8s.IsovalentBGPPeerConfigResource,
		k8s.IsovalentBGPNodeConfigResource,
		k8s.IsovalentBGPNodeConfigOverrideResource,
		k8s.IsovalentBGPAdvertisementResource,
		k8s.IsovalentVRFResource,
		k8s.IsovalentBGPVRFConfigResource,
	),

	cell.ProvidePrivate(
		newSecretResource,
		k8s.IsovalentBFDProfileResource,
		store.NewBGPCPResourceStore[*v1.IsovalentBGPClusterConfig],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPPeerConfig],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPNodeConfigOverride],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPAdvertisement],
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentVRF],
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig],
		store.NewBGPCPResourceStore[*cilium_v2.CiliumNode],
	),

	cell.ProvidePrivate(signaler.NewBGPCPSignaler),

	cell.Config(config.DefaultConfig),
	metrics.Metric(newBGPOperatorMetrics),

	cell.Invoke(
		RegisterBGPResourceMapper,
		registerPeerConfigStatusReconciler,

		// Raise error when OSS and enterprise BGP CPlane are both enabled
		func(cfg config.Config, dc *option.DaemonConfig) error {
			if cfg.Enabled && dc.BGPControlPlaneEnabled() {
				return fmt.Errorf("OSS and Enterprise BGP Control Plane cannot be enabled at the same time")
			}
			return nil
		},
	),
)

func newSecretResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, cc config.Config, dc *option.DaemonConfig) resource.Resource[*slim_core_v1.Secret] {
	if !c.IsEnabled() || !cc.Enabled {
		return nil
	}
	if dc.BGPSecretsNamespace == "" {
		return nil
	}
	return resource.New[*slim_core_v1.Secret](
		lc, utils.ListerWatcherFromTyped(
			c.Slim().CoreV1().Secrets(dc.BGPSecretsNamespace),
		), mp)
}

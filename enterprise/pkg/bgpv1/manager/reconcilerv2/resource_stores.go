// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

func newEnterpriseSecretResource(
	logger *slog.Logger,
	lc cell.Lifecycle,
	c client.Clientset,
	dc *option.DaemonConfig,
	mp workqueue.MetricsProvider,
	bgpConfig config.Config,
) resource.Resource[*slim_corev1.Secret] {
	if !bgpConfig.Enabled || !c.IsEnabled() {
		return nil
	}

	if dc.BGPSecretsNamespace == "" {
		logger.Warn("bgp-secrets-namespace not set, will not be able to use enterprise BGP control plane auth secrets")
		return nil
	}

	return resource.New[*slim_corev1.Secret](
		lc,
		utils.ListerWatcherFromTyped[*slim_corev1.SecretList](
			c.Slim().CoreV1().Secrets(dc.BGPSecretsNamespace),
		),
		mp,
	)
}

func newEnterpriseCiliumPodIPPoolResource(
	logger *slog.Logger,
	lc cell.Lifecycle,
	c client.Clientset,
	dc *option.DaemonConfig,
	mp workqueue.MetricsProvider,
	bgpConfig config.Config,
) resource.Resource[*v2alpha1.CiliumPodIPPool] {
	if !bgpConfig.Enabled || !c.IsEnabled() || dc.IPAM != ipamOption.IPAMMultiPool {
		return nil
	}

	return resource.New[*v2alpha1.CiliumPodIPPool](
		lc,
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumPodIPPoolList](
			c.CiliumV2alpha1().CiliumPodIPPools(),
		),
		mp,
		resource.WithMetric("CiliumPodIPPool"),
	)
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lbipam

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

var EnterpriseCell = cell.DecorateAll(func(
	ipam *LBIPAM,
	dc *option.DaemonConfig,
	bgpConfig config.Config,
) *LBIPAM {
	if !dc.BGPControlPlaneEnabled() && bgpConfig.Enabled {
		// Register BGPLoadBalancerClass if the only enterprise BGP
		// control plane is enabled. This is required because LBIPAM
		// doesn't register the BGP LoadBalancerClass when the OSS BGP
		// CPlane is disabled.
		ipam.lbClasses = append(ipam.lbClasses, v2alpha1.BGPLoadBalancerClass)
	}
	return ipam
})

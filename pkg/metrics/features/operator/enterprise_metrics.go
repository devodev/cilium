//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package features

import (
	daemonOption "github.com/cilium/cilium/pkg/option"

	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type EnterpriseMetrics struct {
	ACLBEnterpriseBGPEnabled   metric.Gauge
	ACLBBFDEnabled             metric.Gauge
	ACLBEgressGatewayHAEnabled metric.Gauge
}

const (
	enterprise  = "enterprise_"
	subsystemDP = "feature_datapath"
)

// NewEnterpriseMetrics returns all enterprise feature metrics. If 'withDefaults' is set, then
// all metrics will have defined all of their possible values.
func NewEnterpriseMetrics(withDefaults bool) EnterpriseMetrics {
	return EnterpriseMetrics{
		ACLBEnterpriseBGPEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "BGP enabled on the operator",
			Name:      "bgp_enabled",
		}),

		ACLBBFDEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "BFD enabled on the operator",
			Name:      "bfd_enabled",
		}),

		ACLBEgressGatewayHAEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "Egress Gateway HA enabled on the operator",
			Name:      "egress_gateway_ha_enabled",
		}),
	}
}

type enterpriseFeatureMetrics interface {
	update(params enabledEnterpriseFeatures, config *option.OperatorConfig, daemonConfig *daemonOption.DaemonConfig)
}

func (m EnterpriseMetrics) update(params enabledEnterpriseFeatures, config *option.OperatorConfig, daemonConfig *daemonOption.DaemonConfig) {
	if params.IsEnterpriseBGPEnabled() {
		m.ACLBEnterpriseBGPEnabled.Set(1)
	}
	if params.IsBFDEnabled() {
		m.ACLBBFDEnabled.Set(1)
	}
	if daemonConfig.EnableIPv4EgressGatewayHA {
		m.ACLBEgressGatewayHAEnabled.Set(1)
	}
}

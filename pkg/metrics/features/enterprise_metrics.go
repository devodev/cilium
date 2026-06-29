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
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

// EnterpriseMetrics represents a collection of enterprise metrics related to a specific feature.
// Each field is named according to the specific feature that it tracks.
type EnterpriseMetrics struct {
	ACLBSRv6                           metric.Gauge
	ACLBEnterpriseBGPEnabled           metric.Gauge
	ACLBBFDEnabled                     metric.Gauge
	ACLBEgressGatewayHAEnabled         metric.Gauge
	ACLBEgressGatewayStandaloneEnabled metric.Gauge
	ACLBMixedRoutingModeEnabled        metric.Gauge
	ACLBEncryptionPolicyEnabled        metric.Gauge
	ACLBPhantomServicesEnabled         metric.Gauge
	ACLBOverlappingPodCIDREnabled      metric.Gauge
	CPFQDNHAEnabled                    metric.Gauge
	CPFQDNOfflineModeEnabled           metric.Gauge
	DPMulticastEnabled                 metric.Gauge
}

const (
	enterprise = "enterprise_"
)

// NewEnterpriseMetrics returns all enterprise feature metrics. If 'withDefaults' is set, then
// all metrics will have defined all of their possible values.
func NewEnterpriseMetrics(withDefaults bool) EnterpriseMetrics {
	return EnterpriseMetrics{
		ACLBSRv6: metric.NewGauge(metric.GaugeOpts{
			Help:      "Cilium SRv6 enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Name:      "srv6_enabled",
		}),

		ACLBEnterpriseBGPEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "BGP enabled on the agent",
			Name:      "bgp_enabled",
		}),

		ACLBBFDEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "BFD enabled on the agent",
			Name:      "bfd_enabled",
		}),

		ACLBEgressGatewayHAEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "Egress Gateway HA enabled on the agent",
			Name:      "egress_gateway_ha_enabled",
		}),

		ACLBEgressGatewayStandaloneEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "Egress Gateway Standalone enabled on the agent",
			Name:      "egress_gateway_standalone_enabled",
		}),

		ACLBMixedRoutingModeEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "Mixed Routing Mode enabled on the agent",
			Name:      "mixed_routing_mode_enabled",
		}),

		ACLBEncryptionPolicyEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "Encryption Policy enabled on the agent",
			Name:      "encryption_policy_enabled",
		}),

		ACLBPhantomServicesEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "Phantom Services enabled on the agent",
			Name:      "phantom_services_enabled",
		}),

		ACLBOverlappingPodCIDREnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Help:      "Overlapping Pod CIDR enabled on the agent",
			Name:      "overlapping_pod_cidr_enabled",
		}),

		CPFQDNHAEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemCP,
			Help:      "FQDN HA enabled on the agent",
			Name:      "fqdn_ha_enabled",
		}),

		CPFQDNOfflineModeEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemCP,
			Help:      "FQDN Offline Mode enabled on the agent",
			Name:      "fqdn_offline_mode_enabled",
		}),

		DPMulticastEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemDP,
			Help:      "Multicast enabled on the agent",
			Name:      "multicast_enabled",
		}),
	}
}

type enterpriseFeatureMetrics interface {
	update(params enabledEnterpriseFeatures, config *option.DaemonConfig)
}

func (m EnterpriseMetrics) update(params enabledEnterpriseFeatures, config *option.DaemonConfig) {
	if config.EnableSRv6 {
		m.ACLBSRv6.Set(1)
	}

	if params.IsEnterpriseBGPEnabled() {
		m.ACLBEnterpriseBGPEnabled.Set(1)
	}

	if params.IsBFDEnabled() {
		m.ACLBBFDEnabled.Set(1)
	}

	if config.EnableIPv4EgressGatewayHA {
		m.ACLBEgressGatewayHAEnabled.Set(1)
	}

	if params.IsEgressGatewayStandaloneEnabled() {
		m.ACLBEgressGatewayStandaloneEnabled.Set(1)
	}

	if params.IsMixedRoutingEnabled() {
		m.ACLBMixedRoutingModeEnabled.Set(1)
	}

	if params.IsEncryptionPolicyEnabled() {
		m.ACLBEncryptionPolicyEnabled.Set(1)
	}

	if params.IsPhantomServicesEnabled() {
		m.ACLBPhantomServicesEnabled.Set(1)
	}

	if params.IsOverlappingPodCIDREnabled() {
		m.ACLBOverlappingPodCIDREnabled.Set(1)
	}

	if params.IsFQDNHAEnabled() {
		m.CPFQDNHAEnabled.Set(1)
	}

	if params.IsFQDNOfflineModeEnabled() {
		m.CPFQDNOfflineModeEnabled.Set(1)
	}

	if params.IsMulticastEnabled() {
		m.DPMulticastEnabled.Set(1)
	}
}

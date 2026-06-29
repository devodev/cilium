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
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	bgpconfig "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	clustermeshConfig "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
	segwcfg "github.com/cilium/cilium/enterprise/pkg/egressgatewayha/standalone/config"
	encryptionPolicyTypes "github.com/cilium/cilium/enterprise/pkg/encryption/policy/types"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	cemrcfg "github.com/cilium/cilium/enterprise/pkg/mixedrouting/config"

	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// EnterpriseCell will retrieve information from all other cells /
// configuration to describe, in form of prometheus metrics, which
// enterprise features are enabled on the agent.
var EnterpriseCell = cell.Module(
	"enabled-enterprise-features",
	"Exports prometheus metrics showing which ent feat are enabled in cilium-agent",

	cell.Invoke(updateEnterpriseAgentConfigMetricOnStart),
	cell.Provide(
		func(m EnterpriseMetrics) enterpriseFeatureMetrics {
			return m
		},
	),
	metrics.Metric(func() EnterpriseMetrics {
		if withDefaults != "" {
			return NewEnterpriseMetrics(true)
		}
		return NewEnterpriseMetrics(false)
	}),
)

type enterpriseFeaturesParams struct {
	cell.In

	Log           *slog.Logger
	JobGroup      job.Group
	Health        cell.Health
	Lifecycle     cell.Lifecycle
	ConfigPromise promise.Promise[*option.DaemonConfig]
	Metrics       enterpriseFeatureMetrics

	BGP                bgpconfig.Config
	BFD                types.BFDConfig
	EgressGAStandalone segwcfg.Config
	MixedRoutingMode   cemrcfg.Config
	EncryptionPolicy   encryptionPolicyTypes.Config
	ClusterMeshConfig  clustermeshConfig.Config
	FQDNHA             config.Config
	Multicast          maps_multicast.Config
}

func (fp *enterpriseFeaturesParams) IsEnterpriseBGPEnabled() bool {
	return fp.BGP.IsEnabled()
}

func (fp *enterpriseFeaturesParams) IsBFDEnabled() bool {
	return fp.BFD.IsEnabled()
}

func (fp *enterpriseFeaturesParams) IsEgressGatewayStandaloneEnabled() bool {
	return fp.EgressGAStandalone.IsEnabled()
}

func (fp *enterpriseFeaturesParams) IsMixedRoutingEnabled() bool {
	return fp.MixedRoutingMode.IsMixedRoutingEnabled()
}

func (fp *enterpriseFeaturesParams) IsEncryptionPolicyEnabled() bool {
	return fp.EncryptionPolicy.IsEnabled()
}

func (fp *enterpriseFeaturesParams) IsPhantomServicesEnabled() bool {
	return fp.ClusterMeshConfig.IsPhantomServicesEnabled()
}

func (fp *enterpriseFeaturesParams) IsOverlappingPodCIDREnabled() bool {
	return fp.ClusterMeshConfig.IsOverlappingPodCIDREnabled()
}

func (fp *enterpriseFeaturesParams) IsFQDNHAEnabled() bool {
	return fp.FQDNHA.IsEnabled()
}

func (fp *enterpriseFeaturesParams) IsFQDNOfflineModeEnabled() bool {
	return fp.FQDNHA.IsOfflineModeEnabled()
}

func (fp *enterpriseFeaturesParams) IsMulticastEnabled() bool {
	return fp.Multicast.MulticastEnabled
}

type enabledEnterpriseFeatures interface {
	IsEnterpriseBGPEnabled() bool
	IsBFDEnabled() bool
	IsEgressGatewayStandaloneEnabled() bool
	IsMixedRoutingEnabled() bool
	IsEncryptionPolicyEnabled() bool
	IsPhantomServicesEnabled() bool
	IsOverlappingPodCIDREnabled() bool
	IsFQDNHAEnabled() bool
	IsFQDNOfflineModeEnabled() bool
	IsMulticastEnabled() bool
}

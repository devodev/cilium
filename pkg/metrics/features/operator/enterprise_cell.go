// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	bgpconfig "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// EnterpriseCell will retrieve information from all other cells /
// configuration to describe, in form of prometheus metrics, which
// enterprise features are enabled on the operator.
var EnterpriseCell = cell.Module(
	"enabled-features",
	"Exports prom metrics describing which ent feat are enabled in operator",

	cell.Invoke(updateEnterpriseOperatorConfigMetricOnStart),
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

	Log       *slog.Logger
	JobGroup  job.Group
	Health    cell.Health
	Lifecycle cell.Lifecycle
	Metrics   enterpriseFeatureMetrics

	OperatorConfig *operatorOption.OperatorConfig
	DaemonConfig   *option.DaemonConfig

	BGP bgpconfig.Config
	BFD types.BFDConfig
}

func (p enterpriseFeaturesParams) IsEnterpriseBGPEnabled() bool {
	return p.BGP.IsEnabled()
}

func (p enterpriseFeaturesParams) IsBFDEnabled() bool {
	return p.BFD.IsEnabled()
}

type enabledEnterpriseFeatures interface {
	IsEnterpriseBGPEnabled() bool
	IsBFDEnabled() bool
}

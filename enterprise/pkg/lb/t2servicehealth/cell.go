// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package t2servicehealth

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"loadbalancer-t2-service-health",
	"Derives per-service T2 readiness from Envoy health state",

	cell.Config(defaultT2ServiceHealthConfig),
	cell.ProvidePrivate(newServiceHealthTable),
	cell.Invoke(registerAggregatorController),
)

type t2ServiceHealthConfig struct {
	MinHealthyBackendsPct uint32 `mapstructure:"loadbalancer-cp-t2-hc-probe-min-healthy-backends"`
}

var defaultT2ServiceHealthConfig = t2ServiceHealthConfig{
	MinHealthyBackendsPct: 20,
}

func (c t2ServiceHealthConfig) Flags(flags *pflag.FlagSet) {
	flags.Uint32("loadbalancer-cp-t2-hc-probe-min-healthy-backends", c.MinHealthyBackendsPct, "The minimum percentage of backends that must be healthy from T2 point of view in order to send traffic from T1 to it")
}

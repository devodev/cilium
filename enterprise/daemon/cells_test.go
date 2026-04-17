//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/features"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var goleakOptions = []testutils.GoleakOption{
	// Ignore all the currently running goroutines spawned
	// by prior tests or by package init() functions (like the
	// client-go logger).
	testutils.GoleakIgnoreCurrent(),
	// Ignore goroutines started by the policy trifecta, see [newPolicyTrifecta].
	testutils.GoleakIgnoreTopFunction("github.com/cilium/cilium/pkg/identity/cache.(*identityWatcher).watch.func1"),
	testutils.GoleakIgnoreTopFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
	// Ignore goroutine started by the ipset reconciler rate limiter
	testutils.GoleakIgnoreTopFunction("github.com/cilium/cilium/pkg/rate.NewLimiter.func1"),
}

// TestEnterpriseAgentCell verifies that the EnterpriseAgent can be instantiated with
// default configuration and thus the EnterpriseAgent hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestEnterpriseAgentCell(t *testing.T) {
	defer testutils.GoleakVerifyNone(t, goleakOptions...)
	defer metrics.Reinitialize()

	logging.SetLogLevel(slog.LevelDebug)
	// Populate config with default values normally set by Viper flag defaults
	option.Config.IPv4ServiceRange = cmd.AutoCIDR
	option.Config.IPv6ServiceRange = cmd.AutoCIDR

	h := hive.New(EnterpriseAgent)

	// Since some features default to true in flags (but false in helm), don't
	// test with strict feature gates here.
	hive.AddConfigOverride(h, func(cfg *features.FeatureGatesConfig) { cfg.StrictFeatureGates = false })
	err := h.Populate(hivetest.Logger(t))
	require.NoError(t, err, "hive.New(EnterpriseAgent).Populate()")
}

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
	_ "embed"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
	policydiagnostics "github.com/cilium/cilium/enterprise/pkg/policy/diagnostics"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health"
	healthTypes "github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

var agentDiagnostics = cell.Group(
	// Provide the diagnostics registry and the controller to write diagnostics
	// to status.log.
	diagnostics.NewCell("cilium-agent", version.GetCiliumVersion().Version),

	// Register diagnostic conditions for OSS features.
	cell.Invoke(registerConditions),

	policydiagnostics.Cell,
)

// The user constants that can be overridden with --diagnostics-constants.
const (
	// keyEndpointRegenMultiplier is the key for setting the threshold for endpoint regeneration latency, e.g.
	// how many times the 24h average latency should the latency be before the condition fails.
	keyEndpointRegenMultiplier = "endpoint_regen_multiplier"

	// defaultEndpointRegenMultiplier is the default threshold multiplier, e.g. if the current average latency
	// (average latency since the last evaluation) multiplied by this multiplier is above the 24h average then
	// the condition is marked failed.
	defaultEndpointRegenMultiplier = 3.0

	// keyStateDBWriteTxnThreshold is the threshold for when to report that there are StateDB WriteTxns that
	// are taking too long.
	keyStateDBWriteTxnThreshold = "statedb_write_txn_latency_seconds"

	// defaultStateDBWriteTxnThresholdSeconds is the default threshold for write transaction durations that
	// we use if a user constant with key [keyStateDBWriteTxnThreshold] is not present.
	defaultStateDBWriteTxnThresholdSeconds = 5.0
)

func registerConditions(reg *diagnostics.Registry, db *statedb.DB, dbMetrics hive.StateDBMetrics, healthTable statedb.Table[healthTypes.Status]) error {
	return reg.Register(
		diagnostics.Condition{
			ID:          "endpoint_regeneration",
			SubSystem:   "Endpoint",
			Description: "Endpoint regeneration is taking longer than expected",
			Evaluator:   evalEndpointRegeneration,
		},

		diagnostics.Condition{
			ID:          "hive_degraded_modules",
			SubSystem:   "Hive",
			Description: "One or more agent module is reporting degraded status",
			Evaluator:   evalHiveHealth(db, healthTable),
		},

		diagnostics.Condition{
			ID:          "statedb",
			SubSystem:   "StateDB",
			Description: "StateDB metrics indicate a potentially problematic access patterns",
			Evaluator:   evalStateDB(db, dbMetrics),
		},

		diagnostics.Condition{
			ID:          "endpoint_components_status",
			SubSystem:   "Endpoint",
			Description: "One or more endpoint components (BPF, Policy) are not healthy",
			Evaluator:   evalEndpointComponentStatus,
		},
	)
}

func evalEndpointRegeneration(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	stats, err := env.Histogram(metrics.EndpointRegenerationTimeStats.Opts().ConfigName, map[string]string{metrics.LabelScope: "total", metrics.LabelStatus: "success"})
	if err != nil {
		return err.Error(), diagnostics.OK
	}

	// Default to 3x the 24h average as the threshold, but allow override with "endpoint_regen_multiplier" constant.
	multp := env.UserConstant(keyEndpointRegenMultiplier, defaultEndpointRegenMultiplier)

	if stats.Avg_24h > 0.0 && stats.Avg_Latest > multp*stats.Avg_24h {
		return fmt.Sprintf("Current average endpoint regeneration latency %.1fs is >%.1fx the 24 hour average of %.1fs",
			stats.Avg_Latest, multp, stats.Avg_24h), diagnostics.Minor
	}
	return fmt.Sprintf("%.2fs OK", stats.Avg_Latest), diagnostics.OK
}

func evalHiveHealth(db *statedb.DB, healthTable statedb.Table[healthTypes.Status]) diagnostics.Evaluator {
	return func(env diagnostics.Environment) (string, diagnostics.Severity) {
		degraded := []string{}
		for status := range healthTable.List(db.ReadTxn(), health.LevelIndex.Query(healthTypes.LevelDegraded)) {
			degraded = append(degraded, status.ID.String())
		}
		if len(degraded) > 0 {
			return "Degraded modules: " + strings.Join(degraded, ", "), diagnostics.Debug
		}
		return "", diagnostics.OK
	}
}

func evalStateDB(db *statedb.DB, statedbMetrics hive.StateDBMetrics) diagnostics.Evaluator {
	evalInits := evalStateDBPendingInitializers(db)

	return func(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
		msgTxn, failedTxn := evalStateDBWriteTxnDuration(statedbMetrics, env)
		msgGraveyard, failedGraveyard := evalStateDBGraveyardObjects(statedbMetrics, env)
		msgInits, failedInits := evalInits(env)
		severity = diagnostics.OK
		if failedTxn || failedGraveyard || failedInits {
			severity = diagnostics.Debug
		}
		msg = strings.Join(
			slices.DeleteFunc([]string{msgTxn, msgGraveyard, msgInits}, func(s string) bool { return len(s) == 0 }),
			", ")
		return
	}
}

// evalStateDB_WriteTxnDuration checks if there are any write transactions that take longer than expected.
// In StateDB it's preferred to keep write transactions fairly short by breaking up processing into batches.
// This reduces table contention when there are multiple writers and keeps the overall latency of the system low.
func evalStateDBWriteTxnDuration(statedbMetrics hive.StateDBMetrics, env diagnostics.Environment) (msg string, failed bool) {
	// Grab all matching "write_txn_duration" metrics regardless of the labels
	writeTxnMetricName := statedbMetrics.WriteTxnDuration.Opts().GetConfigName()
	writeTxnMetrics, err := env.MetricsMatchingLabels(
		writeTxnMetricName,
		nil)
	if err != nil {
		return err.Error(), true
	}

	// See if any of the metrics has an average latency above the threshold
	maxAverage := 0.0
	txnThreshold := env.UserConstant(keyStateDBWriteTxnThreshold, defaultStateDBWriteTxnThresholdSeconds)
	var slowHandles []string
	for _, m := range writeTxnMetrics {
		stats, err := env.Histogram(writeTxnMetricName, m.Labels())
		if err != nil {
			continue
		}
		maxAverage = max(maxAverage, stats.Avg_Latest)
		if stats.Avg_Latest > txnThreshold {
			slowHandles = append(slowHandles, m.LabelsString())
		}
	}
	if len(slowHandles) > 0 {
		return fmt.Sprintf("WriteTxn latency >%.1fs for %v", txnThreshold, slowHandles), true
	}
	return fmt.Sprintf("WriteTxn OK (max %.1fs)", maxAverage), false
}

// evalStateDB_GraveyardObjects checks if there are objects in the graveyard index that are never collected.
// The "graveyard" index is how StateDB implements change events for deleted objects in the Changes() API, e.g.
// if there are consumers for change events then on deletion object is inserted into the graveyard index until
// it has been observed by all consumers. This condition makes sure we don't have stuck consumers for deleted objects.
func evalStateDBGraveyardObjects(statedbMetrics hive.StateDBMetrics, env diagnostics.Environment) (msg string, failed bool) {
	metricName := statedbMetrics.TableGraveyardObjectCount.Opts().GetConfigName()
	metrics, err := env.MetricsMatchingLabels(
		metricName,
		nil)
	if err != nil {
		return err.Error(), true
	}

	// Look at the graveyard object count of each table and fail if the 1 hour average is above 1 object,
	// e.g. this indicates the gauge has not been below 1 in the last hour.
	var failedTables []string
	for _, m := range metrics {
		stats, err := env.Gauge(metricName, m.Labels())
		if err != nil {
			continue
		}
		if stats.Avg_1h > 1.0 {
			failedTables = append(failedTables, m.LabelsString())
		}
	}
	if len(failedTables) > 0 {
		return fmt.Sprintf("Graveyard: Potentially stuck Changes() consumers detected for %v", failedTables), true
	}
	return "Graveyard OK", false
}

const pendingInitializersThresholdDuration = 10 * time.Minute

// evalStateDBPendingInitializers checks if there are any tables that are stuck being initialized.
func evalStateDBPendingInitializers(db *statedb.DB) func(diagnostics.Environment) (string, bool) {
	uninitializedSince := map[string]time.Time{}

	return func(env diagnostics.Environment) (msg string, failed bool) {
		txn := db.ReadTxn()
		now := env.Now()
		var failures []string
		for _, tbl := range db.GetTables(txn) {
			initializers := tbl.PendingInitializers(txn)
			if len(initializers) == 0 {
				delete(uninitializedSince, tbl.Name())
				continue
			}
			if t, ok := uninitializedSince[tbl.Name()]; ok && now.Sub(t) > pendingInitializersThresholdDuration {
				failures = append(failures, fmt.Sprintf("Table %q still waiting for initializers: %v", tbl.Name(), initializers))
			} else {
				uninitializedSince[tbl.Name()] = now
			}
		}
		if len(failures) > 0 {
			msg = strings.Join(failures, ", ")
			failed = true
		}
		return
	}

}

func evalEndpointComponentStatus(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.EndpointComponentStatus.Opts().ConfigName
	allMetrics, err := env.MetricsMatchingLabels(metricName, nil)
	if err != nil {
		return err.Error(), diagnostics.OK
	}

	var failingComponents []string
	for _, m := range allMetrics {
		if m.Labels()[metrics.LabelStatus] == "OK" {
			continue
		}
		stats, err := env.Gauge(metricName, m.Labels())
		if err != nil {
			continue
		}
		if stats.Avg_Latest > 0 {
			failingComponents = append(failingComponents,
				fmt.Sprintf("%s: %.0f", m.LabelsString(), stats.Avg_Latest))
		}
	}

	if len(failingComponents) > 0 {
		return fmt.Sprintf("Endpoints with component failures observed: [%s]", strings.Join(failingComponents, ", ")), diagnostics.Minor
	}
	return "All endpoint components OK", diagnostics.OK
}

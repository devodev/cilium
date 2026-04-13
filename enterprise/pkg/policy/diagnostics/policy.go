//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
	"github.com/cilium/cilium/pkg/metrics"
)

// The user constants that can be overridden with --diagnostics-constants.
const (
	// policyImplementationDelayMultiplierKey is the key for setting the threshold for policy implementation latency, e.g.
	// how many times the 24h average latency should the latency be before the condition fails.
	policyImplementationDelayMultiplierKey = "policy_impl_delay_multiplier"

	// defaultPolicyImplementationDelayMultiplier is the default threshold multiplier, e.g. if the current average latency
	// (average latency since the last evaluation) multiplied by this multiplier is above the 24h average then
	// the condition is marked failed.
	defaultPolicyImplementationDelayMultiplier = 3.0
)

func registerPolicyDiagnosticConditions(reg *diagnostics.Registry) error {
	return reg.Register(
		diagnostics.Condition{
			ID:          "policy_implementation",
			SubSystem:   "Policy",
			Description: "Enforcing policy updates from control plane is taking longer than expected.",
			Evaluator:   evalPolicyImplmentationDelay,
		},

		diagnostics.Condition{
			ID:          "policy_identity_updates",
			SubSystem:   "Policy",
			Description: "Propagation of identity updates to endpoint policy state is taking longer than expected.",
			Evaluator:   evalPolicyIncrementalUpdateLatency,
		},

		diagnostics.Condition{
			ID:          "policy_parsing_failures",
			SubSystem:   "Policy",
			Description: "Failures observed in parsing control plane policy objects(NP, KCNP, CNP, CCNP)",
			Evaluator:   evalPolicyParsingFailures,
		},

		diagnostics.Condition{
			ID:          "xds_failures",
			SubSystem:   "Envoy",
			Description: "Failures observed in propagating xDS config updates to Envoy",
			Evaluator:   evalEnvoyXDSFailures,
		},

		diagnostics.Condition{
			ID:          "policy_missing_proxy_redirects",
			SubSystem:   "Policy",
			Description: "Endpoint policies have missing proxy redirects",
			Evaluator:   evalPolicyMissingProxyRedirects,
		},
	)
}

func evalPolicyImplmentationDelay(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.PolicyImplementationDelay.Opts().ConfigName
	policyImplementationDelayMetrics, err := env.MetricsMatchingLabels(metricName, nil)
	if err != nil {
		return err.Error(), diagnostics.OK
	}

	var (
		overallAverage    float64
		failingConditions []string
	)
	multiplier := env.UserConstant(policyImplementationDelayMultiplierKey, defaultPolicyImplementationDelayMultiplier)
	for _, m := range policyImplementationDelayMetrics {
		stats, err := env.Histogram(metricName, m.Labels())
		if err != nil || stats.Avg_Latest == 0.0 {
			continue
		}

		overallAverage = (overallAverage + stats.Avg_Latest) / 2
		threshold := multiplier * stats.Avg_24h
		if stats.Avg_24h > 0.0 && stats.Avg_Latest > threshold {
			failingConditions = append(failingConditions,
				fmt.Sprintf("%s: %.1fs > %.1fs", m.LabelsString(), stats.Avg_Latest, threshold))
		}
	}

	if len(failingConditions) > 0 {
		return fmt.Sprintf("High policy implementation latency(latest average >%.1fx of 24 hour average): [%s]", multiplier, strings.Join(failingConditions, ", ")), diagnostics.Minor
	}

	return fmt.Sprintf("Policy implementation latency OK (average %.2fs)", overallAverage), diagnostics.OK
}

func evalPolicyIncrementalUpdateLatency(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.PolicyIncrementalUpdateDuration.Opts().ConfigName
	stats, err := env.Histogram(metricName, map[string]string{
		metrics.LabelScope: "global",
	})
	if err != nil {
		return err.Error(), diagnostics.OK
	}

	// Incremental policy update latency indicates the delay in propagating identity updates to policy maps.
	// Use same constants as that of policy implementation delay.
	multiplier := env.UserConstant(policyImplementationDelayMultiplierKey, defaultPolicyImplementationDelayMultiplier)
	if stats.Avg_24h > 0.0 && stats.Avg_Latest > multiplier*stats.Avg_24h {
		return fmt.Sprintf("Current average policy identity update propagation latency %.1fs is >%.1fx the 24 hour average of %.1fs",
			stats.Avg_Latest, multiplier, stats.Avg_24h), diagnostics.Minor
	}
	return fmt.Sprintf("Policy incremental update latency OK (average %.2fs)", stats.Avg_Latest), diagnostics.OK
}

func evalPolicyParsingFailures(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.PolicyChangeTotal.Opts().ConfigName
	failureMetrics, err := env.MetricsMatchingLabels(metricName, map[string]string{
		metrics.LabelOutcome: metrics.LabelValueOutcomeFailure,
	})
	if err != nil {
		return err.Error(), diagnostics.OK
	}

	var (
		totalFailures     int64
		failingConditions []string
	)
	for _, m := range failureMetrics {
		stats, err := env.Counter(metricName, m.Labels())
		if err != nil {
			continue
		}
		if stats.Count_Latest > 0 {
			totalFailures += stats.Count_Latest
			failingConditions = append(failingConditions, fmt.Sprintf("%s: %d", m.LabelsString(), stats.Count_Latest))
		}
	}

	if totalFailures > 0 {
		return fmt.Sprintf("Policy parsing failures observed: %d [%s]", totalFailures, strings.Join(failingConditions, ", ")), diagnostics.Minor
	}
	return "No policy parsing failures", diagnostics.OK
}

func evalEnvoyXDSFailures(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.Namespace + "_xds_events_count"
	nackMetrics, err := env.MetricsMatchingLabels(metricName, map[string]string{
		"status": "nack",
	})
	if err != nil {
		// xDS Events count metric is not registered by default.
		return fmt.Sprintf(`No %s{status="nack"} metric`, metricName), diagnostics.OK
	}

	var (
		totalNACKs        int64
		failingConditions []string
	)
	for _, m := range nackMetrics {
		stats, err := env.Counter(metricName, m.Labels())
		if err != nil {
			continue
		}
		if stats.Count_Latest > 0 {
			totalNACKs += stats.Count_Latest
			failingConditions = append(failingConditions, fmt.Sprintf("%s: %d", m.LabelsString(), stats.Count_Latest))
		}
	}

	if totalNACKs > 0 {
		return fmt.Sprintf("Rejected envoy xDS response observed: %d [%s]", totalNACKs, strings.Join(failingConditions, ", ")), diagnostics.Minor
	}
	return "No xDS failures", diagnostics.OK
}

func evalPolicyMissingProxyRedirects(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.PolicyMissingProxyRedirects.Opts().ConfigName
	stats, err := env.Gauge(metricName, nil)
	if err != nil {
		return err.Error(), diagnostics.OK
	}
	if stats.Avg_Latest > 0 {
		return fmt.Sprintf("%.0f proxy redirects are missing for endpoint policies", stats.Avg_Latest), diagnostics.Minor
	}
	return "No missing proxy redirects", diagnostics.OK
}

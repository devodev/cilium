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
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// gateway-api-controlplane uses a local Prometheus registry instead of
// pkg/metrics.NewCell because the generic Cilium metrics cell pulls in the
// agent-style metrics dependencies (notably *option.DaemonConfig), which this
// binary does not otherwise need.
func newMetricsRegistry() *prometheus.Registry {
	return prometheus.NewPedanticRegistry()
}

type metricsParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Logger    *slog.Logger
	Config    Config
	Metrics   []metric.WithMetadata `group:"hive-metrics"`
	Registry  *prometheus.Registry
}

func registerMetricsServer(p metricsParams) {
	p.Registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile(`^/sched/latencies:seconds`)},
		),
	))
	p.Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	for _, metric := range p.Metrics {
		p.Registry.MustRegister(metric.(prometheus.Collector))
	}

	mux := http.NewServeMux()
	// Serve local controlplane metrics from the private registry and merge in
	// controller-runtime metrics from its global registry.
	mux.Handle("/metrics", promhttp.HandlerFor(prometheus.Gatherers{
		p.Registry,
		prefixedMetricGatherer{
			gatherer: ctrlmetrics.Registry,
			// Only include controller-runtime-specific metric families here so we
			// do not duplicate Go/process metrics already served from the Cilium registry.
			prefixes: []string{
				"controller_runtime_",
				"workqueue_",
				"certwatcher_",
				"rest_client_",
			},
		},
	}, promhttp.HandlerOpts{}))

	server := http.Server{
		Addr:    p.Config.MetricsBindAddress,
		Handler: mux,
	}

	p.JobGroup.Add(job.OneShot("gateway-api-controlplane-prometheus-server", func(ctx context.Context, health cell.Health) error {
		p.Logger.Info("Serving prometheus metrics", logfields.Address, p.Config.MetricsBindAddress)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}, job.WithShutdown()))

	p.Lifecycle.Append(cell.Hook{
		OnStop: func(ctx cell.HookContext) error {
			return server.Shutdown(ctx)
		},
	})
}

type prefixedMetricGatherer struct {
	gatherer prometheus.Gatherer
	prefixes []string
}

func (g prefixedMetricGatherer) Gather() ([]*dto.MetricFamily, error) {
	metricFamilies, err := g.gatherer.Gather()
	if err != nil {
		return nil, err
	}

	filtered := make([]*dto.MetricFamily, 0, len(metricFamilies))
	for _, family := range metricFamilies {
		if family == nil || family.Name == nil {
			continue
		}
		if g.matches(*family.Name) {
			filtered = append(filtered, family)
		}
	}
	return filtered, nil
}

func (g prefixedMetricGatherer) matches(name string) bool {
	for _, prefix := range g.prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

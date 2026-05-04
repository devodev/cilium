package main

import (
	"fmt"
	"net"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

const (
	metricsNamespace = "isovalent"
	metricsSubsystem = "external_dns_proxy"
)

var (
	goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

	Metrics = cell.Module("metrics", "Metrics",
		// ExternalDNSProxyCell uses NewRegistry which currently requires DaemonConfig param.
		// TODO: Remove dependency from DaemonConfig.
		cell.ProvidePrivate(func() *option.DaemonConfig {
			return &option.DaemonConfig{}
		}),

		cell.Provide(func(cfg Config) metrics.RegistryConfig {
			if !cfg.ExposePrometheusMetrics {
				return metrics.RegistryConfig{
					PrometheusServeAddr: "",
				}
			}
			return metrics.RegistryConfig{
				PrometheusServeAddr: fmt.Sprintf(":%d", cfg.PrometheusPort),
			}
		}),

		// DNSProxy metrics registry with default sampler and metrics commands.
		metrics.NewCell("dnsproxy"),

		metrics.Metric(newProxyMetrics),

		cell.Invoke(initializeMetrics),
		cell.Invoke(setVersion),
	)
)

type metricRegistryParams struct {
	cell.In

	Registry *metrics.Registry
	Metrics  [][]metric.WithMetadata `group:"hive-metrics"`
}

type metricsOut struct {
	cell.Out

	Metrics []metric.WithMetadata `group:"hive-metrics"`
}

// Note: metrics are always initialized so we have access to sampler ring buffer data
// for debugging. However, actual prometheus server will be started depending on if
// metrics are enabled.
func initializeMetrics(p metricRegistryParams) {
	p.Registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		),
	))
	p.Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
		Namespace: fmt.Sprintf("%s_%s", metricsNamespace, metricsSubsystem),
	}))

	// Register all metrics added through hive[metrics.Metric(ctor)]
	for _, metrics := range p.Metrics {
		for _, metric := range metrics {
			p.Registry.MustRegister(metric.(prometheus.Collector))
		}
	}

	// Initialize slog handler Errors and Warnings metrics with isovalent namespace.
	metrics.InitErrorsWarningsMetric(metricsNamespace)
	p.Registry.MustRegister(metrics.ErrorsWarnings)
	metrics.FlushLoggingMetrics()

	// TODO: Add TLS support to dnsproxy prometheus server endpoint.
	// Register metric HTTP listener to cell lifecycle.
	p.Registry.AddServerRuntimeHooks("dnsproxy-prometheus-server", nil, net.ListenConfig{})
}

type proxyMetrics struct {
	Version metric.Vec[metric.Gauge]

	OfflineEnabled metric.Gauge
}

func newProxyMetrics() *proxyMetrics {
	return &proxyMetrics{
		Version: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "version",
			Help:      "FQDN Proxy version",
		}, []string{"version"}),

		OfflineEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "offline_enabled",
			Help:      "Whether or not offline-write mode is enabled",
		}),
	}
}

func setVersion(m *proxyMetrics, cfg Config) {
	m.Version.WithLabelValues(version.GetCiliumVersion().Version).Set(1)
	if cfg.EnableOfflineMode {
		m.OfflineEnabled.Set(1)
	} else {
		m.OfflineEnabled.Set(0)
	}
}

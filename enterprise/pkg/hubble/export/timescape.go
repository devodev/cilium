// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	"github.com/cilium/cilium/enterprise/pkg/hubble/timescape"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/hubble"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	exportercell "github.com/cilium/cilium/pkg/hubble/exporter/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

type timescapeTLSConfigPromise promise.Promise[*certloader.WatchedClientConfig]

var timescapeExporterCell = cell.Module(
	"hubble-timescape-exporter",
	"Hubble Timescape Exporter",

	cell.ProvidePrivate(func(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg timescapeExporterConfig) (timescapeTLSConfigPromise, error) {
		config := certloader.Config{
			TLS:              cfg.TLSEnabled,
			TLSCertFile:      cfg.TLSCertFile,
			TLSKeyFile:       cfg.TLSKeyFile,
			TLSClientCAFiles: cfg.TLSCAFiles,
		}
		return certloader.NewWatchedClientConfigPromise(lc, jobGroup, log, config)
	}),
	cell.Provide(newHubbleTimescapeExporter),
	cell.Config(defaultTimescapeExporterConfig),
)

type timescapeExporterConfig struct {
	Enabled                      bool          `mapstructure:"hubble-export-timescape-enabled"`
	Target                       string        `mapstructure:"hubble-export-timescape-target"`
	Allowlist                    string        `mapstructure:"hubble-export-timescape-allowlist"`
	Denylist                     string        `mapstructure:"hubble-export-timescape-denylist"`
	Fieldmask                    []string      `mapstructure:"hubble-export-timescape-fieldmask"`
	NodeName                     string        `mapstructure:"hubble-export-timescape-node-name"`
	Aggregations                 []string      `mapstructure:"hubble-export-timescape-aggregation"`
	AggregationIgnoreSourcePort  bool          `mapstructure:"hubble-export-timescape-aggregation-ignore-source-port"`
	AggregationRenewTTL          bool          `mapstructure:"hubble-export-timescape-aggregation-renew-ttl"`
	AggregationStateChangeFilter []string      `mapstructure:"hubble-export-timescape-aggregation-state-filter"`
	AggregationTTL               time.Duration `mapstructure:"hubble-export-timescape-aggregation-ttl"`
	IngestMode                   string        `mapstructure:"hubble-export-timescape-ingest-mode"`
	BatchSize                    int           `mapstructure:"hubble-export-timescape-batch-size"`
	BatchFlushInterval           time.Duration `mapstructure:"hubble-export-timescape-batch-flush-interval"`
	MaxBufferSize                int           `mapstructure:"hubble-export-timescape-max-buffer-size"`
	ReportDroppedFlowsInterval   time.Duration `mapstructure:"hubble-export-timescape-report-dropped-flows-interval"`
	UseCiliumServiceResolver     bool          `mapstructure:"hubble-export-timescape-use-cilium-service-resolver"`
	TLSEnabled                   bool          `mapstructure:"hubble-export-timescape-tls-enabled"`
	TLSCertFile                  string        `mapstructure:"hubble-export-timescape-tls-cert-file"`
	TLSKeyFile                   string        `mapstructure:"hubble-export-timescape-tls-key-file"`
	TLSCAFiles                   []string      `mapstructure:"hubble-export-timescape-tls-ca-files"`
}

var defaultTimescapeExporterConfig = timescapeExporterConfig{
	Enabled:                      false,
	Target:                       "hubble-timescape-export.hubble-timescape.svc.cluster.local:4261",
	Allowlist:                    "",
	Denylist:                     "",
	Fieldmask:                    []string{},
	NodeName:                     "",
	Aggregations:                 []string{},
	AggregationIgnoreSourcePort:  true,
	AggregationRenewTTL:          true,
	AggregationStateChangeFilter: []string{"new", "error", "closed"},
	AggregationTTL:               30 * time.Second,
	IngestMode:                   "auto",
	BatchSize:                    256,
	BatchFlushInterval:           250 * time.Millisecond,
	MaxBufferSize:                4096,
	ReportDroppedFlowsInterval:   time.Minute,
	UseCiliumServiceResolver:     true,
	TLSEnabled:                   false,
	TLSCertFile:                  "",
	TLSKeyFile:                   "",
	TLSCAFiles:                   []string{},
}

func (def timescapeExporterConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-export-timescape-enabled", def.Enabled, "Whether to enable the Hubble timescape exporter")
	flags.String("hubble-export-timescape-target", def.Target, "Target server to connect to for exporting flows")
	flags.String("hubble-export-timescape-allowlist", def.Allowlist, "Specify allowlist as JSON encoded FlowFilters")
	flags.String("hubble-export-timescape-denylist", def.Denylist, "Specify denylist as JSON encoded FlowFilters")
	flags.StringSlice("hubble-export-timescape-fieldmask", def.Fieldmask, "Specify list of fields to use for field mask in Hubble exporter")
	flags.String("hubble-export-timescape-node-name", def.NodeName, "Override the node_name field in exported flows")
	flags.StringSlice("hubble-export-timescape-aggregation", def.Aggregations, "Perform aggregation pre-storage ('connection', 'identity')")
	flags.Bool("hubble-export-timescape-aggregation-ignore-source-port", def.AggregationIgnoreSourcePort, "Ignore source port during aggregation")
	flags.Bool("hubble-export-timescape-aggregation-renew-ttl", def.AggregationRenewTTL, "Renew flow TTL when a new flow is observed")
	flags.StringSlice("hubble-export-timescape-aggregation-state-filter", def.AggregationStateChangeFilter,
		"The state changes to include while aggregating ('new', 'established', 'first_error', 'error', 'closed')")
	flags.Duration("hubble-export-timescape-aggregation-ttl", def.AggregationTTL, "TTL for flow aggregation")
	flags.String("hubble-export-timescape-ingest-mode", def.IngestMode,
		"Timescape ingest RPC mode to use ('auto', 'batch', 'single')")
	flags.Int("hubble-export-timescape-batch-size", def.BatchSize, "The maximum number of flows sent in a single batch")
	flags.Duration("hubble-export-timescape-batch-flush-interval", def.BatchFlushInterval,
		"The maximum time to wait before flushing a partial flow batch")
	flags.Int("hubble-export-timescape-max-buffer-size", def.MaxBufferSize, "The maximum number of flows to buffer before dropping them")
	flags.Duration("hubble-export-timescape-report-dropped-flows-interval", def.ReportDroppedFlowsInterval,
		"The interval at which to report dropped flows in logs. Set to 0s to disable reporting")
	flags.Bool("hubble-export-timescape-use-cilium-service-resolver", def.UseCiliumServiceResolver,
		"Whether to use Cilium's service resolver to resolve the target address for the Hubble timescape exporter")
	flags.Bool("hubble-export-timescape-tls-enabled", def.TLSEnabled, "Whether to enable TLS for the Hubble timescape exporter")
	flags.String("hubble-export-timescape-tls-cert-file", def.TLSCertFile,
		"Path to the public cert file for the client certificate to connect to the remote server using mTLS (the file must contain PEM encoded data)")
	flags.String("hubble-export-timescape-tls-key-file", def.TLSKeyFile,
		"Path to the private key file for the client certificate to connect to the remote server using mTLS (the file must contain PEM encoded data)")
	flags.StringSlice("hubble-export-timescape-tls-ca-files", def.TLSCAFiles,
		"Paths to one or more public CA files which sign certificates for the remote server")
}

type params struct {
	cell.In

	JobGroup         job.Group
	Lifecycle        cell.Lifecycle
	SvcResolver      dial.Resolver
	Config           timescapeExporterConfig
	TLSConfigPromise timescapeTLSConfigPromise
	Metrics          *metricsHandler

	Logger *slog.Logger
}

type out struct {
	cell.Out

	ExporterBuilders []*exportercell.FlowLogExporterBuilder `group:"hubble-exporter-builders,flatten"`
}

func newHubbleTimescapeExporter(params params) (out, error) {
	if !params.Config.Enabled {
		params.Logger.Info("The Hubble timescape exporter is disabled")
		return out{}, nil
	}

	builder := &exportercell.FlowLogExporterBuilder{
		Name: "timescape-exporter",
		Build: func() (exporter.FlowLogExporter, error) {
			params.Logger.Info("Building the Hubble timescape exporter", logfields.Config, fmt.Sprintf("%+v", params.Config))

			allowList, err := hubble.ParseFlowFilters(params.Config.Allowlist)
			if err != nil {
				return nil, fmt.Errorf("failed to parse allowlist: %w", err)
			}
			denyList, err := hubble.ParseFlowFilters(params.Config.Denylist)
			if err != nil {
				return nil, fmt.Errorf("failed to parse denylist: %w", err)
			}

			var resolvers []dial.Resolver
			if params.Config.UseCiliumServiceResolver {
				if params.SvcResolver != nil {
					params.Logger.Debug("Using the Cilium service resolver")
					resolvers = append(resolvers, params.SvcResolver)
				} else {
					params.Logger.Warn("Cilium service resolver requested but is not available (Is k8s available?)")
				}
			}

			exporterOpts := []timescape.Option{
				timescape.WithAllowListFilter(params.Logger, allowList),
				timescape.WithDenyListFilter(params.Logger, denyList),
				timescape.WithFieldMask(params.Config.Fieldmask),
				timescape.WithNodeName(params.Config.NodeName),
				timescape.WithIngestMode(params.Config.IngestMode),
				timescape.WithBatchSize(params.Config.BatchSize),
				timescape.WithBatchFlushInterval(params.Config.BatchFlushInterval),
				timescape.WithMaxBufferSize(params.Config.MaxBufferSize),
				timescape.WithReportDroppedFlowsInterval(params.Config.ReportDroppedFlowsInterval),
				timescape.WithTLSConfigPromise(params.TLSConfigPromise),
				timescape.WithResolvers(resolvers...),
			}

			// setup aggregator
			if len(params.Config.Aggregations) > 0 {
				aggregator, err := newAggregatorFromStreamConfig(params.Config, params.Logger)
				if err != nil {
					return nil, fmt.Errorf("failed to create enterprise aggregator: %w", err)
				}

				exporterOpts = append(exporterOpts, timescape.WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event) (bool, error) {
					return aggregator.OnExportEvent(ctx, ev, nil)
				}))
				params.JobGroup.Add(job.OneShot("hubble-timescape-flow-aggregator", func(ctx context.Context, _ cell.Health) error {
					aggregator.Start(ctx)
					return nil
				}))
			}

			// setup flow metrics reporting
			//
			// NOTE: make sure this is always the last exporter option so it remains accurate
			// when aggregation/rate-limiting is performed
			metricsHandlerNameLabel := "stream"
			exporterOpts = append(exporterOpts, timescape.WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event) (bool, error) {
				flow := ev.GetFlow()
				if flow == nil {
					// we only care about flow events
					return false, nil
				}
				err := params.Metrics.UpdateFlowMetrics(ctx, flow, metricsHandlerNameLabel)
				if err != nil {
					return false, fmt.Errorf("failed to update flow metrics: %w", err)
				}
				return false, nil
			}))

			// create the timescape exporter
			streamExporter, err := timescape.NewExporter(params.Logger, params.Config.Target, exporterOpts...)
			if err != nil {
				return nil, fmt.Errorf("failed to create Hubble timescape exporter: %w", err)
			}

			params.JobGroup.Add(job.OneShot("hubble-timescape-exporter", func(ctx context.Context, _ cell.Health) error {
				return streamExporter.Run(ctx)
			}))

			return streamExporter, nil
		},
	}

	return out{
		ExporterBuilders: []*exportercell.FlowLogExporterBuilder{builder},
	}, nil
}

func newAggregatorFromStreamConfig(config timescapeExporterConfig, logger *slog.Logger) (*aggregation.EnterpriseAggregator, error) {
	aggFilter, err := aggregator.NewAggregation(
		config.Aggregations,
		config.AggregationStateChangeFilter,
		config.AggregationIgnoreSourcePort,
		config.AggregationTTL,
		config.AggregationRenewTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create flow aggregation filter: %w", err)
	}
	return aggregation.NewEnterpriseAggregator(aggFilter, logger)
}

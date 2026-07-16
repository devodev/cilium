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
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	timescapeexporter "github.com/isovalent/hubble-timescape/exporter"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/hubble"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleexporter "github.com/cilium/cilium/pkg/hubble/exporter"
	exportercell "github.com/cilium/cilium/pkg/hubble/exporter/cell"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

type timescapeTLSConfigPromise promise.Promise[*certloader.WatchedClientConfig]

type timescapeEventExporter interface {
	Export(context.Context, timescapeexporter.Event) error
	Run(context.Context) error
}

type timescapeExportHook func(context.Context, *v1.Event) (bool, error)

type timescapeFlowExporter struct {
	log          *slog.Logger
	exporters    []timescapeEventExporter
	allowFilters filters.FilterFuncs
	denyFilters  filters.FilterFuncs
	fieldMask    fieldmask.FieldMask
	nodeName     string
	hooks        []timescapeExportHook
	newFlowEvent func(*flowpb.Flow) timescapeexporter.Event
}

func newTimescapeFlowExporter(
	log *slog.Logger,
	exporters []timescapeEventExporter,
	allowFilters filters.FilterFuncs,
	denyFilters filters.FilterFuncs,
	fieldMask fieldmask.FieldMask,
	nodeName string,
	hooks []timescapeExportHook,
) *timescapeFlowExporter {
	return &timescapeFlowExporter{
		log:          log,
		exporters:    exporters,
		allowFilters: allowFilters,
		denyFilters:  denyFilters,
		fieldMask:    fieldMask,
		nodeName:     nodeName,
		hooks:        hooks,
		newFlowEvent: timescapeexporter.NewFlowEvent,
	}
}

func (e *timescapeFlowExporter) Export(ctx context.Context, ev *v1.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev == nil || !filters.Apply(e.allowFilters, e.denyFilters, ev) {
		return nil
	}

	for _, hook := range e.hooks {
		stop, err := hook(ctx, ev)
		if err != nil {
			e.log.Warn("Timescape export hook failed", logfields.Error, err)
		}
		if stop {
			return nil
		}
	}

	flow := ev.GetFlow()
	if flow == nil {
		return nil
	}
	event := e.newFlowEvent(e.prepareFlow(flow))
	for _, target := range e.exporters {
		err := target.Export(ctx, event)
		if errors.Is(err, timescapeexporter.ErrBufferFull) || errors.Is(err, timescapeexporter.ErrStopped) {
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (*timescapeFlowExporter) Stop() error { return nil }

func (e *timescapeFlowExporter) prepareFlow(flow *flowpb.Flow) *flowpb.Flow {
	prepared := flow
	if e.fieldMask.Active() {
		masked := new(flowpb.Flow)
		e.fieldMask.Copy(masked.ProtoReflect(), flow.ProtoReflect())
		// FieldMask.Copy may retain message-valued leaves. Clone the selected
		// result so neither side can mutate storage owned by the other.
		prepared = proto.Clone(masked).(*flowpb.Flow)
	} else if e.nodeName != "" {
		prepared = proto.Clone(flow).(*flowpb.Flow)
	}
	if e.nodeName != "" {
		prepared.NodeName = e.nodeName
	}
	return prepared
}

var _ hubbleexporter.FlowLogExporter = (*timescapeFlowExporter)(nil)

type timescapeClientConfig struct {
	batchingConfig             timescapeexporter.BatchingConfig
	ingestMode                 timescapeexporter.IngestMode
	maxBufferSize              int
	reportDroppedFlowsInterval time.Duration
	resolvers                  []dial.Resolver
	tlsConfigPromise           timescapeTLSConfigPromise
}

type timescapeExporterFactory func(*slog.Logger, string, timescapeClientConfig) (timescapeEventExporter, error)

func normalizeTimescapeTarget(target string, resolvers []dial.Resolver) string {
	if len(resolvers) == 0 {
		return target
	}
	return "passthrough:" + strings.TrimPrefix(target, "passthrough:")
}

func newTimescapeEventExporter(
	log *slog.Logger,
	target string,
	config timescapeClientConfig,
) (timescapeEventExporter, error) {
	options := []timescapeexporter.Option{
		timescapeexporter.WithIngestMode(config.ingestMode),
		timescapeexporter.WithMaxBufferSize(config.maxBufferSize),
		timescapeexporter.WithReportDroppedEventsInterval(config.reportDroppedFlowsInterval),
		timescapeexporter.WithDialOptions(
			grpc.WithContextDialer(dial.NewContextDialer(log, config.resolvers...)),
		),
	}
	if config.tlsConfigPromise != nil {
		options = append(options, timescapeexporter.WithTransportCredentialsProvider(
			newTimescapeCredentialsProvider(config.tlsConfigPromise),
		))
	}
	return timescapeexporter.NewBatchingExporter(log, target, config.batchingConfig, options...)
}

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
	Targets                      []string      `mapstructure:"hubble-export-timescape-targets"`
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
	Targets:                      []string{"hubble-timescape-export.hubble-timescape.svc.cluster.local:4261"},
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
	flags.String("hubble-export-timescape-target", def.Target, "(Deprecated) Target server to connect to for exporting flows. Use --hubble-export-timescape-targets instead")
	flags.StringSlice("hubble-export-timescape-targets", def.Targets, "Target servers to connect to for exporting flows")
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
	return newHubbleTimescapeExporterWithFactory(params, newTimescapeEventExporter)
}

func newHubbleTimescapeExporterWithFactory(params params, factory timescapeExporterFactory) (out, error) {
	if !params.Config.Enabled {
		params.Logger.Info("The Hubble timescape exporter is disabled")
		return out{}, nil
	}

	builder := &exportercell.FlowLogExporterBuilder{
		Name: "timescape-exporter",
		Build: func() (hubbleexporter.FlowLogExporter, error) {
			params.Logger.Info("Building the Hubble timescape exporter", logfields.Config, fmt.Sprintf("%+v", params.Config))

			allowList, err := hubble.ParseFlowFilters(params.Config.Allowlist)
			if err != nil {
				return nil, fmt.Errorf("failed to parse allowlist: %w", err)
			}
			denyList, err := hubble.ParseFlowFilters(params.Config.Denylist)
			if err != nil {
				return nil, fmt.Errorf("failed to parse denylist: %w", err)
			}
			allowFilters, err := filters.BuildFilterList(context.Background(), allowList, filters.DefaultFilters(params.Logger))
			if err != nil {
				return nil, fmt.Errorf("failed to build allowlist filter: %w", err)
			}
			denyFilters, err := filters.BuildFilterList(context.Background(), denyList, filters.DefaultFilters(params.Logger))
			if err != nil {
				return nil, fmt.Errorf("failed to build denylist filter: %w", err)
			}

			protoFieldMask, err := fieldmaskpb.New(&flowpb.Flow{}, params.Config.Fieldmask...)
			if err != nil {
				return nil, fmt.Errorf("failed to create field mask: %w", err)
			}
			flowFieldMask, err := fieldmask.New(protoFieldMask)
			if err != nil {
				return nil, fmt.Errorf("failed to create field mask: %w", err)
			}

			ingestMode, err := timescapeexporter.ParseIngestMode(params.Config.IngestMode)
			if err != nil {
				return nil, err
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

			var hooks []timescapeExportHook
			var flowAggregator *aggregation.EnterpriseAggregator
			if len(params.Config.Aggregations) > 0 {
				flowAggregator, err = newAggregatorFromStreamConfig(params.Config, params.Logger)
				if err != nil {
					return nil, fmt.Errorf("failed to create enterprise aggregator: %w", err)
				}
				hooks = append(hooks, func(ctx context.Context, ev *v1.Event) (bool, error) {
					return flowAggregator.OnExportEvent(ctx, ev, nil)
				})
			}

			// Keep metrics last so aggregation decisions are reflected accurately.
			hooks = append(hooks, func(ctx context.Context, ev *v1.Event) (bool, error) {
				flow := ev.GetFlow()
				if flow == nil {
					return false, nil
				}
				err := params.Metrics.UpdateFlowMetrics(ctx, flow, "stream")
				if err != nil {
					return false, fmt.Errorf("failed to update flow metrics: %w", err)
				}
				return false, nil
			})

			targets := slices.Clone(params.Config.Targets)
			if params.Config.Target != "" && !slices.Contains(targets, params.Config.Target) {
				targets = append(targets, params.Config.Target)
				params.Logger.Warn("Using deprecated 'target' field. Please migrate to 'targets' for multiple endpoint support")
			}

			if len(targets) == 0 {
				return nil, fmt.Errorf("no targets configured for Hubble timescape exporter")
			}

			clientConfig := timescapeClientConfig{
				batchingConfig: timescapeexporter.BatchingConfig{
					BatchSize:     params.Config.BatchSize,
					FlushInterval: params.Config.BatchFlushInterval,
				},
				ingestMode:                 ingestMode,
				maxBufferSize:              params.Config.MaxBufferSize,
				reportDroppedFlowsInterval: params.Config.ReportDroppedFlowsInterval,
				resolvers:                  resolvers,
				tlsConfigPromise:           params.TLSConfigPromise,
			}
			exporters := make([]timescapeEventExporter, 0, len(targets))
			for _, target := range targets {
				target = normalizeTimescapeTarget(target, resolvers)
				streamExporter, err := factory(params.Logger, target, clientConfig)
				if err != nil {
					return nil, fmt.Errorf("failed to create Hubble timescape exporter for target %s: %w", target, err)
				}
				exporters = append(exporters, streamExporter)
			}

			if flowAggregator != nil {
				params.JobGroup.Add(job.OneShot("hubble-timescape-flow-aggregator", func(ctx context.Context, _ cell.Health) error {
					flowAggregator.Start(ctx)
					return nil
				}))
			}
			for i, streamExporter := range exporters {
				exporterName := fmt.Sprintf("hubble-timescape-exporter-%d", i)
				params.JobGroup.Add(job.OneShot(exporterName, func(ctx context.Context, _ cell.Health) error {
					return streamExporter.Run(ctx)
				}))
			}

			return newTimescapeFlowExporter(
				params.Logger,
				exporters,
				allowFilters,
				denyFilters,
				flowFieldMask,
				params.Config.NodeName,
				hooks,
			), nil
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

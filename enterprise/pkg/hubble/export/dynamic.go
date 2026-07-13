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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/lumberjack/v2"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
	"github.com/cilium/cilium/pkg/time"
)

var _ exporter.ExporterConfigParser = (*exporterConfigParser)(nil)

type exporterConfigParser struct {
	logger *slog.Logger
}

// Parse implements ExporterConfigParser.
func (e *exporterConfigParser) Parse(r io.Reader) (map[string]exporter.ExporterConfig, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	var config dynamicConfigFile
	if err := yaml.Unmarshal(buf.Bytes(), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}
	configs := config.ToFlowLogConfigs()
	exporterConfigs := make(map[string]exporter.ExporterConfig, len(configs))
	for _, fl := range configs {
		exporterConfigs[fl.Name] = fl
	}
	return exporterConfigs, nil
}

var _ exporter.ExporterFactory = (*exporterFactory)(nil)

type exporterFactory struct {
	logger         *slog.Logger
	jobGroup       job.Group
	metricsHandler *metricsHandler
}

// Create implements ExporterFactory.
func (f *exporterFactory) Create(config exporter.ExporterConfig) (exporter.FlowLogExporter, error) {
	if config, ok := config.(*FlowLogConfig); ok {
		return f.create(config)
	}
	return nil, fmt.Errorf("invalid config type %T (%+v)", config, config)
}

// TODO: one-shot jobs added to the jobGroup are not cleaned up when an exporter is
// removed following a reload. This could lead to a growing health table and somewhat
// of a memory leak in environments with numerous updates to exporters with a large
// name cardinality.
// There is an ongoing effort in hive to support closing health reporters of jobs:
// https://github.com/cilium/hive/pull/20
func (f *exporterFactory) create(config *FlowLogConfig) (exporter.FlowLogExporter, error) {
	f.logger.Debug("Creating new managed exporter",
		logfields.ExporterName, config.Name,
		logfields.Config, fmt.Sprintf("%+v", config),
	)

	// only create a scoped group if we have at least one job to add
	scopedGroup := sync.OnceValue(func() job.ScopedGroup {
		jobName := shortener.ShortenHiveJobName("hubble-exporter-" + config.FlowLogConfig.Name)
		return f.jobGroup.Scoped(jobName)
	})

	// setup writer
	writer := &lumberjack.Logger{
		Filename:   config.FlowLogConfig.FilePath,
		MaxSize:    config.FlowLogConfig.FileMaxSizeMB,
		MaxBackups: config.FlowLogConfig.FileMaxBackups,
		Compress:   config.FlowLogConfig.FileCompress,
	}

	// setup exporter options
	exporterOpts := []exporter.Option{
		exporter.WithAllowList(f.logger, config.FlowLogConfig.IncludeFilters),
		exporter.WithDenyList(f.logger, config.FlowLogConfig.ExcludeFilters),
		exporter.WithFieldMask(config.FlowLogConfig.FieldMask),
		exporter.WithNewWriterFunc(func() (io.WriteCloser, error) {
			var writer io.WriteCloser = writer
			// FIXME: at startup, the metrics handler is not yet initialized
			// and result in missing the first few bytes written updates.
			writer = f.metricsHandler.WrapWriter(writer, config.FlowLogConfig.Name)
			return writer, nil
		}),
		exporter.WithNewEncoderFunc(func(writer io.Writer) (exporter.Encoder, error) {
			return newJsonEncoderFromDynamicConfig(config, writer), nil
		}),
		exporter.WithOnExportEventFunc(func(_ context.Context, _ *v1.Event, _ exporter.Encoder) (bool, error) {
			stop := !config.IsActive()
			return stop, nil
		}),
		exporter.WithOnExportEventFunc(func(_ context.Context, ev *v1.Event, _ exporter.Encoder) (bool, error) {
			// stop export pipeline for non-flow events
			stop := ev.GetFlow() == nil
			return stop, nil
		}),
	}

	// setup aggregator
	aggregatorjobCancel := func() {}
	if len(config.Aggregations) > 0 {
		aggregator, err := newAggregatorFromDynamicConfig(config, f.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create enterprise aggregator: %w", err)
		}
		exporterOpts = append(exporterOpts, exporter.WithOnExportEvent(aggregator))

		jobName := shortener.ShortenHiveJobName("hubble-exporter-aggregator-" + config.FlowLogConfig.Name)
		scopedGroup().Add(job.OneShot(jobName, func(ctx context.Context, _ cell.Health) error {
			ctx, cancel := context.WithCancel(ctx)
			aggregatorjobCancel = cancel
			aggregator.Start(ctx)
			return nil
		}))
	}

	// setup rate-limiting
	if config.RateLimit >= 0 {
		ratelimiter, err := newRateLimiterFromDynamicConfig(config, f.logger)
		if err != nil {
			// non-fatal failure, log and continue
			f.logger.Warn("Failed to create flow export rate limiter",
				logfields.Error, err,
				logfields.Config, config.FlowLogConfig.Name,
			)
		} else {
			exporterOpts = append(exporterOpts, exporter.WithOnExportEvent(ratelimiter))
		}
	}

	// setup flow metrics reporting
	//
	// NOTE: make sure this is always the last exporter option so it remains accurate when
	// aggregation/rate-limiting is performed.
	exporterOpts = append(exporterOpts, exporter.WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event, encoder exporter.Encoder) (bool, error) {
		flow := ev.GetFlow()
		if flow == nil {
			// we only care about flow events
			return false, nil
		}
		// FIXME: at startup, the metrics handler is not yet initialized
		// and result in missing the first few flow metric updates.
		err := f.metricsHandler.UpdateFlowMetrics(ctx, flow, config.FlowLogConfig.Name)
		if err != nil {
			return false, fmt.Errorf("failed to update flow metrics for %q: %w", config.FlowLogConfig.Name, err)
		}
		return false, nil
	}))

	// setup file rotation
	fileRotateJobCancel := func() {}
	if config.FileRotationInterval != 0 {
		f.logger.Info("Periodically rotating JSON export file",
			logfields.FilePath, config.FlowLogConfig.FilePath,
			logfields.Interval, config.FileRotationInterval,
		)

		jobName := shortener.ShortenHiveJobName("hubble-exporter-file-rotate-" + config.FlowLogConfig.Name)
		scopedGroup().Add(job.OneShot(jobName, func(ctx context.Context, health cell.Health) error {
			ctx, cancel := context.WithCancel(ctx)
			fileRotateJobCancel = cancel
			ticker := time.NewTicker(config.FileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					if err := writer.Rotate(); err != nil {
						f.logger.Warn("Failed to rotate JSON export file",
							logfields.Error, err,
							logfields.FilePath, config.FlowLogConfig.FilePath,
						)
					}
				}
			}
		}))
	}

	staticExporter, err := exporter.NewExporter(f.logger, exporterOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create static exporter instance for %q: %w", config.FlowLogConfig.Name, err)
	}
	wrapperExporter := &wrappedExporter{
		FlowLogExporter: staticExporter,
		onStop: func() error {
			aggregatorjobCancel()
			fileRotateJobCancel()
			return nil
		},
	}

	return wrapperExporter, nil
}

func newAggregatorFromDynamicConfig(config *FlowLogConfig, logger *slog.Logger) (*aggregation.EnterpriseAggregator, error) {
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

type flowLogConfig struct {
	exporter.FlowLogConfig

	FileRotationInterval         *Duration `json:"fileRotationInterval,omitempty" yaml:"fileRotationInterval,omitempty"`
	FormatVersion                *string   `json:"formatVersion,omitempty" yaml:"formatVersion,omitempty"`
	RateLimit                    *int      `json:"rateLimit,omitempty" yaml:"rateLimit,omitempty"`
	NodeName                     *string   `json:"nodeName,omitempty" yaml:"nodeName,omitempty"`
	Aggregations                 []string  `json:"aggregation,omitempty" yaml:"aggregation,omitempty"`
	AggregationIgnoreSourcePort  *bool     `json:"aggregationIgnoreSourcePort,omitempty" yaml:"aggregationIgnoreSourcePort,omitempty"`
	AggregationRenewTTL          *bool     `json:"aggregationRenewTTL,omitempty" yaml:"aggregationRenewTTL,omitempty"`
	AggregationStateChangeFilter []string  `json:"aggregationStateFilter,omitempty" yaml:"aggregationStateFilter,omitempty"`
	AggregationTTL               *Duration `json:"aggregationTTL,omitempty" yaml:"aggregationTTL,omitempty"`
}

type dynamicConfigFile struct {
	FlowLogs []*flowLogConfig `json:"flowLogs,omitempty" yaml:"flowLogs,omitempty"`
}

func (c *dynamicConfigFile) Validate() error {
	flowlogNames := make(map[string]any)
	flowlogPaths := make(map[string]any)

	var errs error
	for i, fl := range c.FlowLogs {
		if fl == nil {
			errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d: empty config", i))
			continue
		}

		name := fl.FlowLogConfig.Name
		if name == "" {
			errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d: name is required", i))
		} else {
			if _, ok := flowlogNames[name]; ok {
				errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d: duplicated flowlog name %s", i, name))
			}
			flowlogNames[name] = struct{}{}
		}

		filePath := fl.FlowLogConfig.FilePath
		if filePath == "" {
			errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d: filePath is required", i))
		} else {
			if _, ok := flowlogPaths[filePath]; ok {
				errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d: duplicated flowlog path %s", i, filePath))
			}
			flowlogPaths[filePath] = struct{}{}
		}
	}
	return errs
}

// ToFlowLogConfigs converts the file representation of the dynamic config to a slice of
// FlowLogConfig, taking care of setting default values as needed.
func (c *dynamicConfigFile) ToFlowLogConfigs() []*FlowLogConfig {
	var configs []*FlowLogConfig
	for _, fl := range c.FlowLogs {
		config := &FlowLogConfig{
			FlowLogConfig: fl.FlowLogConfig,
			config:        defaultConfig,
		}

		if fl.FileRotationInterval != nil {
			config.FileRotationInterval = time.Duration(*fl.FileRotationInterval)
		}
		if fl.FormatVersion != nil {
			config.FormatVersion = *fl.FormatVersion
		}
		if fl.RateLimit != nil {
			config.RateLimit = *fl.RateLimit
		}
		if fl.NodeName != nil {
			config.NodeName = *fl.NodeName
		}
		if fl.Aggregations != nil {
			config.Aggregations = fl.Aggregations
		}
		if fl.AggregationIgnoreSourcePort != nil {
			config.AggregationIgnoreSourcePort = *fl.AggregationIgnoreSourcePort
		}
		if fl.AggregationRenewTTL != nil {
			config.AggregationRenewTTL = *fl.AggregationRenewTTL
		}
		if fl.AggregationStateChangeFilter != nil {
			config.AggregationStateChangeFilter = fl.AggregationStateChangeFilter
		}
		if fl.AggregationTTL != nil {
			config.AggregationTTL = time.Duration(*fl.AggregationTTL)
		}

		configs = append(configs, config)
	}
	return configs
}

var _ exporter.ExporterConfig = (*FlowLogConfig)(nil)

// FlowLogConfig represents configuration of single dynamic exporter.
type FlowLogConfig struct {
	exporter.FlowLogConfig
	config
}

// Equal implements the ExporterConfig interface.
func (f *FlowLogConfig) Equal(other any) bool {
	if other, ok := other.(*FlowLogConfig); ok {
		return f.equals(other)
	}
	return false
}

func (f *FlowLogConfig) equals(other *FlowLogConfig) bool {
	if !f.FlowLogConfig.Equal(&other.FlowLogConfig) {
		return false
	}

	if f.FileRotationInterval != other.FileRotationInterval {
		return false
	}
	if f.FormatVersion != other.FormatVersion {
		return false
	}
	if f.RateLimit != other.RateLimit {
		return false
	}
	if f.NodeName != other.NodeName {
		return false
	}
	if !stringSlicesEqual(f.Aggregations, other.Aggregations) {
		return false
	}
	if !stringSlicesEqual(f.AggregationStateChangeFilter, other.AggregationStateChangeFilter) {
		return false
	}
	if f.AggregationIgnoreSourcePort != other.AggregationIgnoreSourcePort {
		return false
	}
	if f.AggregationRenewTTL != other.AggregationRenewTTL {
		return false
	}
	if f.AggregationTTL != other.AggregationTTL {
		return false
	}

	return true
}

var _ exporter.FlowLogExporter = (*wrappedExporter)(nil)

type onStopFn func() error

type wrappedExporter struct {
	exporter.FlowLogExporter
	onStop onStopFn
}

// Stop implements FlowLogExporter.
func (w *wrappedExporter) Stop() error {
	if w.onStop != nil {
		if err := w.onStop(); err != nil {
			return err
		}
	}
	return w.FlowLogExporter.Stop()
}

type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(tmp)
		return nil
	default:
		return errors.New("invalid duration")
	}
}

func stringSlicesEqual(a, b []string) bool {
	xs := make([]string, len(a))
	ys := make([]string, len(b))
	copy(xs, a)
	copy(ys, b)
	slices.Sort(xs)
	slices.Sort(ys)
	return reflect.DeepEqual(xs, ys)
}

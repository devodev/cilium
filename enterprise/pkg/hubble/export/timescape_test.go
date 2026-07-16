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
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	timescapeexporter "github.com/isovalent/hubble-timescape/exporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/dial"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
	"github.com/cilium/cilium/pkg/promise"
)

type testJobGroup struct {
	added int
}

func newTestJobGroup() *testJobGroup {
	return &testJobGroup{}
}

func (g *testJobGroup) Add(jobs ...job.Job) {
	g.added += len(jobs)
}

func (*testJobGroup) Scoped(string) job.ScopedGroup {
	return nil
}

var _ job.Group = (*testJobGroup)(nil)

type testTimescapeEventExporter struct {
	events    []timescapeexporter.Event
	exportErr error
	onExport  func(timescapeexporter.Event)
	runCalls  int
	runErr    error
}

func newTestTimescapeEventExporter() *testTimescapeEventExporter {
	return &testTimescapeEventExporter{}
}

func (e *testTimescapeEventExporter) Export(_ context.Context, event timescapeexporter.Event) error {
	e.events = append(e.events, event)
	if e.onExport != nil {
		e.onExport(event)
	}
	return e.exportErr
}

func (e *testTimescapeEventExporter) Run(context.Context) error {
	e.runCalls++
	return e.runErr
}

var _ timescapeEventExporter = (*testTimescapeEventExporter)(nil)

type testTimescapeFactoryCall struct {
	target string
	config timescapeClientConfig
}

type testTimescapeFactory struct {
	calls     []testTimescapeFactoryCall
	exporters []*testTimescapeEventExporter
	failAt    int
	err       error
}

func newTestTimescapeFactory() *testTimescapeFactory {
	return &testTimescapeFactory{failAt: -1}
}

func (f *testTimescapeFactory) New(
	_ *slog.Logger,
	target string,
	config timescapeClientConfig,
) (timescapeEventExporter, error) {
	f.calls = append(f.calls, testTimescapeFactoryCall{target: target, config: config})
	if len(f.calls)-1 == f.failAt {
		return nil, f.err
	}
	exporter := newTestTimescapeEventExporter()
	f.exporters = append(f.exporters, exporter)
	return exporter, nil
}

type testResolver struct{}

func newTestResolver() *testResolver {
	return &testResolver{}
}

func (*testResolver) Resolve(_ context.Context, host, port string) (string, string) {
	return host, port
}

var _ dial.Resolver = (*testResolver)(nil)

func newTestTimescapeParams(t *testing.T, config timescapeExporterConfig) params {
	t.Helper()
	return params{
		JobGroup: newTestJobGroup(),
		Config:   config,
		Metrics:  &metricsHandler{},
		Logger:   hivetest.Logger(t),
	}
}

func newTestFlowFieldMask(t *testing.T, paths ...string) fieldmask.FieldMask {
	t.Helper()
	protoMask, err := fieldmaskpb.New(&flowpb.Flow{}, paths...)
	require.NoError(t, err)
	mask, err := fieldmask.New(protoMask)
	require.NoError(t, err)
	return mask
}

func TestNewHubbleTimescapeExporterDisabled(t *testing.T) {
	factory := newTestTimescapeFactory()
	out, err := newHubbleTimescapeExporterWithFactory(
		newTestTimescapeParams(t, timescapeExporterConfig{Enabled: false}),
		factory.New,
	)
	require.NoError(t, err)
	assert.Nil(t, out.ExporterBuilders)
	assert.Empty(t, factory.calls)
}

func TestNewHubbleTimescapeExporterMapsTargetsConfigAndJobs(t *testing.T) {
	resolver := newTestResolver()
	resolverPromise, tlsPromise := promise.New[*certloader.WatchedClientConfig]()
	t.Cleanup(func() { resolverPromise.Reject(errors.New("test finished")) })
	config := timescapeExporterConfig{
		Enabled:                    true,
		Targets:                    []string{"one:4261", "passthrough:two:4261"},
		Target:                     "three:4261",
		IngestMode:                 "single",
		BatchSize:                  73,
		BatchFlushInterval:         17 * time.Millisecond,
		MaxBufferSize:              811,
		ReportDroppedFlowsInterval: 19 * time.Second,
		UseCiliumServiceResolver:   true,
	}
	params := newTestTimescapeParams(t, config)
	params.SvcResolver = resolver
	params.TLSConfigPromise = timescapeTLSConfigPromise(tlsPromise)
	factory := newTestTimescapeFactory()

	out, err := newHubbleTimescapeExporterWithFactory(params, factory.New)
	require.NoError(t, err)
	require.Len(t, out.ExporterBuilders, 1)
	assert.Equal(t, "timescape-exporter", out.ExporterBuilders[0].Name)

	built, err := out.ExporterBuilders[0].Build()
	require.NoError(t, err)
	require.IsType(t, &timescapeFlowExporter{}, built)
	require.Len(t, factory.calls, 3)
	assert.Equal(t, []string{
		"passthrough:one:4261",
		"passthrough:two:4261",
		"passthrough:three:4261",
	}, []string{factory.calls[0].target, factory.calls[1].target, factory.calls[2].target})

	for _, call := range factory.calls {
		assert.Equal(t, timescapeexporter.IngestModeSingle, call.config.ingestMode)
		assert.Equal(t, 73, call.config.batchingConfig.BatchSize)
		assert.Equal(t, 17*time.Millisecond, call.config.batchingConfig.FlushInterval)
		assert.Equal(t, 811, call.config.maxBufferSize)
		assert.Equal(t, 19*time.Second, call.config.reportDroppedFlowsInterval)
		require.Len(t, call.config.resolvers, 1)
		assert.Same(t, resolver, call.config.resolvers[0])
		assert.NotNil(t, call.config.tlsConfigPromise)
	}
	assert.Equal(t, 3, params.JobGroup.(*testJobGroup).added)
}

func TestNewHubbleTimescapeExporterMapsEveryIngestMode(t *testing.T) {
	tests := map[string]timescapeexporter.IngestMode{
		"auto":   timescapeexporter.IngestModeAuto,
		"batch":  timescapeexporter.IngestModeBatch,
		"single": timescapeexporter.IngestModeSingle,
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			params := newTestTimescapeParams(t, timescapeExporterConfig{
				Enabled:            true,
				Targets:            []string{"timescape:4261"},
				IngestMode:         input,
				BatchSize:          1,
				BatchFlushInterval: time.Second,
				MaxBufferSize:      1,
			})
			factory := newTestTimescapeFactory()
			out, err := newHubbleTimescapeExporterWithFactory(params, factory.New)
			require.NoError(t, err)
			_, err = out.ExporterBuilders[0].Build()
			require.NoError(t, err)
			require.Len(t, factory.calls, 1)
			assert.Equal(t, want, factory.calls[0].config.ingestMode)
		})
	}
}

func TestNewHubbleTimescapeExporterRegistersAggregationJobAfterClientsBuild(t *testing.T) {
	newConfig := func() timescapeExporterConfig {
		config := defaultTimescapeExporterConfig
		config.Enabled = true
		config.Targets = []string{"timescape:4261"}
		config.Aggregations = []string{"identity"}
		return config
	}

	t.Run("registers aggregation and target jobs", func(t *testing.T) {
		params := newTestTimescapeParams(t, newConfig())
		factory := newTestTimescapeFactory()
		out, err := newHubbleTimescapeExporterWithFactory(params, factory.New)
		require.NoError(t, err)

		_, err = out.ExporterBuilders[0].Build()
		require.NoError(t, err)
		assert.Equal(t, 2, params.JobGroup.(*testJobGroup).added)
	})

	t.Run("registers no jobs when a client fails to build", func(t *testing.T) {
		config := newConfig()
		config.Targets = []string{"one:4261", "two:4261"}
		params := newTestTimescapeParams(t, config)
		factory := newTestTimescapeFactory()
		factory.failAt = 1
		factory.err = errors.New("factory failed")
		out, err := newHubbleTimescapeExporterWithFactory(params, factory.New)
		require.NoError(t, err)

		_, err = out.ExporterBuilders[0].Build()
		require.ErrorContains(t, err, "factory failed")
		assert.Zero(t, params.JobGroup.(*testJobGroup).added)
	})
}

func TestNewHubbleTimescapeExporterBuildErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  timescapeExporterConfig
		factory func(*testTimescapeFactory)
		want    string
	}{
		{
			name: "invalid ingest mode",
			config: timescapeExporterConfig{
				Enabled:    true,
				Targets:    []string{"timescape:4261"},
				IngestMode: "bogus",
			},
			want: "invalid ingest mode",
		},
		{
			name: "no target",
			config: timescapeExporterConfig{
				Enabled:    true,
				IngestMode: "auto",
			},
			want: "no targets configured",
		},
		{
			name: "factory failure",
			config: timescapeExporterConfig{
				Enabled:            true,
				Targets:            []string{"one:4261", "two:4261"},
				IngestMode:         "batch",
				BatchSize:          1,
				BatchFlushInterval: time.Second,
				MaxBufferSize:      1,
			},
			factory: func(factory *testTimescapeFactory) {
				factory.failAt = 1
				factory.err = errors.New("factory failed")
			},
			want: "failed to create Hubble timescape exporter for target two:4261: factory failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := newTestTimescapeParams(t, tc.config)
			factory := newTestTimescapeFactory()
			if tc.factory != nil {
				tc.factory(factory)
			}
			out, err := newHubbleTimescapeExporterWithFactory(params, factory.New)
			require.NoError(t, err)
			_, err = out.ExporterBuilders[0].Build()
			require.ErrorContains(t, err, tc.want)
			assert.Zero(t, params.JobGroup.(*testJobGroup).added)
		})
	}
}

func TestNewHubbleTimescapeExporterMergesDeprecatedTargetWithoutMutatingConfig(t *testing.T) {
	targets := []string{"one:4261"}
	params := newTestTimescapeParams(t, timescapeExporterConfig{
		Enabled:            true,
		Targets:            targets,
		Target:             "two:4261",
		IngestMode:         "auto",
		BatchSize:          1,
		BatchFlushInterval: time.Second,
		MaxBufferSize:      1,
	})
	factory := newTestTimescapeFactory()
	out, err := newHubbleTimescapeExporterWithFactory(params, factory.New)
	require.NoError(t, err)
	_, err = out.ExporterBuilders[0].Build()
	require.NoError(t, err)
	assert.Equal(t, []string{"one:4261"}, targets)
	assert.Equal(t, []string{"one:4261", "two:4261"}, []string{factory.calls[0].target, factory.calls[1].target})

	params.Config.Target = "one:4261"
	factory = newTestTimescapeFactory()
	out, err = newHubbleTimescapeExporterWithFactory(params, factory.New)
	require.NoError(t, err)
	_, err = out.ExporterBuilders[0].Build()
	require.NoError(t, err)
	assert.Len(t, factory.calls, 1)
}

func TestNormalizeTimescapeTarget(t *testing.T) {
	resolver := newTestResolver()
	assert.Equal(t, "timescape:4261", normalizeTimescapeTarget("timescape:4261", nil))
	assert.Equal(t, "passthrough:timescape:4261", normalizeTimescapeTarget("timescape:4261", []dial.Resolver{resolver}))
	assert.Equal(t, "passthrough:timescape:4261", normalizeTimescapeTarget("passthrough:timescape:4261", []dial.Resolver{resolver}))
}

func TestTimescapeFlowExporterPreprocessesOnceBeforeImmutableFanout(t *testing.T) {
	var order []string
	first := newTestTimescapeEventExporter()
	first.onExport = func(timescapeexporter.Event) { order = append(order, "target-one") }
	second := newTestTimescapeEventExporter()
	second.onExport = func(timescapeexporter.Event) { order = append(order, "target-two") }
	exporter := newTimescapeFlowExporter(
		hivetest.Logger(t),
		[]timescapeEventExporter{first, second},
		filters.FilterFuncs{func(*v1.Event) bool {
			order = append(order, "allow")
			return true
		}},
		filters.FilterFuncs{func(*v1.Event) bool {
			order = append(order, "deny")
			return false
		}},
		nil,
		"",
		[]timescapeExportHook{
			func(context.Context, *v1.Event) (bool, error) {
				order = append(order, "aggregate")
				return false, nil
			},
			func(context.Context, *v1.Event) (bool, error) {
				order = append(order, "metrics")
				return false, nil
			},
		},
	)
	var wrapped []*flowpb.Flow
	exporter.newFlowEvent = func(flow *flowpb.Flow) timescapeexporter.Event {
		order = append(order, "wrap")
		wrapped = append(wrapped, flow)
		return timescapeexporter.NewFlowEvent(flow)
	}
	flow := &flowpb.Flow{NodeName: "source-node"}

	require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: flow}))
	assert.Equal(t, []string{"allow", "deny", "aggregate", "metrics", "wrap", "target-one", "target-two"}, order)
	require.Len(t, wrapped, 1, "the flow must be wrapped exactly once before fanout")
	assert.Same(t, flow, wrapped[0], "an unmodified flow should not be cloned")
	require.Len(t, first.events, 1)
	require.Len(t, second.events, 1)
}

func TestTimescapeFlowExporterFiltersStopsAndIgnoresNonFlows(t *testing.T) {
	t.Run("canceled context stops before preprocessing", func(t *testing.T) {
		target := newTestTimescapeEventExporter()
		var filterCalls, hookCalls, wrapCalls int
		exporter := newTimescapeFlowExporter(
			hivetest.Logger(t),
			[]timescapeEventExporter{target},
			filters.FilterFuncs{func(*v1.Event) bool {
				filterCalls++
				return true
			}},
			nil,
			nil,
			"",
			[]timescapeExportHook{func(context.Context, *v1.Event) (bool, error) {
				hookCalls++
				return false, nil
			}},
		)
		exporter.newFlowEvent = func(flow *flowpb.Flow) timescapeexporter.Event {
			wrapCalls++
			return timescapeexporter.NewFlowEvent(flow)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		err := exporter.Export(ctx, &v1.Event{Event: &flowpb.Flow{}})
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, filterCalls)
		assert.Zero(t, hookCalls)
		assert.Zero(t, wrapCalls)
		assert.Empty(t, target.events)
	})

	t.Run("allow filter rejects before hooks", func(t *testing.T) {
		target := newTestTimescapeEventExporter()
		hookCalls := 0
		exporter := newTimescapeFlowExporter(
			hivetest.Logger(t),
			[]timescapeEventExporter{target},
			filters.FilterFuncs{func(*v1.Event) bool { return false }},
			nil,
			nil,
			"",
			[]timescapeExportHook{func(context.Context, *v1.Event) (bool, error) {
				hookCalls++
				return false, nil
			}},
		)
		require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: &flowpb.Flow{}}))
		assert.Zero(t, hookCalls)
		assert.Empty(t, target.events)
	})

	t.Run("deny filter rejects before hooks", func(t *testing.T) {
		target := newTestTimescapeEventExporter()
		hookCalls := 0
		exporter := newTimescapeFlowExporter(
			hivetest.Logger(t),
			[]timescapeEventExporter{target},
			nil,
			filters.FilterFuncs{func(*v1.Event) bool { return true }},
			nil,
			"",
			[]timescapeExportHook{func(context.Context, *v1.Event) (bool, error) {
				hookCalls++
				return false, nil
			}},
		)
		require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: &flowpb.Flow{}}))
		assert.Zero(t, hookCalls)
		assert.Empty(t, target.events)
	})

	t.Run("stopping hook prevents later processing", func(t *testing.T) {
		target := newTestTimescapeEventExporter()
		var hooks []string
		exporter := newTimescapeFlowExporter(
			hivetest.Logger(t),
			[]timescapeEventExporter{target},
			nil,
			nil,
			nil,
			"",
			[]timescapeExportHook{
				func(context.Context, *v1.Event) (bool, error) {
					hooks = append(hooks, "stop")
					return true, nil
				},
				func(context.Context, *v1.Event) (bool, error) {
					hooks = append(hooks, "later")
					return false, nil
				},
			},
		)
		require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: &flowpb.Flow{}}))
		assert.Equal(t, []string{"stop"}, hooks)
		assert.Empty(t, target.events)
	})

	t.Run("hook errors do not prevent later processing", func(t *testing.T) {
		target := newTestTimescapeEventExporter()
		exporter := newTimescapeFlowExporter(
			hivetest.Logger(t),
			[]timescapeEventExporter{target},
			nil,
			nil,
			nil,
			"",
			[]timescapeExportHook{func(context.Context, *v1.Event) (bool, error) {
				return false, errors.New("hook failed")
			}},
		)
		require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: &flowpb.Flow{}}))
		assert.Len(t, target.events, 1)
	})

	t.Run("nil and non-flow events are ignored", func(t *testing.T) {
		target := newTestTimescapeEventExporter()
		hookCalls := 0
		exporter := newTimescapeFlowExporter(
			hivetest.Logger(t),
			[]timescapeEventExporter{target},
			nil,
			nil,
			nil,
			"",
			[]timescapeExportHook{func(context.Context, *v1.Event) (bool, error) {
				hookCalls++
				return false, nil
			}},
		)
		require.NoError(t, exporter.Export(t.Context(), nil))
		require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: &flowpb.AgentEvent{}}))
		assert.Equal(t, 1, hookCalls, "non-flow events still pass through common hooks")
		assert.Empty(t, target.events)
	})
}

func TestTimescapeFlowExporterDoesNotMutateSourceForNodeOverride(t *testing.T) {
	target := newTestTimescapeEventExporter()
	exporter := newTimescapeFlowExporter(
		hivetest.Logger(t),
		[]timescapeEventExporter{target},
		nil,
		nil,
		nil,
		"override-node",
		nil,
	)
	flow := &flowpb.Flow{
		NodeName: "source-node",
		Source:   &flowpb.Endpoint{Namespace: "source-namespace", Labels: []string{"source-label"}},
	}
	wantSource := proto.Clone(flow).(*flowpb.Flow)
	var prepared *flowpb.Flow
	exporter.newFlowEvent = func(flow *flowpb.Flow) timescapeexporter.Event {
		prepared = flow
		return timescapeexporter.NewFlowEvent(flow)
	}

	require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: flow}))
	require.NotNil(t, prepared)
	assert.NotSame(t, flow, prepared)
	assert.Equal(t, "override-node", prepared.GetNodeName())
	assert.True(t, proto.Equal(wantSource, flow), "node override must not mutate the Hubble-owned flow")
	prepared.Source.Labels[0] = "changed"
	assert.Equal(t, "source-label", flow.GetSource().GetLabels()[0], "the clone must not alias nested source data")
}

func TestTimescapeFlowExporterFieldMaskDoesNotAliasOrReuseScratch(t *testing.T) {
	target := newTestTimescapeEventExporter()
	exporter := newTimescapeFlowExporter(
		hivetest.Logger(t),
		[]timescapeEventExporter{target},
		nil,
		nil,
		newTestFlowFieldMask(t, "source"),
		"masked-node",
		nil,
	)
	first := &flowpb.Flow{
		NodeName:    "first-node",
		Source:      &flowpb.Endpoint{Namespace: "first", Labels: []string{"first-label"}},
		Destination: &flowpb.Endpoint{Namespace: "must-be-masked"},
	}
	second := &flowpb.Flow{
		NodeName: "second-node",
		Source:   &flowpb.Endpoint{Namespace: "second", Labels: []string{"second-label"}},
	}
	wantFirst := proto.Clone(first).(*flowpb.Flow)
	wantSecond := proto.Clone(second).(*flowpb.Flow)
	var prepared []*flowpb.Flow
	exporter.newFlowEvent = func(flow *flowpb.Flow) timescapeexporter.Event {
		prepared = append(prepared, flow)
		return timescapeexporter.NewFlowEvent(flow)
	}

	require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: first}))
	require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: second}))
	require.Len(t, prepared, 2)
	assert.NotSame(t, prepared[0], prepared[1])
	assert.NotSame(t, first, prepared[0])
	assert.NotSame(t, second, prepared[1])
	assert.NotSame(t, prepared[0].Source, prepared[1].Source)
	assert.Equal(t, "first", prepared[0].GetSource().GetNamespace(), "the second export must not overwrite the first masked flow")
	assert.Equal(t, "second", prepared[1].GetSource().GetNamespace())
	assert.Equal(t, "masked-node", prepared[0].GetNodeName())
	assert.Equal(t, "masked-node", prepared[1].GetNodeName())
	assert.Nil(t, prepared[0].GetDestination())
	prepared[0].Source.Labels[0] = "changed"
	assert.True(t, proto.Equal(wantFirst, first), "the masked flow must not alias the first source")
	assert.True(t, proto.Equal(wantSecond, second), "the masked flow must not mutate the second source")
}

func TestTimescapeFlowExporterSuppressesDropsAndContinuesFanout(t *testing.T) {
	full := newTestTimescapeEventExporter()
	full.exportErr = fmt.Errorf("full: %w", timescapeexporter.ErrBufferFull)
	stopped := newTestTimescapeEventExporter()
	stopped.exportErr = fmt.Errorf("stopped: %w", timescapeexporter.ErrStopped)
	success := newTestTimescapeEventExporter()
	exporter := newTimescapeFlowExporter(
		hivetest.Logger(t),
		[]timescapeEventExporter{full, stopped, success},
		nil,
		nil,
		nil,
		"",
		nil,
	)

	require.NoError(t, exporter.Export(t.Context(), &v1.Event{Event: &flowpb.Flow{}}))
	assert.Len(t, full.events, 1)
	assert.Len(t, stopped.events, 1)
	assert.Len(t, success.events, 1)
}

func TestTimescapeFlowExporterReturnsUnexpectedErrorsAndStopsFanout(t *testing.T) {
	for name, wantErr := range map[string]error{
		"unexpected": errors.New("unexpected failure"),
		"context":    context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			failed := newTestTimescapeEventExporter()
			failed.exportErr = wantErr
			later := newTestTimescapeEventExporter()
			exporter := newTimescapeFlowExporter(
				hivetest.Logger(t),
				[]timescapeEventExporter{failed, later},
				nil,
				nil,
				nil,
				"",
				nil,
			)

			err := exporter.Export(t.Context(), &v1.Event{Event: &flowpb.Flow{}})
			require.ErrorIs(t, err, wantErr)
			assert.Len(t, failed.events, 1)
			assert.Empty(t, later.events)
		})
	}
}

func TestTimescapeFlowExporterStopIsNoop(t *testing.T) {
	exporter := newTimescapeFlowExporter(hivetest.Logger(t), nil, nil, nil, nil, "", nil)
	require.NoError(t, exporter.Stop())
}

func TestTimescapeCredentialsProvider(t *testing.T) {
	t.Run("rejected promise", func(t *testing.T) {
		resolver, promised := promise.New[*certloader.WatchedClientConfig]()
		wantErr := errors.New("TLS setup failed")
		resolver.Reject(wantErr)
		credentials, err := newTimescapeCredentialsProvider(timescapeTLSConfigPromise(promised))(t.Context())
		assert.Nil(t, credentials)
		require.ErrorIs(t, err, wantErr)
		require.ErrorContains(t, err, "get watched TLS config")
	})

	t.Run("canceled wait", func(t *testing.T) {
		resolver, promised := promise.New[*certloader.WatchedClientConfig]()
		t.Cleanup(func() { resolver.Reject(errors.New("test finished")) })
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		credentials, err := newTimescapeCredentialsProvider(timescapeTLSConfigPromise(promised))(ctx)
		assert.Nil(t, credentials)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("nil watched config", func(t *testing.T) {
		resolver, promised := promise.New[*certloader.WatchedClientConfig]()
		resolver.Resolve(nil)
		credentials, err := newTimescapeCredentialsProvider(timescapeTLSConfigPromise(promised))(t.Context())
		assert.Nil(t, credentials)
		require.EqualError(t, err, "watched TLS config is nil")
	})

	t.Run("resolved watched config", func(t *testing.T) {
		watched, err := certloader.NewWatchedClientConfig(hivetest.Logger(t), nil, "", "")
		require.NoError(t, err)
		t.Cleanup(watched.Stop)
		resolver, promised := promise.New[*certloader.WatchedClientConfig]()
		resolver.Resolve(watched)
		credentials, err := newTimescapeCredentialsProvider(timescapeTLSConfigPromise(promised))(t.Context())
		require.NoError(t, err)
		require.NotNil(t, credentials)
		resolved, ok := credentials.(*timescapeTLSCredentials)
		require.True(t, ok)
		assert.Equal(t, minTimescapeTLSVersion, resolved.baseConf.MinVersion)
		assert.NotSame(t, credentials, credentials.Clone())
	})
}

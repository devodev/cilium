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
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/hubble/timescape"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
)

// testJobGroup is a no-op implementation of job.Group for tests. The exporter
// builder only ever calls Add, so Scoped is stubbed out and Add records how
// many jobs were registered for assertions.
type testJobGroup struct {
	added int
}

func (f *testJobGroup) Add(jobs ...job.Job) { f.added += len(jobs) }

func (f *testJobGroup) Scoped(string) job.ScopedGroup { return nil }

var _ job.Group = (*testJobGroup)(nil)

// testExporter is a configurable FlowLogExporter test double that records calls
// and can be made to fail on Export and/or Stop.
type testExporter struct {
	exported  int
	stopped   bool
	exportErr error
	stopErr   error
}

func (f *testExporter) Export(context.Context, *v1.Event) error {
	f.exported++
	return f.exportErr
}

func (f *testExporter) Stop() error {
	f.stopped = true
	return f.stopErr
}

var _ exporter.FlowLogExporter = (*testExporter)(nil)

// newTestParams returns a params value sufficient to exercise the exporter
// builder. The TLS promise and service resolver are intentionally nil: the
// builder only stores them and they are not dereferenced during Build.
func newTestParams(t *testing.T, cfg timescapeExporterConfig) params {
	return params{
		JobGroup: &testJobGroup{},
		Config:   cfg,
		Metrics:  &metricsHandler{},
		Logger:   hivetest.Logger(t),
	}
}

func TestNewHubbleTimescapeExporter_Disabled(t *testing.T) {
	out, err := newHubbleTimescapeExporter(newTestParams(t, timescapeExporterConfig{Enabled: false}))
	require.NoError(t, err)
	assert.Nil(t, out.ExporterBuilders, "disabled exporter must not register any builder")
}

func TestNewHubbleTimescapeExporter_RegistersBuilder(t *testing.T) {
	tests := []struct {
		name      string
		targets   []string
		wantMulti bool
		wantJobs  int
	}{
		{
			name:      "single target builds a single exporter",
			targets:   []string{"timescape:4261"},
			wantMulti: false,
			wantJobs:  1,
		},
		{
			name:      "multiple targets build a composite exporter",
			targets:   []string{"a:4261", "b:4261", "c:4261"},
			wantMulti: true,
			wantJobs:  3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestParams(t, timescapeExporterConfig{
				Enabled:            true,
				Targets:            tc.targets,
				IngestMode:         "auto",
				BatchSize:          1,
				BatchFlushInterval: 100 * time.Millisecond,
				MaxBufferSize:      1,
			})
			jg := p.JobGroup.(*testJobGroup)

			out, err := newHubbleTimescapeExporter(p)
			require.NoError(t, err)
			require.Len(t, out.ExporterBuilders, 1)
			assert.Equal(t, "timescape-exporter", out.ExporterBuilders[0].Name)

			exp, err := out.ExporterBuilders[0].Build()
			require.NoError(t, err)
			require.NotNil(t, exp)

			if tc.wantMulti {
				me, ok := exp.(*multiExporter)
				require.True(t, ok, "expected *multiExporter, got %T", exp)
				assert.Len(t, me.exporters, len(tc.targets))
			} else {
				_, ok := exp.(*timescape.Exporter)
				assert.True(t, ok, "expected single *timescape.Exporter, got %T", exp)
			}
			// One Run job is registered per target.
			assert.Equal(t, tc.wantJobs, jg.added)
		})
	}
}

func TestNewHubbleTimescapeExporter_TargetMerge(t *testing.T) {
	tests := []struct {
		name      string
		targets   []string
		target    string
		wantErr   bool
		wantMulti bool
		wantJobs  int
	}{
		{
			name:     "only deprecated target builds a single exporter",
			target:   "x:4261",
			wantJobs: 1,
		},
		{
			name:      "target not in targets is appended",
			targets:   []string{"a:4261"},
			target:    "b:4261",
			wantMulti: true,
			wantJobs:  2,
		},
		{
			name:     "target already in targets is not duplicated",
			targets:  []string{"a:4261"},
			target:   "a:4261",
			wantJobs: 1,
		},
		{
			name:    "no targets and no target is an error",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestParams(t, timescapeExporterConfig{
				Enabled:            true,
				Targets:            tc.targets,
				Target:             tc.target,
				IngestMode:         "auto",
				BatchSize:          1,
				BatchFlushInterval: 100 * time.Millisecond,
				MaxBufferSize:      1,
			})
			jg := p.JobGroup.(*testJobGroup)

			out, err := newHubbleTimescapeExporter(p)
			require.NoError(t, err)
			require.Len(t, out.ExporterBuilders, 1)

			exp, err := out.ExporterBuilders[0].Build()
			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, 0, jg.added, "no jobs are registered when the build fails")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, exp)

			if tc.wantMulti {
				_, ok := exp.(*multiExporter)
				assert.True(t, ok, "expected *multiExporter, got %T", exp)
			} else {
				_, ok := exp.(*timescape.Exporter)
				assert.True(t, ok, "expected single *timescape.Exporter, got %T", exp)
			}
			assert.Equal(t, tc.wantJobs, jg.added)
		})
	}
}

func TestMultiExporter_Export(t *testing.T) {
	t.Run("forwards events to every exporter", func(t *testing.T) {
		a, b := &testExporter{}, &testExporter{}
		m := &multiExporter{exporters: []exporter.FlowLogExporter{a, b}}

		require.NoError(t, m.Export(context.Background(), &v1.Event{}))
		assert.Equal(t, 1, a.exported)
		assert.Equal(t, 1, b.exported)
	})

	t.Run("returns on the first export error", func(t *testing.T) {
		wantErr := errors.New("test error")
		a := &testExporter{exportErr: wantErr}
		b := &testExporter{}
		m := &multiExporter{exporters: []exporter.FlowLogExporter{a, b}}

		err := m.Export(context.Background(), &v1.Event{})
		require.ErrorIs(t, err, wantErr)
		assert.Equal(t, 1, a.exported)
		assert.Equal(t, 0, b.exported, "subsequent exporters are not called after an error")
	})
}

func TestMultiExporter_Stop(t *testing.T) {
	t.Run("stops every exporter", func(t *testing.T) {
		a, b := &testExporter{}, &testExporter{}
		m := &multiExporter{exporters: []exporter.FlowLogExporter{a, b}}

		require.NoError(t, m.Stop())
		assert.True(t, a.stopped)
		assert.True(t, b.stopped)
	})

	t.Run("stops all exporters and aggregates errors", func(t *testing.T) {
		a := &testExporter{stopErr: errors.New("a failed")}
		b := &testExporter{}
		c := &testExporter{stopErr: errors.New("c failed")}
		m := &multiExporter{exporters: []exporter.FlowLogExporter{a, b, c}}

		err := m.Stop()
		require.Error(t, err)
		// Every exporter is stopped even when an earlier one fails.
		assert.True(t, a.stopped)
		assert.True(t, b.stopped)
		assert.True(t, c.stopped)
		assert.ErrorContains(t, err, "failed to stop 2 exporters")
	})
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package diagnostics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

type environmentBuilder struct {
	constants Constants
	interval  time.Duration
	registry  *metrics.Registry
}

func (eb environmentBuilder) build() *environment {
	env := environment{
		constants: eb.constants,
		interval:  eb.interval,
		metrics:   map[string][]*dto.Metric{},
	}

	// Sample all metrics (enabled and disabled)
	for metric := range eb.registry.CollectAll() {
		desc := unmarshalDesc(metric.Desc())
		var m dto.Metric
		if err := metric.Write(&m); err == nil {
			env.metrics[desc.FQName] = append(env.metrics[desc.FQName], &m)
		}
	}

	return &env
}

func metricToValue(m *dto.Metric) (float64, error) {
	switch {
	case m.Histogram != nil:
		// Return the average over _all_ the samples.
		if cnt := m.Histogram.GetSampleCount(); cnt > 0 {
			return m.Histogram.GetSampleSum() / float64(m.Histogram.GetSampleCount()), nil
		}
		return 0.0, nil
	case m.Summary != nil:
		if cnt := m.Summary.GetSampleCount(); cnt > 0 {
			return m.Summary.GetSampleSum() / float64(m.Histogram.GetSampleCount()), nil
		}
		return 0.0, nil
	case m.Gauge != nil:
		return m.Gauge.GetValue(), nil
	case m.Counter != nil:
		return m.Counter.GetValue(), nil
	default:
		return 0.0, fmt.Errorf("unhandled metric type")
	}
}

type environment struct {
	constants     Constants
	usedConstants sets.Set[string]
	now           time.Time
	cond          *ConditionStatus
	interval      time.Duration
	metrics       map[string][]*dto.Metric
}

// Gauge implements Environment.
func (e *environment) Gauge(name string, labels prometheus.Labels) (stats GaugeStats, err error) {
	var sample Metric
	sample, err = e.Metric(name, labels)
	if err != nil {
		return
	}

	if sample.Raw.Gauge == nil {
		err = fmt.Errorf("%q is not a gauge", name)
		return
	}

	gs, found := e.cond.GaugeSamplers.Get(sample.key())
	if !found {
		gs = newGaugeSampler(e.now)
		e.cond.GaugeSamplers = e.cond.GaugeSamplers.Set(sample.key(), gs)
	}
	gs.observe(e.now, sample)

	stats.Avg_24h, stats.Avg_4h, stats.Avg_1h, stats.Avg_Latest = gs.Averages()
	return
}

// Histogram implements Environment.
func (e *environment) Histogram(name string, labels prometheus.Labels) (stats HistogramStats, err error) {
	var sample Metric
	sample, err = e.Metric(name, labels)
	if err != nil {
		return
	}

	if sample.Raw.Histogram == nil && sample.Raw.Summary == nil {
		err = fmt.Errorf("%q is not a histogram or a summary", name)
		return
	}

	hs, found := e.cond.HistogramSamplers.Get(sample.key())
	if !found {
		hs = newHistogramSampler(e.now)
		e.cond.HistogramSamplers = e.cond.HistogramSamplers.Set(sample.key(), hs)
	}
	hs.observe(e.now, sample)

	stats.Avg_24h, stats.Avg_4h, stats.Avg_1h, stats.Avg_Latest = hs.Averages()
	stats.P50_24h, stats.P50_4h, stats.P50_1h, stats.P50_Latest = hs.Percentiles(0.5)
	stats.P90_24h, stats.P90_4h, stats.P90_1h, stats.P90_Latest = hs.Percentiles(0.9)
	stats.P99_24h, stats.P99_4h, stats.P99_1h, stats.P99_Latest = hs.Percentiles(0.99)
	return
}

func (e *environment) Counter(name string, labels prometheus.Labels) (stats CounterStats, err error) {
	var sample Metric
	sample, err = e.Metric(name, labels)
	if err != nil {
		return
	}

	if sample.Raw.Counter == nil {
		err = fmt.Errorf("%q is not a counter metric", name)
		return
	}

	cs, found := e.cond.CounterSamplers.Get(sample.key())
	if !found {
		cs = newCounterSampler(e.now)
		e.cond.CounterSamplers = e.cond.CounterSamplers.Set(sample.key(), cs)
	}
	cs.observe(e.now, sample)

	stats.Count_24h, stats.Count_4h, stats.Count_1h, stats.Count_Latest = cs.Increments()
	return
}

// Interval implements Environment.
func (e *environment) Interval() time.Duration {
	return e.interval
}

// use the environment with the given condition.
func (e *environment) use(cond *ConditionStatus, now time.Time) *environment {
	e.cond = cond
	e.now = now
	return e
}

func (e *environment) Metric(name string, labels prometheus.Labels) (Metric, error) {
	metrics, err := e.MetricsMatchingLabels(name, labels)
	if err != nil {
		return Metric{}, err
	}
	return metrics[0], nil
}

func (e *environment) MetricsMatchingLabels(name string, labels prometheus.Labels) (out []Metric, err error) {
	candidates, found := e.metrics[name]
	if !found {
		return nil, fmt.Errorf("metric %q not found", name)
	}
	out = make([]Metric, 0, len(candidates))
	for _, candidate := range candidates {
		remaining := len(labels)
		for key, value := range labels {
			for _, pair := range candidate.Label {
				if pair.GetName() == key && pair.GetValue() == value {
					remaining--
					break
				}
			}
		}
		if remaining > 0 {
			continue
		}
		v, err := metricToValue(candidate)
		if err != nil {
			return nil, err
		}
		out = append(out, Metric{
			Name:  name,
			Value: v,
			Raw:   candidate,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("metric %q found but had no labels matching %v", name, labels)
	}
	return
}

// UserConstant implements Environment.
func (e *environment) UserConstant(key string, fallback float64) float64 {
	if e.usedConstants != nil {
		e.usedConstants.Insert(key)
	}

	if v, ok := e.constants[key]; ok {
		return v
	}
	return fallback
}

func (e *environment) Now() time.Time {
	return time.Now()
}

var _ Environment = &environment{}

type desc struct {
	FQName         string
	Help           string
	ConstLabels    string
	VariableLabels string
}

func unmarshalDesc(desc *prometheus.Desc) (out desc) {
	// [prometheus.Desc] is completely opaque type except for String()
	fmt.Sscanf(desc.String(),
		"Desc{fqName: %q, help: %q, constLabels: {%s}, variableLabels: {%s}}",
		&out.FQName,
		&out.Help,
		&out.ConstLabels,
		&out.VariableLabels,
	)
	return out
}

type FakeEnvironment struct {
	FakeGauge                 GaugeStats
	FakeCounter               CounterStats
	FakeHistogram             HistogramStats
	FakeInterval              time.Duration
	FakeMetric                Metric
	FakeMetricsMatchingLabels []Metric
	FakeUserConstants         map[string]float64
	FakeNow                   time.Time
}

// Gauge implements Environment.
func (f *FakeEnvironment) Gauge(name string, labels prometheus.Labels) (stats GaugeStats, err error) {
	return f.FakeGauge, nil
}

// Histogram implements Environment.
func (f *FakeEnvironment) Histogram(name string, labels prometheus.Labels) (stats HistogramStats, err error) {
	return f.FakeHistogram, nil
}

// Counter implements Environment.
func (f *FakeEnvironment) Counter(name string, labels prometheus.Labels) (stats CounterStats, err error) {
	return f.FakeCounter, nil
}

// Interval implements Environment.
func (f *FakeEnvironment) Interval() time.Duration {
	return f.FakeInterval
}

// Metric implements Environment.
func (f *FakeEnvironment) Metric(name string, labels prometheus.Labels) (Metric, error) {
	return f.FakeMetric, nil
}

// MetricsMatchingLabels implements Environment.
func (f *FakeEnvironment) MetricsMatchingLabels(name string, labels prometheus.Labels) ([]Metric, error) {
	return f.FakeMetricsMatchingLabels, nil
}

// UserConstant implements Environment.
func (f *FakeEnvironment) UserConstant(key string, fallback float64) float64 {
	if v, ok := f.FakeUserConstants[key]; ok {
		return v
	}
	return fallback
}

func (f *FakeEnvironment) Now() time.Time {
	return f.FakeNow
}

var _ Environment = &FakeEnvironment{}

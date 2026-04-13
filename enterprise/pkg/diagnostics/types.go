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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
	ipasys "github.com/isovalent/ipa/system_status/v1alpha"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/time"
)

// ConditionID is a unique identifier for the condition. This is used to associate
// a failing condition with additional metadata that is defined outside, but
// is not shown in its raw form to the user.
//
// The identifier is not fully qualified in the sense that it does not
// include the system (e.g. cilium agent) or its version. This additional
// information is attached alongside it when the condition is reported upwards.

// The identifier thus only needs to be unique within the system.
// Examples of identifiers:
// - go_goroutines
// - bpf_map_capacity
// - endpoint_regeneration_duration
//
// The identifier should usually be prefixed with the Hive module identifier,
// but it's not enforced as we may need to for example define conditions
// for OSS modules via metrics, and since we need to associate separate metadata
// to the condition it's best to keep the id as transparent and obvious as possible.
type ConditionID string

// Condition defines a diagnostic condition that is periodically evaluated
// and on failure reported towards the user.
type Condition struct {
	// ID is the unique identifier for this condition. Only needs to be unique
	// within the application, e.g. "go_goroutines" is a valid identifier.
	ID ConditionID

	// SubSystem impacted by the failing condition
	SubSystem string

	// Description and impact of the condition
	Description string

	// Resolution is an optional suggestion on how to mitigate or resolve
	// the issue.
	Resolution string

	// Evaluator is the function for evaluating whether the condition is
	// triggered.
	Evaluator Evaluator `json:"-" yaml:"-"`
}

// MarshalJSON implemented as [Evaluator] is a function. This allows dumping
// the diagnostics table in sysdumps.
func (c Condition) MarshalJSON() ([]byte, error) {
	var out struct {
		ID        ConditionID
		Evaluator string
	}
	out.ID = c.ID
	out.Evaluator = funcNameAndLocation(c.Evaluator)
	return json.Marshal(&out)
}

func (c Condition) String() string {
	return fmt.Sprintf("%s (%s)", c.ID, funcNameAndLocation(c.Evaluator))
}

func (c Condition) validate() error {
	switch {
	case c.ID == "":
		return fmt.Errorf("'ID' must be specified")
	case c.SubSystem == "":
		return fmt.Errorf("'SubSystem' must be specified")
	case c.Description == "":
		return fmt.Errorf("'Description' must be given")
	case c.Evaluator == nil:
		return fmt.Errorf("'Evaluator' must be specified")
	}
	return nil
}

func (c Condition) toMetadata() *ipasys.ConditionMetadata {
	return &ipasys.ConditionMetadata{
		ConditionId: string(c.ID),
		Subsystem:   c.SubSystem,
		Description: c.Description,
		Resolution:  c.Resolution,
	}
}

type Severity = ipasys.Severity

// Aliases for the severity levels
const (
	OK       = ipasys.Severity_SEVERITY_UNSPECIFIED
	Debug    = ipasys.Severity_SEVERITY_DEBUG
	Minor    = ipasys.Severity_SEVERITY_MINOR
	Major    = ipasys.Severity_SEVERITY_MAJOR
	Critical = ipasys.Severity_SEVERITY_CRITICAL
)

// Evaluator is a function for evaluating a diagnostic condition.
//
// It takes in an [Environment] which provides access to metrics.
// The evaluator is allowed to access other state, but it is encouraged
// to avoid this if the information is available as a metric to keep
// the evaluators simple and predictable.
type Evaluator = func(Environment) (msg Message, severity ipasys.Severity)

// Message is additional information about why the condition
// has failed. This will be user-facing!
type Message = string

type Metric struct {
	// Name of the metric
	Name string

	// Value that was sampled. For Gauge and Counter it is the latest value,
	// for Summary and Histogram it is the average over all samples.
	Value float64

	// Raw is the raw metric.
	Raw *dto.Metric
}

func (m *Metric) Labels() prometheus.Labels {
	if m.Raw == nil {
		return nil
	}
	labels := make(prometheus.Labels, len(m.Raw.Label))
	for _, lp := range m.Raw.Label {
		if lp.Name != nil && lp.Value != nil {
			labels[*lp.Name] = *lp.Value
		}
	}
	return labels
}

// LabelsString returns the labels as a comma-separated list, e.g. "foo=bar, baz=quux"
func (m *Metric) LabelsString() string {
	if m.Raw == nil {
		return ""
	}
	var labels []string
	for _, lp := range m.Raw.Label {
		if lp.Name != nil && lp.Value != nil {
			labels = append(labels, fmt.Sprintf("%s=%s", *lp.Name, *lp.Value))
		}
	}
	return strings.Join(labels, ",")
}

func (m *Metric) key() string {
	return m.Name + "[" + m.LabelsString() + "]"
}

type HistogramStats struct {
	Avg_24h, Avg_4h, Avg_1h, Avg_Latest float64
	P50_24h, P50_4h, P50_1h, P50_Latest float64
	P90_24h, P90_4h, P90_1h, P90_Latest float64
	P99_24h, P99_4h, P99_1h, P99_Latest float64
}

type GaugeStats struct {
	Avg_24h, Avg_4h, Avg_1h, Avg_Latest float64
}

type CounterStats struct {
	Count_24h, Count_4h, Count_1h, Count_Latest int64
}

// Environment for evaluating a condition.
//
// Provides access to common sources like metrics and the user-configurable
// variables.
type Environment interface {
	// Metric collects the given metric.
	// If the metric is a vector then the first one encountered is returned.
	//
	// For gauges and counters it returns the current value and for
	// histogram and summary it returns the average.
	Metric(name string, labels prometheus.Labels) (Metric, error)

	// MetricsMatchingLabels collects the metrics that match the given name
	// and labels.
	MetricsMatchingLabels(name string, labels prometheus.Labels) ([]Metric, error)

	// Histogram returns the 24h/4h/1h/latest averages and 50th/90/99th percentiles
	// for the given histogram (or summary).
	Histogram(name string, labels prometheus.Labels) (stats HistogramStats, err error)

	// Gauge returns the 24h/4h/1h/latest averages and 50th/90/99th percentiles
	// for the given gauge (or summary).
	Gauge(name string, labels prometheus.Labels) (stats GaugeStats, err error)

	// Counter returns the 24h/4h/1h/latest count recorded for the given counter.
	Counter(name string, labels prometheus.Labels) (stats CounterStats, err error)

	// UserConstant returns the value configured by the user. To be used
	// to override constants for e.g. thresholds. If the value is not found
	// the provided default is used.
	UserConstant(key string, fallback float64) float64

	// Interval is the interval at which the conditions are evaluated.
	Interval() time.Duration

	// Now returns the current time for the evaluation
	Now() time.Time
}

var (
	ConditionsTableName = "diagnostics"

	conditionsIndex = statedb.Index[ConditionStatus, ConditionID]{
		Name: "id",
		FromObject: func(obj ConditionStatus) index.KeySet {
			return index.NewKeySet(index.String((string(obj.Condition.ID))))
		},
		FromKey: func(key ConditionID) index.Key {
			return index.String(string(key))
		},
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}
)

func NewConditionsTable(db *statedb.DB) (statedb.RWTable[ConditionStatus], error) {
	return statedb.NewTable(
		db,
		ConditionsTableName,
		conditionsIndex,
	)
}

// ConditionStatus is stored in the conditions table. Holds the registered conditions
// and historical
type ConditionStatus struct {
	Condition Condition

	TotalCount  int
	FailedCount int
	Latest      Evaluation
	LastFailure Evaluation

	GaugeSamplers     part.Map[string, *gaugeSampler]
	CounterSamplers   part.Map[string, *counterSampler]
	HistogramSamplers part.Map[string, *histogramSampler]
}

// TableHeader implements statedb.TableWritable.
func (c ConditionStatus) TableHeader() []string {
	return []string{
		"ID",
		"Total",
		"Failed",
		"Latest",
		"LastFailure",
		"Evaluator",
	}
}

// TableRow implements statedb.TableWritable.
func (c ConditionStatus) TableRow() []string {
	return []string{
		string(c.Condition.ID),
		strconv.FormatInt(int64(c.TotalCount), 10),
		strconv.FormatInt(int64(c.FailedCount), 10),
		c.Latest.String(),
		c.LastFailure.String(),
		funcNameAndLocation(c.Condition.Evaluator),
	}
}

var _ statedb.TableWritable = ConditionStatus{}

// Evaluation is the result of an condition evaluation.
type Evaluation struct {
	EvaluatedAt time.Time
	Severity    Severity
	Message     Message
}

func (e Evaluation) String() string {
	if e.EvaluatedAt.IsZero() {
		return "<none>"
	}

	var b strings.Builder

	if e.Severity != OK {
		sev := e.Severity.String()
		sev, _ = strings.CutPrefix(sev, "SEVERITY_")
		fmt.Fprintf(&b, "Failed %s ago (%s): %s", duration.HumanDuration(time.Since(e.EvaluatedAt)), sev, e.Message)
	} else {
		fmt.Fprintf(&b, "Succeeded %s ago", duration.HumanDuration(time.Since(e.EvaluatedAt)))
		if e.Message != "" {
			fmt.Fprintf(&b, ": %s", e.Message)
		}
	}
	return b.String()
}

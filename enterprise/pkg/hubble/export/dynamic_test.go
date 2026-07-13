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
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hubble/exporter"
)

// nolint:exhaustruct
func TestFlowLogConfigEqual(t *testing.T) {
	cases := []struct {
		name          string
		currentConfig *FlowLogConfig
		newConfig     *FlowLogConfig
		expectEqual   bool
	}{
		{
			name:          "should equal for same FileRotationInterval",
			currentConfig: &FlowLogConfig{config: config{FileRotationInterval: time.Second}},
			newConfig:     &FlowLogConfig{config: config{FileRotationInterval: time.Second}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same FormatVersion",
			currentConfig: &FlowLogConfig{config: config{FormatVersion: formatVersionV1}},
			newConfig:     &FlowLogConfig{config: config{FormatVersion: formatVersionV1}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same RateLimit",
			currentConfig: &FlowLogConfig{config: config{RateLimit: 10}},
			newConfig:     &FlowLogConfig{config: config{RateLimit: 10}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same RateNodeNameLimit",
			currentConfig: &FlowLogConfig{config: config{NodeName: "my-node"}},
			newConfig:     &FlowLogConfig{config: config{NodeName: "my-node"}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same Aggregations",
			currentConfig: &FlowLogConfig{config: config{Aggregations: []string{"identity"}}},
			newConfig:     &FlowLogConfig{config: config{Aggregations: []string{"identity"}}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationIgnoreSourcePort",
			currentConfig: &FlowLogConfig{config: config{AggregationIgnoreSourcePort: true}},
			newConfig:     &FlowLogConfig{config: config{AggregationIgnoreSourcePort: true}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationRenewTTL",
			currentConfig: &FlowLogConfig{config: config{AggregationRenewTTL: true}},
			newConfig:     &FlowLogConfig{config: config{AggregationRenewTTL: true}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationStateChangeFilter",
			currentConfig: &FlowLogConfig{config: config{AggregationStateChangeFilter: []string{"new", "error"}}},
			newConfig:     &FlowLogConfig{config: config{AggregationStateChangeFilter: []string{"new", "error"}}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationTTL",
			currentConfig: &FlowLogConfig{config: config{AggregationTTL: time.Second}},
			newConfig:     &FlowLogConfig{config: config{AggregationTTL: time.Second}},
			expectEqual:   true,
		},
		{
			name:          "should not equal if Aggregations same length",
			currentConfig: &FlowLogConfig{config: config{Aggregations: []string{"identity"}}},
			newConfig:     &FlowLogConfig{config: config{Aggregations: []string{"connection"}}},
			expectEqual:   false,
		},
		{
			name:          "should not equal if AggregationStateChangeFilter same length",
			currentConfig: &FlowLogConfig{config: config{AggregationStateChangeFilter: []string{"new", "error"}}},
			newConfig:     &FlowLogConfig{config: config{AggregationStateChangeFilter: []string{"established", "close"}}},
			expectEqual:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.currentConfig.equals(tc.newConfig)
			assert.Equal(t, tc.expectEqual, result)
		})
	}
}

func TestExporterConfigParser(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    map[string]exporter.ExporterConfig
		wantErr bool
	}{
		{
			name:   "empty",
			config: "",
			want:   map[string]exporter.ExporterConfig{},
		},
		{
			name: "default values",
			config: `
                flowLogs:
                  - name: all
                    filePath: /var/run/cilium/hubble/hubble.log
            `,
			want: map[string]exporter.ExporterConfig{
				"all": &FlowLogConfig{
					// exporter.FlowLogConfig already has tests, no need to re-test parsing here
					FlowLogConfig: exporter.FlowLogConfig{
						Name:           "all",
						FilePath:       "/var/run/cilium/hubble/hubble.log",
						FileMaxSizeMB:  0,
						FileMaxBackups: 0,
						FileCompress:   false,
					},
					config: config{
						FileRotationInterval:         0,
						FormatVersion:                "v1",
						NodeName:                     "",
						RateLimit:                    -1,
						Aggregations:                 []string{},
						AggregationIgnoreSourcePort:  true,
						AggregationRenewTTL:          true,
						AggregationStateChangeFilter: []string{"new", "error", "closed"},
						AggregationTTL:               30 * time.Second,
					},
				},
			},
		},
		{
			name: "empty arrays",
			config: `
                flowLogs:
                  - name: all
                    filePath: /var/run/cilium/hubble/hubble.log
                    aggregation: []
                    aggregationStateFilter: []
            `,
			want: map[string]exporter.ExporterConfig{
				"all": &FlowLogConfig{
					// exporter.FlowLogConfig already has tests, no need to re-test parsing here
					FlowLogConfig: exporter.FlowLogConfig{
						Name:           "all",
						FilePath:       "/var/run/cilium/hubble/hubble.log",
						FileMaxSizeMB:  0,
						FileMaxBackups: 0,
						FileCompress:   false,
					},
					config: config{
						FileRotationInterval:         0,
						FormatVersion:                "v1",
						NodeName:                     "",
						RateLimit:                    -1,
						Aggregations:                 []string{},
						AggregationIgnoreSourcePort:  true,
						AggregationRenewTTL:          true,
						AggregationStateChangeFilter: []string{},
						AggregationTTL:               30 * time.Second,
					},
				},
			},
		},
		{
			name: "complete",
			config: `
                flowLogs:
                  - name: all
                    filePath: /var/run/cilium/hubble/hubble.log
                    fileMaxSizeMb: 10
                    fileMaxBackups: 5
                    fileCompress: true
                    fileRotationInterval: 1m
                    formatVersion: ""
                    nodeName: my-node
                    rateLimit: 10
                    aggregation:
                      - identity
                    aggregationIgnoreSourcePort: false
                    aggregationRenewTTL: false
                    aggregationStateFilter:
                      - new
                      - error
                    aggregationTTL: 60s
            `,
			want: map[string]exporter.ExporterConfig{
				"all": &FlowLogConfig{
					// exporter.FlowLogConfig already has tests, no need to re-test parsing here
					FlowLogConfig: exporter.FlowLogConfig{
						Name:           "all",
						FilePath:       "/var/run/cilium/hubble/hubble.log",
						FileMaxSizeMB:  10,
						FileMaxBackups: 5,
						FileCompress:   true,
					},
					config: config{
						FileRotationInterval:         time.Minute,
						FormatVersion:                "",
						NodeName:                     "my-node",
						RateLimit:                    10,
						Aggregations:                 []string{"identity"},
						AggregationIgnoreSourcePort:  false,
						AggregationRenewTTL:          false,
						AggregationStateChangeFilter: []string{"new", "error"},
						AggregationTTL:               60 * time.Second,
					},
				},
			},
		},
		{
			// Regression test for a nil pointer dereference: when rateLimit is
			// set but nodeName is omitted (nil), the parser used to dereference
			// nodeName guarded by the wrong (rateLimit) check and panic. This
			// matches the default dynamic export config (rateLimit: -1, no
			// nodeName). See customer-support#1763.
			name: "rate limit set without node name",
			config: `
                flowLogs:
                  - name: all
                    filePath: /var/run/cilium/hubble/hubble.log
                    rateLimit: -1
            `,
			want: map[string]exporter.ExporterConfig{
				"all": &FlowLogConfig{
					FlowLogConfig: exporter.FlowLogConfig{
						Name:     "all",
						FilePath: "/var/run/cilium/hubble/hubble.log",
					},
					config: config{
						FileRotationInterval:         0,
						FormatVersion:                "v1",
						NodeName:                     "",
						RateLimit:                    -1,
						Aggregations:                 []string{},
						AggregationIgnoreSourcePort:  true,
						AggregationRenewTTL:          true,
						AggregationStateChangeFilter: []string{"new", "error", "closed"},
						AggregationTTL:               30 * time.Second,
					},
				},
			},
		},
		{
			name: "missing required name",
			config: `
                flowLogs:
                  - filePath: /var/run/cilium/hubble/hubble.log
            `,
			wantErr: true,
		},
		{
			name: "missing required filepath",
			config: `
                flowLogs:
                  - name: all
            `,
			wantErr: true,
		},
		{
			name: "duplicated name",
			config: `
                flowLogs:
                  - name: all
                  - name: all
            `,
			wantErr: true,
		},
		{
			name: "duplicated filepath",
			config: `
                flowLogs:
                  - filePath: /var/run/cilium/hubble/hubble.log
                  - filePath: /var/run/cilium/hubble/hubble.log
            `,
			wantErr: true,
		},
	}

	configParser := exporterConfigParser{logger: slog.Default()}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d. %s", i, test.name), func(t *testing.T) {
			got, err := configParser.Parse(strings.NewReader(test.config))
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			if assert.NoError(t, err) {
				assert.Equal(t, test.want, got)
			}
		})
	}
}

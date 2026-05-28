// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package timescape

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// options stores all the configuration values for the Exporter.
type options struct {
	dialOptions                []grpc.DialOption
	tlsConfigPromise           promise.Promise[*certloader.WatchedClientConfig]
	backoff                    Backoff
	ingestMode                 ingestMode
	batchSize                  int
	batchFlushInterval         time.Duration
	maxBufferSize              int
	reportDroppedFlowsInterval time.Duration

	// clock is used to create timers for the batcher. It is set to a real timer
	// clock by default, but can be overridden for testing purposes.
	clock timerClock

	allowFilters  filters.FilterFuncs
	denyFilters   filters.FilterFuncs
	fieldMask     fieldmask.FieldMask
	fieldMaskFlow *flowpb.Flow
	nodeName      string
	onExportEvent []OnExportEvent
	resolvers     []dial.Resolver
}

// Option customizes the configuration of the Exporter.
type Option func(*options) error

type ingestMode string

const (
	ingestModeAuto   ingestMode = "auto"
	ingestModeBatch  ingestMode = "batch"
	ingestModeSingle ingestMode = "single"
)

func parseIngestMode(mode string) (ingestMode, error) {
	switch ingestMode(mode) {
	case ingestModeAuto, ingestModeBatch, ingestModeSingle:
		return ingestMode(mode), nil
	default:
		return "", fmt.Errorf("invalid ingest mode: %q, must be one of: auto, batch, single", mode)
	}
}

// WithDialOptions sets the dial options for the Exporter.
func WithDialOptions(dialOptions ...grpc.DialOption) Option {
	return func(o *options) error {
		o.dialOptions = dialOptions
		return nil
	}
}

// WithTLSConfigPromise sets the TLS configuration promise for the Exporter.
func WithTLSConfigPromise(tlsConfigPromise promise.Promise[*certloader.WatchedClientConfig]) Option {
	return func(o *options) error {
		o.tlsConfigPromise = tlsConfigPromise
		return nil
	}
}

// WithBackoff sets the backoff strategy for the Exporter.
func WithBackoff(backoff Backoff) Option {
	return func(o *options) error {
		o.backoff = backoff
		return nil
	}
}

// WithIngestMode sets the Timescape ingest RPC selection mode.
func WithIngestMode(mode string) Option {
	return func(o *options) error {
		parsedMode, err := parseIngestMode(mode)
		if err != nil {
			return err
		}
		o.ingestMode = parsedMode
		return nil
	}
}

// WithBatchSize sets the maximum number of flows sent in a single batch.
func WithBatchSize(size int) Option {
	return func(o *options) error {
		if size <= 0 {
			return fmt.Errorf("invalid batch size: %d, must be greater than 0", size)
		}
		o.batchSize = size
		return nil
	}
}

// WithBatchFlushInterval sets the maximum time a partial batch is kept before it is flushed.
func WithBatchFlushInterval(interval time.Duration) Option {
	return func(o *options) error {
		if interval <= 0 {
			return fmt.Errorf("invalid batch flush interval: %v, must be greater than 0", interval)
		}
		o.batchFlushInterval = interval
		return nil
	}
}

// WithMaxBufferSize sets the maximum buffer size for the Exporter.
func WithMaxBufferSize(size int) Option {
	return func(o *options) error {
		if size <= 0 {
			return fmt.Errorf("invalid buffer size: %d, must be greater than 0", size)
		}
		o.maxBufferSize = size
		return nil
	}
}

// WithReportDroppedFlowsInterval sets the interval for reporting dropped flows.
func WithReportDroppedFlowsInterval(interval time.Duration) Option {
	return func(o *options) error {
		if interval < 0 {
			return fmt.Errorf("invalid report dropped flows interval: %v, must be greater or equal than 0", interval)
		}
		o.reportDroppedFlowsInterval = interval
		return nil
	}
}

// WithAllowListFilter sets the allowlist filter for the Exporter.
func WithAllowListFilter(log *slog.Logger, f []*flowpb.FlowFilter) Option {
	return func(o *options) error {
		allowFilters, err := filters.BuildFilterList(context.Background(), f, filters.DefaultFilters(log))
		if err != nil {
			return fmt.Errorf("failed to build allowlist filter: %w", err)
		}
		o.allowFilters = allowFilters
		return nil
	}
}

// WithDenyListFilter sets the denylist filter for the Exporter.
func WithDenyListFilter(log *slog.Logger, f []*flowpb.FlowFilter) Option {
	return func(o *options) error {
		denyFilters, err := filters.BuildFilterList(context.Background(), f, filters.DefaultFilters(log))
		if err != nil {
			return fmt.Errorf("failed to build denylist filter: %w", err)
		}
		o.denyFilters = denyFilters
		return nil
	}
}

// WithFieldMask sets the field mask for the Exporter.
func WithFieldMask(paths []string) Option {
	return func(o *options) error {
		fm, err := fieldmaskpb.New(&flowpb.Flow{}, paths...)
		if err != nil {
			return fmt.Errorf("failed to create field mask: %w", err)
		}
		fieldMask, err := fieldmask.New(fm)
		if err != nil {
			return fmt.Errorf("failed to create field mask: %w", err)
		}
		var flow *flowpb.Flow
		if fieldMask.Active() {
			flow = new(flowpb.Flow)
			fieldMask.Alloc(flow.ProtoReflect())
		}
		o.fieldMask = fieldMask
		o.fieldMaskFlow = flow
		return nil
	}
}

// WithNodeName sets the node name for the Exporter.
func WithNodeName(nodeName string) Option {
	return func(o *options) error {
		o.nodeName = nodeName
		return nil
	}
}

// WithOnExportEvent registers an OnExportEvent hook on the Exporter.
func WithOnExportEvent(onExportEvent OnExportEvent) Option {
	return func(o *options) error {
		o.onExportEvent = append(o.onExportEvent, onExportEvent)
		return nil
	}
}

// WithOnExportEventFunc registers an OnExportEventFunc hook on the Exporter.
func WithOnExportEventFunc(onExportEvent OnExportEventFunc) Option {
	return WithOnExportEvent(onExportEvent)
}

// WithResolvers sets the resolvers used to create a custom dialer to connect
// to Timescape. Resolvers are used to resolve service names to IP addresses,
// which is useful to resolve service names without depending on the DNS. This
// prevents the need for setting the DNSPolicy to ClusterFirstWithHostNet when
// running in host network.
func WithResolvers(resolvers ...dial.Resolver) Option {
	return func(o *options) error {
		o.resolvers = append(o.resolvers, resolvers...)
		return nil
	}
}

// withTestClock sets a custom timerClock for testing purposes.
func withTestClock(clock timerClock) Option {
	return func(o *options) error {
		o.clock = clock
		return nil
	}
}

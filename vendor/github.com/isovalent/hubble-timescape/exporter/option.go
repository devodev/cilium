// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

package exporter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultMaxBufferSize              = 4096
	defaultReportDroppedEventInterval = time.Minute
	defaultShutdownFlushTimeout       = 2 * time.Second
)

// IngestMode controls which Timescape ingestion RPC an exporter uses.
type IngestMode string

const (
	// IngestModeAuto discovers IngestBatch support and falls back to the
	// deprecated single-event RPC when required.
	IngestModeAuto IngestMode = "auto"
	// IngestModeBatch always uses IngestBatch.
	IngestModeBatch IngestMode = "batch"
	// IngestModeSingle uses the flow-only Ingest RPC.
	//
	// Deprecated: Use IngestModeAuto or IngestModeBatch. The Timescape
	// single-event ingestion endpoint is deprecated.
	IngestModeSingle IngestMode = "single"
)

// ParseIngestMode parses an ingest mode.
func ParseIngestMode(mode string) (IngestMode, error) {
	switch parsed := IngestMode(mode); parsed {
	case IngestModeAuto, IngestModeBatch, IngestModeSingle:
		return parsed, nil
	default:
		return "", fmt.Errorf("invalid ingest mode %q: must be one of auto, batch, single", mode)
	}
}

// TransportCredentialsProvider resolves transport credentials when Run starts.
type TransportCredentialsProvider func(context.Context) (credentials.TransportCredentials, error)

type options struct {
	dialOptions                  []grpc.DialOption
	transportCredentials         credentials.TransportCredentials
	transportCredentialsProvider TransportCredentialsProvider
	backoff                      Backoff
	ingestMode                   IngestMode
	maxBufferSize                int
	reportDroppedEventInterval   time.Duration
	shutdownFlushTimeout         time.Duration
}

func defaultOptions() options {
	return options{
		backoff:                    newExponentialBackoff(),
		ingestMode:                 IngestModeAuto,
		maxBufferSize:              defaultMaxBufferSize,
		reportDroppedEventInterval: defaultReportDroppedEventInterval,
		shutdownFlushTimeout:       defaultShutdownFlushTimeout,
	}
}

// Option customizes an [Exporter] or [BatchingExporter].
type Option func(*options) error

// WithDialOptions appends gRPC dial options used to create the connection.
func WithDialOptions(dialOptions ...grpc.DialOption) Option {
	return func(o *options) error {
		o.dialOptions = append(o.dialOptions, dialOptions...)
		return nil
	}
}

// WithTransportCredentials configures static gRPC transport credentials.
func WithTransportCredentials(transportCredentials credentials.TransportCredentials) Option {
	return func(o *options) error {
		if transportCredentials == nil {
			return errors.New("transport credentials are nil")
		}
		o.transportCredentials = transportCredentials
		return nil
	}
}

// WithTransportCredentialsProvider configures credentials resolved when Run starts.
func WithTransportCredentialsProvider(provider TransportCredentialsProvider) Option {
	return func(o *options) error {
		if provider == nil {
			return errors.New("transport credentials provider is nil")
		}
		o.transportCredentialsProvider = provider
		return nil
	}
}

// WithBackoff configures the connection retry backoff.
func WithBackoff(backoff Backoff) Option {
	return func(o *options) error {
		if backoff == nil {
			return errors.New("backoff is nil")
		}
		o.backoff = backoff
		return nil
	}
}

// WithIngestMode configures ingestion RPC selection.
func WithIngestMode(mode IngestMode) Option {
	return func(o *options) error {
		parsed, err := ParseIngestMode(string(mode))
		if err != nil {
			return err
		}
		o.ingestMode = parsed
		return nil
	}
}

// WithMaxBufferSize configures the maximum number of admitted events.
func WithMaxBufferSize(size int) Option {
	return func(o *options) error {
		if size <= 0 {
			return fmt.Errorf("invalid buffer size %d: must be greater than zero", size)
		}
		o.maxBufferSize = size
		return nil
	}
}

// WithReportDroppedEventsInterval configures dropped-event log reporting.
func WithReportDroppedEventsInterval(interval time.Duration) Option {
	return func(o *options) error {
		if interval < 0 {
			return fmt.Errorf("invalid dropped-event reporting interval %s: must not be negative", interval)
		}
		o.reportDroppedEventInterval = interval
		return nil
	}
}

// WithShutdownFlushTimeout configures the shutdown drain grace period.
func WithShutdownFlushTimeout(timeout time.Duration) Option {
	return func(o *options) error {
		if timeout < 0 {
			return fmt.Errorf("invalid shutdown flush timeout %s: must not be negative", timeout)
		}
		o.shutdownFlushTimeout = timeout
		return nil
	}
}

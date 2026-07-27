// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package connectionlog

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/hive/cell"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"

	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// connLogExporter is responsible to collect the connLogDB and write its
// content to disk in the IPA graphV1 format at a given interval.
type connLogExporter struct {
	logger        *slog.Logger
	db            *connLogDB
	interval      time.Duration
	encoder       exporter.Encoder
	writer        io.WriteCloser
	lastTick      time.Time // owned by tick()
	stop, stopped chan struct{}
}

// newExporter initialize a new ConnectionLog exporter. Note that only
// WithNewWriterFunc() and WithNewEncoderFunc() are supported as exporter
// options.
func newExporter(logger *slog.Logger, db *connLogDB, interval time.Duration, options ...exporter.Option) (*connLogExporter, error) {
	// XXX: Should we validate the given interval? Maybe to prevent itto be
	// "too small" for the exporter to tick()? OTHO how much is "too small"
	// depends on many factors, maybe it'd better to adapt it when we detect
	// struggle to keep up?
	opts := exporter.DefaultOptions // start with defaults
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	logger.Info("configuring exporter", logfields.Options, opts)

	writer, err := opts.NewWriterFunc()()
	if err != nil {
		return nil, fmt.Errorf("failed to create writer: %w", err)
	}
	encoder, err := opts.NewEncoderFunc()(writer)
	if err != nil {
		return nil, fmt.Errorf("failed to create encoder: %w", err)
	}

	return &connLogExporter{
		logger:   logger,
		db:       db,
		interval: interval,
		encoder:  encoder,
		writer:   writer,
		// XXX: set the last tick as now, which is not technically correct, but
		// probably close enough.
		lastTick: time.Now(),
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}, nil
}

// Start implements cell.HookInterface
func (e *connLogExporter) Start(_ cell.HookContext) error {
	e.logger.Info("exporter starting")
	go func() {
		ticker := time.NewTicker(e.interval)
		e.logger.Info("exporter started")
		defer e.logger.Info("exporter stopped")
		for {
			select {
			case now := <-ticker.C:
				if err := e.tick(now); err != nil {
					e.logger.Error("writing to disk", logfields.Error, err)
				}
			case <-e.stop:
				// tick one last time.
				if err := e.tick(time.Now()); err != nil {
					e.logger.Error("writing to disk", logfields.Error, err)
				}
				close(e.stopped)
				// from that point, we guarantee to not use exporter
				// writer/encoder.
				return
			}
		}
	}()
	return nil
}

// Stop implements cell.HookInterface
func (e *connLogExporter) Stop(ctx cell.HookContext) error {
	e.logger.Info("exporter stopping")
	close(e.stop)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.stopped: // happy case
		err := e.writer.Close()
		e.logger.Info("exporter stopped")
		return err
	}
}

// tick collect the connLogDB map, translate its content to a graphV1
// ConnectionLog, and write it to disk. It is not safe to call concurently, it
// should be only called by Start().
func (e *connLogExporter) tick(now time.Time) error {
	store := e.db.reset()

	// XXX: handling the time window here is not the most precise as "now" is
	// sampled before db.reset() is called. It would probably be more accurate
	// to let connLogDB handle the time window and return it along with the map
	// itself.
	prev := e.lastTick
	e.lastTick = now

	connections := make([]*graphV1.Connection, 0, len(store))
	for k, v := range store {
		c := flowstatToConnection(k, v)
		if c != nil {
			connections = append(connections, c)
		}
	}
	out := connectionLog(prev, now, connections)

	return e.encoder.Encode(out)
}

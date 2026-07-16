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

import "errors"

var (
	// ErrBufferFull indicates that the configured event capacity is exhausted.
	ErrBufferFull = errors.New("exporter buffer is full")
	// ErrStopped indicates that the exporter no longer accepts events.
	ErrStopped = errors.New("exporter is stopped")
	// ErrInvalidEvent indicates that an event is empty or unsupported.
	ErrInvalidEvent = errors.New("invalid event")
	// ErrInvalidBatch indicates that a batch is empty or unsupported.
	ErrInvalidBatch = errors.New("invalid batch")
	// ErrBatchAlreadyExported indicates that a batch is already claimed or consumed.
	ErrBatchAlreadyExported = errors.New("batch was already exported")
	// ErrAlreadyRunning indicates that Run was called more than once.
	ErrAlreadyRunning = errors.New("exporter can only be run once")
)

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
	"math"
	"time"
)

// Backoff calculates the delay before a connection retry.
type Backoff interface {
	Duration(attempt int) time.Duration
}

type exponentialBackoff struct {
	min time.Duration
	max time.Duration
}

func newExponentialBackoff() exponentialBackoff {
	return exponentialBackoff{min: time.Second, max: time.Minute}
}

func (b exponentialBackoff) Duration(attempt int) time.Duration {
	if attempt <= 1 {
		return b.min
	}
	power := math.Pow(2, float64(attempt-1))
	duration := time.Duration(float64(b.min) * power)
	if duration < b.min || duration > b.max {
		return b.max
	}
	return duration
}

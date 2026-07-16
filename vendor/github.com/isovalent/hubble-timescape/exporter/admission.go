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

import "sync/atomic"

type admission struct {
	max  int64
	used atomic.Int64
}

func newAdmission(maximum int) *admission {
	return &admission{max: int64(maximum)}
}

func (a *admission) acquire(count int) bool {
	if count <= 0 || int64(count) > a.max {
		return false
	}
	for {
		used := a.used.Load()
		if used+int64(count) > a.max {
			return false
		}
		if a.used.CompareAndSwap(used, used+int64(count)) {
			return true
		}
	}
}

func (a *admission) release(count int) {
	if count > 0 {
		a.used.Add(-int64(count))
	}
}

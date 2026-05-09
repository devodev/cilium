// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"errors"
	"log/slog"
	"sort"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
)

// ErrAbortReconcile aborts the remaining reconciliation for the current instance.
var ErrAbortReconcile = errors.New("abort reconcile error")

// EnterpriseConfigReconciler reconciles one Enterprise BGP instance.
type EnterpriseConfigReconciler interface {
	Name() string
	Priority() int
	Init(i *instance.EnterpriseBGPInstance) error
	Cleanup(i *instance.EnterpriseBGPInstance)
	Reconcile(ctx context.Context, params EnterpriseReconcileParams) error
}

// EnterpriseStateReconciler reconciles Enterprise BGP state changes.
type EnterpriseStateReconciler interface {
	Name() string
	Priority() int
	Reconcile(ctx context.Context, params EnterpriseStateReconcileParams) error
}

// GetActiveEnterpriseReconcilers returns CEE config reconcilers ordered by priority.
func GetActiveEnterpriseReconcilers(logger *slog.Logger, reconcilers []EnterpriseConfigReconciler) []EnterpriseConfigReconciler {
	activeReconcilers := make([]EnterpriseConfigReconciler, 0, len(reconcilers))
	seenReconcilers := make(map[string]struct{})
	for _, r := range reconcilers {
		if r == nil {
			continue
		}
		if _, ok := seenReconcilers[r.Name()]; ok {
			logger.Warn("Skipping duplicate BGP reconciler",
				types.ReconcilerLogField, r.Name(),
			)
			continue
		}
		seenReconcilers[r.Name()] = struct{}{}
		logger.Debug("Adding BGP reconciler",
			types.ReconcilerLogField, r.Name(),
			types.PriorityLogField, r.Priority(),
		)
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return activeReconcilers
}

// GetActiveEnterpriseStateReconcilers returns CEE state reconcilers ordered by priority.
func GetActiveEnterpriseStateReconcilers(logger *slog.Logger, reconcilers []EnterpriseStateReconciler) []EnterpriseStateReconciler {
	activeReconcilers := make([]EnterpriseStateReconciler, 0, len(reconcilers))
	seenReconcilers := make(map[string]struct{})
	for _, r := range reconcilers {
		if r == nil {
			continue
		}
		if _, ok := seenReconcilers[r.Name()]; ok {
			logger.Warn("Skipping duplicate BGP state reconciler",
				types.ReconcilerLogField, r.Name(),
			)
			continue
		}
		seenReconcilers[r.Name()] = struct{}{}
		logger.Debug("Adding BGP state reconciler",
			types.ReconcilerLogField, r.Name(),
			types.PriorityLogField, r.Priority(),
		)
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return activeReconcilers
}

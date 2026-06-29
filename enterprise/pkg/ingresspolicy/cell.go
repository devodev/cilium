//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ingresspolicy

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/pkg/ciliumenvoyconfig/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides support for the CEC Ingress Policy
var Cell = cell.Module(
	"cec-ingress-policy",
	"Ingress Policy for CiliumEnvoyConfig",

	cell.Invoke(registerCECK8sReconciler),
	cell.ProvidePrivate(newIngressPolicyManager),
)

type reconcilerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Health    cell.Health

	Config            types.CECPolicyConfig
	DB                *statedb.DB
	CECs              statedb.Table[*ciliumenvoyconfig.CEC]
	RegenerationFence regeneration.Fence

	IngressPolicyManager Updater
}

type cecReconciler struct {
	logger *slog.Logger
	db     *statedb.DB
	cecs   statedb.Table[*ciliumenvoyconfig.CEC]

	initDone chan struct{}

	ingressPolicyManager Updater
}

func registerCECK8sReconciler(params reconcilerParams) {
	if !option.Config.EnableL7Proxy || !option.Config.EnableEnvoyConfig ||
		params.Config.Mode != types.CECPolicyModeDedicated {
		return
	}

	initDone := make(chan struct{})

	params.RegenerationFence.Add("ingresspolicy", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-initDone:
			return nil
		}
	})

	reconciler := &cecReconciler{
		logger:               params.Logger,
		ingressPolicyManager: params.IngressPolicyManager,
		initDone:             initDone,
		db:                   params.DB,
		cecs:                 params.CECs,
	}

	params.JobGroup.Add(job.OneShot(
		"process-cecs",
		reconciler.process,
	))
}

func (r *cecReconciler) process(ctx context.Context, health cell.Health) error {
	wtxn := r.db.WriteTxn(r.cecs)
	changeIter, err := r.cecs.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	for {
		txn := r.db.ReadTxn()
		changes, watch := changeIter.Next(txn)
		for change := range changes {
			cec := change.Object
			if cec.Name.Namespace == "" {
				// Ignore clusterwide configurations.
				continue
			}

			key := resource.Key{
				Name:      cec.Name.Name,
				Namespace: cec.Name.Namespace,
			}

			scopedLogger := r.logger.With(
				logfields.K8sNamespace, cec.Name.Namespace,
				logfields.CiliumEnvoyConfigName, cec.Name.Name,
			)

			var err error
			if !change.Deleted {
				scopedLogger.Debug("Received CiliumEnvoyConfig upsert event")
				err = r.ingressPolicyManager.EnsureIngressPolicy(ctx, key, cec.Labels)
			} else {
				scopedLogger.Debug("Received CiliumEnvoyConfig delete event")
				err = r.ingressPolicyManager.DeleteIngressPolicy(ctx, key, cec.Labels)
			}
			if err != nil {
				scopedLogger.Error("Failed to update ingress policies on CiliumEnvoyConfig change",
					logfields.Error, err,
				)
			}
		}

		var initWatch <-chan struct{}
		if r.initDone != nil {
			var initialized bool
			if initialized, initWatch = r.cecs.Initialized(txn); initialized {
				// All initial CECs processed, unblock endpoint restoration.
				close(r.initDone)
				r.initDone = nil
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch: // wakes on changes
		case <-initWatch: // wakes on table becoming initialized even if empty
		}
	}
}

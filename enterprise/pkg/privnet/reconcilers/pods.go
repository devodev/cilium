//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var PodsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the reconciler handling updates to private-network enabeld pods.
		newPods,
	),

	cell.Invoke(
		(*Pods).registerReconciler,
	),
)

// Pods is a reconciler which watches local pods and updates the activatedAt status
// if changes are detected
type Pods struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	endpointManager           endpoints.EndpointGetter
	endpointActivationManager *EndpointActivationManager

	db         *statedb.DB
	pods       statedb.Table[k8sTables.LocalPod]
	migrations statedb.RWTable[tables.Migration]
}

func newPods(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	EndpointManager           endpoints.EndpointGetter
	EndpointActivationManager *EndpointActivationManager

	DB         *statedb.DB
	Pods       statedb.Table[k8sTables.LocalPod]
	Migrations statedb.RWTable[tables.Migration]
}) *Pods {
	return &Pods{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		endpointManager:           in.EndpointManager,
		endpointActivationManager: in.EndpointActivationManager,

		db:         in.DB,
		pods:       in.Pods,
		migrations: in.Migrations,
	}
}

func (p *Pods) registerReconciler() {
	if !p.cfg.Enabled {
		return
	}

	p.jg.Add(job.OneShot("reconcile-pod-activation", func(ctx context.Context, health cell.Health) error {
		for {
			txn := p.db.ReadTxn()
			pods, watch := p.pods.AllWatch(txn)
			eventTime := time.Now()
			for pod := range pods {
				if !types.HasNetworkAttachmentAnnotation(pod) {
					continue // ignore pods without a private network annotation
				}

				podFullName := pod.GetNamespace() + "/" + pod.GetName()
				newIsInactive, err := types.ExtractInactiveAnnotation(pod)
				if err != nil {
					p.log.Warn("Failed to parse pod annotation",
						logfields.Pod, podFullName,
						logfields.Error, err)
					continue
				}

				eps := p.endpointManager.GetEndpointsByPodName(podFullName)
				for ep := range eps {
					properties, ok := endpoints.ExtractEndpointProperties(ep)
					if !ok {
						// Expected, if only a subset of the pod interfaces is attached
						// to a private network. It may also happen if users added
						// the private networks annotations after the initial pod
						// creation, in which case it would be ignored as well.
						continue
					}

					oldActivatedAt, err := properties.ActivatedAt()
					if err != nil {
						p.log.Error("Invalid activated-at property on endpoint",
							logfields.Pod, podFullName,
							logfields.Error, err)
						continue
					}

					oldIsInactive := oldActivatedAt.IsZero()
					if oldIsInactive != newIsInactive {
						// Endpoint activation state has changed. Set new activatedAt timestamp
						newActivatedAt := eventTime
						if newIsInactive {
							newActivatedAt = time.Time{} // zero means inactive
						}
						// Update endpoint property and inform subscribers
						p.endpointActivationManager.SetActivatedAt(ep, newActivatedAt)
					}
				}

				// Check if this is a migration and whether the VM has now resumed.
				if nodeName, exists := pod.Labels[kubevirtv1.NodeNameLabel]; exists && nodeName == pod.Spec.NodeName {
					if _, exists := pod.Annotations[kubevirtv1.MigrationTargetReadyTimestamp]; exists {
						wtx := p.db.WriteTxn(p.migrations)
						for migration := range p.migrations.Prefix(txn, tables.MigrationByKey(tables.MigrationKey{
							Namespace: pod.Namespace,
							PodName:   pod.Name,
							MAC:       "",
						})) {
							if !migration.Resumed {
								if migration, _, found := p.migrations.Get(wtx, tables.MigrationByKey(migration.MigrationKey)); found && !migration.Resumed {
									migration.Resumed = true
									p.migrations.Insert(wtx, migration)
								}
							}
						}
						wtx.Commit()
					}
				}
			}

			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
		}
	}))
}

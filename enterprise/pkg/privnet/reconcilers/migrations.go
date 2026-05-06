// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	k8stables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/time"
)

// MigrationsCell reflects local KubeVirt pods that are being migrated from another node
// into the migrations table.
var MigrationsCell = cell.Group(
	cell.Provide(
		tables.NewMigrationsTable,
		statedb.RWTable[*tables.Migration].ToTable,
	),
	cell.Invoke(
		podsToMigrationsReflector.register,
	),
)

type podsToMigrationsReflector struct {
	cell.In

	Log         *slog.Logger
	JobGroup    job.Group
	Config      config.Config
	ClusterInfo cmtypes.ClusterInfo

	DB         *statedb.DB
	Migrations statedb.RWTable[tables.Migration]
	Pods       statedb.Table[k8stables.LocalPod]
}

func (m podsToMigrationsReflector) register() {
	if !m.Config.Enabled {
		return
	}

	clusterName := tables.ClusterName(m.ClusterInfo.Name)

	m.JobGroup.Add(
		job.OneShot("reflect-pods-to-migrations", func(ctx context.Context, health cell.Health) error {
			wtxn := m.DB.WriteTxn(m.Pods, m.Migrations)
			changeIter, err := m.Pods.Changes(wtxn)
			_, podsInitWatch := m.Pods.Initialized(wtxn)
			initDone := m.Migrations.RegisterInitializer(wtxn, "pods")
			wtxn.Commit()
			if err != nil {
				return err
			}
			for {
				wtxn := m.DB.WriteTxn(m.Migrations)
				changes, watch := changeIter.Next(wtxn)
				for change := range changes {
					key, ok := migrationKeyFromPod(clusterName, change.Object)
					if !ok {
						// Not a KubeVirt VM
						continue
					}
					if change.Deleted {
						m.Migrations.Delete(wtxn, tables.Migration{MigrationKey: key})
					} else {
						m.reconcilePodUpdate(wtxn, key, change.Object)
					}
				}
				wtxn.Commit()

				select {
				case <-ctx.Done():
					return nil
				case <-watch:
				case <-podsInitWatch:
					wtxn := m.DB.WriteTxn(m.Migrations)
					initDone(wtxn)
					wtxn.Commit()
					podsInitWatch = nil
				}
			}
		}))
}

func (m *podsToMigrationsReflector) reconcilePodUpdate(
	wtxn statedb.WriteTxn,
	key tables.MigrationKey,
	pod k8stables.LocalPod,
) {
	if old, _, found := m.Migrations.Get(wtxn, tables.MigrationByKey(key)); found {
		// The only relevant update we're interested in now is whether
		// the VM has resumed or not which we can derive from the node name label.
		new := old
		if !types.IsKubeVirtMigrationTargetNode(pod, pod.Spec.NodeName) {
			new.Resumed = true
		}
		if !new.Equal(old) {
			new.UpdatedAt = time.Now()
			m.Migrations.Insert(wtxn, new)
		}
		return
	}

	migration := migrationFromPod(key, pod)
	if migration != nil {
		m.Migrations.Insert(wtxn, *migration)
	}
}

func migrationKeyFromPod(clusterName tables.ClusterName, pod k8stables.LocalPod) (tables.MigrationKey, bool) {
	if types.ExtractKubeVirtVMI(pod) == "" {
		return tables.MigrationKey{}, false
	}
	return tables.MigrationKey{
		Cluster:   clusterName,
		Namespace: pod.Namespace,
		PodName:   pod.Name,
	}, true
}

func migrationFromPod(key tables.MigrationKey, pod k8stables.LocalPod) *tables.Migration {
	vmiName := types.ExtractKubeVirtVMI(pod)
	if vmiName == "" || !types.HasNetworkAttachmentAnnotation(pod) || !types.IsKubeVirtMigrationTargetNode(pod, pod.Spec.NodeName) {
		return nil
	}

	sourceNode := types.KubeVirtNodeName(pod)
	if sourceNode == "" {
		return nil
	}

	now := time.Now()
	return &tables.Migration{
		MigrationKey: key,
		VMIName:      vmiName,
		SourceNode:   tables.NodeName(sourceNode),
		TargetNode:   tables.NodeName(pod.Spec.NodeName),
		CreatedAt:    now,
		UpdatedAt:    now,
		Resumed:      false,
		State:        tables.MigrationStateNew,
		Error:        nil,
	}
}

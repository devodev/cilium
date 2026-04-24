// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package strictzone

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

const refreshRetryDelay = time.Second

type zoneWatcherParams struct {
	cell.In

	JobGroup job.Group
	Writer   *writer.Writer
	Nodes    statedb.Table[*node.LocalNode]
}

func registerZoneWatcher(jg job.Group, p zoneWatcherParams) {
	jg.Add(job.OneShot("strict-zone-watcher", zoneWatcher{zoneWatcherParams: p}.run))
}

type zoneWatcher struct {
	zoneWatcherParams
}

// zoneWatcher refreshes strict same-zone frontends when the local node zone changes.
func (zw zoneWatcher) run(ctx context.Context, health cell.Health) error {
	var oldZone string

	for {
		txn := zw.Writer.WriteTxn()
		localNode, _, watch, found := zw.Nodes.GetWatch(txn, node.LocalNodeQuery)

		newZone := ""
		if found {
			newZone = localNode.Labels[corev1.LabelTopologyZone]
		}

		zoneChanged := newZone != oldZone
		var err error
		if zoneChanged {
			if err = zw.updateForZoneChange(txn, health); err != nil {
				txn.Abort()
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(refreshRetryDelay):
				}
				continue
			}
			oldZone = newZone
		}

		if zoneChanged && err == nil {
			txn.Commit()
		} else {
			txn.Abort()
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

func (zw zoneWatcher) updateForZoneChange(txn writer.WriteTxn, health cell.Health) error {
	for svc := range zw.Writer.Services().All(txn) {
		if !isStrictSameZoneService(svc) {
			continue
		}
		if err := zw.Writer.RefreshFrontends(txn, svc.Name); err != nil {
			health.Degraded("strict-zone frontend refresh failed", err)
			return err
		}
	}

	health.OK("Watching local node zone")
	return nil
}

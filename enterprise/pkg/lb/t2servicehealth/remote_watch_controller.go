// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package t2servicehealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"

	api "github.com/cilium/cilium/enterprise/pkg/lb/t2servicehealth/api/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type remoteWatchControllerParams struct {
	cell.In

	Config            t2ServiceHealthConfig
	Logger            *slog.Logger
	JobGroup          job.Group
	DB                *statedb.DB
	LBWriter          *writer.Writer
	RemoteHealthTable statedb.RWTable[*remoteServiceHealth]
}

func registerRemoteWatchController(params remoteWatchControllerParams) {
	if !option.Config.EnableL7Proxy || !params.Config.Enabled {
		return
	}

	controller := &remoteWatchController{
		remoteWatchControllerParams: params,
		watchers:                    map[string]context.CancelFunc{},
	}
	params.JobGroup.Add(job.OneShot("remote-watch-controller", controller.run))
}

type remoteWatchController struct {
	remoteWatchControllerParams

	watchers map[string]context.CancelFunc
}

func (m *remoteWatchController) run(ctx context.Context, _ cell.Health) error {
	watchSet := statedb.NewWatchSet()

	for {
		watchSet.Clear()

		targets := m.collectTargets(watchSet)
		m.reconcileWatchers(ctx, targets)
		if err := m.gcExpiredRows(); err != nil {
			return err
		}

		if _, err := watchSet.Wait(ctx, time.Second); err != nil {
			return err
		}
	}
}

func (m *remoteWatchController) collectTargets(watchSet *statedb.WatchSet) map[string]struct{} {
	rtxn := m.LBWriter.ReadTxn()
	svcs, svcWatch := m.LBWriter.Services().AllWatch(rtxn)
	watchSet.Add(svcWatch)

	targets := map[string]struct{}{}
	for svc := range svcs {
		if !isRemoteT2HealthService(svc) {
			continue
		}

		bes, besWatch := m.LBWriter.BackendsForService(rtxn, svc.Name)
		watchSet.Add(besWatch)
		for be := range bes {
			if !be.Address.Addr().IsValid() {
				continue
			}
			targets[be.Address.Addr().String()] = struct{}{}
		}
	}

	return targets
}

func (m *remoteWatchController) reconcileWatchers(ctx context.Context, targets map[string]struct{}) {
	for target, cancel := range m.watchers {
		if _, found := targets[target]; found {
			continue
		}
		cancel()
		delete(m.watchers, target)
		_ = m.deleteRowsForTarget(target)
	}

	for target := range targets {
		if _, found := m.watchers[target]; found {
			continue
		}

		targetCtx, cancel := context.WithCancel(ctx)
		m.watchers[target] = cancel
		go m.watchTarget(targetCtx, target)
	}
}

func (m *remoteWatchController) watchTarget(ctx context.Context, target string) {
	backoff := time.Second

	for {
		err := m.watchTargetOnce(ctx, target)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = time.Second
			continue
		}

		if !errors.Is(err, context.Canceled) {
			m.Logger.Warn("Watching remote T2 service health failed",
				logfields.Address, target,
				logfields.Error, err,
			)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

func (m *remoteWatchController) watchTargetOnce(ctx context.Context, target string) error {
	conn, err := DialGRPC(net.JoinHostPort(target, fmt.Sprintf("%d", m.Config.Port)))
	if err != nil {
		return err
	}
	defer conn.Close()

	stream, err := NewGRPCClient(conn).Watch(ctx, &api.WatchRequest{})
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		if resp.GetFullSnapshot() {
			if err := m.applyFullSnapshot(target, resp.GetEvents()); err != nil {
				return err
			}
			continue
		}

		if err := m.applyDelta(target, resp.GetEvents()); err != nil {
			return err
		}
	}
}

func (m *remoteWatchController) applyFullSnapshot(target string, events []*api.WatchResponse_Event) error {
	desired := map[remoteServiceHealthKey]*remoteServiceHealth{}
	for _, event := range events {
		row := remoteRowFromEvent(target, event)
		if row == nil {
			continue
		}
		desired[remoteServiceHealthKey{
			TargetAddr: target,
			Service:    loadbalancer.NewServiceName(row.Namespace, row.Name),
		}] = row
	}

	wtxn := m.DB.WriteTxn(m.RemoteHealthTable)
	defer wtxn.Commit()
	now := time.Now()

	existing := map[remoteServiceHealthKey]*remoteServiceHealth{}
	for row := range m.RemoteHealthTable.List(wtxn, remoteServiceHealthTargetIndex.Query(remoteServiceHealthTargetKey{TargetAddr: target})) {
		existing[remoteServiceHealthKey{
			TargetAddr: row.TargetAddr,
			Service:    loadbalancer.NewServiceName(row.Namespace, row.Name),
		}] = row
	}

	for key, row := range desired {
		delete(existing, key)
		if _, _, err := m.RemoteHealthTable.Insert(wtxn, row); err != nil {
			wtxn.Abort()
			return err
		}
	}

	for _, row := range existing {
		if shouldRetainExistingRemoteRowOnFullSnapshot(row, now) {
			continue
		}
		if _, _, err := m.RemoteHealthTable.Delete(wtxn, row); err != nil {
			wtxn.Abort()
			return err
		}
	}

	return nil
}

func shouldRetainExistingRemoteRowOnFullSnapshot(row *remoteServiceHealth, now time.Time) bool {
	if row == nil || row.ExpiresAt.IsZero() {
		return false
	}

	return now.Before(row.ExpiresAt)
}

func (m *remoteWatchController) applyDelta(target string, events []*api.WatchResponse_Event) error {
	wtxn := m.DB.WriteTxn(m.RemoteHealthTable)
	defer wtxn.Commit()

	for _, event := range events {
		row := remoteRowFromEvent(target, event)
		if row == nil {
			continue
		}

		if event.GetDeleted() {
			existing, _, found := m.RemoteHealthTable.Get(wtxn, remoteServiceHealthPrimaryIndex.Query(remoteServiceHealthKey{
				TargetAddr: row.TargetAddr,
				Service:    loadbalancer.NewServiceName(row.Namespace, row.Name),
			}))
			if !found {
				continue
			}
			if _, _, err := m.RemoteHealthTable.Delete(wtxn, existing); err != nil {
				wtxn.Abort()
				return err
			}
			continue
		}

		if _, _, err := m.RemoteHealthTable.Insert(wtxn, row); err != nil {
			wtxn.Abort()
			return err
		}
	}

	return nil
}

func (m *remoteWatchController) deleteRowsForTarget(target string) error {
	wtxn := m.DB.WriteTxn(m.RemoteHealthTable)
	defer wtxn.Commit()

	for row := range m.RemoteHealthTable.List(wtxn, remoteServiceHealthTargetIndex.Query(remoteServiceHealthTargetKey{TargetAddr: target})) {
		if _, _, err := m.RemoteHealthTable.Delete(wtxn, row); err != nil {
			wtxn.Abort()
			return err
		}
	}

	return nil
}

func (m *remoteWatchController) gcExpiredRows() error {
	now := time.Now()
	wtxn := m.DB.WriteTxn(m.RemoteHealthTable)
	defer wtxn.Commit()

	for row := range m.RemoteHealthTable.All(wtxn) {
		if row.ExpiresAt.IsZero() || now.Before(row.ExpiresAt) {
			continue
		}
		if _, _, err := m.RemoteHealthTable.Delete(wtxn, row); err != nil {
			wtxn.Abort()
			return err
		}
	}

	return nil
}

func remoteRowFromEvent(target string, event *api.WatchResponse_Event) *remoteServiceHealth {
	if event == nil || event.GetNamespace() == "" || event.GetName() == "" {
		return nil
	}

	var expiresAt time.Time
	if ts := event.GetExpiresAt(); ts != nil {
		expiresAt = ts.AsTime()
	}

	return &remoteServiceHealth{
		TargetAddr: target,
		Namespace:  event.GetNamespace(),
		Name:       event.GetName(),
		Healthy:    event.GetHealthy(),
		ExpiresAt:  expiresAt,
	}
}

var _ grpc.ClientConnInterface = (*grpc.ClientConn)(nil)

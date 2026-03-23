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
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type remoteBackendHealthControllerParams struct {
	cell.In

	Config            t2ServiceHealthConfig
	JobGroup          job.Group
	Logger            *slog.Logger
	LBWriter          *writer.Writer
	RemoteHealthTable statedb.RWTable[*remoteServiceHealth]
}

func registerRemoteBackendHealthController(params remoteBackendHealthControllerParams) {
	if !option.Config.EnableL7Proxy || !params.Config.Enabled {
		return
	}

	controller := &remoteBackendHealthController{
		remoteBackendHealthControllerParams: params,
		lastDesired:                         map[remoteBackendKey]bool{},
	}
	params.JobGroup.Add(job.OneShot("remote-backend-health-controller", controller.run))
}

type remoteBackendHealthController struct {
	remoteBackendHealthControllerParams

	lastDesired map[remoteBackendKey]bool
}

type remoteBackendKey struct {
	Service loadbalancer.ServiceName
	Backend loadbalancer.L3n4Addr
}

func (c *remoteBackendHealthController) run(ctx context.Context, _ cell.Health) error {
	watchSet := statedb.NewWatchSet()

	for {
		watchSet.Clear()

		desired := c.computeDesired(watchSet)
		if err := c.applyDesired(desired); err != nil {
			return err
		}

		if _, err := watchSet.Wait(ctx, time.Second); err != nil {
			return err
		}
	}
}

func (c *remoteBackendHealthController) computeDesired(watchSet *statedb.WatchSet) map[remoteBackendKey]bool {
	rtxn := c.LBWriter.ReadTxn()

	remoteByServiceAndTarget := map[remoteServiceHealthKey]*remoteServiceHealth{}
	remoteRows, remoteWatch := c.RemoteHealthTable.AllWatch(rtxn)
	watchSet.Add(remoteWatch)
	for row := range remoteRows {
		remoteByServiceAndTarget[remoteServiceHealthKey{
			TargetAddr: row.TargetAddr,
			Service:    loadbalancer.NewServiceName(row.Namespace, row.Name),
		}] = row
	}

	svcs, svcWatch := c.LBWriter.Services().AllWatch(rtxn)
	watchSet.Add(svcWatch)

	desired := map[remoteBackendKey]bool{}
	now := time.Now()

	for svc := range svcs {
		if !isRemoteT2HealthService(svc) {
			continue
		}

		bes, besWatch := c.LBWriter.BackendsForService(rtxn, svc.Name)
		watchSet.Add(besWatch)
		for be := range bes {
			if !be.Address.Addr().IsValid() {
				continue
			}

			row, found := remoteByServiceAndTarget[remoteServiceHealthKey{
				TargetAddr: be.Address.Addr().String(),
				Service:    svc.Name,
			}]

			healthy := found && !row.ExpiresAt.IsZero() && now.Before(row.ExpiresAt) && row.Healthy
			desired[remoteBackendKey{
				Service: svc.Name,
				Backend: be.Address,
			}] = healthy
		}
	}

	return desired
}

func (c *remoteBackendHealthController) applyDesired(desired map[remoteBackendKey]bool) error {
	wtxn := c.LBWriter.WriteTxn()
	defer wtxn.Commit()

	for key, healthy := range desired {
		lastHealthy, found := c.lastDesired[key]
		if found && lastHealthy == healthy {
			continue
		}

		if _, err := c.LBWriter.UpdateBackendHealth(wtxn, key.Service, key.Backend, healthy); err != nil && !errors.Is(err, loadbalancer.ErrServiceNotFound) {
			wtxn.Abort()
			return err
		}
	}

	for key := range c.lastDesired {
		if _, found := desired[key]; found {
			continue
		}

		if _, err := c.LBWriter.UpdateBackendHealth(wtxn, key.Service, key.Backend, true); err != nil && !errors.Is(err, loadbalancer.ErrServiceNotFound) {
			c.Logger.Error("Restoring backend health failed",
				logfields.ServiceName, key.Service,
				logfields.Address, key.Backend,
				logfields.Error, err,
			)
		}
	}

	c.lastDesired = desired
	return nil
}

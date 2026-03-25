// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/loadbalancer"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

func registerController(p controllerParams) error {
	if !p.Config.EnableActiveLbHealthChecking {
		return nil
	}

	c := &controller{
		controllerParams:   p,
		lastHealthRevision: 0,
		serviceWatchSets:   map[lb.ServiceName]*statedb.WatchSet{},
		closedChannels:     nil,
	}

	p.Writer.SetIsServiceHealthCheckedFunc(c.isServiceHealthChecked)

	p.JobGroup.Add(job.OneShot("run", c.run))

	return nil
}

type controllerParams struct {
	cell.In

	Config       Config
	LBConfig     lb.Config
	JobGroup     job.Group
	DB           *statedb.DB
	Log          *slog.Logger
	Writer       *writer.Writer
	HealthChecks statedb.RWTable[*healthCheck]
}

// controller performs the following tasks:
// - 1. Create Table[healthCheck] objects for backends that require health checking
// - 2. Synchronize the healthy status from Table[healthCheck] back to backends.
//
// This splits the responsibilities in two: controller interacts with the load-balancing
// control-plane and instructs health checking via Table[healthCheck] and the checker
// deals with only health checking and updating status back to Table[healthCheck].
type controller struct {
	controllerParams

	lastHealthRevision statedb.Revision
	serviceWatchSets   map[lb.ServiceName]*statedb.WatchSet
	closedChannels     []<-chan struct{}
}

func (c *controller) run(ctx context.Context, health cell.Health) error {
	// The amount of time to wait for changes to settle before processing.
	// This avoids processing intermediate states and significantly reduces
	// the overhead of checking the services. We do iterate over all services
	// on changes, but do a quick check to see if it actually changed, so very
	// little processing is usually done per service.
	waitTime := 200 * time.Millisecond

	c.serviceWatchSets = map[lb.ServiceName]*statedb.WatchSet{}
	var closedChannels []<-chan struct{}
	watchSet := statedb.NewWatchSet()

	for {
		watchSet.Clear()

		// Compute what health checks are needed.
		deletedHealthChecks := c.computeHealthChecks(watchSet, closedChannels)

		// Update backend health based on new probe results.
		c.updateBackendHealth(watchSet, deletedHealthChecks)

		// Wait for any of the inputs change. We wait for additional [waitTime] for further
		// changes.
		var err error
		closedChannels, err = watchSet.Wait(ctx, waitTime)
		if err != nil {
			return err
		}
	}
}

func (c *controller) computeHealthChecks(watchSet *statedb.WatchSet, closedChannels []<-chan struct{}) []*healthCheck {
	// Update the desired health checks from changed services and backends.
	wtxn := c.DB.WriteTxn(c.HealthChecks)
	defer wtxn.Commit()

	// Keep track of the current services that exist to find orphans.
	visited := sets.New[lb.ServiceName]()

	deletedHealthChecks := []*healthCheck{}

	svcs, watchServices := c.Writer.Services().AllWatch(wtxn)
	watchSet.Add(watchServices)

	for svc := range svcs {
		visited.Insert(svc.Name)

		// Use a set of watch channels per service to figure out when we need to
		// recompute the health checking state for this service.
		svcWatchSet, found := c.serviceWatchSets[svc.Name]
		if !found {
			svcWatchSet = statedb.NewWatchSet()
			c.serviceWatchSets[svc.Name] = svcWatchSet
		} else if !svcWatchSet.HasAny(closedChannels) {
			// No changes to this service or associated data.
			watchSet.Merge(svcWatchSet)
			continue
		}
		svcWatchSet.Clear()

		// Add the watch channel for this specific service to recompute when it changes.
		_, _, svcWatch, _ := c.Writer.Services().GetWatch(wtxn, lb.ServiceByName(svc.Name))
		svcWatchSet.Add(svcWatch)

		cfg := getAnnotationHealthCheckConfig(svc.Annotations)
		if cfg.State == HealthCheckDisabled || cfg.State == HealthCheckEnabledExternal {
			for hc := range c.HealthChecks.List(wtxn, healthCheckByService(svc.Name)) {
				c.HealthChecks.Delete(wtxn, hc)
				deletedHealthChecks = append(deletedHealthChecks, hc)
			}
			continue
		}

		// Grab the frontends for the service in case they're needed for the health checking.
		fesSeq, fesWatch := c.Writer.Frontends().ListWatch(wtxn, lb.FrontendByServiceName(svc.Name))
		svcWatchSet.Add(fesWatch)

		// The 'LoadBalancer' frontend IPs are used for DSR probes
		fesLoadBalancerAddrs := statedb.Collect(
			statedb.Map(
				statedb.Filter(fesSeq, func(fe *lb.Frontend) bool { return fe.Type == lb.SVCTypeLoadBalancer }),
				func(fe *lb.Frontend) lb.L3n4Addr { return fe.Address }))

		// Iterate over all backends associated with the frontends and create/update the corresponding
		// HealthChecks.
		beAddrs := sets.New[lb.L3n4Addr]()
		for fe := range fesSeq {
			for be := range fe.HealthCheckBackends {
				if beAddrs.Has(be.Address) {
					continue
				}
				if be.State != lb.BackendStateActive {
					continue
				}
				beAddrs.Insert(be.Address)

				// Skip if the HealthCheck entry exists and has the right parameters
				old, _, found := c.HealthChecks.Get(wtxn, healthCheckByServiceAndBackend(svc.Name, be.Address))
				outdated := !found || !addrsEqual(old.Frontends, fesLoadBalancerAddrs) || !old.Config.DeepEqual(&cfg)
				if !outdated {
					continue
				}

				// This is either a new backend or health checking parameters have changed. Write out a
				// new HealthCheck discarding any previous health state.
				c.HealthChecks.Insert(
					wtxn,
					&healthCheck{
						Service:   svc.Name,
						Backend:   be.Address,
						Config:    cfg,
						Frontends: fesLoadBalancerAddrs,
						UpdatedAt: time.Now(),
						Healthy:   true,
					})
			}
		}

		// Remove orphaned health checks.
		for hc := range c.HealthChecks.List(wtxn, healthCheckByService(svc.Name)) {
			if !beAddrs.Has(hc.Backend) {
				c.HealthChecks.Delete(wtxn, hc)
			}
		}
		watchSet.Merge(svcWatchSet)
	}

	// Remove orphaned health checks.
	for svc := range c.serviceWatchSets {
		if visited.Has(svc) {
			continue
		}
		for hc := range c.HealthChecks.List(wtxn, healthCheckByService(svc)) {
			c.HealthChecks.Delete(wtxn, hc)
		}
	}

	return deletedHealthChecks
}

func (c *controller) updateBackendHealth(watchSet *statedb.WatchSet, deletedHealthChecks []*healthCheck) {
	wtxn := c.Writer.WriteTxn()
	healthChecks, watchHealthChecks := c.HealthChecks.LowerBoundWatch(wtxn, statedb.ByRevision[*healthCheck](c.lastHealthRevision))
	watchSet.Add(watchHealthChecks)
	for hc, rev := range healthChecks {
		if !hc.ProbedAt.IsZero() {
			_, err := c.Writer.UpdateBackendHealth(wtxn, hc.Service, hc.Backend, hc.Healthy)
			if err != nil && !errors.Is(err, lb.ErrServiceNotFound) {
				// Any other error here besides ErrServiceNotFound is a bug in the implementation.
				c.Log.Error("BUG: Updating backend health failed",
					logfields.Address, hc.Backend,
					logfields.ServiceName, hc.Service,
					logfields.Error, err)
			}
		}
		c.lastHealthRevision = rev
	}
	if len(deletedHealthChecks) > 0 {
		for _, hc := range deletedHealthChecks {
			c.Writer.UpdateBackendHealth(wtxn, hc.Service, hc.Backend, true)
		}
	}
	wtxn.Commit()
}

func (c *controller) isServiceHealthChecked(svc *loadbalancer.Service) bool {
	return IsHealthCheckEnabled(svc.Annotations)
}

func addrsEqual(a, b []lb.L3n4Addr) bool {
	return slices.EqualFunc(
		a, b,
		func(a, b lb.L3n4Addr) bool {
			return a == b
		})
}

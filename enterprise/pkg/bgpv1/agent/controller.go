// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agent

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/util/wait"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// Controller is the agent side BGP Control Plane controller.
//
// Controller listens for events and drives BGP related sub-systems
// to maintain a desired state.
type Controller struct {
	Logger *slog.Logger

	// CiliumNodeResource provides a stream of events for changes to the local CiliumNode resource.
	CiliumNodeResource daemon_k8s.LocalCiliumNodeResource
	// LocalCiliumNode is the CiliumNode object for the local node.
	LocalCiliumNode *v2.CiliumNode

	// BGP node store
	BGPNodeConfigStore store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfig]

	// Sig informs the Controller that a Kubernetes
	// event of interest has occurred.
	//
	// The signal itself provides no other information,
	// when it occurs the Controller will query each
	// informer for the latest API information required
	// to drive it's control loop.
	Sig *signaler.BGPCPSignaler

	// BGPMgr is an implementation of the EnterpriseBGPRouterManager interface
	// and provides a declarative API for configuring BGP peers.
	BGPMgr EnterpriseBGPRouterManager
}

// ControllerParams contains all parameters needed to construct a Controller
type ControllerParams struct {
	cell.In

	Logger                  *slog.Logger
	Lifecycle               cell.Lifecycle
	Health                  cell.Health
	JobGroup                job.Group
	Shutdowner              hive.Shutdowner
	Sig                     *signaler.BGPCPSignaler
	RouteMgr                EnterpriseBGPRouterManager
	BGPNodeConfigStore      store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfig]
	BGPConfig               config.Config
	LocalCiliumNodeResource daemon_k8s.LocalCiliumNodeResource
}

// NewController constructs a new Enterprise BGP Control Plane Controller.
//
// When the constructor returns the Controller will be actively watching for
// events and configuring BGP related sub-systems.
func NewController(params ControllerParams) (*Controller, error) {
	if !params.BGPConfig.Enabled {
		return nil, nil
	}

	c := &Controller{
		Logger:             params.Logger,
		Sig:                params.Sig,
		BGPMgr:             params.RouteMgr,
		BGPNodeConfigStore: params.BGPNodeConfigStore,
		CiliumNodeResource: params.LocalCiliumNodeResource,
	}

	params.JobGroup.Add(
		job.OneShot("enterprise-bgp-controller",
			func(ctx context.Context, health cell.Health) (err error) {
				// run the controller
				c.Run(ctx)
				return nil
			},
			job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}),
			job.WithShutdown()),
	)

	return c, nil
}

// Run places the Controller into its control loop.
//
// When new events trigger a signal the control loop will be evaluated.
//
// A cancel of the provided ctx will kill the control loop along with the running
// informers.
func (c *Controller) Run(ctx context.Context) {
	scopedLog := c.Logger.With(types.ComponentLogField, "Controller.Run")

	scopedLog.Info("Cilium BGP Control Plane Controller now running...")
	ciliumNodeCh := c.CiliumNodeResource.Events(ctx)
	for {
		select {
		case ev, ok := <-ciliumNodeCh:
			if !ok {
				scopedLog.Info("LocalCiliumNode resource channel closed, Cilium BGP Control Plane Controller shut down")
				return
			}
			switch ev.Kind {
			case resource.Upsert:
				// Set the local CiliumNode.
				c.LocalCiliumNode = ev.Object
				// Signal the reconciliation logic.
				c.Sig.Event(struct{}{})
			}
			ev.Done(nil)
		case <-ctx.Done():
			scopedLog.Info("Cilium BGP Control Plane Controller shut down")
			return
		case <-c.Sig.Sig:
			if c.LocalCiliumNode == nil {
				scopedLog.Debug("localCiliumNode has not been set yet")
			} else if err := c.reconcileWithRetry(ctx); err != nil {
				scopedLog.Error(
					"Reconciliation with retries failed",
					logfields.Error, err,
				)
			} else {
				scopedLog.Debug("Successfully completed reconciliation")
			}
		}
	}
}

// reconcileWithRetry runs Reconcile and retries if it fails until the iterations count defined in backoff is reached.
func (c *Controller) reconcileWithRetry(ctx context.Context) error {
	// reconciliation will repeat for ~15 seconds
	backoff := wait.Backoff{
		Duration: 500 * time.Millisecond,
		Factor:   2,
		Jitter:   0.5,
		Steps:    5,
	}

	var err error
	retryFn := func(ctx context.Context) (bool, error) {
		err = c.Reconcile(ctx)
		if err != nil {
			c.Logger.Debug("Reconciliation failed", logfields.Error, err)
			return false, nil
		}
		return true, nil
	}

	if retryErr := wait.ExponentialBackoffWithContext(ctx, backoff, retryFn); retryErr != nil {
		if wait.Interrupted(retryErr) && err != nil {
			return err // return the actual reconciliation error
		}
		return retryErr
	}
	return nil
}

// Reconcile is the main reconciliation loop for the Enterprise BGP Control Plane Controller.
func (c *Controller) Reconcile(ctx context.Context) error {
	bgpnc, bgpncExists, err := c.BGPNodeConfigStore.GetByKey(resource.Key{
		Name: c.LocalCiliumNode.Name,
	})
	if err != nil {
		if errors.Is(err, store.ErrStoreUninitialized) {
			c.Logger.Debug("BGPNodeConfig store not yet initialized")
			return nil // skip the reconciliation - once the store is initialized, it will trigger new reconcile event
		}
		c.Logger.Error("failed to get BGPNodeConfig", logfields.Error, err)
		return err
	}
	if bgpncExists {
		bgpnc = bgpnc.DeepCopy() // reconcilers can mutate the NodeConfig, make a copy to not mutate the version in store
	}

	return c.BGPMgr.ReconcileEnterpriseInstances(ctx, bgpnc, c.LocalCiliumNode)
}

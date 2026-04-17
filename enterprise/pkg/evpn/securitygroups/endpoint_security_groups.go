// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package securitygroups

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/client-go/util/workqueue"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn/securitygroups/tables"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var (
	errLocalEndpointNotFound = errors.New("local endpoint not found in endpoint manager")
)

type endpointSecurityGroups struct {
	log      *slog.Logger
	jobGroup job.Group
	cfg      evpnConfig.Config

	db        *statedb.DB
	localNode statedb.Table[*node.LocalNode]
	sgTable   statedb.Table[tables.SecurityGroup]
	esgTable  statedb.RWTable[tables.EndpointSecurityGroup]

	endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	epLookup          endpointLookupProvider
	epRestorerPromise promise.Promise[endpointstate.Restorer]
	epCache           map[resource.Key]endpointMapping
}

type endpointMapping struct {
	EndpointID      uint16
	Labels          labels.LabelArray
	SecurityGroupID uint16
}

func newEndpointSecurityGroups(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group
	Config   evpnConfig.Config

	DB        *statedb.DB
	LocalNode statedb.Table[*node.LocalNode]
	SGTable   statedb.Table[tables.SecurityGroup]
	ESGTable  statedb.RWTable[tables.EndpointSecurityGroup]

	EPRestorerPromise promise.Promise[endpointstate.Restorer]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	EPLookup          endpointLookupProvider
}) (*endpointSecurityGroups, error) {
	m := &endpointSecurityGroups{
		log:               in.Log,
		jobGroup:          in.JobGroup,
		cfg:               in.Config,
		db:                in.DB,
		localNode:         in.LocalNode,
		sgTable:           in.SGTable,
		esgTable:          in.ESGTable,
		epRestorerPromise: in.EPRestorerPromise,
		endpoints:         in.Endpoints,
		epLookup:          in.EPLookup,
		epCache:           make(map[resource.Key]endpointMapping),
	}
	if !in.Config.Enabled || !in.Config.SecurityGroupTagsEnabled {
		return m, nil
	}
	if in.Endpoints == nil {
		return nil, errors.New("EndpointSecurityGroup reconciliation requires local CiliumEndpoint resource support")
	}
	return m, nil
}

func (r *endpointSecurityGroups) registerReconciler() {
	if !r.cfg.Enabled || !r.cfg.SecurityGroupTagsEnabled {
		return
	}

	wtx := r.db.WriteTxn(r.esgTable)
	initDone := r.esgTable.RegisterInitializer(wtx, "endpoint-security-groups")
	wtx.Commit()

	r.jobGroup.Add(job.OneShot("endpoint-security-groups", func(ctx context.Context, health cell.Health) error {
		if err := r.waitForInitializers(ctx); err != nil {
			health.Degraded("Initialization failed", err)
			return err
		}
		return r.run(ctx, health, initDone)
	}))
}

func (r *endpointSecurityGroups) waitForInitializers(ctx context.Context) error {
	// Wait until all endpoints have been restored so that endpoint lookup works for them
	restorer, err := r.epRestorerPromise.Await(ctx)
	if err != nil {
		return err
	}
	err = restorer.WaitForEndpointRestoreWithoutRegeneration(ctx)
	if err != nil {
		return err
	}

	// Wait for LocalNode table init
	_, wait := r.localNode.Initialized(r.db.ReadTxn())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wait:
	}

	// Wait for SecurityGroup table init
	_, wait = r.sgTable.Initialized(r.db.ReadTxn())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wait:
	}
	return nil
}

func (r *endpointSecurityGroups) run(ctx context.Context, health cell.Health, initDoneCb func(statedb.WriteTxn)) error {
	eventsRateLimit := workqueue.NewTypedItemExponentialFailureRateLimiter[resource.WorkItem](20*time.Millisecond, 30*time.Minute)
	endpointEvents := r.endpoints.Events(ctx, resource.WithRateLimiter(eventsRateLimit))

	endpointsSynced := false
	initDone := false
	_, fsgWatch := r.sgTable.AllWatch(r.db.ReadTxn()) // no need for initial reconcile as there are no endpoints in the epCache

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-fsgWatch:
			if err := r.resyncAllEndpoints(); err != nil {
				r.log.Error("Endpoint security group resync error", logfields.Error, err)
				health.Degraded("Endpoint security group resync error", err)
			} else {
				health.OK("Reconciliation completed")
			}
			_, fsgWatch = r.sgTable.AllWatch(r.db.ReadTxn())
		case event, ok := <-endpointEvents:
			if !ok {
				return nil
			}
			var err error
			switch event.Kind {
			case resource.Sync:
				endpointsSynced = true
			case resource.Upsert:
				err = r.upsertEndpoint(ctx, event.Key, event.Object)
			case resource.Delete:
				err = r.deleteEndpoint(ctx, event.Key)
			}
			if err != nil {
				if errors.Is(err, errLocalEndpointNotFound) {
					r.log.Debug("Transient endpoint security group reconciliation error", logfields.Error, err)
				} else {
					r.log.Error("Endpoint security group reconciliation error", logfields.Error, err)
					health.Degraded("Endpoint security group reconciliation error", err)
				}
			} else {
				health.OK("Reconciliation completed")
			}
			event.Done(err)
		}

		if endpointsSynced && !initDone {
			wtxn := r.db.WriteTxn(r.esgTable)
			initDoneCb(wtxn)
			wtxn.Commit()
			initDone = true
			health.OK("Initialized")
		}
	}
}

func (r *endpointSecurityGroups) upsertEndpoint(ctx context.Context, key resource.Key, cep *k8sTypes.CiliumEndpoint) error {
	isLocal, err := r.isLocalEndpoint(cep)
	if err != nil {
		return err
	}
	if !isLocal {
		return r.deleteEndpoint(ctx, key) // skip non-local endpoints, delete in case it existed on a local node previously
	}

	epID, isPrivnet := r.epLookup.lookupEndpointMetadataByName(key.String())
	if epID == 0 {
		// If the endpoint is not yet present in the endpointmanager,
		// returning an error here will re-queue the endpoint event to retry later.
		return errLocalEndpointNotFound
	}
	if !isPrivnet {
		return r.deleteEndpoint(ctx, key) // skip non-privnet endpoints, they are not relevant for EVPN, so reduce churn in the table
	}

	ep := endpointMapping{
		EndpointID: epID,
	}
	if cep.Identity != nil {
		ep.Labels = labels.ParseLabelArrayFromArray(cep.Identity.Labels)
	}
	ep.SecurityGroupID = r.matchSecurityGroup(ep.Labels)

	// delete old mapping if endpoint ID changed for the same key
	if prev, ok := r.epCache[key]; ok && prev.EndpointID != ep.EndpointID {
		if err := r.deleteMapping(prev); err != nil {
			return err
		}
	}

	if err := r.upsertMapping(ep); err != nil {
		return err
	}

	r.epCache[key] = ep
	return nil
}

func (r *endpointSecurityGroups) isLocalEndpoint(ep *k8sTypes.CiliumEndpoint) (bool, error) {
	if ep == nil {
		return false, nil
	}
	ln, _, lnFound := r.localNode.Get(r.db.ReadTxn(), node.LocalNodeQuery)
	if !lnFound {
		return false, errors.New("local node not found")
	}
	if ep.Networking != nil && ep.Networking.NodeIP == node.GetCiliumEndpointNodeIP(*ln) {
		return true, nil
	}
	return false, nil
}

func (r *endpointSecurityGroups) deleteEndpoint(_ context.Context, key resource.Key) error {
	ep, found := r.epCache[key]
	if !found {
		return nil // non-local or non-relevant endpoint
	}

	err := r.deleteMapping(ep)
	if err != nil {
		return err
	}

	delete(r.epCache, key)
	return nil
}

// matchSecurityGroup matches the security group for an endpoint based on its labels using these rules:
//   - if no security group selects the endpoint's labels, the endpoint is associated with the default SG,
//   - if multiple security groups select the endpoint's labels, the endpoint is associated with the SG
//     with the highest group ID.
func (r *endpointSecurityGroups) matchSecurityGroup(labels labels.LabelArray) uint16 {
	if len(labels) == 0 {
		return r.cfg.DefaultSecurityGroupID
	}
	var (
		best  uint16
		found bool
	)
	rtxn := r.db.ReadTxn()
	for securityGroup := range r.sgTable.All(rtxn) {
		if securityGroup.EndpointSelector != nil && securityGroup.EndpointSelector.Matches(labels) && securityGroup.GroupID > best {
			best = securityGroup.GroupID
			found = true
		}
	}
	if found {
		return best
	}
	return r.cfg.DefaultSecurityGroupID
}

func (r *endpointSecurityGroups) upsertMapping(ep endpointMapping) error {
	wtx := r.db.WriteTxn(r.esgTable)

	if existing, _, exists := r.esgTable.Get(wtx, tables.EndpointSecurityGroupByEndpointID(ep.EndpointID)); exists {
		if existing.SecurityGroupID == ep.SecurityGroupID {
			// Existing entry already contains desired security group ID, do not Insert() to not trigger a new revision
			// and watcher event for no-op updates (note that Modify() with the same value would do that).
			wtx.Abort()
			return nil
		}
	}

	_, _, err := r.esgTable.Insert(wtx, tables.EndpointSecurityGroup{
		EndpointID:      ep.EndpointID,
		SecurityGroupID: ep.SecurityGroupID,
	})
	wtx.Commit()
	return err
}

func (r *endpointSecurityGroups) deleteMapping(ep endpointMapping) error {
	wtx := r.db.WriteTxn(r.esgTable)
	defer wtx.Commit()

	_, _, err := r.esgTable.Delete(wtx, tables.EndpointSecurityGroup{EndpointID: ep.EndpointID})
	return err
}

// resyncAllEndpoints resyncs all endpoints group membership upon security group changes.
// We do a full resync for simplicity, as due to "highest group ID wins" rule, any update in a security group
// with higher ID may cause an endpoint with lower assigned group ID, or default group ID to change their membership.
func (r *endpointSecurityGroups) resyncAllEndpoints() error {
	for key, ep := range r.epCache {
		newGroupID := r.matchSecurityGroup(ep.Labels)
		if newGroupID == ep.SecurityGroupID {
			continue
		}
		ep.SecurityGroupID = newGroupID
		if err := r.upsertMapping(ep); err != nil {
			return err
		}
		r.epCache[key] = ep
	}
	return nil
}

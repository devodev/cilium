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
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	eptypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointstate"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var LocalWorkloadsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite LocalWorkloads table.
		tables.NewLocalWorkloadsTable,

		// Provides the reconciler handling local private network workloads.
		newLocalWorkloads,
	),

	cell.Provide(
		// Provides the ReadOnly LocalWorkloads table.
		statedb.RWTable[*tables.LocalWorkload].ToTable,
	),

	cell.Invoke(
		// Starts reflecting local endpoints into the local workloads table
		(*LocalWorkloads).registerReconciler,
	),
)

// LocalWorkloads is a reconciler which populates the local workload tables based on local endpoint events
type LocalWorkloads struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	endpointManager           endpoints.EndpointGetter
	endpointActivationManager *EndpointActivationManager
	restorerPromise           promise.Promise[endpointstate.Restorer]

	db  *statedb.DB
	tbl statedb.RWTable[*tables.LocalWorkload]
}

func newLocalWorkloads(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	EndpointManager           endpoints.EndpointGetter
	EndpointActivationManager *EndpointActivationManager
	RestorerPromise           promise.Promise[endpointstate.Restorer]

	DB    *statedb.DB
	Table statedb.RWTable[*tables.LocalWorkload]
}) *LocalWorkloads {
	return &LocalWorkloads{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		endpointManager:           in.EndpointManager,
		endpointActivationManager: in.EndpointActivationManager,
		restorerPromise:           in.RestorerPromise,

		db:  in.DB,
		tbl: in.Table,
	}
}

func (l *LocalWorkloads) registerReconciler() {
	if !l.cfg.Enabled {
		return
	}

	wtx := l.db.WriteTxn(l.tbl)
	initialized := l.tbl.RegisterInitializer(wtx, "privnet-eps-restored")
	wtx.Commit()

	// Subscribe to endpoint creation/deletion/activation events
	l.endpointManager.Subscribe(l)
	l.endpointActivationManager.Subscribe(l)

	l.jg.Add(job.OneShot("privnet-ep-sync", func(ctx context.Context, health cell.Health) error {
		// Block until all endpoints have been restored (i.e. received by EndpointRestored callback),
		// as otherwise downstream consumers might publish a partial snapshot.
		health.OK("Waiting for restorer promise")
		restorer, err := l.restorerPromise.Await(ctx)
		if err != nil {
			health.Degraded("Failed to resolve restorer promise", err)
			return err
		}

		health.OK("Waiting for endpoint restoration to finish")
		err = restorer.WaitForEndpointRestoreWithoutRegeneration(ctx)
		if err != nil {
			health.Degraded("Failed to wait for endpoint restoration", err)
			return err
		}

		// Mark table as initialized
		health.OK("Initializing local workloads table")
		wtx := l.db.WriteTxn(l.tbl)
		initialized(wtx)
		wtx.Commit()

		return nil
	}))
}

// upsertEndpoint upserts the local endpoint into the local workload table if it has
// private network properties. Endpoints without private network properties or
// endpoints without a backing CEP are ignored.
func (l *LocalWorkloads) upsertEndpoint(ep endpoints.Endpoint) {
	k8sNamespace, k8sName, ok := strings.Cut(ep.GetK8sNamespaceAndCEPName(), "/")
	if !ok {
		l.log.Debug("Skipping local endpoint without K8s namespace/name",
			logfields.EndpointID, ep.GetID16())
		return
	}

	privNetAddr, err := extractPrivateNetworkAddressing(ep)
	if err != nil {
		l.log.Error("Failed to extract private network endpoint properties",
			logfields.EndpointID, ep.GetID16(),
			logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
			logfields.Error, err,
		)
		return
	} else if privNetAddr == nil {
		l.log.Debug("Skipping local endpoint without private network properties",
			logfields.EndpointID, ep.GetID16(),
			logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
		)
		return
	}

	wtx := l.db.WriteTxn(l.tbl)
	defer wtx.Commit()

	lw := &tables.LocalWorkload{
		EndpointID: ep.GetID16(),
		Namespace:  k8sNamespace,
		Subnet:     tables.SubnetName(privNetAddr.subnet),
		Endpoint: iso_v1alpha1.PrivateNetworkEndpointSliceEndpoint{
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: ep.GetIPv4Address(),
				IPv6: ep.GetIPv6Address(),
			},
			Name: k8sName,
		},
		Flags: iso_v1alpha1.PrivateNetworkEndpointSliceFlags{
			External: ep.IsProperty(eptypes.PropertyWithouteBPFDatapath),
		},
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: privNetAddr.ipv4,
				IPv6: privNetAddr.ipv6,
			},
			MAC:     privNetAddr.mac,
			Network: privNetAddr.network,
		},
		ActivatedAt: privNetAddr.activatedAt,
		UsesDHCPv4:  privNetAddr.usesDHCPv4,
		LXC: tables.LocalWorkloadLXC{
			IfName:  ep.HostInterface(),
			IfIndex: ep.GetIfIndex(),
		},
		NICIndex: privNetAddr.nicIndex,
	}
	_, _, err = l.tbl.Insert(wtx, lw)
	if err != nil {
		l.log.Error("BUG: Failed to insert local endpoint. "+
			"Please report this bug to Cilium developers.",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return
	}
}

// deleteEndpoint deletes the endpoint from the local workload table (if it exists)
func (l *LocalWorkloads) deleteEndpoint(ep endpoints.Endpoint) {
	wtx := l.db.WriteTxn(l.tbl)
	defer wtx.Commit()

	_, _, err := l.tbl.Delete(wtx, &tables.LocalWorkload{EndpointID: ep.GetID16()})
	if err != nil {
		l.log.Error("BUG: Failed to delete local endpoint. "+
			"Please report this bug to Cilium developers.",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return
	}
}

// EndpointActivationChanged implements endpointActivationSubscriber
func (l *LocalWorkloads) EndpointActivationChanged(ep endpoints.Endpoint) {
	l.upsertEndpoint(ep)
}

// EndpointCreated implements endpoints.EndpointSubscriber.
func (l *LocalWorkloads) EndpointCreated(ep endpoints.Endpoint) {
	l.upsertEndpoint(ep)
}

// EndpointRestored implements endpoints.EndpointSubscriber.
func (l *LocalWorkloads) EndpointRestored(ep endpoints.Endpoint) {
	l.upsertEndpoint(ep)
}

// EndpointDeleted implements endpoints.EndpointSubscriber.
func (l *LocalWorkloads) EndpointDeleted(ep endpoints.Endpoint) {
	l.deleteEndpoint(ep)
}

// privateNetworkAddressing contains the extracted private network endpoint properties
type privateNetworkAddressing struct {
	network string
	subnet  string

	ipv4       string
	ipv6       string
	mac        string
	usesDHCPv4 bool
	nicIndex   uint8

	activatedAt time.Time
}

// extractPrivateNetworkAddressing extracts private network properties from the endpoint.
// Returns nil if the endpoint is not attached to a private network or does not have
// any private network IP.
func extractPrivateNetworkAddressing(ep endpoints.Endpoint) (*privateNetworkAddressing, error) {
	properties, ok := endpoints.ExtractEndpointProperties(ep)
	if !ok {
		return nil, nil
	}

	activatedAt, err := properties.ActivatedAt()
	if err != nil {
		return nil, err
	}

	nicidx, err := properties.NICIndex()
	if err != nil {
		return nil, err
	}

	addr := &privateNetworkAddressing{
		network:     properties.PrivateNetwork(),
		subnet:      properties.PrivateSubnet(),
		mac:         ep.LXCMac().String(),
		activatedAt: activatedAt,
		usesDHCPv4:  properties.NetworkIPv4UsesDHCP(),
		nicIndex:    nicidx,
	}

	ipv4, err := properties.NetworkIPv4()
	if err != nil {
		return nil, err
	}

	if ipv4.IsValid() {
		addr.ipv4 = ipv4.String()
	}
	ipv6, err := properties.NetworkIPv6()
	if err != nil {
		return nil, err
	}
	if ipv6.IsValid() {
		addr.ipv6 = ipv6.String()
	}

	// ignore endpoints without any valid addresses configured
	if !(ipv4.IsValid() || ipv6.IsValid()) {
		return nil, nil
	}

	return addr, nil
}

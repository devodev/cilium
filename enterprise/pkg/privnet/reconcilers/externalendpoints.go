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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/maps/extepspolicy"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var ExternalEndpointsCell = cell.Group(
	cell.ProvidePrivate(
		tables.NewExternalEndpointsTable,

		newExternalEndpoints,
	),

	cell.Invoke(
		// Reflects PrivateNetworkExternalEndpoints into the StateDB table
		(*ExternalEndpoints).registerK8sReflector,
		// Writes the PrivateNetworkExternalEndpoints status
		(*ExternalEndpoints).registerK8sStatusReconciler,
		// Creates and manages local endpoints based on the StateDB table
		(*ExternalEndpoints).registerEndpointCreationReconciler,
		// Starts the logic to populate the external endpoint policy maps
		(*ExternalEndpoints).startEndpointPolicyMapUpdater,
	),

	cell.Provide(
		// Hooks into endpoint restoration for external endpoints
		(*ExternalEndpoints).registerExternalEndpointRestorer,
	),

	// Observe endpoint events only when running on INB
	endpoints.EnableEndpointEventObserver(func(cfg config.Config) bool {
		return cfg.EnabledAsBridge() && cfg.ExternalEndpoints
	}),
	// Enable the external endpoint policy map when running on INB
	extepspolicy.Enable(func(cfg config.Config) bool {
		return cfg.EnabledAsBridge() && cfg.ExternalEndpoints
	}),
)

// ExternalEndpoints reconciles various things related to PrivateNetworkExternalEndpoints.
// See the individual methods for details.
type ExternalEndpoints struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db  *statedb.DB
	tbl statedb.RWTable[*tables.ExternalEndpoint]
}

func newExternalEndpoints(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB    *statedb.DB
	Table statedb.RWTable[*tables.ExternalEndpoint]
}) *ExternalEndpoints {
	return &ExternalEndpoints{
		log: in.Log,
		jg:  in.JobGroup,
		cfg: in.Config,
		db:  in.DB,
		tbl: in.Table,
	}
}

type externalEndpointK8sReflector struct {
	db *statedb.DB

	endpoints  statedb.RWTable[*tables.ExternalEndpoint]
	namespaces statedb.Table[daemonK8s.Namespace]
}

// parsePrivateNetworkExternalEndpoint parses a K8s PrivateNetworkExternalEndpoint into tables.ExternalEndpoint
func (e *externalEndpointK8sReflector) parsePrivateNetworkExternalEndpoint(
	txn statedb.ReadTxn,
	pnee *iso_v1alpha1.PrivateNetworkExternalEndpoint,
) (*tables.ExternalEndpoint, error) {
	var activatedAt time.Time
	if !pnee.Spec.Inactive {
		if !pnee.Status.ActivatedAt.IsZero() {
			// Extract activatedAt timestamp from status if present
			activatedAt = pnee.Status.ActivatedAt.Time
		} else {
			// Otherwise assume this is a fresh PrivateNetworkExternalEndpoint
			activatedAt = time.Now()
		}
	}

	endpointStatus := reconciler.StatusPending()
	k8sStatus := reconciler.StatusPending()

	macAddr, err := mac.ParseMAC(pnee.Spec.Interface.MAC)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC address: %w", err)
	}

	var ipv4Addr netip.Addr
	if pnee.Spec.Interface.Addressing.IPv4 != "" {
		ipv4Addr, err = netip.ParseAddr(pnee.Spec.Interface.Addressing.IPv4)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPv4 address: %w", err)
		}
	}

	var ipv6Addr netip.Addr
	if pnee.Spec.Interface.Addressing.IPv6 != "" {
		ipv6Addr, err = netip.ParseAddr(pnee.Spec.Interface.Addressing.IPv6)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPv6 address: %w", err)
		}
	}

	if !ipv4Addr.IsValid() && !ipv6Addr.IsValid() {
		return nil, fmt.Errorf("neither IPv4 (%q) nor IPv6 addresses are valid (%q)",
			pnee.Spec.Interface.Addressing.IPv4,
			pnee.Spec.Interface.Addressing.IPv6)
	}

	var namespaceLabels map[string]string
	ns, _, hasNamespaceLabels := e.namespaces.Get(txn, daemonK8s.NamespaceByName(pnee.Namespace))
	if hasNamespaceLabels {
		namespaceLabels = ns.Labels
	} else {
		// We cannot create the endpoint without namespace labels.
		// The endpoint status will be set to pending once the namespace
		// has been discovered.
		endpointStatus = reconciler.StatusDone()
	}

	return &tables.ExternalEndpoint{
		NamespacedName: k8sTypes.NamespacedName{
			Name:      pnee.Name,
			Namespace: pnee.Namespace,
		},
		UID:                pnee.UID,
		ResourceVersion:    pnee.ResourceVersion,
		K8sLabels:          pnee.Labels,
		K8sNamespaceLabels: namespaceLabels,

		Network:     tables.NetworkName(pnee.Spec.Interface.Network),
		IPv4:        ipv4Addr,
		IPv6:        ipv6Addr,
		MAC:         macAddr,
		ActivatedAt: activatedAt,

		EndpointStatus: endpointStatus,
		K8sStatus:      k8sStatus,
	}, nil
}

// handleNamespaceChange updates the labels of every external endpoint in said namespace.
// [wtx] needs to be a write transaction on e.endpoints.
func (e *externalEndpointK8sReflector) handleNamespaceChange(wtx statedb.WriteTxn, ns daemonK8s.Namespace) {
	for ep := range e.endpoints.Prefix(wtx, tables.ExternalEndpointsByNamespace(ns.Name)) {
		if ep.K8sNamespaceLabels != nil && maps.Equal(ep.K8sNamespaceLabels, ns.Labels) {
			continue
		}

		// Update the external endpoint labels and trigger an endpoint reconciler update
		newEP := *ep
		newEP.K8sNamespaceLabels = ns.Labels
		newEP.EndpointStatus = reconciler.StatusPending()
		e.endpoints.Insert(wtx, &newEP)
	}
}

// registerK8sReflector registers the reflector which reads PrivateNetworkExternalEndpoints from K8s and writes them
// into the [tables.ExternalEndpoint] StateDB table.
func (e *ExternalEndpoints) registerK8sReflector(in struct {
	cell.In

	Client     client.Clientset
	CRDSync    promise.Promise[k8sSynced.CRDSync]
	Namespaces statedb.Table[daemonK8s.Namespace]
}) error {
	if !(e.cfg.EnabledAsBridge() && e.cfg.ExternalEndpoints) {
		return nil
	}

	if !in.Client.IsEnabled() {
		return errors.New("private networks requires Kubernetes support to be enabled")
	}

	r := externalEndpointK8sReflector{
		db:         e.db,
		endpoints:  e.tbl,
		namespaces: in.Namespaces,
	}

	// Start a job that watches for namespace updates to add namespace labels to the external endpoints
	wtx := e.db.WriteTxn(e.tbl)
	nsInitialized := e.tbl.RegisterInitializer(wtx, "namespaces-initialized")
	wtx.Commit()
	e.jg.Add(job.OneShot("external-endpoints-namespace-watch", func(ctx context.Context, health cell.Health) error {
		wtx := e.db.WriteTxn(in.Namespaces)
		changeIter, _ := in.Namespaces.Changes(wtx)
		wtx.Commit()

		initDone := false
		for {
			wtx = e.db.WriteTxn(e.tbl)
			changes, watch := changeIter.Next(wtx)
			for change := range changes {
				if change.Deleted {
					continue // endpoints will be deleted by reflector below
				}
				r.handleNamespaceChange(wtx, change.Object)
			}

			var initWatch <-chan struct{}
			if !initDone {
				init, nw := in.Namespaces.Initialized(wtx)
				switch {
				case !init:
					initWatch = nw
				default:
					initDone = true
					nsInitialized(wtx)
				}
			}

			wtx.Commit()
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			case <-initWatch:
			}
		}
	}))

	// Register a reflector that parses the K8s PrivateNetworkExternalEndpoints
	return k8s.RegisterReflector(e.jg, e.db, k8s.ReflectorConfig[*tables.ExternalEndpoint]{
		Name:  "to-table",
		Table: e.tbl,
		ListerWatcher: k8sUtils.ListerWatcherFromTyped(
			in.Client.IsovalentV1alpha1().PrivateNetworkExternalEndpoints(corev1.NamespaceAll),
		),
		CRDSync: in.CRDSync,
		Transform: func(txn statedb.ReadTxn, obj any) (*tables.ExternalEndpoint, bool) {
			pnee, ok := obj.(*iso_v1alpha1.PrivateNetworkExternalEndpoint)
			if !ok {
				return nil, false
			}

			extEp, err := r.parsePrivateNetworkExternalEndpoint(txn, pnee)
			if err != nil {
				e.log.Warn("failed to parse private network external endpoint",
					logfields.Name, pnee.Name,
					logfields.K8sNamespace, pnee.Namespace,
					logfields.Error, err,
				)
				return nil, false
			}

			return extEp, true
		},
		Merge: func(old *tables.ExternalEndpoint, new *tables.ExternalEndpoint) *tables.ExternalEndpoint {
			// Avoid re-triggering the reconcilers if no relevant fields have changed
			if new.ActivatedAt.Equal(old.ActivatedAt) {
				// ActivatedAt is already up to date, no need to reconcile the K8s status
				new.K8sStatus = old.K8sStatus
				if maps.Equal(new.K8sLabels, old.K8sLabels) &&
					maps.Equal(new.K8sNamespaceLabels, old.K8sNamespaceLabels) {
					// Labels and ActivatedAt have both not changed, no need to update the local endpoint
					new.EndpointStatus = old.EndpointStatus
				}
			}

			// Emit error if immutable fields changed (this should be rejected by K8s, but just in case)
			if old.UID == new.UID &&
				(old.Network != new.Network ||
					old.IPv4 != new.IPv4 ||
					old.IPv6 != new.IPv6 ||
					!bytes.Equal(old.MAC, new.MAC)) {
				e.log.Error("Ignoring change to immutable field(s) in PrivateNetworkExternalEndpoint",
					logfields.K8sNamespace, new.Namespace,
					logfields.Name, new.Name,
				)
			}

			return new
		},
	})
}

// externalEndpointK8sReconcilerOps implements reconciler.Operations to reconcile
// the status field of PrivateNetworkExternalEndpoint resources based on the
// [tables.ExternalEndpoint] table.
type externalEndpointK8sReconcilerOps struct {
	client client.Clientset
}

// Update implements reconciler.Operations.
// Please note that tables.ExternalEndpoint has multiple reconcilers status fields, so ensure that [obj] is not modified.
func (e *externalEndpointK8sReconcilerOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *tables.ExternalEndpoint) error {
	client := e.client.IsovalentV1alpha1().PrivateNetworkExternalEndpoints(obj.Namespace)
	ipStr := func(addr netip.Addr) string {
		if !addr.IsValid() {
			return ""
		}
		return addr.String()
	}
	pnee := &iso_v1alpha1.PrivateNetworkExternalEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:            obj.Name,
			Namespace:       obj.Namespace,
			ResourceVersion: obj.ResourceVersion,
			Labels:          obj.K8sLabels, // workaround for script test bug
			UID:             obj.UID,       // workaround for script test bug
		},
		// The object spec (and labels) are ignored by K8s when doing UpdateStatus.
		// However, our script test framework has a bug where it does not ignore
		// them and will replace them in the object tracker, so set them anyway.
		Spec: iso_v1alpha1.PrivateNetworkExternalEndpointSpec{
			Inactive: obj.ActivatedAt.IsZero(),
			Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
				Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
					IPv4: ipStr(obj.IPv4),
					IPv6: ipStr(obj.IPv6),
				},
				MAC:     obj.MAC.String(),
				Network: string(obj.Network),
			},
		},
		Status: iso_v1alpha1.PrivateNetworkExternalEndpointStatus{
			ActivatedAt: metav1.NewMicroTime(obj.ActivatedAt),
		},
	}
	_, err := client.UpdateStatus(ctx, pnee, metav1.UpdateOptions{})
	return err
}

// Delete implements reconciler.Delete.
func (e *externalEndpointK8sReconcilerOps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *tables.ExternalEndpoint) error {
	return nil // nothing to do
}

// Prune implements reconciler.Prune.
func (e *externalEndpointK8sReconcilerOps) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*tables.ExternalEndpoint, statedb.Revision]) error {
	return nil // pruning is disabled
}

// registerK8sStatusReconciler registers the reconciler which reconcile the status field of
// PrivateNetworkExternalEndpoint resources. This is needed to persist the ActivatedAt timestamp
// across node reboots, as we cannot rely on the filesystem to store this information like we do
// for regular endpoints.
func (e *ExternalEndpoints) registerK8sStatusReconciler(client client.Clientset, params reconciler.Params) error {
	if !(e.cfg.EnabledAsBridge() && e.cfg.ExternalEndpoints) {
		return nil
	}

	if !client.IsEnabled() {
		return errors.New("private networks requires Kubernetes support to be enabled")
	}

	ops := &externalEndpointK8sReconcilerOps{
		client: client,
	}
	_, err := reconciler.Register(
		// params
		params,
		// table
		e.tbl,
		// clone
		func(e *tables.ExternalEndpoint) *tables.ExternalEndpoint {
			// shallow copy is enough for reconciler
			cpy := *e
			return &cpy
		},
		// setStatus
		func(e *tables.ExternalEndpoint, s reconciler.Status) *tables.ExternalEndpoint {
			e.K8sStatus = s
			return e
		},
		// getStatus
		func(e *tables.ExternalEndpoint) reconciler.Status {
			return e.K8sStatus
		},
		// ops
		ops,
		// batchOps
		nil,
		// options
		reconciler.WithoutPruning(),
		reconciler.WithName("external-endpoints-k8s"),
	)
	return err
}

// externalEndpointReconcilerOps implements reconciler.Operations to reconcile
// the creation (or update) of local endpoints
type externalEndpointReconcilerOps struct {
	log *slog.Logger

	db  *statedb.DB
	tbl statedb.Table[*tables.ExternalEndpoint]

	ipam        endpoints.IPAM
	hostIP      net.IP
	clusterName string

	epCreate   endpoints.EndpointCreator
	epRemove   endpoints.EndpointRemover
	epLookup   endpoints.EndpointGetter
	epActivate *EndpointActivationManager
}

func (e *externalEndpointReconcilerOps) cepOwner(obj *tables.ExternalEndpoint) endpoints.CEPOwner {
	return endpoints.CEPOwner{
		APIVersion: iso_v1alpha1.SchemeGroupVersion.String(),
		Kind:       iso_v1alpha1.PrivateNetworkExternalEndpointKindDefinition,
		Namespace:  obj.Namespace,
		Name:       obj.Name,
		UID:        obj.UID,
		Labels:     obj.K8sLabels,
		HostIP:     e.hostIP.String(),
	}
}

// k8sSanitizedLabels returns the merged and sanitized labels of the K8s PrivateNetworkExternalEndpoint resource and
// the labels of the namespace it is in.
func (e *externalEndpointReconcilerOps) k8sSanitizedLabels(obj *tables.ExternalEndpoint) labels.Labels {
	return labels.Map2Labels(
		k8sUtils.SanitizePodLabels(obj.K8sLabels,
			&slim_metav1.ObjectMeta{
				Name:   obj.Namespace,
				Labels: obj.K8sNamespaceLabels,
			}, "", e.clusterName,
		),
		labels.LabelSourceK8s,
	)
}

// createEndpoint creates a local endpoint for a given external endpoint object. It is responsible for allocating
// the endpoints P-IP using the IPAM allocator and setting the correct properties to make this a private network
// external endpoint.
func (e *externalEndpointReconcilerOps) createEndpoint(ctx context.Context, obj *tables.ExternalEndpoint) (err error) {
	cepName := obj.NamespacedName.String()

	// Allocate endpoint IPs with the CEP name as the owner. If endpoint creation fails, we will try to release the IPs
	// in the defer statement below
	ipstr := func(result *ipam.AllocationResult) string {
		if result == nil || result.IP == nil {
			return ""
		}
		return result.IP.String()
	}
	pipv4, pipv6, err := e.ipam.AllocateNext("", cepName, ipam.PoolDefault())
	if err != nil {
		return fmt.Errorf("failed to allocate IPs for external endpoint %q: %w", cepName, err)
	}
	hasPIPv4 := pipv4 != nil && pipv4.IP != nil
	hasPIPv6 := pipv6 != nil && pipv6.IP != nil
	defer func() {
		if err != nil {
			if hasPIPv4 {
				releaseErr := e.ipam.ReleaseIP(pipv4.IP, ipam.PoolDefault())
				if releaseErr != nil {
					e.log.Warn("IPv4 cleanup failed. Leaking IPv4 for external endpoint",
						logfields.Error, releaseErr,
						logfields.CEPName, cepName,
						logfields.IPv4, pipv4.IP,
					)
				}
			}
			if hasPIPv6 {
				releaseErr := e.ipam.ReleaseIP(pipv6.IP, ipam.PoolDefault())
				if releaseErr != nil {
					e.log.Warn("IPv6 cleanup failed. Leaking IPv6 for external endpoint",
						logfields.Error, releaseErr,
						logfields.CEPName, cepName,
						logfields.IPv6, pipv6.IP,
					)
				}
			}
		}
	}()

	// Materialize and sanitize labels from K8s object and namespace
	lbls := e.k8sSanitizedLabels(obj)
	lbls[types.CNINetworkNameLabel] = labels.NewLabel(types.CNINetworkNameLabel, string(obj.Network), labels.LabelSourceCNI)

	// Assemble endpoint creation request.
	cepOwner := e.cepOwner(obj)
	epReq := &models.EndpointChangeRequest{
		K8sNamespace: obj.Namespace,
		Addressing: &models.AddressPair{
			IPv4: ipstr(pipv4),
			IPv6: ipstr(pipv6),
		},
		State: models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		Properties: map[string]any{
			// PropertyFakeEndpoint really should not be needed. However, upstream does not
			// respect PropertyWithouteBPFDatapath properly at the moment, so we need to set
			// on PropertyFakeEndpoint such that the loader does not try to look for an endpoint
			// interface.
			endpoint.PropertyFakeEndpoint: true,

			endpoint.PropertySkipBPFPolicy:       false,
			endpoint.PropertyWithouteBPFDatapath: true,
			endpoint.PropertyCEPOwner:            cepOwner,
			endpoint.PropertyCEPName:             cepOwner.Name,

			endpoints.PropertyPrivNetNetwork:     string(obj.Network),
			endpoints.PropertyPrivNetActivatedAt: endpoints.FormatActivatedAtProperty(obj.ActivatedAt),
		},
		Labels: lbls.GetModel(),
		Mac:    obj.MAC.String(),
	}
	if hasPIPv4 {
		if !obj.IPv4.Is4() {
			return fmt.Errorf("IPv4 is enabled, but no valid IPv4 address was provided: %s", obj.IPv4)
		}
		epReq.Properties[endpoints.PropertyPrivNetIPv4] = obj.IPv4.String()
	}
	if hasPIPv6 {
		if !obj.IPv6.Is6() {
			return fmt.Errorf("IPv6 is enabled, but no valid IPv6 address was provided: %s", obj.IPv6)
		}
		epReq.Properties[endpoints.PropertyPrivNetIPv6] = obj.IPv6.String()
	}

	// Create the endpoint
	ep, err := e.epCreate.CreateEndpoint(ctx, epReq)
	if err != nil {
		return fmt.Errorf("failed to create external endpoint %q: %w", cepName, err)
	}
	// Set K8s metadata, this is needed to ensure HaveK8sMetadata returns true.
	// Without it, the endpoint subsystem will not create a CiliumEndpoint resource in Kubernetes
	ep.SetK8sMetadata([]slim_core_v1.ContainerPort{})
	return nil
}

// updateEndpoint handles changes to the labels or activatedAt timestamp of the external endpoint. All other
// fields are assumed to be immutable.
func (e *externalEndpointReconcilerOps) updateEndpoint(ctx context.Context, ep endpoints.Endpoint, obj *tables.ExternalEndpoint) error {
	epID := endpoints.EndpointID(ep.GetID16())

	prop, ok := endpoints.ExtractEndpointProperties(ep)
	if !ok {
		// This should never happen, no point in letting the reconciler re-try
		e.log.Error("BUG: Existing endpoint is not an external endpoint",
			logfields.EndpointID, epID,
			logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
		)
		return nil
	}

	// Update activatedAt property if necessary
	oldActivatedAt, err := prop.ActivatedAt()
	if err != nil {
		return fmt.Errorf("failed to get old activatedAt timestamp for external endpoint %d: %w", epID, err)
	}
	if !oldActivatedAt.Equal(obj.ActivatedAt) {
		e.epActivate.SetActivatedAt(ep, obj.ActivatedAt)
	}

	// Materialize and sanitize labels from K8s object and namespace
	newK8sLabels := e.k8sSanitizedLabels(obj)
	// The labels filter removes any labels that are not considered identity relevant based on user
	// configuration.
	identityLabels, infoLabels := labelsfilter.Filter(newK8sLabels)
	// Update labels with the K8s label source. This will remove any `k8s:` labels from the endpoint if
	// they are not present in newK8sLabels, and leave any other labels (e.g. `cni:` labels) untouched.
	ep.UpdateLabels(ctx, labels.LabelSourceK8s, identityLabels, infoLabels, false)

	// Update the labels in CEP owner
	ep.SetPropertyValue(endpoint.PropertyCEPOwner, e.cepOwner(obj))

	return nil
}

// deleteEndpoint ensures that external endpoints are deleted together with their owner
func (e *externalEndpointReconcilerOps) deleteEndpoint(obj *tables.ExternalEndpoint) error {
	// We can directly delete the endpoint and do not have to do anything else,
	// at least in this reconciler.
	// The IPs allocated in createEndpoint will be released by the endpoint manager once
	// the endpoint is gone, because we created the endpoint with `ExternalIpam=false`.
	ep := e.epLookup.LookupCEPName(obj.NamespacedName.String())
	if ep == nil {
		return nil
	}
	return e.epRemove.RemoveEndpoint(ep)
}

// endpointUID returns the UID of the local endpoint (if there is one)
func endpointUID(ep endpoints.Endpoint) (k8sTypes.UID, bool) {
	cepOwner, ok := ep.GetPropertyValue(endpoint.PropertyCEPOwner).(endpoint.CEPOwnerInterface)
	if !ok || cepOwner == nil {
		return "", false
	}

	return cepOwner.GetUID(), true
}

// Update implements reconciler.Operations.
func (e *externalEndpointReconcilerOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *tables.ExternalEndpoint) error {
	cepName := obj.NamespacedName.String()

	// The CiliumEndpoint and PrivateNetworkExternalEndpoint have the same name.
	// Therefore, we can identify the endpoint that belongs to a PrivateNetworkExternalEndpoint
	// based on its name and UID.
	ep := e.epLookup.LookupCEPName(cepName)
	if ep == nil {
		// No endpoint exists, create a new one
		return e.createEndpoint(ctx, obj)
	}

	// Extract UID to determine if the owning PrivateNetworkExternalEndpoint has changed
	epUID, ok := endpointUID(ep)
	if !ok {
		// This should not happen, as any endpoint with a CEP name should also have a UID
		return fmt.Errorf("unable to determine UID of endpoint with CEP name %s", cepName)
	}

	// If the PrivateNetworkExternalEndpoint resource is deleted and re-created,
	// it can happen that the deletion and re-creation is coalesced into a single
	// update event, which changes fundamental properties of the endpoint like
	// its network. In such a case, we want to delete the old endpoint and create
	// a new one for the new PrivateNetworkExternalEndpoint.
	// We detect that the PrivateNetworkExternalEndpoint resource has been recreated
	// by comparing the UID.
	if obj.UID != epUID {
		e.log.Info("PrivateNetworkExternalEndpoint UID has changed. Re-creating endpoint",
			logfields.EndpointID, ep.GetID16(),
			logfields.CEPName, cepName,
		)

		err := e.deleteEndpoint(obj)
		if err != nil {
			return err
		}
		return e.createEndpoint(ctx, obj)
	}

	// Otherwise update the labels and activatedAt timestamp of the existing endpoint
	return e.updateEndpoint(ctx, ep, obj)
}

// Delete implements reconciler.Operations.
func (e *externalEndpointReconcilerOps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *tables.ExternalEndpoint) error {
	return e.deleteEndpoint(obj)
}

// Prune implements reconciler.Operations.
func (e *externalEndpointReconcilerOps) Prune(
	ctx context.Context,
	txn statedb.ReadTxn,
	objects iter.Seq2[*tables.ExternalEndpoint, statedb.Revision],
) (err error) {
	pneeAPIVersion := iso_v1alpha1.SchemeGroupVersion.String()
	pneeKind := iso_v1alpha1.PrivateNetworkExternalEndpointKindDefinition
	alivePNEEs := sets.New[k8sTypes.NamespacedName]()
	for obj := range objects {
		alivePNEEs.Insert(obj.NamespacedName)
	}

	// The following loop deletes all endpoints which are no longer backed by
	// a live PrivateNetworkExternalEndpoint.
	// We only check if the PrivateNetworkExternalEndpoint matches by name.
	// If a PrivateNetworkExternalEndpoint happened to be re-created during
	// an agent restart, we rely on Update() to delete the stale endpoint and
	// re-create it.
	for ep := range e.epLookup.GetEndpoints() {
		// Check if the endpoint is owned by a PrivateNetworkExternalEndpoint
		cepOwner, ok := ep.GetPropertyValue(endpoint.PropertyCEPOwner).(endpoint.CEPOwnerInterface)
		if !ok || cepOwner == nil ||
			cepOwner.GetAPIVersion() != pneeAPIVersion ||
			cepOwner.GetKind() != pneeKind {
			continue
		}

		// Check if the owning PrivateNetworkExternalEndpoint still exists
		pneeNamespacedName := k8sTypes.NamespacedName{
			Namespace: cepOwner.GetNamespace(),
			Name:      cepOwner.GetName(),
		}
		if alivePNEEs.Has(pneeNamespacedName) {
			continue
		}

		// If the PrivateNetworkExternalEndpoint no longer exists, then delete the stale endpoint
		e.log.Info("Deleting stale external endpoint",
			logfields.EndpointID, ep.GetID16(),
			logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
		)
		err = errors.Join(err, e.epRemove.RemoveEndpoint(ep))
	}

	return err
}

// registerEndpointCreationReconciler registers the reconciler that creates, updates and deletes
// endpoints based on the state of the [tables.ExternalEndpoint] StateDB table.
func (e *ExternalEndpoints) registerEndpointCreationReconciler(in struct {
	cell.In

	DaemonConfig *option.DaemonConfig

	ReconcilerParams reconciler.Params
	RestorerPromise  promise.Promise[endpointstate.Restorer]

	IPAM           endpoints.IPAM
	LocalNodeStore *node.LocalNodeStore
	ClusterInfo    cmtypes.ClusterInfo

	EPCreate endpoints.EndpointCreator
	EPRemove endpoints.EndpointRemover
	EPLookup endpoints.EndpointGetter

	EPActivate *EndpointActivationManager
}) {
	if !(e.cfg.EnabledAsBridge() && e.cfg.ExternalEndpoints) {
		return
	}

	e.jg.Add(job.OneShot("register-external-eps-reconciler", func(ctx context.Context, health cell.Health) error {
		// Obtain local node reference
		health.OK("Waiting for local node information")
		ln, err := in.LocalNodeStore.Get(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve local node store: %w", err)
		}

		// Extract hostIP - IPv4 if enabled, otherwise IPv6
		hostIP := ln.GetNodeIP(!in.DaemonConfig.IPv4Enabled())

		// Block until all endpoints have been restored before starting the reconciler.
		// This is needed to ensure we don't attempt to re-create a restored endpoint
		// during bootstrap. Endpoints do not have to be regenerated, they only have
		// to be part of the endpoint manager, which is guaranteed by
		// WaitForEndpointRestoreWithoutRegeneration.
		health.OK("Waiting endpoint restoration to finish")
		restorer, err := in.RestorerPromise.Await(ctx)
		if err != nil {
			return err
		}
		err = restorer.WaitForEndpointRestoreWithoutRegeneration(ctx)
		if err != nil {
			return err
		}

		ops := &externalEndpointReconcilerOps{
			log: e.log,
			db:  e.db,
			tbl: e.tbl,

			ipam:        in.IPAM,
			hostIP:      hostIP,
			clusterName: in.ClusterInfo.Name,

			epCreate:   in.EPCreate,
			epRemove:   in.EPRemove,
			epLookup:   in.EPLookup,
			epActivate: in.EPActivate,
		}

		_, err = reconciler.Register(
			// params
			in.ReconcilerParams,
			// table
			e.tbl,
			// clone
			func(e *tables.ExternalEndpoint) *tables.ExternalEndpoint {
				// shallow copy is enough for reconciler
				cpy := *e
				return &cpy
			},
			// setStatus
			func(e *tables.ExternalEndpoint, s reconciler.Status) *tables.ExternalEndpoint {
				e.EndpointStatus = s
				return e
			},
			// getStatus
			func(e *tables.ExternalEndpoint) reconciler.Status {
				return e.EndpointStatus
			},
			// ops
			ops,
			// batchOps
			nil,
			// options
			reconciler.WithName("external-endpoints"),
		)
		health.OK("Registered reconciler")
		return err
	}))
}

// isPrivateNetworkExternalEndpoint returns true if the given endpoint is a private network external endpoint
func isPrivateNetworkExternalEndpoint(ep endpoints.Endpoint) bool {
	return ep.GetPropertyValue(endpoints.PropertyPrivNetNetwork) != nil &&
		ep.IsProperty(endpoint.PropertyWithouteBPFDatapath)
}

// externalEndpointRestorer implements two workarounds for the fact that endpoint
// restoration is basically broken upstream for our use-case. There are two
// issues that are worked around here:
//   - The [endpoint.PropertyCEPOwner] value needs to be an object that implements
//     [endpoint.CEPOwnerInterface], but after restoration it is just a map[string]any.
//     To work around this, this function takes the restored CEP owner and turns it into
//     the [endpoints.CEPOwner] that it used to be at creation time.
//   - If an endpoint has [endpoint.PropertyFakeEndpoint] set, upstream doesn't restore
//     the IP via IPAM. So we do this here, to ensure all allocated IPs remain allocated
//     after an agent restart.
type externalEndpointRestorer struct {
	log  *slog.Logger
	ipam endpoints.IPAM
}

// fixupRestoredEndpointProperties fixes up the endpoint properties for endpoints parsed from disk
func (e *externalEndpointRestorer) fixupRestoredEndpointProperties(ep endpoints.Endpoint) {
	// Ignore endpoints which were not created by us
	owner := ep.GetPropertyValue(endpoint.PropertyCEPOwner)
	if owner == nil || !isPrivateNetworkExternalEndpoint(ep) {
		return
	}

	// Marshal the map[string]any as JSON again
	jsonBytes, err := json.Marshal(owner)
	if err != nil {
		e.log.Warn("Failed to re-encode CEP owner for restored external endpoint. "+
			"K8s CiliumEndpoint resource will be orphaned",
			logfields.EndpointID, ep.GetID16(),
			logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
			logfields.Error, err,
		)
	}

	// And unmarshal into a proper [endpoints.CEPOwner] struct
	typedOwner := endpoints.CEPOwner{}
	err = json.Unmarshal(jsonBytes, &typedOwner)
	if err != nil {
		e.log.Warn("Failed to decode CEP owner for restored external endpoint. "+
			"K8s CiliumEndpoint resource will be orphaned",
			logfields.EndpointID, ep.GetID16(),
			logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
			logfields.Error, err,
		)
	}

	// Set the correctly typed CEPOwner.
	ep.SetPropertyValue(endpoint.PropertyCEPOwner, typedOwner)

	// Also set K8s metadata again. For pods, RunRestoredMetadataResolver would do this, but we do not
	// have a pod, so RunRestoredMetadataResolver is skipped upstream.
	ep.SetK8sMetadata([]slim_core_v1.ContainerPort{})
}

// RestorationNotify implements endpoints.RestorationNotifier
// This is called when restored endpoint candidates have been deserialized from disk,
// very early in the agent lifecycle. We use it to fix up the endpoint properties, but
// we delay IP restoration to the EndpointRestored callback below, as IPAM is not
// available here.
func (e *externalEndpointRestorer) RestorationNotify(possible iter.Seq[endpoints.Endpoint]) {
	for ep := range possible {
		e.fixupRestoredEndpointProperties(ep)
	}
}

// EndpointRestored implements endpoints.EndpointSubscriber
// This is called when the restored endpoint has been added to the endpoint manager
// and might already be regenerating.
// At that point, the IPAM subsystem is available, but new endpoints are not being created yet,
// so this allows us to re-allocate the IPs of restored external endpoints.
func (e *externalEndpointRestorer) EndpointRestored(ep endpoints.Endpoint) {
	if !(isPrivateNetworkExternalEndpoint(ep) && ep.IsProperty(endpoint.PropertyFakeEndpoint)) {
		return // not a private endpoint with PropertyFakeEndpoint
	}

	// Upstream does not attempt to re-allocate P-IPs for fake endpoints. Let's rectify this here.
	for _, ip := range []netip.Addr{ep.IPv4Address(), ep.IPv6Address()} {
		if !ip.IsValid() {
			continue
		}

		_, err := e.ipam.AllocateIPWithoutSyncUpstream(ip.AsSlice(), ep.GetK8sNamespaceAndCEPName()+" [restored]", ipam.PoolDefault())
		if err != nil {
			e.log.Error("Failed to re-allocate external endpoint IP address",
				logfields.EndpointID, ep.GetID16(),
				logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
				logfields.IPAddr, ip,
				logfields.Error, err,
			)
		}
	}
}

// EndpointCreated implements endpoints.EndpointSubscriber
func (e *externalEndpointRestorer) EndpointCreated(ep endpoints.Endpoint) {
	// ignored
}

// EndpointDeleted implements endpoints.EndpointSubscriber
func (e *externalEndpointRestorer) EndpointDeleted(ep endpoints.Endpoint) {
	// ignored
}

// registerExternalEndpointRestorer hooks into endpoint restoration to implement restoration-related
// workarounds. See the description of the externalEndpointRestorer struct for more details.
func (e *ExternalEndpoints) registerExternalEndpointRestorer(
	epLookup endpoints.EndpointGetter,
	ipam endpoints.IPAM,
) endpoints.RestorationNotifierOut {
	if !(e.cfg.EnabledAsBridge() && e.cfg.ExternalEndpoints) {
		return endpoints.RestorationNotifierOut{}
	}

	r := &externalEndpointRestorer{
		log:  e.log,
		ipam: ipam,
	}

	// Register an endpoint subscriber to receive EndpointRestored callbacks.
	epLookup.Subscribe(r)
	// Register a restoration notifier to receive RestorationNotify callbacks.
	return endpoints.RestorationNotifierOut{Restorer: r}
}

// externalEndpointPolicyMapUpdater populates the external endpoints policy map.
type externalEndpointPolicyMapUpdater struct {
	log      *slog.Logger
	writer   extepspolicy.Writer
	epLookup endpoints.EndpointGetter

	endpointIPs map[endpoints.EndpointID][]netip.Addr
}

// upsertPolicyMap inserts the policy map of the given endpoint into the extepspolicy map.
// The endpoint needs to be a private network external endpoint. We store the IPs of the
// endpoints that we upserted to be able to remove them later. This is needed because
// there is no guarantee that we can access the endpoint object after we have observed
// an endpoint deletion event.
func (e *externalEndpointPolicyMapUpdater) upsertPolicyMap(epID endpoints.EndpointID) {
	ep := e.epLookup.LookupID(uint16(epID))
	if ep == nil {
		e.log.Info(
			"Received endpoint regeneration notification for unknown endpoint",
			logfields.EndpointID, epID,
		)
		return
	}

	if !isPrivateNetworkExternalEndpoint(ep) {
		return
	}

	policyMap, err := ep.GetPolicyMap()
	if err != nil {
		e.log.Warn(
			"Failed to retrieve policy map for endpoint",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return
	}

	realizedEndpointIPs := make([]netip.Addr, 0, 2)
	candidateEndpointIPs := make([]netip.Addr, 0, 2)
	if ipv4 := ep.IPv4Address(); ipv4.IsValid() {
		candidateEndpointIPs = append(candidateEndpointIPs, ipv4)
	}
	if ipv6 := ep.IPv6Address(); ipv6.IsValid() {
		candidateEndpointIPs = append(candidateEndpointIPs, ipv6)
	}

	for _, ip := range candidateEndpointIPs {
		// No need to re-try if Upsert fails, as any errors it returns are persistent.
		// Writer has an internal reconciler that will re-try any ephemeral errors.
		err = e.writer.Upsert(ip, policyMap)
		if err != nil {
			e.log.Warn(
				"Failed to upsert endpoint policy map",
				logfields.EndpointID, epID,
				logfields.IPAddr, ip,
				logfields.Error, err,
			)
			continue
		}
		realizedEndpointIPs = append(realizedEndpointIPs, ip)
	}
	e.endpointIPs[epID] = realizedEndpointIPs
}

// deletePolicyMap removes all known IPs for the given endpoint from the external endpoint policy map
func (e *externalEndpointPolicyMapUpdater) deletePolicyMap(epID endpoints.EndpointID) {
	for _, ip := range e.endpointIPs[epID] {
		err := e.writer.Delete(ip)
		if err != nil {
			e.log.Warn(
				"Failed to delete endpoint policy map",
				logfields.EndpointID, epID,
				logfields.IPAddr, ip,
				logfields.Error, err,
			)
		}
	}
	delete(e.endpointIPs, epID)
}

// markInitialized prunes the external endpoint policy map by marking it as initialized
func (e *externalEndpointPolicyMapUpdater) markInitialized() {
	e.writer.MarkInitialized()
}

// startEndpointPolicyMapUpdater starts the observer which updates the external endpoint policy map
// based on events from the endpoint subsystem.
func (e *ExternalEndpoints) startEndpointPolicyMapUpdater(in struct {
	cell.In

	PolicyMapWriter extepspolicy.Writer

	EPLookup endpoints.EndpointGetter
	EPEvents endpoints.EndpointEventObserver
}) {
	if !(e.cfg.EnabledAsBridge() && e.cfg.ExternalEndpoints) {
		return
	}

	epPolicyMapUpdater := &externalEndpointPolicyMapUpdater{
		log:         e.log,
		writer:      in.PolicyMapWriter,
		epLookup:    in.EPLookup,
		endpointIPs: make(map[endpoints.EndpointID][]netip.Addr),
	}
	e.jg.Add(job.Observer(
		"external-eps-policy-map-updater",
		func(ctx context.Context, events endpoints.EndpointEvents) error {
			for _, event := range events {
				switch event.EventKind {
				case endpoints.EndpointRegenSuccess:
					// We only upsert the policy map once the endpoint has finished regeneration.
					// This ensures that the policy map has already been created by the loader and
					// is fully populated. This is important because otherwise we could race with
					// the loader, which would also call `OpenOrCreate` on the endpoint policy map.
					epPolicyMapUpdater.upsertPolicyMap(event.Object)
				case endpoints.EndpointDelete:
					// We delete the policy map entry once the endpoint is deleted.
					epPolicyMapUpdater.deletePolicyMap(event.Object)
				case endpoints.EndpointInitRegenAllDone:
					// All endpoints have been restored and regenerated, mark the policy map as
					// initialized for pruning.
					epPolicyMapUpdater.markInitialized()
				}
			}
			return nil
		},
		in.EPEvents))
}

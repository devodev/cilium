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
	"errors"
	"iter"
	"log/slog"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	cs_iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/promise"
)

var LocalEndpointSlicesCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite EndpointSlices table.
		tables.NewEndpointSlicesTable,

		// Provides the reconciler publishing endpoint slices
		newEndpointSlices,
	),

	cell.Provide(
		// Provides the ReadOnly EndpointSlices table.
		statedb.RWTable[tables.EndpointSlice].ToTable,
	),

	cell.Invoke(
		// Reflects local endpoint slices into the local endpoint slices table
		(*LocalEndpointSlices).registerK8sReflector,
		// Watches local workloads and marks the corresponding local endpoint slices as pending
		(*LocalEndpointSlices).registerLocalWorkloadsWatcher,
		// Starts the reconciler which publishes endpoint slices based on pending entries in the local endpoint slice table
		(*LocalEndpointSlices).registerReconciler,
	),
)

// LocalEndpointSlices reconciles the local workloads table with published PrivateNetworkEndpointSlices in K8s
type LocalEndpointSlices struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db             *statedb.DB
	localWorkloads statedb.Table[*tables.LocalWorkload]
	tbl            statedb.RWTable[tables.EndpointSlice]

	client           cs_iso_v1alpha1.PrivateNetworkEndpointSlicesGetter
	reconcilerParams reconciler.Params

	localNodeResource daemonK8s.LocalCiliumNodeResource
}

func newEndpointSlices(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB                *statedb.DB
	Table             statedb.RWTable[tables.EndpointSlice]
	LocalWorkloads    statedb.Table[*tables.LocalWorkload]
	LocalNodeResource daemonK8s.LocalCiliumNodeResource

	Client           client.Clientset
	ReconcilerParams reconciler.Params
}) (*LocalEndpointSlices, error) {
	reconciler := &LocalEndpointSlices{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:                in.DB,
		localWorkloads:    in.LocalWorkloads,
		localNodeResource: in.LocalNodeResource,

		tbl: in.Table,

		reconcilerParams: in.ReconcilerParams,
	}

	if !in.Config.Enabled {
		return reconciler, nil
	}

	if !in.Client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	reconciler.client = in.Client.IsovalentV1alpha1()

	return reconciler, nil
}

func (e *LocalEndpointSlices) registerK8sReflector(sync promise.Promise[synced.CRDSync], listerWatcher endpointSliceSharedListerWatcher) error {
	if !e.cfg.Enabled {
		return nil
	}

	cfg := k8s.ReflectorConfig[tables.EndpointSlice]{
		Name:                "to-table", // the full name will be "job-k8s-reflector-privnet-local-endpointslices-to-table"
		Table:               e.tbl,
		SharedListerWatcher: listerWatcher,
		MetricScope:         "PrivateNetworkEndpointSlices",
		CRDSync:             sync,

		Transform: func(txn statedb.ReadTxn, obj any) (es tables.EndpointSlice, ok bool) {
			slice, ok := obj.(*iso_v1alpha1.PrivateNetworkEndpointSlice)
			if !ok {
				return tables.EndpointSlice{}, false
			}
			if slice.Name != nodeTypes.GetName() {
				return tables.EndpointSlice{}, false
			}
			return tables.EndpointSlice{
				Namespace: slice.Namespace,
				Slice:     slice,
				Status:    reconciler.StatusPending(),
			}, true
		},
	}

	return k8s.RegisterReflector(e.jg, e.db, cfg)
}

func (e *LocalEndpointSlices) registerLocalWorkloadsWatcher() {
	if !e.cfg.Enabled {
		return
	}

	// This job watches the upstream local workloads table and marks endpoint slices as pending if they need to be updated
	e.jg.Add(job.OneShot("watch-local-workloads", func(ctx context.Context, _ cell.Health) error {
		txn := e.db.WriteTxn(e.localWorkloads)
		changeIter, _ := e.localWorkloads.Changes(txn)
		txn.Commit()

		for {
			txn := e.db.WriteTxn(e.tbl)
			changes, watch := changeIter.Next(txn)

			for change := range changes {
				e.log.Debug("Processing table event",
					logfields.Table, e.localWorkloads.Name(),
					logfields.Event, change,
				)

				// At this stage, we have received a local workload change event. We want this
				// change event to be reflected in the local endpoint slice. Thus, tell the
				// endpoint slices reconciler to update the endpoint slice of the local workload's namespace.
				namespace := change.Object.Namespace

				// if the endpoint slice for this namespace does not yet exist, tell reconciler to create a new one
				es := tables.EndpointSlice{
					Namespace: namespace,
					Status:    reconciler.StatusPending(),
				}
				_, _, err := e.tbl.Modify(txn, es,
					func(old, new tables.EndpointSlice) tables.EndpointSlice {
						// mark the existing endpoint slice as pending,
						// which will cause the reconciler to update it
						old.Status = reconciler.StatusPending()
						return old
					},
				)
				if err != nil {
					txn.Abort()
					return err
				}
			}

			txn.Commit()

			// Wait until there's new changes to consume
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
		}
	}))
}

// endpointSlicesReconcilerOps implements reconciler.Operations[tables.EndpointSlices]
type endpointSlicesReconcilerOps struct {
	log *slog.Logger

	db             *statedb.DB
	tbl            statedb.Table[tables.EndpointSlice]
	localWorkloads statedb.Table[*tables.LocalWorkload]

	client       cs_iso_v1alpha1.PrivateNetworkEndpointSlicesGetter
	localNodeRef *localCiliumNodeRef
}

func (e *LocalEndpointSlices) registerReconciler() error {
	if !e.cfg.Enabled {
		return nil
	}

	// Observes the local CiliumNode. This is needed as we use it for the name
	// and owner reference of the published PrivateNetworkEndpointSlices.
	localNodeRef := newLocalCiliumNodeRef()
	e.jg.Add(job.Observer("observe-local-ciliumnode",
		func(ctx context.Context, ev resource.Event[*cilium_v2.CiliumNode]) error {
			switch ev.Kind {
			case resource.Upsert:
				localNodeRef.Set(metav1.OwnerReference{
					APIVersion: cilium_v2.SchemeGroupVersion.String(),
					Kind:       cilium_v2.CNKindDefinition,
					Name:       ev.Object.Name,
					UID:        ev.Object.UID,
				})
			case resource.Delete:
				localNodeRef.Set(metav1.OwnerReference{})
			}
			ev.Done(nil)
			return nil
		}, e.localNodeResource),
	)

	// Construct new reconciler
	ops := &endpointSlicesReconcilerOps{
		log:            e.log,
		db:             e.db,
		localWorkloads: e.localWorkloads,
		tbl:            e.tbl,
		client:         e.client,
		localNodeRef:   localNodeRef,
	}
	_, err := reconciler.Register(
		// params
		e.reconcilerParams,
		// table
		e.tbl,
		// clone
		func(e tables.EndpointSlice) tables.EndpointSlice {
			// shallow copy is enough for reconciler
			return e
		},
		// setStatus
		func(e tables.EndpointSlice, s reconciler.Status) tables.EndpointSlice {
			e.Status = s
			return e
		},
		// getStatus
		func(e tables.EndpointSlice) reconciler.Status {
			return e.Status
		},
		// ops
		ops,
		// batchOps
		nil,
		// options
		reconciler.WithName("local-endpoint-slices"),
	)
	return err
}

func (r *endpointSlicesReconcilerOps) updateEndpointSlice(ctx context.Context, namespace string) error {
	// This blocks until the owner reference is available
	ownerRef, err := r.localNodeRef.Get(ctx)
	if err != nil {
		return err
	}
	nodeName, resourceName := ownerRef.Name, ownerRef.Name

	// Create a new read transaction to read the latest snapshot.
	// This is intentional, in case the reconciler lags behind
	// e.g. due to the above waiting taking a long time.
	txn := r.db.ReadTxn()

	// Materialize list of endpoints in the requested namespace.
	eps := []iso_v1alpha1.PrivateNetworkEndpointSliceEntry{}
	for lw := range r.localWorkloads.List(txn, tables.LocalWorkloadsByNamespace(namespace)) {
		if !lw.HasUsableIP() {
			// The workload has no usable network IPv4 or IPv6. Skip publishing it altogether.
			continue
		}
		eps = append(eps, iso_v1alpha1.PrivateNetworkEndpointSliceEntry{
			Endpoint:    lw.Endpoint,
			Interface:   lw.Interface,
			Flags:       lw.Flags,
			ActivatedAt: metav1.NewMicroTime(lw.GetActivatedAt()),
		})
	}

	// Get latest snapshot of the K8s endpoint slice
	es, _, exists := r.tbl.Get(txn, tables.EndpointSlicesByNamespace(namespace))

	// If there are no longer any endpoints in this namespace, delete the slice and return
	if len(eps) == 0 {
		// Skip deletion if the slice doesn't exist in the latest snapshot.
		// This usually happens if we got triggered because we just deleted
		// the slice ourselves a few moments ago because the last endpoint went away.
		// In such a case there is no point in trying to delete it again.
		if !exists {
			return nil
		}

		err = r.client.PrivateNetworkEndpointSlices(namespace).Delete(ctx, resourceName, metav1.DeleteOptions{})
		if err == nil || k8sErrors.IsNotFound(err) {
			return nil
		} else {
			return err
		}
	}

	// If we have endpoints and the slice does not yet exist, we need to create a new one.
	if !exists || es.Slice == nil {
		// On failure, we rely on the reconciler to re-try.
		_, err = r.client.PrivateNetworkEndpointSlices(namespace).
			Create(ctx, &iso_v1alpha1.PrivateNetworkEndpointSlice{
				// TypeMeta currently needs to be set explicitly to work around a script test bug (cilium/cilium#41724)
				TypeMeta: metav1.TypeMeta{
					APIVersion: iso_v1alpha1.SchemeGroupVersion.String(),
					Kind:       iso_v1alpha1.PrivateNetworkEndpointSliceKindDefinition,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: resourceName,
					OwnerReferences: []metav1.OwnerReference{
						ownerRef,
					},
				},
				Endpoints: eps,
				NodeName:  nodeName,
			}, metav1.CreateOptions{})
		return err
	}

	// If the slice exists, and we just need to update it, check first if changes are even needed
	if slices.Equal(eps, es.Slice.Endpoints) && nodeName == es.Slice.NodeName {
		r.log.Debug("Skipping update of PrivateNetworkEndpointSlice", logfields.Name, es.Slice.Name)
		return nil
	}

	// Update the existing object. On failure, we rely on the reconciler to re-try.
	slice := es.Slice.DeepCopy()
	slice.Endpoints = eps
	slice.NodeName = nodeName
	_, err = r.client.PrivateNetworkEndpointSlices(namespace).Update(ctx, slice, metav1.UpdateOptions{})
	return err
}

// Update is called either when a local workload change marked this endpoint slice as requiring an update,
// or if the endpoint slice itself was modified in K8s (which could be in because we just updated it).
// In either case, updateEndpointSlice will reconcile the K8s object with our local state, or do nothing if
// the K8s state already matches our local state.
func (r *endpointSlicesReconcilerOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, es tables.EndpointSlice) error {
	return r.updateEndpointSlice(ctx, es.Namespace)
}

// Delete is called when the K8s endpoint slice was deleted. Usually, it was just deleted by us due to a
// workload update, in which case updateEndpointSlice will do nothing. However, it could also have been
// deleted by some external actor, in which case updateEndpointSlice will re-create it.
func (r *endpointSlicesReconcilerOps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, es tables.EndpointSlice) error {
	return r.updateEndpointSlice(ctx, es.Namespace)
}

func (r *endpointSlicesReconcilerOps) Prune(ctx context.Context, txn statedb.ReadTxn, endpointSlices iter.Seq2[tables.EndpointSlice, statedb.Revision]) error {
	// Collect list of namespaces which currently do contain endpoint slices,
	// and merge it with the list of namespaces with should contain endpoint slices.
	allNamespaces := make(sets.Set[string])
	for es := range endpointSlices {
		allNamespaces.Insert(es.Namespace)
	}
	for lw := range r.localWorkloads.All(txn) {
		allNamespaces.Insert(lw.Namespace)
	}

	// Invoke update on all namespaces. If the namespace no longer has any
	// local workloads, updateEndpointSlice will remove the slice.
	// Otherwise, the endpoint slice is updated to reflect the local state.
	var err error
	for namespace := range allNamespaces {
		err = errors.Join(err, r.updateEndpointSlice(ctx, namespace))
	}
	return err
}

// localCiliumNodeRef stores an OwnerReference for the local CiliumNode CR
type localCiliumNodeRef struct {
	mu       *lock.Mutex
	cond     *sync.Cond
	ownerRef metav1.OwnerReference
}

func newLocalCiliumNodeRef() *localCiliumNodeRef {
	mu := new(lock.Mutex)
	cond := sync.NewCond(mu)
	return &localCiliumNodeRef{
		mu:       mu,
		cond:     cond,
		ownerRef: metav1.OwnerReference{},
	}
}

// Set updates the owner reference
func (l *localCiliumNodeRef) Set(ownerRef metav1.OwnerReference) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ownerRef = ownerRef
	l.cond.Broadcast()
}

// Get returns the current owner reference. Blocks if no owner reference has been set.
func (l *localCiliumNodeRef) Get(ctx context.Context) (ownerRef metav1.OwnerReference, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Fast path
	var empty metav1.OwnerReference
	if l.ownerRef != empty {
		return l.ownerRef, nil
	}

	// Wake up the for-loop below if the context is cancelled.
	// See https://pkg.go.dev/context#AfterFunc for a more detailed
	// explanation of this pattern
	cleanupCancellation := context.AfterFunc(ctx, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.cond.Broadcast()
	})
	defer cleanupCancellation()

	// Wait for owner ref to be non-empty or the context to be cancelled
	for l.ownerRef == empty && ctx.Err() == nil {
		l.cond.Wait()
	}
	return l.ownerRef, ctx.Err()
}

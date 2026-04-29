//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"context"
	"log/slog"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

type endpointRegistry interface {
	Subscribe(endpointmanager.Subscriber)
	Unsubscribe(endpointmanager.Subscriber)
	GetEndpoints() []*endpoint.Endpoint
	LookupCiliumID(id uint16) *endpoint.Endpoint
}

type inspectionReconciler struct {
	logger                *slog.Logger
	configResource        resource.Resource[*isovalent_api_v1alpha1.IsovalentInspectionConfig]
	endpointManager       endpointRegistry
	selectorStore         *inspectionConfig.SelectorStore
	mu                    lock.RWMutex
	synced                chan struct{}
	syncedOnce            sync.Once
	pendingEndpointIDs    map[uint16]struct{}
	fullReconcilePending  bool
	reconcileRequestsChan chan struct{}
}

type reconcilerIn struct {
	cell.In

	Logger           *slog.Logger
	Lifecycle        cell.Lifecycle
	JobGroup         job.Group
	InspectionConfig inspectionConfig.Config
	SelectorStore    *inspectionConfig.SelectorStore
	ConfigResource   resource.Resource[*isovalent_api_v1alpha1.IsovalentInspectionConfig]
	EndpointManager  endpointmanager.EndpointManager
}

var _ endpointmanager.Subscriber = (*inspectionReconciler)(nil)

func registerReconciler(in reconcilerIn) {
	if !in.InspectionConfig.Enabled {
		return
	}

	selectorStore := in.SelectorStore
	if selectorStore == nil {
		selectorStore = inspectionConfig.NewSelectorStore()
	}

	r := &inspectionReconciler{
		logger:                in.Logger,
		configResource:        in.ConfigResource,
		endpointManager:       in.EndpointManager,
		selectorStore:         selectorStore,
		synced:                make(chan struct{}),
		pendingEndpointIDs:    map[uint16]struct{}{},
		reconcileRequestsChan: make(chan struct{}, 1),
	}
	if in.ConfigResource == nil {
		// No CRD watcher: wildcard semantics — all endpoints selected.
		r.setSelector(nil)
		r.markSynced()
		r.enqueueFullReconcile()
	}

	in.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			in.EndpointManager.Subscribe(r)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			in.EndpointManager.Unsubscribe(r)
			return nil
		},
	})

	in.JobGroup.Add(job.OneShot("inspection-endpoint-reconciler", func(ctx context.Context, _ cell.Health) error {
		var configEvents <-chan resource.Event[*isovalent_api_v1alpha1.IsovalentInspectionConfig]
		if r.configResource != nil {
			configEvents = r.configResource.Events(ctx)
		}
		for {
			select {
			case event, ok := <-configEvents:
				if !ok {
					configEvents = nil
					continue
				}
				r.handleConfigEvent(event)
				event.Done(nil)
			case <-r.reconcileRequestsChan:
				if !r.isSynced() {
					continue
				}
				r.processPendingReconciles()
			case <-ctx.Done():
				return nil
			}
		}
	}, job.WithShutdown()))
}

func (r *inspectionReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	r.enqueueEndpointID(ep.GetID16())
}

func (r *inspectionReconciler) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pendingEndpointIDs, ep.GetID16())
}

func (r *inspectionReconciler) EndpointRestored(ep *endpoint.Endpoint) {
	r.enqueueEndpointID(ep.GetID16())
}

func (r *inspectionReconciler) enqueueEndpointID(id uint16) {
	r.mu.Lock()
	r.pendingEndpointIDs[id] = struct{}{}
	r.mu.Unlock()
	r.notifyReconcile()
}

func (r *inspectionReconciler) enqueueFullReconcile() {
	r.mu.Lock()
	r.fullReconcilePending = true
	clear(r.pendingEndpointIDs)
	r.mu.Unlock()
	r.notifyReconcile()
}

func (r *inspectionReconciler) notifyReconcile() {
	select {
	case r.reconcileRequestsChan <- struct{}{}:
	default:
	}
}

func (r *inspectionReconciler) snapshotPending() (bool, []uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullReconcilePending := r.fullReconcilePending
	r.fullReconcilePending = false

	pendingIDs := make([]uint16, 0, len(r.pendingEndpointIDs))
	for id := range r.pendingEndpointIDs {
		pendingIDs = append(pendingIDs, id)
	}
	slices.Sort(pendingIDs)
	clear(r.pendingEndpointIDs)

	return fullReconcilePending, pendingIDs
}

func (r *inspectionReconciler) processPendingReconciles() {
	fullReconcilePending, pendingIDs := r.snapshotPending()

	if fullReconcilePending {
		r.reconcileAllEndpoints()
		return
	}

	for _, endpointID := range pendingIDs {
		ep := r.endpointManager.LookupCiliumID(endpointID)
		if ep == nil {
			continue
		}
		r.reconcileEndpoint(ep)
	}
}

func (r *inspectionReconciler) reconcileEndpoint(ep *endpoint.Endpoint) {
	r.reconcileEndpointState(ep, func() {
		ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
			Reason:            regeneration.ReasonAnnotationsUpdate,
			Message:           "inspection config updated",
			RegenerationLevel: regeneration.RegenerateWithDatapath,
		})
	})
}

func (r *inspectionReconciler) reconcileAllEndpoints() {
	for _, ep := range r.endpointManager.GetEndpoints() {
		r.reconcileEndpoint(ep)
	}
}

type endpointState interface {
	K8sNamespaceAndPodNameIsSet() bool
	GetSecurityIdentity() (*identity.Identity, error)
	GetPropertyValue(key string) any
	SetPropertyValue(key string, value any) any
}

func (r *inspectionReconciler) reconcileEndpointState(ep endpointState, regenerate func()) {
	enabled, ok := r.desiredEnabledForEndpoint(ep)
	if !ok {
		return
	}
	old, ok := ep.GetPropertyValue(inspectionConfig.PropertyEndpointEnabled).(bool)
	if ok && old == enabled {
		return
	}

	ep.SetPropertyValue(inspectionConfig.PropertyEndpointEnabled, enabled)
	regenerate()
}

func (r *inspectionReconciler) desiredEnabledForEndpoint(ep endpointState) (bool, bool) {
	return r.selectorStore.DesiredEnabledForEndpoint(ep)
}

func (r *inspectionReconciler) setSelector(selector *policyTypes.LabelSelector) {
	r.selectorStore.SetSelector(selector)
}

func (r *inspectionReconciler) sanitizeEndpointSelector(es *api.EndpointSelector) (*policyTypes.LabelSelector, bool) {
	if es == nil || es.LabelSelector == nil || es.IsWildcard() {
		return nil, true
	}

	// Sanitize() applies the "any" source prefix so the selector matches
	// regardless of label source, mirroring CNP semantics. It mutates the
	// receiver, so operate on a copy to avoid touching the cached resource
	// object.
	sanitized := *es
	if err := sanitized.Sanitize(); err != nil {
		r.logger.Warn("Invalid inspection endpointSelector; preserving previous selector",
			logfields.Error, err)
		return nil, false
	}
	return policyTypes.NewLabelSelector(sanitized), true
}

func (r *inspectionReconciler) handleConfigEvent(event resource.Event[*isovalent_api_v1alpha1.IsovalentInspectionConfig]) {
	switch event.Kind {
	case resource.Upsert:
		r.upsertConfig(event.Object)
	case resource.Delete:
		r.deleteConfig(event.Key.Name)
	case resource.Sync:
		if !r.selectorStore.HasSelector() {
			r.setSelector(nil)
		}
		r.markSynced()
		r.enqueueFullReconcile()
	}
}

func (r *inspectionReconciler) upsertConfig(cfg *isovalent_api_v1alpha1.IsovalentInspectionConfig) {
	if cfg.Name != isovalent_api_v1alpha1.InspectionConfigName {
		return
	}

	selector, ok := r.sanitizeEndpointSelector(cfg.Spec.EndpointSelector)
	if !ok {
		if !r.selectorStore.HasSelector() {
			r.selectorStore.SetSelectNone()
			r.enqueueFullReconcile()
		}
		return
	}
	r.setSelector(selector)
	r.enqueueFullReconcile()
}

func (r *inspectionReconciler) deleteConfig(name string) {
	if name != isovalent_api_v1alpha1.InspectionConfigName {
		return
	}

	r.setSelector(nil)
	r.enqueueFullReconcile()
}

func (r *inspectionReconciler) markSynced() {
	r.syncedOnce.Do(func() {
		close(r.synced)
	})
}

func (r *inspectionReconciler) isSynced() bool {
	select {
	case <-r.synced:
		return true
	default:
		return false
	}
}

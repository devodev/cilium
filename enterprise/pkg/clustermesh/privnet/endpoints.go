//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package privnet

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	pnkvs "github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	pnobs "github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

var EndpointsCell = cell.Group(
	cell.ProvidePrivate(
		newEndpointsFactory,
	),

	cell.Provide(
		(*EndpointsFactory).ToFactoryOut,
	),

	cell.Invoke(
		(*EndpointsFactory).PropagateSynchronization,
	),
)

// EndpointsFactory is the factory handling the creation of private network endpoints observers.
type EndpointsFactory struct {
	cfg config.Config
	obs *pnobs.PrivateNetworkEndpoints
}

func newEndpointsFactory(cfg config.Config, obs *pnobs.PrivateNetworkEndpoints) *EndpointsFactory {
	return &EndpointsFactory{cfg: cfg, obs: obs}
}

func (ef *EndpointsFactory) ToFactoryOut(sf store.Factory) observer.FactoryOut {
	return observer.NewFactoryOut(
		func(cluster string, onSync func()) observer.Observer {
			return ef.NewObserver(cluster, sf, onSync)
		},
	)
}

// NewObserver constructs a new observer for the target cluster.
func (ef *EndpointsFactory) NewObserver(cluster string, sf store.Factory, onSync func()) observer.Observer {
	var onSyncOnce = sync.OnceFunc(onSync)

	return &EndpointsObserver{
		cfg:     ef.cfg,
		cluster: cluster,
		onSync:  onSyncOnce,
		watcher: sf.NewWatchStore(
			cluster,
			pnkvs.EndpointKeyCreator(
				pnkvs.EndpointClusterNameValidator(cluster),
			),
			ef.obs,
			store.RWSWithOnSyncCallback(func(context.Context) { onSyncOnce() }),
		),
	}
}

// PropagateSynchronization propagates the synchronization signal to the underlying
// [PrivateNetworkEndpoints] observer, once the initial list of entries has been
// retrieved from all remote clusters, or the maximum wait period has expired.
func (ef *EndpointsFactory) PropagateSynchronization(jg job.Group, cm *clustermesh.ClusterMesh) {
	if !ef.cfg.Enabled {
		return
	}

	// ClusterMesh is disabled, immediately mark as synced.
	if cm == nil {
		ef.obs.OnSync()
		return
	}

	jg.Add(
		job.OneShot(
			"clustermesh-privnet-endpoints-sync",
			func(ctx context.Context, health cell.Health) error {
				health.OK("Waiting")

				if err := cm.ObserverSynced(ctx, (*EndpointsObserver)(nil).Name()); err != nil {
					return err
				}

				ef.obs.OnSync()
				return nil
			},
		),
	)
}

// EndpointsObserver knows how to watch private network endpoints from a target cluster.
type EndpointsObserver struct {
	cfg config.Config

	cluster string
	onSync  func()

	enabled atomic.Bool
	watcher store.WatchStore
}

var _ observer.Observer = (*EndpointsObserver)(nil)

// Name returns the name of the endpoints observer.
func (obs *EndpointsObserver) Name() observer.Name {
	return observer.Name("private network endpoints")
}

// Status returns the status of the endpoints observer.
func (obs *EndpointsObserver) Status() observer.Status {
	return observer.Status{
		Enabled: obs.cfg.Enabled && obs.enabled.Load(),
		Synced:  obs.watcher.Synced(),
		Entries: obs.watcher.NumEntries(),
	}
}

// Register registers the observer with the given [store.WatchStoreManager], to
// watch the private networks prefix.
func (obs *EndpointsObserver) Register(mgr store.WatchStoreManager,
	backend kvstore.BackendOperations, cfg types.CiliumClusterConfig) {

	if !obs.cfg.Enabled {
		return
	}

	if ptr.Deref(cfg.Capabilities.PrivateNetworksEnabled, false) {
		var prefix = pnkvs.EndpointsPrefix
		if cfg.Capabilities.Cached {
			prefix = kvstore.StateToCachePrefix(prefix)
		}

		obs.enabled.Store(true)
		mgr.Register(prefix, func(ctx context.Context) {
			obs.watcher.Watch(ctx, backend, kvstore.JoinKey(prefix, obs.cluster))
		})
	} else {
		obs.enabled.Store(false)

		// Drain all previously observed entries, and force synchronization in
		// case private networks is no longer enabled in the remote cluster.
		obs.watcher.Drain()
		obs.onSync()
	}
}

// Drain emits a deletion event for all previously observed entries, upon
// disconnection from the target remote cluster.
func (obs *EndpointsObserver) Drain() {
	if !obs.cfg.Enabled {
		return
	}

	obs.watcher.Drain()
}

// Revoke possibly emits a deletion event for all previously observed entries,
// if connectivity to the target remote cluster is lost.
func (obs *EndpointsObserver) Revoke() {}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observers

import (
	"maps"
	"slices"

	"github.com/cilium/stream"

	grpcConfig "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	nomgr "github.com/cilium/cilium/pkg/node/manager"
	notypes "github.com/cilium/cilium/pkg/node/types"
)

type (
	// NodeEvents is a sequence of node events.
	NodeEvents = Events[*types.Node, resource.EventKind]
)

// Nodes wraps [nomgr.NodeManager] to intercept and observe node events. This
// is a temporary workaround until a dedicated nodes statedb table is introduced,
// as at that point we could directly observe it rather than needing this hack.
type Nodes struct {
	nomgr.NodeManager
	*Generic[*types.Node, resource.EventKind]

	ipv6Underlay bool
	defGRPCPort  uint16

	cacheMu lock.RWMutex
	cache   map[types.ClusterName]map[types.NodeName]*types.Node

	syncMu                lock.Mutex
	localSync, remoteSync bool
}

var (
	_ nomgr.NodeManager             = (*Nodes)(nil)
	_ stream.Observable[NodeEvents] = (*Nodes)(nil)
)

func NewNodes(nm nomgr.NodeManager, tcfg tunnel.Config, grpcCfg grpcConfig.Config) *Nodes {
	return &Nodes{
		NodeManager:  nm,
		Generic:      NewGeneric[*types.Node, resource.EventKind](),
		ipv6Underlay: tcfg.UnderlayProtocol() == tunnel.IPv6,
		defGRPCPort:  grpcCfg.Port,
		cache:        make(map[types.ClusterName]map[types.NodeName]*types.Node),
	}
}

// List returns all nodes belonging to the given cluster.
func (o *Nodes) List(cluster types.ClusterName) []*types.Node {
	o.cacheMu.RLock()
	defer o.cacheMu.RUnlock()

	// Return a slice, instead of an iterator, as we need to access the map
	// while holding the lock, to prevent concurrent reads and writes.
	return slices.Collect(maps.Values(o.cache[cluster]))
}

// Get a node. Returns nil if not found.
func (o *Nodes) Get(cluster types.ClusterName, name types.NodeName) *types.Node {
	o.cacheMu.RLock()
	defer o.cacheMu.RUnlock()
	if m := o.cache[cluster]; m != nil {
		return m[name]
	}
	return nil
}

// NodeUpdated wraps the corresponding [NodeManager] method.
func (o *Nodes) NodeUpdated(no notypes.Node) {
	slim := types.NewNode(no, o.ipv6Underlay, o.defGRPCPort)

	o.cacheMu.Lock()
	inner := o.cache[slim.Cluster]
	if inner == nil {
		inner = make(map[types.NodeName]*types.Node)
		o.cache[slim.Cluster] = inner
	}
	inner[slim.Name] = slim
	o.cacheMu.Unlock()

	o.Queue(resource.Upsert, slim)
	o.NodeManager.NodeUpdated(no)
}

// NodeDeleted wraps the corresponding [NodeManager] method.
func (o *Nodes) NodeDeleted(no notypes.Node) {
	slim := types.NewNode(no, o.ipv6Underlay, o.defGRPCPort)

	o.cacheMu.Lock()
	inner := o.cache[slim.Cluster]
	delete(inner, slim.Name)
	if len(inner) == 0 {
		delete(o.cache, slim.Cluster)
	}
	o.cacheMu.Unlock()

	o.Queue(resource.Delete, slim)
	o.NodeManager.NodeDeleted(no)
}

// NodeSync wraps the corresponding [NodeManager] method.
func (o *Nodes) NodeSync() {
	o.syncMu.Lock()
	if !o.localSync && o.remoteSync {
		o.Queue(resource.Sync, nil)
	}
	o.localSync = true
	o.syncMu.Unlock()

	o.NodeManager.NodeSync()
}

// MeshNodeSync wraps the corresponding [NodeManager] method.
func (o *Nodes) MeshNodeSync() {
	o.syncMu.Lock()
	if !o.remoteSync && o.localSync {
		o.Queue(resource.Sync, nil)
	}
	o.remoteSync = true
	o.syncMu.Unlock()

	o.NodeManager.MeshNodeSync()
}

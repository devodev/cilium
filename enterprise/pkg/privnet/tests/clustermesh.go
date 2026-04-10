//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"fmt"
	"maps"
	"os"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	nomgr "github.com/cilium/cilium/pkg/node/manager"
	nostore "github.com/cilium/cilium/pkg/node/store"
	notypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

var ClusterMeshObservers = cell.Group(
	cell.Provide(
		func(obs *observers.PrivateNetworkEndpoints) uhive.ScriptCmdsOut {
			return uhive.NewScriptCmds(
				cmObserver[*kvstore.ValidatingEndpoint]{
					name: "endpoints",
					kc:   kvstore.EndpointKeyCreator(),
					obs:  obs,
				}.cmds(),
			)
		},

		// Strictly speaking the nodes observer, as currently implemented, is not
		// limited to clustermesh nodes only. However, let's reuse the same testing
		// machinery, given that scaffolding is already there, and it does not make
		// any difference from the practical point of view.
		func() nomgr.NodeManager {
			return &mockNM{
				nodes: map[notypes.Identity]notypes.Node{},
			}
		},
		func(obs *observers.Nodes) uhive.ScriptCmdsOut {
			return uhive.NewScriptCmds(
				cmObserver[*notypes.Node]{
					name: "nodes",
					kc:   nostore.KeyCreator,
					obs:  &nodesAdapter{obs},
				}.cmds(),
			)
		},
	),

	cell.Invoke(
		// Explicitly depend on [nomgr.NodeManager] to make sure it is initialized.
		func(nomgr.NodeManager) {},
	),
)

type nodesAdapter struct{ *observers.Nodes }

func (obs nodesAdapter) OnUpdate(key store.Key)      { obs.Nodes.NodeUpdated(*key.(*notypes.Node)) }
func (obs nodesAdapter) OnDelete(key store.NamedKey) { obs.Nodes.NodeDeleted(*key.(*notypes.Node)) }
func (obs nodesAdapter) OnSync()                     { obs.Nodes.NodeSync(); obs.Nodes.MeshNodeSync() }

type cmObserver[T store.Key] struct {
	name string
	kc   store.KeyCreator
	obs  interface {
		store.Observer
		OnSync()
	}
}

func (obs cmObserver[T]) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		fmt.Sprintf("clustermesh/%s/upsert", obs.name): obs.upsertDelete(false),
		fmt.Sprintf("clustermesh/%s/delete", obs.name): obs.upsertDelete(true),
		fmt.Sprintf("clustermesh/%s/sync", obs.name):   obs.sync(),
	}
}

func (obs cmObserver[T]) upsertDelete(delete bool) script.Cmd {
	str := "upsert"
	if delete {
		str = "delete"
	}

	return script.Command(
		script.CmdUsage{
			Summary: fmt.Sprintf("%s clustermesh %s", str, obs.name),
			Args:    "key value-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected key and value file", script.ErrUsage)
			}

			b, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("could not read %q: %w", s.Path(args[1]), err)
			}

			entry := obs.kc()
			if err := entry.Unmarshal(args[0], b); err != nil {
				return nil, fmt.Errorf("could not unmarshal %q: %w", s.Path(args[1]), err)
			}

			if delete {
				obs.obs.OnDelete(entry)
			} else {
				obs.obs.OnUpdate(entry)
			}

			return nil, nil
		},
	)
}

func (obs cmObserver[t]) sync() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: fmt.Sprintf("mark the clustermesh %s observer as synchronized", obs.name),
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			obs.obs.OnSync()
			return nil, nil
		},
	)
}

type mockNM struct {
	mu    lock.Mutex
	nodes map[notypes.Identity]notypes.Node
}

var _ nomgr.NodeManager = &mockNM{}

func (nm *mockNM) GetNodes() map[notypes.Identity]notypes.Node {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	return maps.Clone(nm.nodes)
}
func (nm *mockNM) NodeUpdated(n notypes.Node) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.nodes[notypes.Identity{
		Name:    n.Name,
		Cluster: n.Cluster,
	}] = n
}

func (nm *mockNM) NodeDeleted(n notypes.Node) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	delete(nm.nodes, notypes.Identity{
		Name:    n.Name,
		Cluster: n.Cluster,
	})
}

func (*mockNM) ClusterSizeDependantInterval(time.Duration) time.Duration { panic("unimplemented") }
func (*mockNM) GetNodeIdentities() []notypes.Identity                    { panic("unimplemented") }
func (*mockNM) Subscribe(node.Handler)                                   { panic("unimplemented") }
func (*mockNM) Unsubscribe(node.Handler)                                 { panic("unimplemented") }

func (*mockNM) SetPrefixClusterMutatorFn(func(*notypes.Node) []cmtypes.PrefixClusterOpts) {}

func (*mockNM) NodeSync()     {}
func (*mockNM) MeshNodeSync() {}

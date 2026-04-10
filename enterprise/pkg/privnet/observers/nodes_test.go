//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observers_test

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	grpccfg "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node"
	nomgr "github.com/cilium/cilium/pkg/node/manager"
	notypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

type mocknm struct {
	nodes      sets.Set[notypes.Identity]
	localSync  bool
	remoteSync bool
}

var _ nomgr.NodeManager = (*mocknm)(nil)

func (*mocknm) ClusterSizeDependantInterval(time.Duration) time.Duration { panic("unimplemented") }
func (*mocknm) GetNodeIdentities() []notypes.Identity                    { panic("unimplemented") }
func (*mocknm) GetNodes() map[notypes.Identity]notypes.Node              { panic("unimplemented") }
func (*mocknm) Subscribe(node.Handler)                                   { panic("unimplemented") }
func (*mocknm) Unsubscribe(node.Handler)                                 { panic("unimplemented") }

func (*mocknm) SetPrefixClusterMutatorFn(func(*notypes.Node) []cmtypes.PrefixClusterOpts) {}

func (nm *mocknm) NodeUpdated(no notypes.Node) { nm.nodes.Insert(no.Identity()) }
func (nm *mocknm) NodeDeleted(no notypes.Node) { nm.nodes.Delete(no.Identity()) }
func (nm *mocknm) NodeSync()                   { nm.localSync = true }
func (nm *mocknm) MeshNodeSync()               { nm.remoteSync = true }

func TestNodesObserver(t *testing.T) {
	const timeout = 3 * time.Second

	var (
		grpcCfg = grpccfg.Config{Port: 1234}
		mock    = &mocknm{nodes: sets.New[notypes.Identity]()}

		mgr nomgr.NodeManager
		obs *observers.Nodes

		no1 = notypes.Node{Cluster: "foo", Name: "sharing-swine"}
		no2 = notypes.Node{Cluster: "foo", Name: "eminent-alpaca"}
		no3 = notypes.Node{Cluster: "bar", Name: "ethical-manatee"}
	)

	err := hive.New(
		cell.Provide(
			func() tunnel.Config { return tunnel.NewTestConfig(tunnel.VXLAN) },
			func() grpccfg.Config { return grpcCfg },
			func() nomgr.NodeManager { return mock },
			observers.NewNodes,
		),

		cell.DecorateAll(
			func(obs *observers.Nodes) nomgr.NodeManager { return obs },
		),

		cell.Invoke(
			func(mgr_ nomgr.NodeManager, obs_ *observers.Nodes) {
				mgr, obs = mgr_, obs_
			},
		),
	).Populate(hivetest.Logger(t))

	require.NoError(t, err, "hive.Populate failed")

	// Perform a bunch of operations...
	mgr.NodeUpdated(no1)
	mgr.NodeUpdated(no2)
	mgr.NodeSync()

	// And assert that they have been propagated to the downstream.
	require.ElementsMatch(t, []notypes.Identity{no1.Identity(), no2.Identity()}, mock.nodes.UnsortedList())
	require.True(t, mock.localSync, "NodeSync should have been called")
	require.False(t, mock.remoteSync, "MeshNodeSync should not have been called")

	// Perform a few more...
	mgr.NodeDeleted(no1)
	mgr.NodeUpdated(no3)
	mgr.MeshNodeSync()

	// Calling NodeSync/MeshNodeSync again shall not emit more sync events.
	mgr.NodeSync()
	mgr.MeshNodeSync()

	// And assert again that they have been propagated to the downstream.
	require.ElementsMatch(t, []notypes.Identity{no2.Identity(), no3.Identity()}, mock.nodes.UnsortedList())
	require.True(t, mock.remoteSync, "MeshNodeSync should have been called")

	select {
	case got := <-stream.ToChannel(t.Context(), obs):
		require.Equal(t, observers.Events[*types.Node, resource.EventKind]{
			{Object: types.NewNode(no1, false, grpcCfg.Port), EventKind: resource.Upsert},
			{Object: types.NewNode(no2, false, grpcCfg.Port), EventKind: resource.Upsert},
			{Object: types.NewNode(no1, false, grpcCfg.Port), EventKind: resource.Delete},
			{Object: types.NewNode(no3, false, grpcCfg.Port), EventKind: resource.Upsert},
			{EventKind: resource.Sync},
		}, got)
	case <-time.After(timeout):
		require.FailNow(t, "No events observed")
	}

	// Assert that List returns the correct nodes snapshot.
	require.ElementsMatch(t, []*types.Node{types.NewNode(no2, false, grpcCfg.Port)}, obs.List("foo"))
	require.ElementsMatch(t, []*types.Node{types.NewNode(no3, false, grpcCfg.Port)}, obs.List("bar"))
	require.Empty(t, obs.List("other"))
}

func TestNodesObserverSync(t *testing.T) {
	const timeout = 3 * time.Second

	tests := []struct {
		name string
		do   func(nm nomgr.NodeManager)
	}{
		{
			"Local first",
			func(nm nomgr.NodeManager) { nm.NodeSync(); nm.MeshNodeSync() },
		},
		{
			"Remote first",
			func(nm nomgr.NodeManager) { nm.MeshNodeSync(); nm.NodeSync() },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := observers.NewNodes(&mocknm{}, tunnel.Config{}, grpccfg.Config{})
			tt.do(obs)

			select {
			case got := <-stream.ToChannel(t.Context(), obs):
				require.Equal(t, observers.Events[*types.Node, resource.EventKind]{
					{EventKind: resource.Sync},
				}, got)
			case <-time.After(timeout):
				require.FailNow(t, "No events observed")
			}
		})
	}
}

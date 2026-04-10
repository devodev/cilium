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
	"fmt"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl/fake"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	clientv1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	testNodeName = "test-node"
)

type testFixture struct {
	hive *hive.Hive

	ncClient      clientv1alpha1.IsovalentBFDNodeConfigInterface
	profileClient clientv1alpha1.IsovalentBFDProfileInterface

	db            *statedb.DB
	deviceTable   statedb.RWTable[*tables.Device]
	neighborTable statedb.RWTable[*tables.Neighbor]
	peerTable     statedb.RWTable[*types.BFDPeerStatus]
}

func newTestFixture(t *testing.T, ctx context.Context) (*testFixture, func()) {
	var ncOnce, peerOnce sync.Once
	ncWatchStarted, profileWatchStarted := make(chan struct{}), make(chan struct{})
	f := &testFixture{}

	f.hive = hive.New(
		Cell,
		cell.Provide(
			func() types.BFDServer {
				return newFakeBFDServer()
			},
		),
		cell.Config(types.BFDConfig{
			BFDEnabled: true,
		}),

		cell.Provide(
			k8sfake.NewFakeClientset,
		),

		cell.Provide(func() *node.LocalNodeStore {
			return node.NewTestLocalNodeStore(node.LocalNode{
				Node: nodetypes.Node{
					Name: testNodeName,
				},
			})
		}),

		cell.Provide(func() sysctl.Sysctl { return &fake.Sysctl{} }),

		cell.Provide(
			tables.NewDeviceTable,
			tables.NewNeighborTable,

			statedb.RWTable[*tables.Device].ToTable,
			statedb.RWTable[*tables.Neighbor].ToTable,
		),
		cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*types.BFDPeerStatus]) {
			f.db = db
			f.peerTable = table
		}),
		cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*tables.Device]) {
			f.deviceTable = table
		}),
		cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*tables.Neighbor]) {
			f.neighborTable = table
		}),

		cell.Invoke(func(clientset *k8sfake.FakeClientset) {
			f.ncClient = clientset.IsovalentV1alpha1().IsovalentBFDNodeConfigs()
			f.profileClient = clientset.IsovalentV1alpha1().IsovalentBFDProfiles()

			// catch-all watch reactor that allows us to inject the WatchStarted channels
			clientset.CiliumFakeClientset.PrependWatchReactor("*",
				func(action k8stesting.Action) (handled bool, ret watch.Interface, err error) {
					w := action.(k8stesting.WatchAction)
					gvr := w.GetResource()
					ns := w.GetNamespace()
					var opts []metav1.ListOptions
					if watchAction, ok := action.(k8stesting.WatchActionImpl); ok {
						opts = append(opts, watchAction.ListOptions)
					}
					watch, err := clientset.CiliumFakeClientset.Tracker().Watch(gvr, ns, opts...)
					if err != nil {
						return false, nil, err
					}
					switch w.GetResource().Resource {
					case v1alpha1.IsovalentBFDNodeConfigPluralName:
						ncOnce.Do(func() { close(ncWatchStarted) })
					case v1alpha1.IsovalentBFDProfilePluralName:
						peerOnce.Do(func() { close(profileWatchStarted) })
					default:
						return false, watch, nil
					}
					return true, watch, nil
				})
		}),
	)

	// blocks until watchers are initialized (call before the test starts)
	watchersReadyFn := func() {
		select {
		case <-ncWatchStarted:
		case <-ctx.Done():
			t.Fatalf("%s is not initialized", v1alpha1.IsovalentBFDNodeConfigPluralName)
		}

		select {
		case <-profileWatchStarted:
		case <-ctx.Done():
			t.Fatalf("%s is not initialized", v1alpha1.IsovalentBFDProfilePluralName)
		}
	}
	return f, watchersReadyFn
}

type fakeBFDServer struct {
	peers    map[string]*types.BFDPeerStatus
	statusCh chan types.BFDPeerStatus
	mcast    stream.Observable[types.BFDPeerStatus]
	connect  func(context.Context)
}

func newFakeBFDServer() *fakeBFDServer {
	s := &fakeBFDServer{
		peers:    make(map[string]*types.BFDPeerStatus),
		statusCh: make(chan types.BFDPeerStatus, 100),
	}
	s.mcast, s.connect = stream.ToMulticast(stream.FromChannel(s.statusCh))
	return s
}

func (s *fakeBFDServer) Run(ctx context.Context) {
	s.connect(ctx)
}

func (s *fakeBFDServer) AddPeer(peer *types.BFDPeerConfig) error {
	key := s.peerKey(peer)
	if _, exists := s.peers[key]; exists {
		return fmt.Errorf("peer with key %s already exists", key)
	}
	s.peers[key] = s.generatePeerStatus(peer)
	return nil
}

func (s *fakeBFDServer) UpdatePeer(peer *types.BFDPeerConfig) error {
	key := s.peerKey(peer)
	if _, exists := s.peers[key]; !exists {
		return fmt.Errorf("peer with key %s does not exist", key)
	}
	s.peers[key] = s.generatePeerStatus(peer)
	return nil
}

func (s *fakeBFDServer) DeletePeer(peer *types.BFDPeerConfig) error {
	key := s.peerKey(peer)
	if _, exists := s.peers[key]; !exists {
		return fmt.Errorf("peer with key %s does not exist", key)
	}
	delete(s.peers, key)
	return nil
}

func (s *fakeBFDServer) Observe(ctx context.Context, next func(types.BFDPeerStatus), complete func(error)) {
	s.mcast.Observe(ctx, next, complete)
}

func (s *fakeBFDServer) peerKey(peer *types.BFDPeerConfig) string {
	return peer.PeerAddress.String() + peer.Interface
}

func (s *fakeBFDServer) generatePeerStatus(peer *types.BFDPeerConfig) *types.BFDPeerStatus {
	status := types.BFDPeerStatus{
		PeerAddress: peer.PeerAddress,
		Interface:   peer.Interface,
		Local: types.BFDSessionStatus{
			State:               types.BFDStateDown,
			ReceiveInterval:     peer.ReceiveInterval,
			TransmitInterval:    peer.TransmitInterval,
			EchoReceiveInterval: peer.EchoReceiveInterval,
			DetectMultiplier:    peer.DetectMultiplier,
		},
	}
	s.statusCh <- status
	return &status
}

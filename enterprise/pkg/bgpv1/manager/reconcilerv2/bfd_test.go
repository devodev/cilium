// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	clientv1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/time"
)

const (
	bfdTestTimeout = 5 * time.Second
)

type bfdTestFixture struct {
	hive *hive.Hive

	router      *fake.EnterpriseFakeRouter
	reconciler  *BFDStateReconciler
	instance    *instance.EnterpriseBGPInstance
	bgpSignaler *signaler.BGPCPSignaler

	db            *statedb.DB
	bfdPeersTable statedb.RWTable[*types.BFDPeerStatus]
	pcClient      clientv1.IsovalentBGPPeerConfigInterface
}

func newBFDTestFixture(t *testing.T, ctx context.Context, nodeInstance *v1.IsovalentBGPNodeInstance) (*bfdTestFixture, func()) {
	var pcOnce sync.Once
	pcWatchStarted := make(chan struct{})

	router := fake.NewEnterpriseFakeRouter()
	f := &bfdTestFixture{
		router: router,
		instance: &instance.EnterpriseBGPInstance{
			Name:   "test-instance",
			Router: router,
		},
	}

	f.hive = hive.New(
		// test module so that BFDStateReconciler gets a job.Group
		cell.Module("bfd-state-reconciler-test", "BFD State Reconciler test",
			cell.Config(config.Config{
				Enabled:             true,
				StatusReportEnabled: true,
			}),
			cell.Config(types.BFDConfig{
				BFDEnabled: true,
			}),

			cell.Provide(
				NewBFDStateReconciler,

				signaler.NewBGPCPSignaler,
				func() paramUpgrader {
					return newUpgraderMock(nodeInstance)
				},

				types.NewBFDPeersTable,
				statedb.RWTable[*types.BFDPeerStatus].ToTable,

				k8s.IsovalentBGPPeerConfigResource,
				k8sfake.NewFakeClientset,
			),

			cell.Invoke(func(p BFDStateReconcilerIn) {
				out := NewBFDStateReconciler(p)
				f.reconciler = out.EnterpriseReconciler.(*BFDStateReconciler)
				f.reconciler.Init(f.instance)
			}),
			cell.Invoke(func(sig *signaler.BGPCPSignaler) {
				f.bgpSignaler = sig
			}),

			cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*types.BFDPeerStatus]) {
				f.db = db
				f.bfdPeersTable = table
			}),

			cell.Invoke(func(clientset *k8sfake.FakeClientset) {
				f.pcClient = clientset.IsovalentV1().IsovalentBGPPeerConfigs()
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
						if w.GetResource().Resource == v1.IsovalentBGPPeerConfigPluralName {
							pcOnce.Do(func() { close(pcWatchStarted) })
							return true, watch, nil
						}
						return false, watch, nil
					})
			}),
		),
	)

	watchersReadyFn := func() {
		select {
		case <-pcWatchStarted:
		case <-ctx.Done():
			t.Fatalf("%s is not initialized", v1.IsovalentBGPPeerConfigPluralName)
		}
	}
	return f, watchersReadyFn
}

func TestBFDStateReconciler(t *testing.T) {
	var (
		peer1Addr = netip.MustParseAddr("10.0.0.1")
		peer2Addr = netip.MustParseAddr("10.0.0.2")
		peer3Addr = netip.MustParseAddr("10.0.0.3")
	)

	peerConfigBFDEnabled := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bfd-enabled",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			BFDProfileRef: ptr.To[string]("frr"),
		},
	}
	peerConfigBFDDisabled := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bfd-disabled",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{},
	}

	var nodeInstance = &v1.IsovalentBGPNodeInstance{
		Name:     "test-instance",
		LocalASN: ptr.To[int64](65001),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				PeerAddress: ptr.To[string](peer1Addr.String()),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigBFDEnabled.Name,
				},
			},
			{
				PeerAddress: ptr.To[string](peer2Addr.String()),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigBFDEnabled.Name,
				},
			},
			{
				PeerAddress: ptr.To[string](peer3Addr.String()),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigBFDDisabled.Name,
				},
			},
		},
	}
	var table = []struct {
		name          string
		desiredConfig *v1.IsovalentBGPNodeInstance
		peerChanges   []*types.BFDPeerStatus
		deletePeers   bool
		expectSignal  bool
		expectReset   []netip.Addr
	}{
		{
			name:          "peer 1 goes AdminDown",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateAdminDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: false, // nothing should happen
		},
		{
			name:          "peer 1 goes Init",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: false, // nothing should happen
		},
		{
			name:          "peer 1 goes Down",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: true,
			// no reset as was not Up previously
		},
		{
			name:          "peer 1 goes Up",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 1 goes Down - reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
				},
			},
			expectSignal: true,
			expectReset:  []netip.Addr{peer1Addr},
		},
		{
			name:          "peer 1 stays Down - no action",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
				},
			},
			expectSignal: false,
		},
		{
			name:          "peer 1 goes Up again",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 1 goes Down again - reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer1Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
			expectReset:  []netip.Addr{peer1Addr},
		},
		{
			name:          "peer 2 goes Down",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: true,
			// no reset as was not Up previously
		},
		{
			name:          "peer 2 goes Up",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 2 goes Down - reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
			expectReset:  []netip.Addr{peer2Addr},
		},
		{
			name:          "peer 2 goes Up once more",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 2 goes Down - remote AdminDown",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateAdminDown,
					},
				},
			},
			expectSignal: true,
			// no reset as remote is AdminDown
		},
		{
			name:          "peer 2 goes Up again",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 2 goes AdminDown",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer2Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateAdminDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
				},
			},
			expectSignal: false,
			// no reset, as we are admin down
		},
		{
			name:          "peer 3 goes Down",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer3Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateInit,
					},
				},
			},
			expectSignal: true,
			// no reset as was not Up previously / and BFD is not configured
		},
		{
			name:          "peer 3 goes Up",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer3Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
		},
		{
			name:          "peer 3 goes Down - no reset",
			desiredConfig: nodeInstance,
			peerChanges: []*types.BFDPeerStatus{
				{
					PeerAddress: peer3Addr,
					Local: types.BFDSessionStatus{
						State: types.BFDStateDown,
					},
					Remote: types.BFDSessionStatus{
						State: types.BFDStateUp,
					},
				},
			},
			expectSignal: true,
			// no reset as BFD is not configured
		},
	}

	// create test fixture
	testCtx, cancel := context.WithTimeout(context.Background(), bfdTestTimeout)
	t.Cleanup(func() {
		cancel()
	})
	f, waitWatchersReady := newBFDTestFixture(t, testCtx, nodeInstance)

	// start the test hive
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})

	// wait until the watchers are ready
	waitWatchersReady()

	// configure Peer configs
	_, err = f.pcClient.Create(testCtx, peerConfigBFDEnabled, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.pcClient.Create(testCtx, peerConfigBFDDisabled, metav1.CreateOptions{})
	require.NoError(t, err)

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// write peer changes to statedb
			txn := f.db.WriteTxn(f.bfdPeersTable)
			for _, peer := range tt.peerChanges {
				if tt.deletePeers {
					_, _, err = f.bfdPeersTable.Delete(txn, peer)
				} else {
					_, _, err = f.bfdPeersTable.Insert(txn, peer)
				}
				require.NoError(t, err)
			}
			txn.Commit()

			if tt.expectSignal {
				// wait for BGP signal
				select {
				case <-f.bgpSignaler.Sig:
				case <-testCtx.Done():
					t.Fatalf("missed expected BGP reconciliation signal")
				}

				// run reconciliation
				reconcileParams := EnterpriseReconcileParams{
					BGPInstance:   f.instance,
					DesiredConfig: tt.desiredConfig,
				}
				err = f.reconciler.Reconcile(testCtx, reconcileParams)
				require.NoError(t, err)
			} else {
				require.Empty(t, f.bgpSignaler.Sig, "unexpected BGP reconciliation signal")
			}

			if len(tt.expectReset) > 0 {
				// check that expected sessions have been reset
				for range tt.expectReset {
					select {
					case reset := <-f.router.ResetPeersCh:
						require.Contains(t, tt.expectReset, reset)
					case <-testCtx.Done():
						t.Fatalf("missed expected peer reset")
					}
				}
			} else {
				// check no session have been reset
				require.Empty(t, f.router.ResetPeersCh, "unexpected peer reset")
			}
		})
	}
}

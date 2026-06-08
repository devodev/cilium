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
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	clientv1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1"
	k8s_fake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	TestTimeout = time.Second * 5
)

type crdStatusFixture struct {
	hive            *hive.Hive
	reconciler      *StatusReconciler
	db              *statedb.DB
	reconcileErrTbl statedb.RWTable[*tables.BGPReconcileError]
	fakeClientSet   *k8s_fake.FakeClientset
	bgpnClient      clientv1.IsovalentBGPNodeConfigInterface
	bgpncMockStore  *store.MockBGPCPResourceStore[*v1.IsovalentBGPNodeConfig]
}

func newCRDStatusFixture(l *slog.Logger) *crdStatusFixture {
	f := &crdStatusFixture{}
	f.fakeClientSet, _ = k8s_fake.NewFakeClientset(l)
	f.bgpnClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1().IsovalentBGPNodeConfigs()

	f.hive = hive.New(cell.Module("test", "test",
		cell.Provide(
			tables.NewBGPReconcileErrorTable,
			statedb.RWTable[*tables.BGPReconcileError].ToTable,
		),
		cell.Provide(func() k8s_client.Clientset {
			return f.fakeClientSet
		}),
		cell.Provide(func() store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfig] {
			f.bgpncMockStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPNodeConfig]()
			return f.bgpncMockStore
		}),
		cell.Provide(func() *node.LocalNodeStore {
			return node.NewTestLocalNodeStore(node.LocalNode{
				Node: nodetypes.Node{
					Name: "node0",
				},
			})
		}),
		cell.Invoke(
			func(p StatusReconcilerIn) {
				out := NewStatusReconciler(p)
				f.reconciler = out.EnterpriseReconciler.(*StatusReconciler)
				f.reconciler.reconcileInterval = 100 * time.Millisecond
			}),
		cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*tables.BGPReconcileError]) {
			f.db = db
			f.reconcileErrTbl = table
		}),
		cell.Config(config.Config{
			Enabled:             true,
			StatusReportEnabled: true,
		}),
	))

	return f
}

func TestCRDConditions(t *testing.T) {
	var tests = []struct {
		name               string
		statedbData        []*tables.BGPReconcileError
		initNodeConfig     *v1.IsovalentBGPNodeConfig
		expectedNodeConfig *v1.IsovalentBGPNodeConfig
	}{
		{
			name: "new error conditions",
			statedbData: []*tables.BGPReconcileError{
				{
					Instance: "bgp-instance-0",
					ErrorID:  0,
					Error:    "error 00",
				},
				{
					Instance: "bgp-instance-0",
					ErrorID:  1,
					Error:    "error 01",
				},
				{
					Instance: "bgp-instance-1",
					ErrorID:  0,
					Error:    "error 10",
				},
			},
			initNodeConfig: &v1.IsovalentBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "node0",
					Generation: 19,
				},
			},
			expectedNodeConfig: &v1.IsovalentBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "node0",
					Generation: 19,
				},
				Spec: v1.IsovalentBGPNodeSpec{},
				Status: v1.IsovalentBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:               v1.BGPInstanceConditionReconcileError,
							Status:             metav1.ConditionTrue,
							Reason:             "ReconcileFailed",
							ObservedGeneration: 19,
							Message: "bgp-instance-0: error 00\n" +
								"bgp-instance-0: error 01\n" +
								"bgp-instance-1: error 10\n",
						},
					},
				},
			},
		},
		{
			name: "modify previous error conditions",
			statedbData: []*tables.BGPReconcileError{
				{
					Instance: "bgp-instance-0",
					ErrorID:  0,
					Error:    "error 00",
				},
			},
			initNodeConfig: &v1.IsovalentBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v1.IsovalentBGPNodeSpec{},
				Status: v1.IsovalentBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:   v1.BGPInstanceConditionReconcileError,
							Status: metav1.ConditionTrue,
							Reason: "ReconcileFailed",
							Message: "bgp-instance-0: error 00\n" +
								"bgp-instance-0: error 01\n" +
								"bgp-instance-1: error 10\n",
						},
					},
				},
			},
			expectedNodeConfig: &v1.IsovalentBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Status: v1.IsovalentBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:    v1.BGPInstanceConditionReconcileError,
							Status:  metav1.ConditionTrue,
							Reason:  "ReconcileFailed",
							Message: "bgp-instance-0: error 00\n",
						},
					},
				},
			},
		},
		{
			name:        "delete previous error conditions",
			statedbData: []*tables.BGPReconcileError{},
			initNodeConfig: &v1.IsovalentBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v1.IsovalentBGPNodeSpec{},
				Status: v1.IsovalentBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:   v1.BGPInstanceConditionReconcileError,
							Status: metav1.ConditionTrue,
							Reason: "ReconcileFailed",
							Message: "bgp-instance-0: error 00\n" +
								"bgp-instance-0: error 01\n" +
								"bgp-instance-1: error 10\n",
						},
					},
				},
			},
			expectedNodeConfig: &v1.IsovalentBGPNodeConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Status: v1.IsovalentBGPNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:    v1.BGPInstanceConditionReconcileError,
							Status:  metav1.ConditionFalse,
							Reason:  "ReconcileSucceeded",
							Message: "",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			logger := hivetest.Logger(t)

			f := newCRDStatusFixture(logger)
			require.NoError(t, f.hive.Start(logger, ctx))
			t.Cleanup(func() {
				f.hive.Stop(logger, ctx)
				cancel()
			})

			// initialize BGP node config
			if tt.initNodeConfig != nil {
				_, err := f.bgpnClient.Create(ctx, tt.initNodeConfig, metav1.CreateOptions{})
				require.NoError(t, err)

				// insert the node config into the mock store
				f.bgpncMockStore.Upsert(tt.initNodeConfig)
			}

			// create local node
			_, err := f.fakeClientSet.CiliumV2().CiliumNodes().Create(
				ctx,
				&v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
				},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// wait for node to be detected by reconciler
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				f.reconciler.Lock()
				defer f.reconciler.Unlock()
				assert.Equal(c, "node0", f.reconciler.nodeName)
			}, time.Second*10, time.Millisecond*100)

			// setup statedb
			txn := f.db.WriteTxn(f.reconcileErrTbl)
			for _, errObj := range tt.statedbData {
				_, _, err := f.reconcileErrTbl.Insert(txn, errObj)
				require.NoError(t, err)
			}
			txn.Commit()

			err = f.reconciler.updateErrorConditions()
			require.NoError(t, err)

			// check eventually the conditions are updated
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				nodeConfig, err := f.bgpnClient.Get(ctx, "node0", metav1.GetOptions{})
				if !assert.NoError(c, err) {
					return
				}
				if !assert.Len(c, nodeConfig.Status.Conditions, len(tt.expectedNodeConfig.Status.Conditions)) {
					return
				}

				// we can not compare the whole status object because the timestamp is different.
				for i, cond := range nodeConfig.Status.Conditions {
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Type, cond.Type)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].ObservedGeneration, cond.ObservedGeneration)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Status, cond.Status)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Reason, cond.Reason)
					assert.Equal(c, tt.expectedNodeConfig.Status.Conditions[i].Message, cond.Message)
				}
			}, time.Second*10, time.Millisecond*100)
		})
	}
}

func TestDisableStatusReport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	logger := hivetest.Logger(t)

	var cs k8s_client.Clientset
	hive := hive.New(cell.Module("test", "test",
		cell.Provide(
			func() *config.Config {
				return &config.Config{
					Enabled:             true,
					StatusReportEnabled: false,
				}
			},
			k8s_fake.NewFakeClientset,
		),
		cell.Provide(func() *node.LocalNodeStore {
			return node.NewTestLocalNodeStore(node.LocalNode{
				Node: nodetypes.Node{
					Name: "node0",
				},
			})
		}),
		cell.Invoke(func(jg job.Group, ln *node.LocalNodeStore, _cs k8s_client.Clientset) {
			cs = _cs

			// Create a LocalNode to obtain local node name
			_, err := cs.CiliumV2().CiliumNodes().Create(
				ctx,
				&v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
				},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Create a NodeConfig for this node
			_, err = cs.IsovalentV1().IsovalentBGPNodeConfigs().Create(
				ctx,
				&v1.IsovalentBGPNodeConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
					// Spec can be empty for this test
					Spec: v1.IsovalentBGPNodeSpec{},
					// Fill with some dummy status
					Status: v1.IsovalentBGPNodeStatus{
						BGPInstances: []v1.IsovalentBGPNodeInstanceStatus{
							{
								CiliumBGPNodeInstanceStatus: v2.CiliumBGPNodeInstanceStatus{
									Name: "foo",
								},
							},
						},
					},
				},

				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Ensure the status is not empty at this point
			nc, err := cs.IsovalentV1().IsovalentBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
			require.NoError(t, err)
			require.False(t, nc.Status.DeepEqual(&v1.IsovalentBGPNodeStatus{}), "Status is already empty before cleanup job")

			// Register cleanup job. This should cleanup the status of the NodeConfig above.
			r := &StatusReconciler{
				LocalNodeStore: ln,
				ClientSet:      cs,
			}
			jg.Add(job.OneShot("cleanup-status", r.cleanupStatus))
		}),
	))

	require.NoError(t, hive.Start(logger, ctx))
	t.Cleanup(func() {
		hive.Stop(logger, ctx)
	})

	// Wait for status to be cleared
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		nc, err := cs.IsovalentV1().IsovalentBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
		if !assert.NoError(ct, err) {
			return
		}
		// The status should be cleared to empty
		assert.True(ct, nc.Status.DeepEqual(&v1.IsovalentBGPNodeStatus{}), "Status is not empty")
	}, time.Second*5, time.Millisecond*100)
}

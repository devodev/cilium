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
	"maps"
	"net/netip"
	"slices"

	"github.com/YutaroHayakawa/go-ra"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	enterpriseInstance "github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

type mockEGWPolicy struct {
	id        k8stypes.NamespacedName
	labels    map[string]string
	egressIPs []netip.Addr
}

func newEGWManagerMock(d []mockEGWPolicy) egressgatewayha.EgressIPsProvider {
	return &egwManagerMock{
		data: d,
	}
}

// egwManagerMock is a mock implementation of EGWIPsProvider ( EGWManager ). This is
// used to provide the egress IPs for the tests.
type egwManagerMock struct {
	data []mockEGWPolicy
}

func (e *egwManagerMock) AdvertisedEgressIPs(policySelector *slimv1.LabelSelector) (map[k8stypes.NamespacedName][]netip.Addr, error) {
	selector, err := slimv1.LabelSelectorAsSelector(policySelector)
	if err != nil {
		return nil, err
	}

	result := make(map[k8stypes.NamespacedName][]netip.Addr)
	for _, policy := range e.data {
		if selector.Matches(k8sLabels.Set(policy.labels)) {
			result[policy.id] = policy.egressIPs
		}
	}

	return result, nil
}

var _ resource.Store[runtime.Object] = (*mockResourceStore[runtime.Object])(nil)

// mockResourceStore is a mock implementation of resource.Store used for testing.
type mockResourceStore[T runtime.Object] struct {
	objMu   lock.Mutex
	objects map[resource.Key]T
}

func newMockResourceStore[T runtime.Object]() *mockResourceStore[T] {
	return &mockResourceStore[T]{
		objects: make(map[resource.Key]T),
	}
}

func (mds *mockResourceStore[T]) List() []T {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return slices.Collect(maps.Values(mds.objects))
}

func (mds *mockResourceStore[T]) IterKeys() resource.KeyIter {
	return nil
}

func (mds *mockResourceStore[T]) Get(obj T) (item T, exists bool, err error) {
	return mds.GetByKey(resource.NewKey(obj))
}

func (mds *mockResourceStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	item, exists = mds.objects[key]

	return item, exists, nil
}

func (mds *mockResourceStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, nil
}

func (mds *mockResourceStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	return nil, nil
}

func (mds *mockResourceStore[T]) CacheStore() cache.Store {
	return nil
}

func (mds *mockResourceStore[T]) Upsert(obj T) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	key := resource.NewKey(obj)
	mds.objects[key] = obj
}

func (mds *mockResourceStore[T]) Delete(key resource.Key) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	delete(mds.objects, key)
}

func InitMockStore[T runtime.Object](objects []T) resource.Store[T] {
	store := newMockResourceStore[T]()
	for _, obj := range objects {
		store.Upsert(obj)
	}
	return store
}

type mockSRv6Manager struct {
	lock.Mutex
	preinstalledVRFs map[k8stypes.NamespacedName]*srv6.VRF
}

func newMockSRv6Manager(vrfs map[k8stypes.NamespacedName]*srv6.VRF) *mockSRv6Manager {
	return &mockSRv6Manager{
		preinstalledVRFs: vrfs,
	}
}

func (m *mockSRv6Manager) GetVRFByName(vrfName k8stypes.NamespacedName) (*srv6.VRF, bool) {
	m.Lock()
	defer m.Unlock()

	vrf, exists := m.preinstalledVRFs[vrfName]
	if !exists {
		return nil, false
	}

	return vrf.DeepCopy(), true
}

func (m *mockSRv6Manager) GetEgressPolicies() []*srv6.EgressPolicy {
	return nil
}

func (m *mockSRv6Manager) upsertVRF(key k8stypes.NamespacedName, vrf *srv6.VRF) {
	m.Lock()
	defer m.Unlock()

	m.preinstalledVRFs[key] = vrf
}

type mockRADaemon struct {
	config *ra.Config
}

func (m *mockRADaemon) Run(ctx context.Context) {

}

func (m *mockRADaemon) Reload(ctx context.Context, newConfig *ra.Config) error {
	m.config = newConfig
	return nil
}

func (m *mockRADaemon) Status() *ra.Status {
	s := &ra.Status{}
	if m.config != nil {
		for _, interfaceConfig := range m.config.Interfaces {
			s.Interfaces = append(s.Interfaces, &ra.InterfaceStatus{
				Name: interfaceConfig.Name,
			})
		}
	}
	return s
}

type mockStateReconcilerIn struct {
	cell.In

	JG               job.Group
	Logger           *slog.Logger
	Instance         *enterpriseInstance.EnterpriseBGPInstance
	StateCh          types.StateNotificationCh
	StateReconcilers []EnterpriseStateReconciler `group:"enterprise-bgp-state-reconciler"`
}

// Mocked state reconciler. It only supports pre-configured, single instance.
// It only supports Update event.
type mockStateReconciler struct {
	in          mockStateReconcilerIn
	reconcilers []EnterpriseStateReconciler
}

func registerMockStateReconciler(in mockStateReconcilerIn) *mockStateReconciler {
	r := &mockStateReconciler{
		in: in,
		reconcilers: GetActiveEnterpriseStateReconcilers(
			in.Logger,
			in.StateReconcilers,
		),
	}
	in.JG.Add(job.OneShot("loop", r.loop))
	return r
}

func (m *mockStateReconciler) reconcile(ctx context.Context, retries int) (bool, error) {
	params := EnterpriseStateReconcileParams{
		UpdatedInstance: &EnterpriseBGPInstance{
			Name:   m.in.Instance.Name,
			Config: m.in.Instance.Config,
			Router: m.in.Instance.Router,
		},
	}

	for _, reconciler := range m.reconcilers {
		if err := reconciler.Reconcile(ctx, params); err != nil {
			m.in.Logger.Debug("Reconcile failed", logfields.Error, err)
			return false, nil
		}
	}

	return false, nil
}

func (m *mockStateReconciler) loop(ctx context.Context, _ cell.Health) error {
	for {
		select {
		case <-m.in.StateCh:
			if err := resiliency.Retry(
				ctx,
				100*time.Millisecond,
				100,
				m.reconcile,
			); err != nil {
				m.in.Logger.Debug(
					"Reconcile retry failed",
					logfields.Error, err,
				)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

type mockNodeStatusProvider struct {
	nodeStatus NodeStatus
}

func newMockNodeStatusProvider() *mockNodeStatusProvider {
	return &mockNodeStatusProvider{
		nodeStatus: NodeReady,
	}
}

func (m *mockNodeStatusProvider) SetNodeStatus(status NodeStatus) {
	m.nodeStatus = status
}

func (m *mockNodeStatusProvider) GetNodeStatus() NodeStatus {
	return m.nodeStatus
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package multicast

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"

	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	ipsecConfigTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	fake "github.com/cilium/cilium/pkg/datapath/linux/sysctl/fake"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	k8sFake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	maxTestDuration = 10 * time.Second
)

type fixture struct {
	testCtx          context.Context
	req              *require.Assertions
	hive             *hive.Hive
	manager          *MulticastManager
	fakeClientSet    *k8sFake.FakeClientset
	mcastGroupClient isovalent_client_v1alpha1.IsovalentMulticastGroupInterface
	mcastNodeClient  isovalent_client_v1alpha1.IsovalentMulticastNodeInterface
	endpointClient   client_v2.CiliumEndpointInterface
	bpfMap           maps_multicast.GroupV4Map
}

func newFixture(t *testing.T, ctx context.Context, req *require.Assertions, initBPF map[netip.Addr][]*maps_multicast.SubscriberV4) (*fixture, func()) {
	f := &fixture{}

	f.testCtx = ctx
	f.req = req

	// initialize BPF map
	f.bpfMap = newFakeMaps()
	for groupAddr, subscribers := range initBPF {
		err := f.bpfMap.Insert(groupAddr)
		req.NoError(err)

		subMap, err := f.bpfMap.Lookup(groupAddr)
		req.NoError(err)

		for _, sub := range subscribers {
			err := subMap.Insert(sub)
			req.NoError(err)
		}
	}

	f.fakeClientSet, _ = k8sFake.NewFakeClientset(hivetest.Logger(t))
	f.mcastGroupClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentMulticastGroups()
	f.mcastNodeClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentMulticastNodes()
	f.endpointClient = f.fakeClientSet.CiliumV2().CiliumEndpoints(slim_corev1.NamespaceAll)

	rws := map[string]*struct {
		once    sync.Once
		watchCh chan any
	}{
		"isovalentmulticastgroups": {watchCh: make(chan any)},
		"isovalentmulticastnodes":  {watchCh: make(chan any)},
		"ciliumendpoints":          {watchCh: make(chan any)},
	}

	watchReactorFn := func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		w := action.(k8sTesting.WatchAction)
		gvr := w.GetResource()
		ns := w.GetNamespace()
		var opts []metav1.ListOptions
		if watchAction, ok := action.(k8sTesting.WatchActionImpl); ok {
			opts = append(opts, watchAction.ListOptions)
		}
		watch, err := f.fakeClientSet.CiliumFakeClientset.Tracker().Watch(gvr, ns, opts...)
		if err != nil {
			return false, nil, err
		}
		rw, ok := rws[w.GetResource().Resource]
		if !ok {
			return false, watch, nil
		}
		rw.once.Do(func() { close(rw.watchCh) })
		return true, watch, nil
	}
	f.fakeClientSet.CiliumFakeClientset.PrependWatchReactor("*", watchReactorFn)

	// make sure watchers are initialized before the test starts
	watchersReadyFn := func() {
		for name, rw := range rws {
			select {
			case <-ctx.Done():
				t.Fatalf("Context expired while waiting for %s", name)
			case <-rw.watchCh:
			}
		}
	}

	f.hive = hive.New(
		cell.Provide(func(lc cell.Lifecycle, c k8sClient.Clientset, mp workqueue.MetricsProvider) resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastGroup] {
			return resource.New[*isovalent_api_v1alpha1.IsovalentMulticastGroup](
				lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentMulticastGroupList](
					c.IsovalentV1alpha1().IsovalentMulticastGroups(),
				), mp,
			)
		}),

		cell.Provide(func(lc cell.Lifecycle, c k8sClient.Clientset, mp workqueue.MetricsProvider) resource.Resource[*isovalent_api_v1alpha1.IsovalentMulticastNode] {
			return resource.New[*isovalent_api_v1alpha1.IsovalentMulticastNode](
				lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentMulticastNodeList](
					c.IsovalentV1alpha1().IsovalentMulticastNodes(),
				), mp,
			)
		}),

		cell.Provide(func(lc cell.Lifecycle, c k8sClient.Clientset, mp workqueue.MetricsProvider) resource.Resource[*k8sTypes.CiliumEndpoint] {
			lw := utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](c.CiliumV2().CiliumEndpoints(slim_corev1.NamespaceAll))
			return resource.New[*k8sTypes.CiliumEndpoint](lc, lw, mp,
				resource.WithLazyTransform(func() runtime.Object {
					return &cilium_api_v2.CiliumEndpoint{}
				}, k8s.TransformToCiliumEndpoint),
			)
		}),

		// fake BPF multicast map and config
		cell.Provide(func() maps_multicast.GroupV4Map {
			return f.bpfMap
		}),

		cell.Provide(func() maps_multicast.Config {
			return maps_multicast.Config{
				MulticastEnabled: true,
			}
		}),

		// LocalNodeStore
		cell.Provide(func() *node.LocalNodeStore {
			store := node.NewTestLocalNodeStore(node.LocalNode{
				Node: types.Node{
					Name: testLocalNodeName,
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.ParseIP(testLocalNodeIP),
						},
					},
				},
			})
			return store
		}),

		// fake daemon config, with vxlan enabled.
		cell.Provide(func() tunnel.Config {
			return tunnel.NewTestConfig(tunnel.VXLAN)
		}),

		cell.Provide(func() k8sClient.Clientset {
			return f.fakeClientSet
		}),

		// provide fake sysctl
		cell.Provide(func() sysctl.Sysctl { return &fake.Sysctl{} }),

		// provide daemon config
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{}
		}),

		// fake IPSec config with encrypted overlay enabled
		cell.Provide(func() ipsecConfigTypes.Config {
			return ipsecTypes.Config{
				EncryptedOverlay: true,
			}
		}),

		cell.Invoke(func(mcastManager *MulticastManager) {
			f.manager = mcastManager
		}),

		Cell,
	)

	return f, watchersReadyFn
}

// fakeMaps implements maps_multicast.GroupV4Map for testing purposes
type fakeGroupV4Map struct {
	lock.Mutex
	data map[netip.Addr]maps_multicast.SubscriberV4Map
}

func newFakeMaps() maps_multicast.GroupV4Map {
	return &fakeGroupV4Map{
		data: make(map[netip.Addr]maps_multicast.SubscriberV4Map),
	}
}

func (fgm *fakeGroupV4Map) Lookup(multicastAddr netip.Addr) (maps_multicast.SubscriberV4Map, error) {
	fgm.Lock()
	defer fgm.Unlock()

	sm, exists := fgm.data[multicastAddr]
	if !exists {
		return nil, ebpf.ErrKeyNotExist
	}
	return sm, nil
}

func (fgm *fakeGroupV4Map) Insert(multicastAddr netip.Addr) error {
	fgm.Lock()
	defer fgm.Unlock()

	fgm.data[multicastAddr] = newFakeSubscriberV4Map()
	return nil
}

func (fgm *fakeGroupV4Map) Delete(multicastAddr netip.Addr) error {
	fgm.Lock()
	defer fgm.Unlock()

	delete(fgm.data, multicastAddr)
	return nil
}

func (fgm *fakeGroupV4Map) List() ([]netip.Addr, error) {
	fgm.Lock()
	defer fgm.Unlock()

	res := make([]netip.Addr, 0, len(fgm.data))
	for k := range fgm.data {
		res = append(res, k)
	}

	return res, nil
}

type fakeSubscriberV4Map struct {
	lock.Mutex

	data []*maps_multicast.SubscriberV4
}

func newFakeSubscriberV4Map() maps_multicast.SubscriberV4Map {
	return &fakeSubscriberV4Map{}
}

func (fsm *fakeSubscriberV4Map) Insert(subscriber *maps_multicast.SubscriberV4) error {
	fsm.Lock()
	defer fsm.Unlock()

	fsm.data = append(fsm.data, subscriber)
	return nil
}

func (fsm *fakeSubscriberV4Map) Lookup(Src netip.Addr) (*maps_multicast.SubscriberV4, error) {
	fsm.Lock()
	defer fsm.Unlock()

	for _, v := range fsm.data {
		if v.SAddr.Compare(Src) == 0 {
			cp := *v
			return &cp, nil
		}
	}

	return nil, ebpf.ErrKeyNotExist
}

func (fsm *fakeSubscriberV4Map) Delete(Src netip.Addr) error {
	fsm.Lock()
	defer fsm.Unlock()

	for i, v := range fsm.data {
		if v.SAddr.Compare(Src) == 0 {
			fsm.data = append(fsm.data[:i], fsm.data[i+1:]...)
			return nil
		}
	}
	return ebpf.ErrKeyNotExist
}

func (fsm *fakeSubscriberV4Map) List() ([]*maps_multicast.SubscriberV4, error) {
	fsm.Lock()
	defer fsm.Unlock()

	// make deep copy
	cpy := make([]*maps_multicast.SubscriberV4, len(fsm.data))
	for i, v := range fsm.data {
		cp := *v
		cpy[i] = &cp
	}
	return cpy, nil
}

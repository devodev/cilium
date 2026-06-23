// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bfd"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	bfdTypes "github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/hive"
	healthTypes "github.com/cilium/cilium/pkg/hive/health/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	isovalent_client_v1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	k8s_fake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	TestTimeout = 10 * time.Second
)

var (
	isoClusterConfig = &v1.IsovalentBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "test-bgp-cluster-config",
			Labels: map[string]string{
				"bgp": "dummy_label",
			},
		},
		Spec: v1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"bgp": "rack1",
				},
			},
			BGPInstances: []v1.IsovalentBGPInstance{
				{
					Name:      "instance-1",
					LocalASN:  ptr.To[int64](65001),
					LocalPort: ptr.To[int32](179),
					Peers: []v1.IsovalentBGPPeer{
						{
							Name:        "peer-1",
							PeerAddress: ptr.To[string]("192.168.10.10"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v1.PeerConfigReference{
								Name: "peer-config-1",
							},
						},
						{
							Name:        "peer-2",
							PeerAddress: ptr.To[string]("192.168.10.20"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v1.PeerConfigReference{
								Name: "peer-config-2",
							},
						},
						{
							Name:        "peer-3",
							PeerAddress: ptr.To[string]("192.168.10.30"),
							PeerASN:     ptr.To[int64](65002),
						},
					},
				},
			},
		},
	}

	isoNodeConfigSpec = v1.IsovalentBGPNodeInstance{
		Name:      "instance-1",
		LocalASN:  ptr.To[int64](65001),
		LocalPort: ptr.To[int32](179),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				Name:        "peer-1",
				PeerAddress: ptr.To[string]("192.168.10.10"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config-1",
				},
			},
			{
				Name:        "peer-2",
				PeerAddress: ptr.To[string]("192.168.10.20"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config-2",
				},
			},
			{
				Name:        "peer-3",
				PeerAddress: ptr.To[string]("192.168.10.30"),
				PeerASN:     ptr.To[int64](65002),
			},
		},
	}
)

type fixture struct {
	hive          *hive.Hive
	fakeClientSet *k8s_fake.FakeClientset

	isoClusterClient       isovalent_client_v1.IsovalentBGPClusterConfigInterface
	isoPeerConfClient      isovalent_client_v1.IsovalentBGPPeerConfigInterface
	isoBGPNodeConfClient   isovalent_client_v1.IsovalentBGPNodeConfigInterface
	isoBGPNodeConfORClient isovalent_client_v1.IsovalentBGPNodeConfigOverrideInterface
	isoVrfClient           isovalent_client_v1alpha1.IsovalentVRFInterface
	isoBGPVrfClient        isovalent_client_v1alpha1.IsovalentBGPVRFConfigInterface

	// node client
	nodeClient cilium_client_v2.CiliumNodeInterface

	// db client
	db          *statedb.DB
	healthTable statedb.Table[healthTypes.Status]
}

type fixtureConfig struct {
	enableBFD          bool
	enableStatusReport bool
}

func newFixture(t *testing.T, ctx context.Context, req *require.Assertions, fc fixtureConfig) *fixture {
	f := &fixture{}
	f.fakeClientSet, _ = k8s_fake.NewFakeClientset(hivetest.Logger(t))

	// enterprise clients
	f.isoClusterClient = f.fakeClientSet.IsovalentV1().IsovalentBGPClusterConfigs()
	f.isoPeerConfClient = f.fakeClientSet.IsovalentV1().IsovalentBGPPeerConfigs()
	f.isoBGPNodeConfClient = f.fakeClientSet.IsovalentV1().IsovalentBGPNodeConfigs()
	f.isoBGPNodeConfORClient = f.fakeClientSet.IsovalentV1().IsovalentBGPNodeConfigOverrides()
	f.isoVrfClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentVRFs()
	f.isoBGPVrfClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPVRFConfigs()

	// node client
	f.nodeClient = f.fakeClientSet.CiliumV2().CiliumNodes()

	f.hive = hive.New(
		cell.Provide(func(lc cell.Lifecycle, c k8s_client.Clientset, mp workqueue.MetricsProvider) resource.Resource[*cilium_v2.CiliumNode] {
			return resource.New[*cilium_v2.CiliumNode](
				lc, utils.ListerWatcherFromTyped(
					c.CiliumV2().CiliumNodes(),
				), mp,
			)
		}),

		cell.Provide(
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableSRv6:          true,
					BGPSecretsNamespace: "kube-system",
				}
			},
		),

		cell.Provide(func() k8s_client.Clientset {
			return f.fakeClientSet
		}),

		cell.Invoke(
			func(db *statedb.DB, h statedb.Table[healthTypes.Status]) {
				f.db = db
				f.healthTable = h
			},
		),

		bfd.Cell,

		Cell,
	)

	hive.AddConfigOverride(f.hive, func(cfg *config.Config) {
		cfg.Enabled = true
		cfg.StatusReportEnabled = fc.enableStatusReport
	})
	hive.AddConfigOverride(f.hive, func(cfg *bfdTypes.BFDConfig) { cfg.BFDEnabled = fc.enableBFD })

	return f
}

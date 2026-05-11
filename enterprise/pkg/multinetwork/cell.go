// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/network"
	"github.com/cilium/cilium/enterprise/pkg/api"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"multinetwork-manager",
	"Determines which pod network a pod attaches to",

	cell.ProvidePrivate(isovalentPodNetworkResource),
	cell.Provide(newMultiNetworkManager),
	cell.Provide(newNetworkAPIHandler),
	cell.Config(defaultConfig),
)

var defaultConfig = Config{
	EnableMultiNetwork:               false,
	MultiNetworkAutoDirectNodeRoutes: true,
}

type Config struct {
	EnableMultiNetwork               bool `cilium-feature:"MultiNetwork"`
	MultiNetworkAutoDirectNodeRoutes bool
}

func (c Config) IsEnabled() bool {
	return c.EnableMultiNetwork
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-multi-network", c.EnableMultiNetwork, "Enable support for multiple pod networks")
	flags.Bool("multi-network-auto-direct-node-routes", c.MultiNetworkAutoDirectNodeRoutes, "Enable multi-network aware automatic L2 routing between nodes (experimental)")
}

// isovalentPodNetworkResource returns a resource handle for IsovalentPodNetworks
// Note: Ideally, his would live in github.com/cilium/cilium/daemon/k8s
// But to keep merge conflicts with Cilium OSS to a minimum, and since we are
// the only user of this resource anyway, we keep this private for now.
func isovalentPodNetworkResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*iso_v1alpha1.IsovalentPodNetwork], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*iso_v1alpha1.IsovalentPodNetworkList](cs.IsovalentV1alpha1().IsovalentPodNetworks()),
		opts...,
	)
	return resource.New[*iso_v1alpha1.IsovalentPodNetwork](lc, lw, mp, resource.WithMetric("IsovalentPodNetwork")), nil
}

type managerParams struct {
	cell.In

	Logger *slog.Logger

	Lifecycle cell.Lifecycle
	Config    Config

	DB                 *statedb.DB
	DaemonConfig       *option.DaemonConfig
	Sysctl             sysctl.Sysctl
	Pods               statedb.Table[tables.LocalPod]
	NetworkResource    resource.Resource[*iso_v1alpha1.IsovalentPodNetwork]
	CiliumNodeResource resource.Resource[*cilium_api_v2.CiliumNode]
	LocalNodeStore     *node.LocalNodeStore
}

func newMultiNetworkManager(params managerParams) *Manager {
	if !params.Config.EnableMultiNetwork {
		return nil
	}

	manager := &Manager{
		logger:       params.Logger,
		config:       params.Config,
		daemonConfig: params.DaemonConfig,
		sysctl:       params.Sysctl,

		controllerManager: controller.NewManager(),

		db:                 params.DB,
		pods:               params.Pods,
		networkResource:    params.NetworkResource,
		ciliumNodeResource: params.CiliumNodeResource,
		localNodeStore:     params.LocalNodeStore,
	}
	params.Lifecycle.Append(manager)

	return manager
}

// newNetworkHandler returns a default handler for the /network/attachments endpoint
func newNetworkAPIHandler(m *Manager) network.GetNetworkAttachmentHandler {
	return api.NewHandler(func(p network.GetNetworkAttachmentParams) middleware.Responder {
		if m == nil {
			return network.NewGetNetworkAttachmentDisabled()
		}

		attachments, err := m.GetNetworksForPod(p.PodNamespace, p.PodName)
		if err != nil {
			return network.NewGetNetworkAttachmentFailure().WithPayload(models.Error(err.Error()))
		}

		return network.NewGetNetworkAttachmentOK().WithPayload(attachments)
	})
}

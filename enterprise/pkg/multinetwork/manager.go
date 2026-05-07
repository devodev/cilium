// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/go-openapi/swag"

	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

var (
	controllerGroup = controller.NewGroup("multi-network")
)

const (
	// PodNetworkKey is the annotation name used to store the pod network names
	// a pod should be attached to.
	PodNetworkKey = "network.v1alpha1.isovalent.com/pod-networks"

	defaultNetwork = "default"
)

// ManagerStoppedError is returned when a API call is being made while the manager is stopped
type ManagerStoppedError struct{}

func (m *ManagerStoppedError) Error() string {
	return "multi-network-manager has been stopped"
}

// ResourceNotFound is returned when a Kubernetes resource
// (e.g. Pod, IsovalentPodNetwork) is not found
type ResourceNotFound struct {
	Resource  string
	Name      string
	Namespace string
}

func (r *ResourceNotFound) Error() string {
	name := r.Name
	if r.Namespace != "" {
		name = r.Namespace + "/" + r.Name
	}
	return fmt.Sprintf("resource %s %q not found", r.Resource, name)
}

func (r *ResourceNotFound) Is(target error) bool {
	targetErr, ok := target.(*ResourceNotFound)
	if !ok {
		return false
	}
	if r != nil && targetErr.Resource != "" {
		return r.Resource == targetErr.Resource
	}
	return true
}

type daemonConfig interface {
	IPv4Enabled() bool
	IPv6Enabled() bool
}

// Manager is responsible for managing multi-networking. It implements the
// Cilium API stubs to provide multi-networking information to the Cilium CNI
// plugin and contains an implementation of the multi-networking-aware auto direct
// node routes logic.
type Manager struct {
	logger       *slog.Logger
	config       Config
	daemonConfig daemonConfig
	sysctl       sysctl.Sysctl

	controllerManager *controller.Manager
	cancelController  context.CancelFunc

	db   *statedb.DB
	pods statedb.Table[tables.LocalPod]

	ciliumNodeResource resource.Resource[*cilium_api_v2.CiliumNode]
	localNodeStore     *node.LocalNodeStore

	networkResource resource.Resource[*iso_v1alpha1.IsovalentPodNetwork]
	networkStore    resource.Store[*iso_v1alpha1.IsovalentPodNetwork]
}

// Start initializes the manager and starts watching the Kubernetes resources.
// Invoked by the hive framework.
func (m *Manager) Start(ctx cell.HookContext) (err error) {
	m.networkStore, err = m.networkResource.Store(ctx)
	if err != nil {
		return err
	}

	if m.config.MultiNetworkAutoDirectNodeRoutes {
		var controllerCtx context.Context
		controllerCtx, m.cancelController = context.WithCancel(context.Background())
		m.startRoutingController(controllerCtx)
		m.startLocalIPCollector(controllerCtx)
	}

	return nil
}

// Stop stops the manager, meaning it can no longer serve API requests.
// Invoked by the hive framework.
func (m *Manager) Stop(ctx cell.HookContext) error {
	m.networkStore = nil
	if m.cancelController != nil {
		m.cancelController()
	}

	m.controllerManager.RemoveControllerAndWait(localNodeSyncController)
	m.controllerManager.RemoveControllerAndWait(remoteRouteController)

	return nil
}

// GetNetworksForPod returns the networks a pod should be attached to.
// The returned list of networks contains the network name, routes, and IPAM
// pool name for each network.
//
// This function is invoked via the Cilium API from the Cilium CNI plugin during
// a CNI ADD request. It uses this information to determine how many endpoints
// (and thereby intefaces) have to be created for the new pod.
//
// We determine attached networks by looking at the
// network.v1alpha1.isovalent.com/pod-networks annotation on the pod. If the
// annotation is not present, we default to the "default" network. Otherwise,
// we require all to-be-attached networks to be listed in the annotation,
// including the "default" one.
//
// If the pod or requested network is not yet known, we return an error. This
// will cause the CNI ADD request to fail, but it will be retried later, at which
// point the pod and/or network should hopefully be available.
func (m *Manager) GetNetworksForPod(podNamespace, podName string) (*models.NetworkAttachmentList, error) {
	if m.networkStore == nil {
		return nil, &ManagerStoppedError{}
	}

	pod, _, ok := m.pods.Get(m.db.ReadTxn(), tables.PodByName(podNamespace, podName))
	if !ok {
		return nil, &ResourceNotFound{Resource: "Pod", Namespace: podNamespace, Name: podName}
	}

	networkAnnotation, hasAnnotation := pod.Annotations[PodNetworkKey]
	if !hasAnnotation {
		networkAnnotation = defaultNetwork
	}

	var attachments []*models.NetworkAttachmentElement
	for networkName := range strings.SplitSeq(networkAnnotation, ",") {
		network, ok, err := m.networkStore.GetByKey(resource.Key{Name: networkName})
		if err != nil {
			return nil, fmt.Errorf("failed to lookup IsovalentPodNetwork %q: %w", networkName, err)
		} else if !ok {
			return nil, &ResourceNotFound{Resource: "IsovalentPodNetwork", Name: networkName}
		}

		var routes []*models.NetworkAttachmentRoute
		for _, route := range network.Spec.Routes {
			routes = append(routes, &models.NetworkAttachmentRoute{
				Destination: string(route.Destination),
				Gateway:     string(route.Gateway),
			})
		}

		attachments = append(attachments, &models.NetworkAttachmentElement{
			Name:   swag.String(networkName),
			Routes: routes,
			Ipam: &models.NetworkAttachmentIPAMParameters{
				IpamPool: network.Spec.IPAM.Pool.Name,
			},
		})
	}

	return &models.NetworkAttachmentList{
		Attachments:  attachments,
		PodName:      podName,
		PodNamespace: podNamespace,
	}, nil
}

// startRoutingController implements a multi-network aware version of auto-direct-node-routes.
// We currently duplicate this logic here because the routing logic in the open-source linuxNodeHandler
// is not multi-network aware, but the goal is to eventually upstream this.
// The remoteNodeRouteManager logic of the routing feature subscribes to all remote CiliumNode objects,
// correlates pod CIDRs with the remote node's secondary IP, and then installs a route for each pod CIDR.
func (m *Manager) startRoutingController(ctx context.Context) {
	// remoteNodeRouteManager is responsible for managing multi-network auto direct node routes
	remoteNodes := &remoteNodeRouteManager{
		logger:       m.logger,
		networkStore: m.networkStore,
		mutex:        lock.Mutex{},
		nodes:        make(map[string]*remoteNode),
	}

	m.ciliumNodeResource.Observe(ctx,
		func(ev resource.Event[*cilium_api_v2.CiliumNode]) {
			switch ev.Kind {
			case resource.Upsert:
				remoteNodes.upsertCiliumNode(ev.Object.Name, ev.Object)
			case resource.Delete:
				remoteNodes.upsertCiliumNode(ev.Object.Name, nil)
			}
			ev.Done(nil)
		},
		func(err error) {
			if err != nil {
				m.logger.Error("CiliumNode watcher unexpectedly stopped. Multi-network aware direct node routes will not be updated anymore.",
					logfields.Error, err,
				)
			}
		},
	)

	// Regularly reinstall all routes in case networks have changed or routes have been manually removed
	m.controllerManager.UpdateController(remoteRouteController, controller.ControllerParams{
		DoFunc:      remoteNodes.resyncNodes,
		RunInterval: 1 * time.Minute,
		Group:       controllerGroup,
		Context:     ctx,
	})
}

// startLocalIPCollector is part of the multi-network-aware auto-direct-node-routes feature.
// The localNetworkIPCollector auto-detects the secondary node IPs of the local node (based on network routes)
// and announces them in the CiliumNode object via NodeDiscovery.
// This must be called after the CiliumNode resource has already been registered, as it invokes
// NodeDiscovery.UpdateLocalNode.
func (m *Manager) startLocalIPCollector(ctx context.Context) {
	if !m.config.MultiNetworkAutoDirectNodeRoutes || m.networkStore == nil {
		return
	}

	// localNetworkIPCollector auto-detects local node IPs and provides them to
	// nodeDiscovery
	localIP := &localNetworkIPCollector{
		logger:              m.logger,
		daemonConfig:        m.daemonConfig,
		localNodeStore:      m.localNodeStore,
		networkStore:        m.networkStore,
		mutex:               lock.Mutex{},
		nodeIPByNetworkName: make(map[string]nodeIPPair),
	}

	// Collects local podCIDRs and stores them in nodeIPByNetworkName
	m.controllerManager.UpdateController(localNodeSyncController, controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			return localIP.updateNodeIPAddresses(m.sysctl)
		},
		RunInterval: 15 * time.Second,
		Group:       controllerGroup,
		Context:     ctx,
	})

}

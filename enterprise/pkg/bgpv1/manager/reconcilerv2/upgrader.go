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
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	ErrNotInitialized        = errors.New("not initialized")
	ErrEntNodeConfigNotFound = errors.New("enterprise node config not found")
	ErrUpdateConfigNotSet    = errors.New("config missing")
)

// EnterpriseReconcileParams is an enterprise specific version of
// reconcilerv2.ReconcileParams. It must be created with
// reconcileParamsUpgrader.upgrade.
type EnterpriseReconcileParams struct {
	BGPInstance   *EnterpriseBGPInstance
	DesiredConfig *v1.IsovalentBGPNodeInstance
	CiliumNode    *v2.CiliumNode
}

// EnterpriseStateReconcileParams is an enterprise specific version of
// reconcilerv2.StateReconcileParams. It must be created with
// reconcileParamsUpgrader.upgradeState.
type EnterpriseStateReconcileParams struct {
	DesiredConfig   *v1.IsovalentBGPNodeInstance
	UpdatedInstance *EnterpriseBGPInstance
	DeletedInstance string
}

// EnterpriseBGPInstance is an enterprise specific version of
// reconcilerv2.BGPInstance. It must be created with
// reconcileParamsUpgrader.upgrade.
type EnterpriseBGPInstance struct {
	Name   string
	Config *v1.IsovalentBGPNodeInstance
	Router types.EnterpriseRouter
	Global ossTypes.BGPGlobal
}

type paramUpgrader interface {
	upgrade(params reconciler.ReconcileParams) (EnterpriseReconcileParams, error)
	upgradeState(params reconciler.StateReconcileParams) (EnterpriseStateReconcileParams, error)
}

type reconcilerParamsUpgraderIn struct {
	cell.In

	Logger             *slog.Logger
	BGPConfig          config.Config
	BGPNodeConfigStore store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfig] // BGPCPResourceStore triggers BGP CP reconciliation upon IsovalentBGPNodeConfig events
	LocalNodeRes       daemon_k8s.LocalCiliumNodeResource
	Signaler           *signaler.BGPCPSignaler
	JobGroup           job.Group
}

type reconcileParamsUpgrader struct {
	initialized   atomic.Bool
	nodeName      string
	nodeNameMutex lock.Mutex
	store         store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfig]
}

func newReconcileParamsUpgrader(in reconcilerParamsUpgraderIn) paramUpgrader {
	u := &reconcileParamsUpgrader{
		store: in.BGPNodeConfigStore,
	}
	if !in.BGPConfig.Enabled {
		// No need to initialize the upgrader if enterprise BGP control plane is not enabled.
		return u
	}

	in.JobGroup.Add(job.OneShot("bgp-reconcile-params-upgrader-init", func(ctx context.Context, health cell.Health) error {
		for event := range in.LocalNodeRes.Events(ctx) {
			switch event.Kind {
			case resource.Upsert:
				u.setNodeName(event.Object.GetName())

				// initialize upgrader once we have the node name
				u.initialized.Store(true)
				in.Logger.Debug("BGP params upgrader initialized")
			}
			event.Done(nil)
		}

		return nil
	}))

	return u
}

func (u *reconcileParamsUpgrader) upgrade(params reconciler.ReconcileParams) (EnterpriseReconcileParams, error) {
	if !u.initialized.Load() {
		return EnterpriseReconcileParams{}, ErrNotInitialized
	}

	if params.BGPInstance == nil || params.DesiredConfig == nil || params.CiliumNode == nil {
		return EnterpriseReconcileParams{}, fmt.Errorf("invalid params")
	}

	nc, exists, err := u.store.GetByKey(resource.Key{Name: params.CiliumNode.Name})
	if err != nil {
		return EnterpriseReconcileParams{}, err
	}

	if !exists {
		return EnterpriseReconcileParams{}, ErrEntNodeConfigNotFound
	}

	for i, inst := range nc.Spec.BGPInstances {
		// compare BGP instance names to find the matching instance.
		// We check desired config instead of BGPInstance.Config because
		// BGPInstance.Config is nil at first reconciliation loop. Desired config
		// is considered source of truth.
		if inst.Name != params.DesiredConfig.Name {
			continue
		}
		// copy link-local PeerAddress from OSS DesiredConfig for auto-discovered peers
		// (set there by the CEE LinkLocalReconciler / OSS DefaultGatewayReconciler)
		desiredConfig := nc.Spec.BGPInstances[i].DeepCopy()
		for peerIdx, peer := range desiredConfig.Peers {
			if peer.AutoDiscovery != nil &&
				(peer.AutoDiscovery.Mode == v1.BGPADUnnumbered || peer.AutoDiscovery.Mode == v1.BGPADDefaultGateway) {
				ossPeer, err := getOSSNodePeerByName(params.DesiredConfig, peer.Name)
				if err != nil {
					return EnterpriseReconcileParams{}, err
				}
				desiredConfig.Peers[peerIdx].PeerAddress = ossPeer.PeerAddress
			}
		}

		return EnterpriseReconcileParams{
			BGPInstance: &EnterpriseBGPInstance{
				Name: params.BGPInstance.Name,
				// So far, we don't need to keep the previous
				// config. Once we have a use case for it, we
				// can consider storing it in the metadata and
				// copying it here.
				Config: nil,
				Router: upgradeRouter(params.BGPInstance.Router),
				Global: params.BGPInstance.Global,
			},
			DesiredConfig: desiredConfig,
			CiliumNode:    params.CiliumNode,
		}, nil
	}

	return EnterpriseReconcileParams{}, fmt.Errorf("enterprise node instance not found")
}

func (u *reconcileParamsUpgrader) upgradeState(params reconciler.StateReconcileParams) (EnterpriseStateReconcileParams, error) {
	if !u.initialized.Load() {
		return EnterpriseStateReconcileParams{}, ErrNotInitialized
	}

	// If the instance is being deleted, we don't need to find the instance in the config.
	if params.DeletedInstance != "" {
		return EnterpriseStateReconcileParams{
			DesiredConfig:   nil,
			UpdatedInstance: nil,
			DeletedInstance: params.DeletedInstance,
		}, nil
	}

	if params.UpdatedInstance == nil || params.UpdatedInstance.Config == nil {
		return EnterpriseStateReconcileParams{}, ErrUpdateConfigNotSet
	}

	nc, exists, err := u.store.GetByKey(resource.Key{Name: u.getNodeName()})
	if err != nil {
		return EnterpriseStateReconcileParams{}, err
	}

	if !exists {
		return EnterpriseStateReconcileParams{}, ErrEntNodeConfigNotFound
	}

	for i, inst := range nc.Spec.BGPInstances {
		if inst.Name == params.UpdatedInstance.Config.Name {
			return EnterpriseStateReconcileParams{
				DesiredConfig: &nc.Spec.BGPInstances[i],
				UpdatedInstance: &EnterpriseBGPInstance{
					Name: params.UpdatedInstance.Name,
					// So far, we don't need to keep the previous
					// config. Once we have a use case for it, we
					// can consider storing it in the metadata and
					// copying it here.
					Config: nil,
					Router: upgradeRouter(params.UpdatedInstance.Router),
				},
			}, nil
		}
	}

	return EnterpriseStateReconcileParams{}, fmt.Errorf("enterprise node instance not found")
}

func (u *reconcileParamsUpgrader) getNodeName() string {
	u.nodeNameMutex.Lock()
	defer u.nodeNameMutex.Unlock()
	return u.nodeName
}

func (u *reconcileParamsUpgrader) setNodeName(name string) {
	u.nodeNameMutex.Lock()
	u.nodeName = name
	u.nodeNameMutex.Unlock()
}

func getOSSNodePeerByName(ni *v2.CiliumBGPNodeInstance, peerName string) (*v2.CiliumBGPNodePeer, error) {
	for _, peer := range ni.Peers {
		if peer.Name == peerName {
			return &peer, nil
		}
	}
	return nil, fmt.Errorf("peer %s not found in the OSS instance %s", peerName, ni.Name)
}

// upgradeRouter converts an OSS Router to an Enterprise Router.
func upgradeRouter(r ossTypes.Router) types.EnterpriseRouter {
	if rt, ok := r.(types.EnterpriseRouter); ok {
		return rt
	}
	panic(fmt.Sprintf("unknown router type %T", r))
}

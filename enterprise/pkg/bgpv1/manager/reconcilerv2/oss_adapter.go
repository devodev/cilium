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

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	ossInstance "github.com/cilium/cilium/pkg/bgp/manager/instance"
	ossReconciler "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

// ossConfigReconcilerAdapter takes enterprise config reconciler and
// adapts it to be used as an OSS config reconciler. We can remove this once all
// reconcilers are migrated to the EnterpriseConfigReconciler interface.
type ossConfigReconcilerAdapter struct {
	reconciler EnterpriseConfigReconciler
	upgrader   paramUpgrader
}

var _ ossReconciler.ConfigReconciler = (*ossConfigReconcilerAdapter)(nil)

func newOSSConfigReconcilerAdapter(reconciler EnterpriseConfigReconciler, upgrader paramUpgrader) ossReconciler.ConfigReconciler {
	if reconciler == nil || upgrader == nil {
		return nil
	}
	return ossConfigReconcilerAdapter{
		reconciler: reconciler,
		upgrader:   upgrader,
	}
}

func (a ossConfigReconcilerAdapter) Name() string {
	return a.reconciler.Name()
}

func (a ossConfigReconcilerAdapter) Priority() int {
	return a.reconciler.Priority()
}

func (a ossConfigReconcilerAdapter) Init(i *ossInstance.BGPInstance) error {
	return a.reconciler.Init(&instance.EnterpriseBGPInstance{
		// All current reconcilers only use the Name. We're ok to be
		// short-sighted here since we only use this adapter during the
		// transition period.
		Name: i.Name,
	})
}

func (a ossConfigReconcilerAdapter) Cleanup(i *ossInstance.BGPInstance) {
	a.reconciler.Cleanup(&instance.EnterpriseBGPInstance{
		// All current reconcilers only use the Name. We're ok to be
		// short-sighted here since we only use this adapter during the
		// transition period.
		Name: i.Name,
	})
}

// Reconcile upgrades the OSS ReconcileParams to EnterpriseReconcileParams and
// calls the Enterprise reconciler.
func (a ossConfigReconcilerAdapter) Reconcile(ctx context.Context, params ossReconciler.ReconcileParams) error {
	ep, err := a.upgrader.upgrade(params)
	if err != nil {
		if errors.Is(err, ErrEntNodeConfigNotFound) || errors.Is(err, ErrNotInitialized) {
			return nil
		}
		return err
	}
	if ep.BGPInstance == nil {
		return errors.Join(errors.New("BUG: reconciler called with nil BGPInstance"), ErrAbortReconcile)
	}
	if ep.DesiredConfig == nil {
		return errors.Join(errors.New("BUG: reconciler called with nil IsovalentBGPNodeInstance"), ErrAbortReconcile)
	}
	if ep.CiliumNode == nil {
		return errors.Join(errors.New("BUG: reconciler called with nil CiliumNode"), ErrAbortReconcile)
	}

	if err := a.reconciler.Reconcile(ctx, ep); err != nil {
		return err
	}

	if a.reconciler.Name() == LinkLocalReconcilerName {
		// When OSS and CEE BGP control planes are both enabled, later OSS
		// reconcilers still consume the OSS desired config. LinkLocal resolves
		// unnumbered peer addresses in the Enterprise config, so copy those
		// resolved addresses back for the remaining OSS reconciler pass.
		copyAutoDiscoveredPeerAddressesToOSS(params.DesiredConfig, ep.DesiredConfig)
	}

	return nil
}

func copyAutoDiscoveredPeerAddressesToOSS(ossConfig *v2.CiliumBGPNodeInstance, enterpriseConfig *v1.IsovalentBGPNodeInstance) {
	if ossConfig == nil || enterpriseConfig == nil {
		return
	}

	for _, enterprisePeer := range enterpriseConfig.Peers {
		if enterprisePeer.AutoDiscovery == nil {
			continue
		}
		for i := range ossConfig.Peers {
			if ossConfig.Peers[i].Name == enterprisePeer.Name {
				ossConfig.Peers[i].PeerAddress = enterprisePeer.PeerAddress
				break
			}
		}
	}
}

type ossStateReconcilerAdapter struct {
	reconciler EnterpriseStateReconciler
	upgrader   paramUpgrader
}

func newOSSStateReconcilerAdapter(reconciler EnterpriseStateReconciler, upgrader paramUpgrader) ossReconciler.StateReconciler {
	if reconciler == nil || upgrader == nil {
		return nil
	}
	return ossStateReconcilerAdapter{
		reconciler: reconciler,
		upgrader:   upgrader,
	}
}

func (a ossStateReconcilerAdapter) Name() string {
	return a.reconciler.Name()
}

func (a ossStateReconcilerAdapter) Priority() int {
	return a.reconciler.Priority()
}

func (a ossStateReconcilerAdapter) Reconcile(ctx context.Context, params ossReconciler.StateReconcileParams) error {
	enterpriseParams, err := a.upgrader.upgradeState(params)
	if err != nil {
		if errors.Is(err, ErrEntNodeConfigNotFound) ||
			errors.Is(err, ErrNotInitialized) ||
			errors.Is(err, ErrUpdateConfigNotSet) {
			return nil
		}
		return err
	}
	return a.reconciler.Reconcile(ctx, enterpriseParams)
}

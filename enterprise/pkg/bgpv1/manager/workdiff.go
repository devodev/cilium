// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"fmt"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

type reconcileDiff struct {
	seen map[string]*v1.IsovalentBGPNodeInstance

	ciliumNode *v2.CiliumNode

	register  []string
	withdraw  []string
	reconcile []string
}

// newReconcileDiff constructs a new *reconcileDiff with all internal structures
// initialized.
func newReconcileDiff(ciliumNode *v2.CiliumNode) *reconcileDiff {
	return &reconcileDiff{
		seen:       make(map[string]*v1.IsovalentBGPNodeInstance),
		ciliumNode: ciliumNode,
		register:   []string{},
		withdraw:   []string{},
		reconcile:  []string{},
	}
}

func (wd *reconcileDiff) diff(existingInstances map[string]*instance.EnterpriseBGPInstance, desiredConfig *v1.IsovalentBGPNodeConfig) error {
	if err := wd.registerOrReconcileDiff(existingInstances, desiredConfig); err != nil {
		return fmt.Errorf("encountered error creating register or reconcile diff: %w", err)
	}
	wd.withdrawDiff(existingInstances)
	return nil
}

// String provides a string representation of the reconcileDiff.
func (wd *reconcileDiff) String() string {
	return fmt.Sprintf("Registering: %v Withdrawing: %v Reconciling: %v",
		wd.register,
		wd.withdraw,
		wd.reconcile,
	)
}

// empty informs the caller whether the reconcileDiff contains any work to undertake.
func (wd *reconcileDiff) empty() bool {
	switch {
	case len(wd.register) > 0:
		fallthrough
	case len(wd.withdraw) > 0:
		fallthrough
	case len(wd.reconcile) > 0:
		return false
	}
	return true
}

// registerOrReconcileDiff will populate the `seen` field of the reconcileDiff with `policy`,
// compute BgpServers which must be registered and mark existing BgpServers for
// reconciliation of their configuration.
//
// since registerOrReconcileDiff populates the `seen` field of a diff, this method should always
// be called first when computing a reconcileDiff.
func (wd *reconcileDiff) registerOrReconcileDiff(existingInstances map[string]*instance.EnterpriseBGPInstance, desiredConfig *v1.IsovalentBGPNodeConfig) error {
	for i, config := range desiredConfig.Spec.BGPInstances {
		if _, ok := wd.seen[config.Name]; !ok {
			wd.seen[config.Name] = &desiredConfig.Spec.BGPInstances[i]
		} else {
			return fmt.Errorf("encountered duplicate BGP instance with name %s", config.Name)
		}
		if existing, ok := existingInstances[config.Name]; !ok {
			// new instance
			wd.register = append(wd.register, config.Name)
		} else {
			// existing instance
			recreate, err := wd.requiresRecreate(existing, &desiredConfig.Spec.BGPInstances[i])
			if err != nil {
				return err
			}
			if recreate {
				wd.withdraw = append(wd.withdraw, config.Name)
				wd.register = append(wd.register, config.Name) // register does an initial reconciliation as well
			} else {
				wd.reconcile = append(wd.reconcile, config.Name)
			}
		}
	}
	return nil
}

// requiresRecreate returns true if the desired config change requires full recreate of the BGP instance.
func (wd *reconcileDiff) requiresRecreate(existing *instance.EnterpriseBGPInstance, desiredConfig *v1.IsovalentBGPNodeInstance) (bool, error) {
	localASN, err := getLocalASN(desiredConfig)
	if err != nil {
		return false, fmt.Errorf("failed to get local ASN for instance %v: %w", desiredConfig.Name, err)
	}

	localPort, err := getLocalPort(desiredConfig)
	if err != nil {
		return false, fmt.Errorf("failed to get local port for instance %v: %w", desiredConfig.Name, err)
	}

	routerID, err := getRouterID(desiredConfig, wd.ciliumNode)
	if err != nil {
		return false, fmt.Errorf("failed to get router ID for instance %v: %w", desiredConfig.Name, err)
	}

	return localASN != int64(existing.Global.ASN) || localPort != existing.Global.ListenPort || routerID != existing.Global.RouterID, nil
}

// withdrawDiff will populate the `withdraw` field of a reconcileDiff, indicating which
// existing BgpInstances must be disconnected and removed from the Manager.
func (wd *reconcileDiff) withdrawDiff(existingInstances map[string]*instance.EnterpriseBGPInstance) {
	for k := range existingInstances {
		if _, ok := wd.seen[k]; !ok {
			wd.withdraw = append(wd.withdraw, k)
		}
	}
}

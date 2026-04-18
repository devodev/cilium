//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vrf

import (
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"

	"github.com/cilium/cilium/enterprise/pkg/vrf/config"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func NewVRFTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset, cfg config.Config) (statedb.Table[VRF], error) {
	tbl, err := NewVRFTable(db)
	if err != nil {
		return nil, err
	}
	if !cfg.EnableVRF || !cs.IsEnabled() {
		return tbl, nil
	}

	lw := utils.ListerWatcherFromTyped[*isovalentv1alpha1.IsovalentCoreVRFList](cs.IsovalentV1alpha1().IsovalentCoreVRFs())

	err = k8s.RegisterReflector(jg, db, k8s.ReflectorConfig[VRF]{
		Name:          "vrf",
		Table:         tbl,
		ListerWatcher: lw,
		MetricScope:   "IsovalentCoreVRF",
		Transform: func(_ statedb.ReadTxn, obj any) (VRF, bool) {
			cv, ok := obj.(*isovalentv1alpha1.IsovalentCoreVRF)
			if !ok {
				return VRF{}, false
			}
			return VRF{
				Name:         cv.Name,
				ID:           cv.Spec.ID,
				Table:        cv.Spec.Table,
				NodeSelector: cv.Spec.NodeSelector,
				Selector:     cv.Spec.Selector,
				Interfaces:   cv.Spec.Interfaces,
			}, true
		},
	})
	return tbl, err
}

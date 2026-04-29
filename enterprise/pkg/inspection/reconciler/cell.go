//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"github.com/cilium/hive/cell"
	"k8s.io/apimachinery/pkg/fields"

	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	"github.com/cilium/cilium/pkg/k8s"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

var Cell = cell.Module(
	"inspection-reconciler",
	"Inspection config reconciliation",

	cell.Provide(newInspectionConfigResource),
	cell.Invoke(registerReconciler),
)

func newInspectionConfigResource(cfg inspectionConfig.Config, params k8s.CiliumResourceParams) (resource.Resource[*isovalent_api_v1alpha1.IsovalentInspectionConfig], error) {
	if !cfg.Enabled || !params.ClientSet.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithFields(
		utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentInspectionConfigList](params.ClientSet.IsovalentV1alpha1().IsovalentInspectionConfigs()),
		fields.OneTermEqualSelector("metadata.name", isovalent_api_v1alpha1.InspectionConfigName),
	)
	return resource.New[*isovalent_api_v1alpha1.IsovalentInspectionConfig](params.Lifecycle, lw, params.MetricsProvider,
		resource.WithMetric("IsovalentInspectionConfig"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package t2servicehealth

import (
	enterpriseannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func isRemoteT2HealthService(svc *loadbalancer.Service) bool {
	if svc == nil {
		return false
	}

	if svc.Annotations["loadbalancer.isovalent.com/type"] != "t1" {
		return false
	}

	return svc.Annotations[enterpriseannotation.ServiceHealthMode] == enterpriseannotation.ServiceHealthModeExternal
}

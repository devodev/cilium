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
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

// EnterpriseReconcileParams is an enterprise specific version of reconciler
// params passed to Enterprise config reconcilers.
type EnterpriseReconcileParams struct {
	BGPInstance   *EnterpriseBGPInstance
	DesiredConfig *v1.IsovalentBGPNodeInstance
	CiliumNode    *v2.CiliumNode
}

// EnterpriseStateReconcileParams is an enterprise specific version of
// reconciler params passed to Enterprise state reconcilers.
type EnterpriseStateReconcileParams struct {
	UpdatedInstance *EnterpriseBGPInstance
	DeletedInstance string
}

// FIXME: EnterpriseBGPInstance keeps the existing reconciler code on its
// current local name while the native manager starts using manager/instance
// directly. This is a temporary type alias to minimize the code churn. We can
// remove it once reconcilers fully migrate to the enterprise native
// implementation.
type EnterpriseBGPInstance = instance.EnterpriseBGPInstance

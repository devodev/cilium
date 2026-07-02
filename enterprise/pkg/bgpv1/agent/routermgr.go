// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agent

import (
	"context"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossAgent "github.com/cilium/cilium/pkg/bgp/agent"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

type EnterpriseBGPRouterManager interface {
	ossAgent.BGPRouterManager

	// GetGlobalsExtended returns global BGP configuration of all BGP instances.
	GetGlobalsExtended(ctx context.Context) (*GetGlobalsResponse, error)

	// GetRoutesExtended returns BGP routes of the specified BGP instance from underlying router.
	// If BGP instance is not specified, returns the result of all instances.
	GetRoutesExtended(ctx context.Context, req *GetRoutesExtendedRequest) (*GetRoutesExtendedResponse, error)

	// GetRoutePoliciesExtended returns BGP routing policies of the specified BGP instance from underlying router.
	// If BGP instance is not specified, returns the result of all instances.
	GetRoutePoliciesExtended(ctx context.Context, instance string) (map[string][]*types.ExtendedRoutePolicy, error)

	// ReconcileEnterpriseInstances is the Enterprise-native reconciliation
	// entry point used during the OSS/CEE separation. Once all Enterprise
	// reconcilers use the native config path, this should replace
	// ReconcileInstances.
	ReconcileEnterpriseInstances(ctx context.Context, nodeObj *v1.IsovalentBGPNodeConfig, ciliumNode *v2.CiliumNode) error
}

// GetGlobalsResponse is the response type for GetGlobalsExtended method.
type GetGlobalsResponse struct {
	Instances []InstanceGlobal
}

// GetRoutesExtendedRequest is a request for GetRoutesExtended method.
type GetRoutesExtendedRequest struct {
	TableType ossTypes.TableType
	Family    ossTypes.Family
}

// GetRoutesExtendedResponse is the response type for GetRoutesExtended method.
type GetRoutesExtendedResponse struct {
	Instances []InstanceRoutesExtended
}

// InstanceGlobal holds global BGP configuration for a specific BGP instance.
type InstanceGlobal struct {
	Name   string
	Global ossTypes.BGPGlobal
}

// InstanceRoutesExtended holds routes for a specific BGP instance.
type InstanceRoutesExtended struct {
	InstanceName string
	NeighborName string
	Routes       []*types.ExtendedRoute
}

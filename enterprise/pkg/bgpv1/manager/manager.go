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
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossAgent "github.com/cilium/cilium/pkg/bgp/agent"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/option"
)

type BGPRouterManagerParams struct {
	cell.In

	DaemonConfig     *option.DaemonConfig
	BGPConfig        config.Config
	OSSRouterManager ossAgent.BGPRouterManager
}

func NewBGPRouterManager(params BGPRouterManagerParams) agent.EnterpriseBGPRouterManager {
	// Whenever the OSS BGP Control Plane is enabled, keep using the OSS
	// manager as EnterpriseBGPRouterManager.
	if params.DaemonConfig.BGPControlPlaneEnabled() {
		return params.OSSRouterManager.(agent.EnterpriseBGPRouterManager)
	}

	if !params.BGPConfig.Enabled {
		return nil
	}

	return &BGPRouterManager{}
}

// BGPRouterManager is the Enterprise BGP router manager implementation.
type BGPRouterManager struct{}

func (*BGPRouterManager) ReconcileInstances(context.Context, *v2.CiliumBGPNodeConfig, *v2.CiliumNode) error {
	return nil
}

func (*BGPRouterManager) ReconcileEnterpriseInstances(context.Context, *v1.IsovalentBGPNodeConfig, *v2.CiliumNode) error {
	return nil
}

func (*BGPRouterManager) GetPeers(context.Context, *ossAgent.GetPeersRequest) (*ossAgent.GetPeersResponse, error) {
	return &ossAgent.GetPeersResponse{}, nil
}

func (*BGPRouterManager) GetPeersLegacy(context.Context) ([]*models.BgpPeer, error) {
	return nil, nil
}

func (*BGPRouterManager) GetRoutesLegacy(context.Context, restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	return nil, nil
}

func (*BGPRouterManager) GetRoutePoliciesLegacy(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error) {
	return nil, nil
}

func (*BGPRouterManager) GetRoutes(context.Context, *ossAgent.GetRoutesRequest) (*ossAgent.GetRoutesResponse, error) {
	return &ossAgent.GetRoutesResponse{}, nil
}

func (*BGPRouterManager) GetRoutePolicies(context.Context, *ossAgent.GetRoutePoliciesRequest) (*ossAgent.GetRoutePoliciesResponse, error) {
	return nil, nil
}

func (*BGPRouterManager) Stop(cell.HookContext) error {
	return nil
}

func (*BGPRouterManager) GetRoutesExtended(context.Context, *agent.GetRoutesExtendedRequest) (*agent.GetRoutesExtendedResponse, error) {
	return &agent.GetRoutesExtendedResponse{}, nil
}

func (*BGPRouterManager) GetRoutePoliciesExtended(context.Context, string) (map[string][]*types.ExtendedRoutePolicy, error) {
	return nil, nil
}

var _ agent.EnterpriseBGPRouterManager = (*BGPRouterManager)(nil)

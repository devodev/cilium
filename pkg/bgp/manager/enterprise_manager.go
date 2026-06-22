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
	"fmt"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

var _ agent.EnterpriseBGPRouterManager = (*BGPRouterManager)(nil)

// GetRoutesExtended returns BGP routes of the specified BGP instance from underlying router.
func (m *BGPRouterManager) GetRoutesExtended(ctx context.Context, req *agent.GetRoutesExtendedRequest) (*agent.GetRoutesExtendedResponse, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	var res agent.GetRoutesExtendedResponse
	for _, i := range m.BGPInstances {
		entRouter := i.Router.(types.EnterpriseRouter)

		switch req.TableType {
		case ossTypes.TableTypeAdjRIBIn, ossTypes.TableTypeAdjRIBOut:
			peerState, err := i.Router.GetPeerState(ctx, &ossTypes.GetPeerStateRequest{})
			if err != nil {
				return nil, err
			}

			for _, peer := range peerState.Peers {
				rs, err := entRouter.GetRoutesExtended(ctx, &types.GetRoutesExtendedRequest{
					GetRoutesRequest: ossTypes.GetRoutesRequest{
						TableType: req.TableType,
						Family:    req.Family,
						Neighbor:  peer.Address,
					},
				})
				if err != nil {
					return nil, err
				}
				res.Instances = append(res.Instances, agent.InstanceRoutesExtended{
					InstanceName: i.Name,
					NeighborName: peer.Name,
					Routes:       rs.Routes,
				})
			}
		default:
			rs, err := entRouter.GetRoutesExtended(ctx, &types.GetRoutesExtendedRequest{
				GetRoutesRequest: ossTypes.GetRoutesRequest{
					TableType: req.TableType,
					Family:    req.Family,
				},
			})
			if err != nil {
				return nil, err
			}
			res.Instances = append(res.Instances, agent.InstanceRoutesExtended{
				InstanceName: i.Name,
				Routes:       rs.Routes,
			})
		}
	}
	return &res, nil
}

// GetRoutePoliciesExtended returns BGP routing policies of the specified BGP instance from underlying router.
func (m *BGPRouterManager) GetRoutePoliciesExtended(ctx context.Context, instanceName string) (map[string][]*types.ExtendedRoutePolicy, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	res := make(map[string][]*types.ExtendedRoutePolicy)

	for _, i := range m.BGPInstances {
		if instanceName != "" && i.Name != instanceName {
			continue
		}
		if entRouter, ok := i.Router.(types.EnterpriseRouter); ok {
			resp, err := entRouter.GetRoutePoliciesExtended(ctx)
			if err != nil {
				return nil, err
			}
			res[i.Name] = resp.Policies
		}
	}
	return res, nil
}

// ReconcileEnterpriseInstances is not used by the OSS manager. This exists so
// the OSS manager can satisfy EnterpriseBGPRouterManager while the OSS and CEE
// BGP control planes are both enabled.
func (m *BGPRouterManager) ReconcileEnterpriseInstances(context.Context, *v1.IsovalentBGPNodeConfig, *v2.CiliumNode) error {
	return nil
}

// NotifyStateChange notifies all BGP instances of a state change in the
// underlying router. This is used as a k8s-driven state notification trigger.
func (m *BGPRouterManager) NotifyStateChange() {
	m.Lock()
	defer m.Unlock()

	if !m.running {
		return
	}

	for _, instance := range m.BGPInstances {
		instance.NotifyStateChange()
	}
}

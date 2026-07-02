// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fake

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	ceeTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossFake "github.com/cilium/cilium/pkg/bgp/fake"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

type EnterpriseFakeRouter struct {
	*ossFake.FakeRouter
	Resets           map[netip.Addr]ossTypes.SoftResetDirection
	ResetPeersCh     chan netip.Addr
	extendedPolicies map[string]*ceeTypes.ExtendedRoutePolicy
}

func NewEnterpriseFakeRouter() *EnterpriseFakeRouter {
	return &EnterpriseFakeRouter{
		FakeRouter:       ossFake.NewFakeRouter(),
		Resets:           make(map[netip.Addr]ossTypes.SoftResetDirection),
		ResetPeersCh:     make(chan netip.Addr, 10),
		extendedPolicies: make(map[string]*ceeTypes.ExtendedRoutePolicy),
	}
}

func (f *EnterpriseFakeRouter) GetBGPExtended(ctx context.Context) (*ceeTypes.GetBGPExtendedResponse, error) {
	return nil, fmt.Errorf("GetBGPExtended is not implemented in the fake router")
}

func (f *EnterpriseFakeRouter) GetPeerStateExtended(ctx context.Context, r *ceeTypes.GetPeerStateExtendedRequest) (*ceeTypes.GetPeerStateExtendedResponse, error) {
	return nil, fmt.Errorf("GetPeerStateExtended is not implemented in the fake router")
}

func (f *EnterpriseFakeRouter) ResetNeighbor(ctx context.Context, r ossTypes.ResetNeighborRequest) error {
	if r.Soft {
		f.Resets[r.PeerAddress] = r.SoftResetDirection
	}
	select {
	case f.ResetPeersCh <- r.PeerAddress:
	default:
	}
	return nil
}

func (f *EnterpriseFakeRouter) ResetAllNeighbors(ctx context.Context, r ossTypes.ResetAllNeighborsRequest) error {
	if r.Soft {
		// Use an invalid address to indicate the all reset
		f.Resets[netip.Addr{}] = r.SoftResetDirection
	}
	return nil
}

func (f *EnterpriseFakeRouter) GetRoutesExtended(ctx context.Context, r *ceeTypes.GetRoutesExtendedRequest) (*ceeTypes.GetRoutesExtendedResponse, error) {
	var errs error

	ossResp, err := f.GetRoutes(ctx, &r.GetRoutesRequest)
	if err != nil {
		errs = errors.Join(errs, err)
	}

	extendedRoutes := []*ceeTypes.ExtendedRoute{}
	for _, ossRoute := range ossResp.Routes {
		extendedRoute := &ceeTypes.ExtendedRoute{
			Prefix: ossRoute.Prefix,
		}
		for _, ossPath := range ossRoute.Paths {
			extendedPath := &ceeTypes.ExtendedPath{
				Path: *ossPath,
			}
			extendedRoute.Paths = append(extendedRoute.Paths, extendedPath)
		}
		extendedRoutes = append(extendedRoutes, extendedRoute)
	}

	return &ceeTypes.GetRoutesExtendedResponse{
		Routes: extendedRoutes,
	}, errs
}

// AddRoutePolicyExtended adds a new enterprise-specific routing policy into the underlying router.
func (f *EnterpriseFakeRouter) AddRoutePolicyExtended(ctx context.Context, p ceeTypes.RoutePolicyExtendedRequest) error {
	f.extendedPolicies[p.Policy.Name] = p.Policy
	return nil
}

// RemoveRoutePolicyExtended removes an enterprise-specific routing policy from the underlying router.
func (f *EnterpriseFakeRouter) RemoveRoutePolicyExtended(ctx context.Context, p ceeTypes.RoutePolicyExtendedRequest) error {
	delete(f.extendedPolicies, p.Policy.Name)
	return nil
}

// GetRoutePoliciesExtended retrieves enterprise-specific route extendedPolicies from the underlying router
func (f *EnterpriseFakeRouter) GetRoutePoliciesExtended(ctx context.Context) (*ceeTypes.GetRoutePoliciesExtendedResponse, error) {
	var policies []*ceeTypes.ExtendedRoutePolicy
	for _, policy := range f.extendedPolicies {
		policies = append(policies, policy)
	}
	return &ceeTypes.GetRoutePoliciesExtendedResponse{Policies: policies}, nil
}

// AddNeighborExtended adds a new enterprise-specific BGP peer into the underlying router.
func (f *EnterpriseFakeRouter) AddNeighborExtended(ctx context.Context, n *ceeTypes.EnterpriseNeighbor) error {
	return nil
}

// UpdateNeighborExtended updates enterprise-specific BGP peer into the underlying router.
func (f *EnterpriseFakeRouter) UpdateNeighborExtended(ctx context.Context, n *ceeTypes.EnterpriseNeighbor) error {
	return nil
}

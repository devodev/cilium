// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gobgp

import (
	"errors"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

func ToAgentPathsExtended(paths []*gobgp.Path) ([]*types.ExtendedPath, error) {
	var errs error

	ps := []*types.ExtendedPath{}

	for _, path := range paths {
		p, err := ToAgentPathExtended(path)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		ps = append(ps, p)
	}

	return ps, errs
}

func ToAgentPathExtended(p *gobgp.Path) (*types.ExtendedPath, error) {
	ossPath, err := ToAgentPath(p)
	if err != nil {
		return nil, err
	}

	// We need to handle "invalid IP" case as GoBGP has a bug where it
	// returns string "invalid IP" instead of an empty string for unset
	// neighbor IPs (most likely in case of locally originated paths).
	var neighborAddr netip.Addr
	if p.NeighborIp != "" && p.NeighborIp != "invalid IP" {
		neighborAddr, err = netip.ParseAddr(p.NeighborIp)
		if err != nil {
			return nil, err
		}
	}

	return &types.ExtendedPath{
		Path:         *ossPath,
		NeighborAddr: neighborAddr,
	}, nil
}

func toGoBGPPolicyExtended(apiPolicy *types.ExtendedRoutePolicy) (*gobgp.Policy, []*gobgp.DefinedSet) {
	var definedSets []*gobgp.DefinedSet

	policy := &gobgp.Policy{
		Name: apiPolicy.Name,
	}
	for i, stmt := range apiPolicy.Statements {
		statement, dSets := toGoBGPPolicyStatementExtended(stmt, policyStatementName(apiPolicy.Name, i))
		policy.Statements = append(policy.Statements, statement)
		definedSets = append(definedSets, dSets...)
	}

	return policy, definedSets
}

func toGoBGPPolicyStatementExtended(apiStatement *types.ExtendedRoutePolicyStatement, name string) (*gobgp.Statement, []*gobgp.DefinedSet) {
	// Convert OSS part. This part doesn't have any test coverage as we are
	// relying on the OSS tests. If we cannot reuse the OSS function
	// anymore, we need to add tests for the common conversions as well.
	ossStatement := &ossTypes.RoutePolicyStatement{
		Conditions: apiStatement.Conditions.RoutePolicyConditions,
		Actions:    apiStatement.Actions.RoutePolicyActions,
	}
	s, definedSets := toGoBGPPolicyStatement(ossStatement, name)

	// CEE extensions conversion below

	// defined sets to match communities
	if apiStatement.Conditions.MatchCommunities != nil && len(apiStatement.Conditions.MatchCommunities.Communities) > 0 {
		ds := &gobgp.DefinedSet{
			DefinedType: gobgp.DefinedType_COMMUNITY,
			Name:        policyCommunityDefinedSetName(name),
			List:        apiStatement.Conditions.MatchCommunities.Communities,
		}
		s.Conditions.CommunitySet = &gobgp.MatchSet{
			Type: toGoBGPPolicyMatchType(apiStatement.Conditions.MatchCommunities.Type),
			Name: ds.Name,
		}
		definedSets = append(definedSets, ds)
	}

	// defined sets to match large communities
	if apiStatement.Conditions.MatchLargeCommunities != nil && len(apiStatement.Conditions.MatchLargeCommunities.Communities) > 0 {
		ds := &gobgp.DefinedSet{
			DefinedType: gobgp.DefinedType_LARGE_COMMUNITY,
			Name:        policyLargeCommunityDefinedSetName(name),
			List:        apiStatement.Conditions.MatchLargeCommunities.Communities,
		}
		s.Conditions.LargeCommunitySet = &gobgp.MatchSet{
			Type: toGoBGPPolicyMatchType(apiStatement.Conditions.MatchLargeCommunities.Type),
			Name: ds.Name,
		}
		definedSets = append(definedSets, ds)
	}

	// as path prepend action
	if apiStatement.Actions.ASPathPrepend != nil {
		s.Actions.AsPrepend = &gobgp.AsPrependAction{
			Repeat: apiStatement.Actions.ASPathPrepend.Repeat,
			// "LeftMost" means the last AS added to the AS path.
			// For self-originated routes, this means self-ASN.
			UseLeftMost: true,
		}
	}

	return s, definedSets
}

func toAgentPolicyExtended(p *gobgp.Policy, definedSets map[string]*gobgp.DefinedSet, assignment *gobgp.PolicyAssignment) *types.ExtendedRoutePolicy {
	policy := &types.ExtendedRoutePolicy{
		Name: p.Name,
		Type: toAgentPolicyType(assignment.Direction),
	}
	for _, s := range p.Statements {
		policy.Statements = append(policy.Statements, toAgentPolicyStatementExtended(s, definedSets))
	}
	return policy
}

func toAgentPolicyStatementExtended(s *gobgp.Statement, definedSets map[string]*gobgp.DefinedSet) *types.ExtendedRoutePolicyStatement {
	// Convert OSS part. This part doesn't have any test coverage as we are
	// relying on the OSS tests. If we cannot reuse the OSS function
	// anymore, we need to add tests for the common conversions as well.
	ossStmt := toAgentPolicyStatement(s, definedSets)
	stmt := &types.ExtendedRoutePolicyStatement{
		Conditions: types.ExtendedRoutePolicyConditions{
			RoutePolicyConditions: ossStmt.Conditions,
		},
		Actions: types.ExtendedRoutePolicyActions{
			RoutePolicyActions: ossStmt.Actions,
		},
	}

	// CEE extensions conversion below

	if s.Conditions != nil {
		if s.Conditions.CommunitySet != nil && definedSets[s.Conditions.CommunitySet.Name] != nil {
			stmt.Conditions.MatchCommunities = &types.RoutePolicyCommunityMatch{
				Type:        toAgentPolicyMatchType(s.Conditions.CommunitySet.Type),
				Communities: definedSets[s.Conditions.CommunitySet.Name].List,
			}
		}
		if s.Conditions.LargeCommunitySet != nil && definedSets[s.Conditions.LargeCommunitySet.Name] != nil {
			stmt.Conditions.MatchLargeCommunities = &types.RoutePolicyCommunityMatch{
				Type:        toAgentPolicyMatchType(s.Conditions.LargeCommunitySet.Type),
				Communities: definedSets[s.Conditions.LargeCommunitySet.Name].List,
			}
		}
	}

	if s.Actions != nil && s.Actions.AsPrepend != nil {
		stmt.Actions.ASPathPrepend = &types.ExtendedRoutePolicyActionASPathPrepend{
			Repeat: s.Actions.AsPrepend.Repeat,
		}
	}

	return stmt
}

func policyCommunityDefinedSetName(policyStatementName string) string {
	return policyStatementName + "-community"
}

func policyLargeCommunityDefinedSetName(policyStatementName string) string {
	return policyStatementName + "-large-community"
}

func toGoBGPRouteReflector(n *types.NeighborRouteReflector, g *gobgp.Peer) {
	if n == nil {
		return
	}
	g.RouteReflector = &gobgp.RouteReflector{
		RouteReflectorClient:    n.Client,
		RouteReflectorClusterId: n.ClusterID,
	}
}

func toGoBGPAddPaths(a *types.NeighborAddPath, g *gobgp.Peer) {
	if a == nil {
		return
	}
	addpath := &gobgp.AddPaths{
		Config: &gobgp.AddPathsConfig{
			Receive: false,
			SendMax: a.SendMax,
		},
	}
	for _, fam := range g.AfiSafis {
		fam.AddPaths = addpath
	}
}

func toGoBGPPeerExtended(n *types.EnterpriseNeighbor, oldPeer *gobgp.Peer, v4 bool) *gobgp.Peer {
	goBgpPeer := ToGoBGPPeer(&n.Neighbor, oldPeer, v4)
	toGoBGPRouteReflector(n.RouteReflector, goBgpPeer)
	toGoBGPAddPaths(n.AddPath, goBgpPeer)

	return goBgpPeer
}

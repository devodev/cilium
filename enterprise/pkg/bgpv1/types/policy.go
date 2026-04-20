// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

// RoutePolicyExtendedRequest contains parameters for adding or removing a routing policy.
type RoutePolicyExtendedRequest struct {
	DefaultExportAction ossTypes.RoutePolicyAction
	Policy              *ExtendedRoutePolicy
}

// GetRoutePoliciesExtendedResponse contains route policies retrieved from the underlying router
type GetRoutePoliciesExtendedResponse struct {
	Policies []*ExtendedRoutePolicy
}

// ExtendedRoutePolicy represents a BGP routing policy, also called "route map" in some BGP implementations.
//
// +deepequal-gen=true
type ExtendedRoutePolicy struct {
	// Name is a unique string identifier of the policy for the given router.
	Name string
	// RoutePolicyType is the type of the policy.
	Type ossTypes.RoutePolicyType
	// Statements is an ordered list of policy statements.
	Statements []*ExtendedRoutePolicyStatement
}

// ExtendedRoutePolicyStatement represents a single statement of a routing RoutePolicy. It contains conditions for
// matching a route and actions taken if a route matches the conditions.
//
// +deepequal-gen=true
type ExtendedRoutePolicyStatement struct {
	// Conditions of the statement. If ALL of them match a route, the Actions are taken on the route.
	Conditions ExtendedRoutePolicyConditions
	// Actions define actions taken on a matched route.
	Actions ExtendedRoutePolicyActions
}

// ExtendedRoutePolicyActions represent actions of a policy statement.
//
// +deepequal-gen=true
type ExtendedRoutePolicyActions struct {
	ossTypes.RoutePolicyActions

	// ASPathPrepend contains AS path prepending action parameters.
	ASPathPrepend *ExtendedRoutePolicyActionASPathPrepend
}

// ExtendedRoutePolicyActionASPathPrepend represents AS path prepend action of a policy statement.
//
// +deepequal-gen=true
type ExtendedRoutePolicyActionASPathPrepend struct {
	// How many times the local AS path should be prepended.
	Repeat uint32
}

// ExtendedRoutePolicyConditions represent conditions of a policy statement.
//
// +deepequal-gen=true
type ExtendedRoutePolicyConditions struct {
	ossTypes.RoutePolicyConditions

	// MatchCommunities matches BGP standard community with the provided match rules.
	MatchCommunities *RoutePolicyCommunityMatch

	// MatchLargeCommunities matches BGP large community with the provided match rules.
	MatchLargeCommunities *RoutePolicyCommunityMatch
}

// RoutePolicyCommunityMatch matches BGP community with the provided communities using the provided match logic type.
//
// +deepequal-gen=true
type RoutePolicyCommunityMatch struct {
	// Type of the policy matching logic in case of multiple communities.
	Type ossTypes.RoutePolicyMatchType
	// Communities contains a list of BGP standard communities to match with. Full community values or regexp patterns are allowed.
	Communities []string
}

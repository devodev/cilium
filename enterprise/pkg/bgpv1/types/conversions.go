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
	"errors"
	"net/netip"

	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

func ToRoutePolicy(p *v1.BGPImportPolicy, name string, neighbor netip.Addr, family types.Family) *ExtendedRoutePolicy {
	ret := &ExtendedRoutePolicy{
		Name:       name,
		Type:       types.RoutePolicyTypeImport,
		Statements: make([]*ExtendedRoutePolicyStatement, 0, len(p.Statements)),
	}
	for _, statement := range p.Statements {
		ret.Statements = append(ret.Statements, ToRoutePolicyStatement(&statement, neighbor, family))
	}
	return ret
}

func ValidateAndDefaultImportPolicy(p *v1.BGPImportPolicy, family v2.CiliumBGPFamily) error {
	var errs error
	for i, stmt := range p.Statements {
		err := ValidateAndDefaultPolicyStatement(&stmt, family)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		p.Statements[i] = stmt
	}
	return errs
}

func ToRoutePolicyStatement(s *v1.BGPPolicyStatement, neighbor netip.Addr, family types.Family) *ExtendedRoutePolicyStatement {
	return &ExtendedRoutePolicyStatement{
		Conditions: ToRoutePolicyConditions(&s.Conditions, neighbor, family),
		Actions:    ToRoutePolicyActions(&s.Actions),
	}
}

func ValidateAndDefaultPolicyStatement(s *v1.BGPPolicyStatement, family v2.CiliumBGPFamily) error {
	var errs error
	if err := ValidateAndDefaultPolicyConditions(&s.Conditions, family); err != nil {
		errs = errors.Join(errs, err)
	}
	return errs
}

func ToRoutePolicyConditions(c *v1.BGPPolicyConditions, neighbor netip.Addr, family types.Family) ExtendedRoutePolicyConditions {
	var (
		prefixMatch         *types.RoutePolicyPrefixMatch
		communityMatch      *RoutePolicyCommunityMatch
		largeCommunityMatch *RoutePolicyCommunityMatch
	)

	// We render PrefixesV4 only for the ipv4-unicast family. We never render both v4 and v6 at the same time.
	if c.PrefixesV4 != nil && (family == types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast}) {
		prefixMatch = &types.RoutePolicyPrefixMatch{
			Type: ToRoutePolicyMatchType(c.PrefixesV4.MatchType),
		}
		for _, match := range c.PrefixesV4.Matches {
			p, err := netip.ParsePrefix(match.Prefix)
			if err != nil {
				// Impossible as long as the k8s validation is in place
				continue
			}
			if match.MaxLen == nil {
				// Don't render incomplete match. Should call defaulting before conversion.
				continue
			}
			if match.MinLen == nil {
				// Don't render incomplete match. Should call defaulting before conversion.
				continue
			}
			prefixMatch.Prefixes = append(prefixMatch.Prefixes, types.RoutePolicyPrefix{
				CIDR:         p,
				PrefixLenMax: int(*match.MaxLen),
				PrefixLenMin: int(*match.MinLen),
			})
		}
	}

	// We render PrefixesV6 only for the ipv6-unicast family. We never render both v4 and v6 at the same time.
	if c.PrefixesV6 != nil && (family == types.Family{Afi: types.AfiIPv6, Safi: types.SafiUnicast}) {
		prefixMatch = &types.RoutePolicyPrefixMatch{
			Type: ToRoutePolicyMatchType(c.PrefixesV6.MatchType),
		}
		for _, match := range c.PrefixesV6.Matches {
			p, err := netip.ParsePrefix(match.Prefix)
			if err != nil {
				// Impossible as long as the k8s validation is in place
				continue
			}
			if match.MaxLen == nil {
				// Don't render incomplete match. Should call defaulting before conversion.
				continue
			}
			if match.MinLen == nil {
				// Don't render incomplete match. Should call defaulting before conversion.
				continue
			}
			prefixMatch.Prefixes = append(prefixMatch.Prefixes, types.RoutePolicyPrefix{
				CIDR:         p,
				PrefixLenMax: int(*match.MaxLen),
				PrefixLenMin: int(*match.MinLen),
			})
		}
	}

	if c.Communities != nil {
		communityMatch = &RoutePolicyCommunityMatch{
			Type: ToRoutePolicyMatchType(c.Communities.MatchType),
		}
		for _, match := range c.Communities.Matches {
			if match.Community != nil {
				communityMatch.Communities = append(communityMatch.Communities, (string)(*match.Community))
			}
			if match.WellKnown != nil {
				communityMatch.Communities = append(communityMatch.Communities, (string)(*match.WellKnown))
			}
		}
	}

	if c.LargeCommunities != nil {
		largeCommunityMatch = &RoutePolicyCommunityMatch{
			Type: ToRoutePolicyMatchType(c.LargeCommunities.MatchType),
		}
		for _, match := range c.LargeCommunities.Matches {
			largeCommunityMatch.Communities = append(largeCommunityMatch.Communities, (string)(match.Community))
		}
	}

	return ExtendedRoutePolicyConditions{
		RoutePolicyConditions: types.RoutePolicyConditions{
			MatchNeighbors: &types.RoutePolicyNeighborMatch{
				Type:      types.RoutePolicyMatchAny,
				Neighbors: []netip.Addr{neighbor},
			},
			MatchFamilies: []types.Family{family},
			MatchPrefixes: prefixMatch,
		},
		MatchCommunities:      communityMatch,
		MatchLargeCommunities: largeCommunityMatch,
	}
}

func ValidateAndDefaultPolicyConditions(c *v1.BGPPolicyConditions, family v2.CiliumBGPFamily) error {
	var (
		errs     error
		hasMatch bool
	)
	if c.PrefixesV4 != nil && (family.Afi == "ipv4" && family.Safi == "unicast") {
		hasMatch = true
		if err := ValidateAndDefaultPrefixesV4Condition(c.PrefixesV4); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if c.PrefixesV6 != nil && (family.Afi == "ipv6" && family.Safi == "unicast") {
		hasMatch = true
		if err := ValidateAndDefaultPrefixesV6Condition(c.PrefixesV6); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if c.Communities != nil || c.LargeCommunities != nil {
		hasMatch = true
	}
	if !hasMatch {
		errs = errors.Join(errs, errors.New("no usable match in the conditions"))
	}
	return errs
}

func ValidateAndDefaultPrefixesV4Condition(c *v1.PrefixesV4Condition) error {
	var errs error
	for i, match := range c.Matches {
		if err := ValidateAndDefaultPrefixV4Match(&match); err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		c.Matches[i] = match
	}
	return errs
}

func ValidateAndDefaultPrefixV4Match(m *v1.PrefixV4Match) error {
	p, err := netip.ParsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	pLen := uint8(p.Bits())
	if m.MaxLen == nil {
		m.MaxLen = &pLen
	}
	if m.MinLen == nil {
		m.MinLen = m.MaxLen
	}
	if *m.MinLen > *m.MaxLen {
		return errors.New("minLen must be less than or equal to maxLen")
	}
	return nil
}

func ValidateAndDefaultPrefixesV6Condition(c *v1.PrefixesV6Condition) error {
	var errs error
	for i, match := range c.Matches {
		if err := ValidateAndDefaultPrefixV6Match(&match); err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		c.Matches[i] = match
	}
	return errs
}

func ValidateAndDefaultPrefixV6Match(m *v1.PrefixV6Match) error {
	p, err := netip.ParsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	pLen := uint8(p.Bits())
	if m.MaxLen == nil {
		m.MaxLen = &pLen
	}
	if m.MinLen == nil {
		m.MinLen = m.MaxLen
	}
	if *m.MinLen > *m.MaxLen {
		return errors.New("minLen must be less than or equal to maxLen")
	}
	return nil
}

func ToRoutePolicyActions(a *v1.BGPPolicyActions) ExtendedRoutePolicyActions {
	return ExtendedRoutePolicyActions{
		RoutePolicyActions: types.RoutePolicyActions{
			RouteAction: ToRoutePolicyAction(a.RouteAction),
		},
	}
}

func ToRoutePolicyAction(a v1.BGPRouteAction) types.RoutePolicyAction {
	switch a {
	case v1.BGPRouteActionAccept:
		return types.RoutePolicyActionAccept
	case v1.BGPRouteActionReject:
		return types.RoutePolicyActionReject
	default:
		return types.RoutePolicyActionNone
	}
}

func ToRoutePolicyMatchType(m v1.BGPPolicyMatchType) types.RoutePolicyMatchType {
	switch m {
	case v1.BGPPolicyMatchTypeAnd:
		return types.RoutePolicyMatchAll
	case v1.BGPPolicyMatchTypeNot:
		return types.RoutePolicyMatchInvert
	default:
		return types.RoutePolicyMatchAny
	}
}

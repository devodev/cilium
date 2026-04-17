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
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ResourceRoutePolicyMap holds the route policies per resource.
type ResourceRoutePolicyMap map[resource.Key]RoutePolicyMap

// RoutePolicyMap holds routing policies configured by the policy reconciler keyed by policy name.
type RoutePolicyMap map[string]*types.ExtendedRoutePolicy

type ReconcileRoutePoliciesParams struct {
	Logger          *slog.Logger
	Ctx             context.Context
	Router          types.EnterpriseRouter
	DesiredPolicies RoutePolicyMap
	CurrentPolicies RoutePolicyMap
}

type resetDirections struct {
	in  bool
	out bool
}

func (rd *resetDirections) Update(dir ossTypes.RoutePolicyType) {
	switch dir {
	case ossTypes.RoutePolicyTypeExport:
		rd.out = true
	case ossTypes.RoutePolicyTypeImport:
		rd.in = true
	}
}

func (rd *resetDirections) SoftResetDirection() ossTypes.SoftResetDirection {
	if rd.in && rd.out {
		return ossTypes.SoftResetDirectionBoth
	} else if rd.in {
		return ossTypes.SoftResetDirectionIn
	} else if rd.out {
		return ossTypes.SoftResetDirectionOut
	}
	return ossTypes.SoftResetDirectionNone
}

// ReconcileRoutePolicies reconciles routing policies between the desired and the current state.
// It returns the updated routing policies and an error if the reconciliation fails.
func ReconcileRoutePolicies(rp *ReconcileRoutePoliciesParams) (RoutePolicyMap, error) {
	runningPolicies := make(RoutePolicyMap)
	maps.Copy(runningPolicies, rp.CurrentPolicies)

	var toAdd, toRemove, toUpdate []*types.ExtendedRoutePolicy

	// Tracks which peers have to be reset which direction because of policy change
	resetPeers := map[netip.Addr]*resetDirections{}
	allResetDirs := &resetDirections{}

	upsertResetPeers := func(p *types.ExtendedRoutePolicy) {
		addrs, allPeers := peerAddressesFromPolicy(p)
		if allPeers {
			allResetDirs.Update(p.Type)
			return
		}
		for _, peer := range addrs {
			dirs, found := resetPeers[peer]
			if !found {
				dirs = &resetDirections{}
			}
			dirs.Update(p.Type)
			resetPeers[peer] = dirs
		}
	}

	for _, desired := range rp.DesiredPolicies {
		if current, found := rp.CurrentPolicies[desired.Name]; found {
			if !current.DeepEqual(desired) {
				toUpdate = append(toUpdate, desired)

				// This can be optimized further by checking whether the update
				// is only for the list of neighbors. In that case, the peers in
				// the old policy would not need a reset. At this point, we
				// blindly reset all peers in the old policy for simplicity.
				upsertResetPeers(desired)
				upsertResetPeers(current)
			}
		} else {
			toAdd = append(toAdd, desired)
			upsertResetPeers(desired)
		}
	}
	for _, current := range rp.CurrentPolicies {
		if _, found := rp.DesiredPolicies[current.Name]; !found {
			toRemove = append(toRemove, current)
			upsertResetPeers(current)
		}
	}

	// add missing policies
	for _, p := range toAdd {
		rp.Logger.Debug(
			"Adding route policy",
			ossTypes.PolicyLogField, p.Name,
		)

		err := rp.Router.AddRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{
			DefaultExportAction: ossTypes.RoutePolicyActionReject, // do not advertise routes by default
			Policy:              p,
		})
		if err != nil {
			return runningPolicies, err
		}

		runningPolicies[p.Name] = p
	}

	// update modified policies
	for _, p := range toUpdate {
		// As proper implementation of an update operation for complex policies would be quite involved,
		// we resort to recreating the policies that need an update here.
		rp.Logger.Debug(
			"Updating (re-creating) route policy",
			ossTypes.PolicyLogField, p.Name,
		)

		existing := rp.CurrentPolicies[p.Name]
		err := rp.Router.RemoveRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{Policy: existing})
		if err != nil {
			return runningPolicies, err
		}
		delete(runningPolicies, existing.Name)

		err = rp.Router.AddRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{
			DefaultExportAction: ossTypes.RoutePolicyActionReject, // do not advertise routes by default
			Policy:              p,
		})
		if err != nil {
			return runningPolicies, err
		}

		runningPolicies[p.Name] = p
	}

	// remove old policies
	for _, p := range toRemove {
		rp.Logger.Debug(
			"Removing route policy",
			ossTypes.PolicyLogField, p.Name,
		)

		err := rp.Router.RemoveRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{Policy: p})
		if err != nil {
			return runningPolicies, err
		}
		delete(runningPolicies, p.Name)
	}

	// If we have all reset, process it first
	if allResetDirs.SoftResetDirection() != ossTypes.SoftResetDirectionNone {
		rp.Logger.Debug(
			"Resetting all peers due to a routing policy change",
			ossTypes.DirectionLogField, allResetDirs.SoftResetDirection().String(),
		)

		req := ossTypes.ResetAllNeighborsRequest{
			Soft:               true,
			SoftResetDirection: allResetDirs.SoftResetDirection(),
		}

		if err := rp.Router.ResetAllNeighbors(rp.Ctx, req); err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			rp.Logger.Debug(
				"resetting all peers failed after a routing policy change",
				logfields.Error, err,
				ossTypes.DirectionLogField, allResetDirs.SoftResetDirection().String(),
			)
		}
	}

	// Handle individual neighbor resets
	// soft-reset affected BGP peers to apply the changes on already advertised routes
	for peer, dirs := range resetPeers {
		// Skip if we already did all reset for this exact direction
		if allResetDirs.SoftResetDirection() == dirs.SoftResetDirection() {
			continue
		}
		// Skip if we did all reset for both directions (covers this peer)
		if allResetDirs.SoftResetDirection() == ossTypes.SoftResetDirectionBoth {
			continue
		}
		rp.Logger.Debug(
			"Resetting peer due to a routing policy change",
			ossTypes.PeerLogField, peer,
			ossTypes.DirectionLogField, dirs.SoftResetDirection().String(),
		)

		req := ossTypes.ResetNeighborRequest{
			PeerAddress:        peer,
			Soft:               true,
			SoftResetDirection: dirs.SoftResetDirection(),
		}

		if err := rp.Router.ResetNeighbor(rp.Ctx, req); err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			rp.Logger.Debug(
				"resetting peer failed after a routing policy change",
				logfields.Error, err,
				ossTypes.PeerLogField, peer,
				ossTypes.DirectionLogField, dirs.SoftResetDirection().String(),
			)
		}
	}

	return runningPolicies, nil
}

// PolicyName returns a unique route policy name for the provided peer, family and advertisement type.
// If there is a need for multiple route policies per advertisement type, unique resourceID can be provided.
func PolicyName(peer, family string, advertType v1.IsovalentBGPAdvertType, resourceID string) string {
	if resourceID == "" {
		return fmt.Sprintf("%s-%s-%s", peer, family, advertType)
	}
	return fmt.Sprintf("%s-%s-%s-%s", peer, family, advertType, resourceID)
}

// MergePolicies merges two route policies into a single policy, policy statements are sorted
// based on length of the first prefix in the match prefix list.
func MergePolicies(policyA, policyB *ossTypes.RoutePolicy) (*ossTypes.RoutePolicy, error) {
	// combine route policies into a single policy
	merged, err := reconciler.MergeRoutePolicies(policyA, policyB)
	if err != nil {
		return nil, err
	}

	// Sort statements based on prefix length:
	// - Statements with greater prefix length should go first, so that longer prefix match has higher priority.
	//   Main use-case is service route aggregation, where a single svc can have e.g. /32 and /24 match statements,
	//   and the /32 one should be prioritized.
	// - For simplicity, we only compare the length of the first prefix, as we never populate different prefix lengths
	//   in a single condition. PrefixLenMin and PrefixLenMax are always populated equally, so we only compare one of them.
	sort.SliceStable(merged.Statements, func(i, j int) bool {
		condI := merged.Statements[i].Conditions
		condJ := merged.Statements[j].Conditions
		if condI.MatchPrefixes != nil && condJ.MatchPrefixes != nil &&
			len(condI.MatchPrefixes.Prefixes) > 0 && len(condJ.MatchPrefixes.Prefixes) > 0 {
			return condI.MatchPrefixes.Prefixes[0].PrefixLenMin > condJ.MatchPrefixes.Prefixes[0].PrefixLenMin
		}
		return false
	})

	return merged, nil
}

// MergeRoutePolicies evaluates two instances of RoutePolicy{} and returns a single RoutePolicy{} representing
// the merger of the two.  The merge operation focuses on each policy's Statements.  Statements define one or more
// Actions, and these actions may include setting BGP Communities, Local Preference, and others.  Statements are
// keyed by their Conditions, which define the BGP Neighbor, AF, and Prefixes it applies to.
//
// The merge operation evaluates Actions across only those statements with the same key. For these Statements,
// the merge takes the union of all BGP Communities set.  When differing Local Preference values are set, the
// higher value is selected.
func MergeRoutePolicies(policyA *types.ExtendedRoutePolicy, policyB *types.ExtendedRoutePolicy) (*types.ExtendedRoutePolicy, error) {
	if policyA == nil || policyB == nil {
		return nil, fmt.Errorf("route policy is nil")
	}
	if policyA.Name != policyB.Name {
		return nil, fmt.Errorf("route policy names do not match")
	}
	if policyA.Type != policyB.Type {
		return nil, fmt.Errorf("route policy types do not match")
	}

	mergedPolicy := &types.ExtendedRoutePolicy{
		Name:       policyA.Name,
		Type:       policyA.Type,
		Statements: []*types.ExtendedRoutePolicyStatement{},
	}

	// Maps a string key representing the unique combination of RoutePolicyConditions{} to a RoutePolicyStatement{}.
	// When multiple instances of the same key are observed, the existing RoutePolicyStatement{} will be updated to
	// reflect the union of attributes set.
	mergedPolicyStatements := map[string]*types.ExtendedRoutePolicyStatement{}

	// Extract the first policy's statements and attributes
	mergedPolicyStatements = mergePolicy(policyA, mergedPolicyStatements)

	// Extract and merge the second policy's statements and attributes
	mergedPolicyStatements = mergePolicy(policyB, mergedPolicyStatements)

	for _, mergedStatement := range mergedPolicyStatements {
		mergedPolicy.Statements = append(mergedPolicy.Statements, mergedStatement)
	}

	// Deduplicate communities
	for _, statement := range mergedPolicy.Statements {
		if len(statement.Actions.RoutePolicyActions.AddCommunities) != 0 {
			uniqueCommunities := sets.NewString(statement.Actions.RoutePolicyActions.AddCommunities...).List()
			statement.Actions.RoutePolicyActions.AddCommunities = uniqueCommunities
		}
		if len(statement.Actions.RoutePolicyActions.AddLargeCommunities) != 0 {
			uniqueLargeCommunities := sets.NewString(statement.Actions.RoutePolicyActions.AddLargeCommunities...).List()
			statement.Actions.RoutePolicyActions.AddLargeCommunities = uniqueLargeCommunities
		}
	}

	// Sort statements based on prefix length:
	// - Statements with greater prefix length should go first, so that longer prefix match has higher priority.
	//   Main use-case is service route aggregation, where a single svc can have e.g. /32 and /24 match statements,
	//   and the /32 one should be prioritized.
	// - For simplicity, we only compare the length of the first prefix, as we never populate different prefix lengths
	//   in a single condition. PrefixLenMin and PrefixLenMax are always populated equally, so we only compare one of them.
	sort.SliceStable(mergedPolicy.Statements, func(i, j int) bool {
		condI := mergedPolicy.Statements[i].Conditions
		condJ := mergedPolicy.Statements[j].Conditions
		if condI.MatchPrefixes != nil && condJ.MatchPrefixes != nil &&
			len(condI.MatchPrefixes.Prefixes) > 0 && len(condJ.MatchPrefixes.Prefixes) > 0 {
			return condI.MatchPrefixes.Prefixes[0].PrefixLenMin > condJ.MatchPrefixes.Prefixes[0].PrefixLenMin
		}
		return false
	})

	return mergedPolicy, nil
}

func mergePolicy(
	policy *types.ExtendedRoutePolicy,
	inputPolicyStatements map[string]*types.ExtendedRoutePolicyStatement,
) (outputPolicyStatements map[string]*types.ExtendedRoutePolicyStatement) {

	// This function aims to be purely functional.  Here, we are creating a copy of the input to hold the result
	// of the merge operation.
	outputPolicyStatements = map[string]*types.ExtendedRoutePolicyStatement{}
	maps.Copy(outputPolicyStatements, inputPolicyStatements)

	for _, statement := range policy.Statements {
		key := statement.Conditions.String()
		if _, found := outputPolicyStatements[key]; !found {
			outputPolicyStatements[key] = &types.ExtendedRoutePolicyStatement{
				Actions:    statement.Actions,
				Conditions: statement.Conditions,
			}
		} else {
			if len(statement.Actions.RoutePolicyActions.AddCommunities) > 0 {
				outputPolicyStatements[key].Actions.RoutePolicyActions.AddCommunities = append(
					outputPolicyStatements[key].Actions.RoutePolicyActions.AddCommunities, statement.Actions.RoutePolicyActions.AddCommunities...)
			}
			if len(statement.Actions.RoutePolicyActions.AddLargeCommunities) > 0 {
				outputPolicyStatements[key].Actions.RoutePolicyActions.AddLargeCommunities = append(
					outputPolicyStatements[key].Actions.RoutePolicyActions.AddLargeCommunities, statement.Actions.RoutePolicyActions.AddLargeCommunities...)
			}

			// RFC 4271 states "The higher degree of preference MUST be preferred."
			if statement.Actions.RoutePolicyActions.SetLocalPreference != nil {
				if outputPolicyStatements[key].Actions.RoutePolicyActions.SetLocalPreference == nil {
					// This is the first with Local Preference set
					outputPolicyStatements[key].Actions.RoutePolicyActions.SetLocalPreference = statement.Actions.RoutePolicyActions.SetLocalPreference
				} else if *statement.Actions.RoutePolicyActions.SetLocalPreference > *outputPolicyStatements[key].Actions.RoutePolicyActions.SetLocalPreference {
					// This statement's Local Preference is better than the previous best, use this one.
					outputPolicyStatements[key].Actions.RoutePolicyActions.SetLocalPreference = statement.Actions.RoutePolicyActions.SetLocalPreference
				}
			}
		}
	}

	return outputPolicyStatements
}

// peerAddressesFromPolicy returns neighbor addresses found in a routing policy.
// It returns true when the policy contains the empty MatchNeighbors which means
// all neighbors.
func peerAddressesFromPolicy(p *types.ExtendedRoutePolicy) ([]netip.Addr, bool) {
	if p == nil {
		return []netip.Addr{}, false
	}
	addrs := []netip.Addr{}
	allPeers := false
	for _, s := range p.Statements {
		if s.Conditions.MatchNeighbors == nil || len(s.Conditions.MatchNeighbors.Neighbors) == 0 {
			allPeers = true
		} else {
			addrs = append(addrs, s.Conditions.MatchNeighbors.Neighbors...)
		}
	}
	return addrs, allPeers
}

func CreatePolicy(name string, peerAddr netip.Addr, v4Prefixes, v6Prefixes ossTypes.PolicyPrefixList, advert v1.BGPAdvertisement) (*types.ExtendedRoutePolicy, error) {
	policy := &types.ExtendedRoutePolicy{
		Name: name,
		Type: ossTypes.RoutePolicyTypeExport,
	}

	// sort prefixes to have consistent order for DeepEqual
	sort.Slice(v4Prefixes, v4Prefixes.Less)
	sort.Slice(v6Prefixes, v6Prefixes.Less)

	// get communities
	communities, largeCommunities, err := getCommunities(advert)
	if err != nil {
		return nil, err
	}

	// get local preference
	var localPref *int64
	if advert.Attributes != nil {
		localPref = advert.Attributes.LocalPreference
	}

	// Due to a GoBGP limitation, we need to generate a separate statement for v4 and v6 prefixes, as families
	// can not be mixed in a single statement. Nevertheless, they can be both part of the same Policy.
	if len(v4Prefixes) > 0 {
		policy.Statements = append(policy.Statements, policyStatement(peerAddr, v4Prefixes, localPref, communities, largeCommunities))
	}
	if len(v6Prefixes) > 0 {
		policy.Statements = append(policy.Statements, policyStatement(peerAddr, v6Prefixes, localPref, communities, largeCommunities))
	}

	return policy, nil
}

func getCommunities(advert v1.BGPAdvertisement) (standard, large []string, err error) {
	standard, err = mergeAndDedupCommunities(advert)
	if err != nil {
		return nil, nil, err
	}
	large = dedupLargeCommunities(advert)

	return standard, large, nil
}

// mergeAndDedupCommunities merges numeric standard community and well-known community strings,
// deduplicated by their actual community values.
func mergeAndDedupCommunities(advert v1.BGPAdvertisement) ([]string, error) {
	var res []string

	if advert.Attributes == nil || advert.Attributes.Communities == nil {
		return res, nil
	}

	standard := advert.Attributes.Communities.Standard
	wellKnown := advert.Attributes.Communities.WellKnown

	existing := sets.New[uint32]()
	for _, c := range standard {
		val, err := parseCommunity(string(c))
		if err != nil {
			return nil, fmt.Errorf("failed to parse standard BGP community: %w", err)
		}
		if existing.Has(val) {
			continue
		}
		existing.Insert(val)
		res = append(res, string(c))
	}

	for _, c := range wellKnown {
		val, ok := bgp.WellKnownCommunityValueMap[string(c)]
		if !ok {
			return nil, fmt.Errorf("invalid well-known community value '%s'", c)
		}
		if existing.Has(uint32(val)) {
			continue
		}
		existing.Insert(uint32(val))
		res = append(res, string(c))
	}
	return res, nil
}

func parseCommunity(communityStr string) (uint32, error) {
	// parse as <0-65535>:<0-65535>
	if elems := strings.Split(communityStr, ":"); len(elems) == 2 {
		fst, err := strconv.ParseUint(elems[0], 10, 16)
		if err != nil {
			return 0, err
		}
		snd, err := strconv.ParseUint(elems[1], 10, 16)
		if err != nil {
			return 0, err
		}
		return uint32(fst<<16 | snd), nil
	}
	// parse as a single decimal number
	c, err := strconv.ParseUint(communityStr, 10, 32)
	return uint32(c), err
}

// dedupLargeCommunities returns deduplicated large communities as a string slice.
func dedupLargeCommunities(advert v1.BGPAdvertisement) []string {
	var res []string

	if advert.Attributes == nil || advert.Attributes.Communities == nil {
		return res
	}

	communities := advert.Attributes.Communities.Large

	existing := sets.New[string]()
	for _, c := range communities {
		if existing.Has(string(c)) {
			continue
		}
		existing.Insert(string(c))
		res = append(res, string(c))
	}
	return res
}

func policyStatement(neighborAddr netip.Addr, prefixes ossTypes.PolicyPrefixList, localPref *int64, communities, largeCommunities []string) *types.ExtendedRoutePolicyStatement {
	return &types.ExtendedRoutePolicyStatement{
		Conditions: types.ExtendedRoutePolicyConditions{
			RoutePolicyConditions: ossTypes.RoutePolicyConditions{
				MatchNeighbors: &ossTypes.RoutePolicyNeighborMatch{
					Type:      ossTypes.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{neighborAddr},
				},
				MatchPrefixes: &ossTypes.RoutePolicyPrefixMatch{
					Type:     ossTypes.RoutePolicyMatchAny,
					Prefixes: prefixes,
				},
			},
		},
		Actions: types.ExtendedRoutePolicyActions{
			RoutePolicyActions: ossTypes.RoutePolicyActions{
				RouteAction:         ossTypes.RoutePolicyActionAccept,
				SetLocalPreference:  localPref,
				AddCommunities:      communities,
				AddLargeCommunities: largeCommunities,
			},
		},
	}
}

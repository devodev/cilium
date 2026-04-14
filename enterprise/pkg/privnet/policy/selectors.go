//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"maps"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

var (
	privateNetworkLabel    = labels.LabelSourceCNI + labels.SourceDelimiter + types.CNINetworkNameLabel
	privateNetworkLabelAny = labels.LabelSourceAny + labels.SourceDelimiter + types.CNINetworkNameLabel
)

// hasNetworkSelector returns true if the provided selector has a requirement on types.CNINetworkNameLabel
func hasNetworkSelector(selector *slim_metav1.LabelSelector) bool {
	if _, ok := selector.MatchLabels[privateNetworkLabel]; ok {
		return true
	}
	if _, ok := selector.MatchLabels[privateNetworkLabelAny]; ok {
		return true
	}

	for _, expr := range selector.MatchExpressions {
		if expr.Key == privateNetworkLabel || expr.Key == privateNetworkLabelAny {
			return true
		}
	}

	return false
}

// extractNetworkSelector returns a new selector that contains only the requirements related to types.CNINetworkNameLabel
func extractNetworkSelector(selector *slim_metav1.LabelSelector) *slim_metav1.LabelSelector {
	networkSelector := &slim_metav1.LabelSelector{}

	if match, ok := selector.MatchLabels[privateNetworkLabel]; ok {
		if networkSelector.MatchLabels == nil {
			networkSelector.MatchLabels = make(map[string]string, 1)
		}
		networkSelector.MatchLabels[privateNetworkLabel] = match
	}

	if match, ok := selector.MatchLabels[privateNetworkLabelAny]; ok {
		if networkSelector.MatchLabels == nil {
			networkSelector.MatchLabels = make(map[string]string, 1)
		}
		networkSelector.MatchLabels[privateNetworkLabelAny] = match
	}

	for _, expr := range selector.MatchExpressions {
		if expr.Key == privateNetworkLabel || expr.Key == privateNetworkLabelAny {
			networkSelector.MatchExpressions = append(networkSelector.MatchExpressions, expr)
		}
	}

	return networkSelector
}

// mergedEndpointSelector returns a new endpoint selector that the merged set of the a and b selectors.
func mergedEndpointSelector(a, b *slim_metav1.LabelSelector) *slim_metav1.LabelSelector {
	out := a.DeepCopy()
	maps.Copy(out.MatchLabels, b.MatchLabels)
	out.MatchExpressions = append(out.MatchExpressions, b.MatchExpressions...)
	return out
}

func isWildcard(selector *slim_metav1.LabelSelector) bool {
	return selector != nil &&
		len(selector.MatchLabels)+len(selector.MatchExpressions) == 0
}

// rewriteRuleSelectors rewrites the subject and peer selectors in the provided rule.
// First, we extract the constraints of the subject selector on the network label
// of the selected endpoints. If no constraints are found, we force the subject
// selector to only match endpoints without any network label, i.e. to match only
// endpoints in the default network.
// Second, once the subject selector network constraints have been determined,
// all peer selectors without any network constraints on their own are rewritten
// to inherit the network constraints of the subject selector.
func rewriteRuleSelectors(rule *policyTypes.PolicyEntry) {
	if rule == nil || rule.Subject == nil {
		return
	}

	// Extract network label constraints from the subject selector
	subjectLabelSelector := rule.Subject.GetLabelSelector()
	subjectNetworkConstraints := extractNetworkSelector(subjectLabelSelector)
	if isWildcard(subjectNetworkConstraints) {
		// No network constraints found - force the subject selector to match the default network
		subjectNetworkConstraints.MatchExpressions = append(subjectNetworkConstraints.MatchExpressions,
			slim_metav1.LabelSelectorRequirement{
				Key:      privateNetworkLabel,
				Operator: slim_metav1.LabelSelectorOpDoesNotExist,
			},
		)
		// Rewrite subject selector to contain the above network constraint
		rule.Subject = policyTypes.NewLabelSelector(api.EndpointSelector{
			LabelSelector: mergedEndpointSelector(subjectLabelSelector, subjectNetworkConstraints),
		})
	}

	// Inject network constraints from the subject selector into the peer selectors
	for i, peerSelector := range rule.L3 {
		peerEndpointSelector, ok := peerSelector.(*policyTypes.LabelSelector)
		if !ok {
			continue // not an endpoint selector
		}

		peerLabelSelector := peerEndpointSelector.GetLabelSelector()
		if isWildcard(peerLabelSelector) || hasNetworkSelector(peerLabelSelector) {
			// Leave selectors that have their own network selectors unmodified.
			// Also leave wild card selectors unmodified, as otherwise we break
			// the BPF map optimization were we can write the special ANY identity
			// instead of enumerating all identities in the policy map.
			continue
		}

		// Rewrite peer selector to contain the subject network constraint
		rule.L3[i] = policyTypes.NewLabelSelector(api.EndpointSelector{
			LabelSelector: mergedEndpointSelector(peerLabelSelector, subjectNetworkConstraints),
		})
	}
}

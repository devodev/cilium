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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func matchLabels(lbls ...labels.Label) map[string]string {
	ml := map[string]string{}
	for _, lbl := range lbls {
		ml[lbl.GetExtendedKey()] = lbl.Value
	}
	return ml
}

func Test_rewriteRuleSelectors(t *testing.T) {
	appFooLabel := labels.ParseSelectLabel("app=foo")
	appBarLabel := labels.ParseSelectLabel("app=bar")
	appQuxLabel := labels.ParseSelectLabel("app=qux")

	networkLabel := labels.NewLabel(types.CNINetworkNameLabel, "", labels.LabelSourceCNI)
	networkLabelAny := labels.NewLabel(types.CNINetworkNameLabel, "", labels.LabelSourceAny)
	networkLabelBlue := labels.NewLabel(types.CNINetworkNameLabel, "blue", labels.LabelSourceCNI)
	networkLabelGreen := labels.NewLabel(types.CNINetworkNameLabel, "green", labels.LabelSourceCNI)
	networkLabelRed := labels.NewLabel(types.CNINetworkNameLabel, "red", labels.LabelSourceAny)

	networkRequirementDefault := []slim_metav1.LabelSelectorRequirement{
		{
			Key:      networkLabel.String(),
			Operator: slim_metav1.LabelSelectorOpDoesNotExist,
		},
	}
	networkRequirementBlueOrGreen := []slim_metav1.LabelSelectorRequirement{
		{
			Key:      networkLabel.String(),
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"blue", "green"},
		},
	}
	networkRequirementBlueOrRed := []slim_metav1.LabelSelectorRequirement{
		{
			Key:      networkLabelAny.String(),
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"blue", "red"},
		},
	}

	tests := []struct {
		name string
		rule *policyTypes.PolicyEntry
		want *policyTypes.PolicyEntry
	}{
		{
			name: "nil rule",
		},
		{
			name: "nil subject",
			rule: &policyTypes.PolicyEntry{},
			want: &policyTypes.PolicyEntry{},
		},
		{
			name: "regular subject matches default network",
			rule: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelectorFromLabels(appFooLabel),
				L3: []policyTypes.Selector{
					policyTypes.NewLabelSelectorFromLabels(appBarLabel),
					policyTypes.NewLabelSelectorFromLabels(appQuxLabel, networkLabelBlue),
					policyTypes.WildcardSelector,
				},
			},
			want: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelector(
					// Assert added default network requirement
					api.NewESFromMatchRequirements(
						matchLabels(appFooLabel),
						networkRequirementDefault,
					),
				),
				L3: []policyTypes.Selector{
					// Assert added default network requirement
					policyTypes.NewLabelSelector(
						api.NewESFromMatchRequirements(
							matchLabels(appBarLabel),
							networkRequirementDefault,
						),
					),
					// Assert network requirement unchanged
					policyTypes.NewLabelSelectorFromLabels(appQuxLabel, networkLabelBlue),
					// Assert wildcard selector is unmodified
					policyTypes.WildcardSelector,
				},
			},
		},
		{
			name: "network subject is inherited by peers",
			rule: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelectorFromLabels(appFooLabel, networkLabelBlue),
				L3: []policyTypes.Selector{
					policyTypes.NewLabelSelectorFromLabels(appBarLabel),
					policyTypes.NewLabelSelectorFromLabels(appQuxLabel, networkLabelGreen),
					policyTypes.WildcardSelector,
				},
			},
			want: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelectorFromLabels(appFooLabel, networkLabelBlue),
				L3: []policyTypes.Selector{
					// Assert bar label is added to peers (if absent)
					policyTypes.NewLabelSelectorFromLabels(appBarLabel, networkLabelBlue),
					policyTypes.NewLabelSelectorFromLabels(appQuxLabel, networkLabelGreen),
					// Assert wildcard selector is unmodified
					policyTypes.WildcardSelector,
				},
			},
		},
		{
			name: "match expressions are inherited by peers",
			rule: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelector(
					api.NewESFromMatchRequirements(
						matchLabels(appFooLabel, networkLabelGreen),
						networkRequirementBlueOrGreen,
					),
				),
				L3: []policyTypes.Selector{
					policyTypes.NewLabelSelectorFromLabels(appBarLabel),
					policyTypes.NewLabelSelectorFromLabels(appQuxLabel),
				},
			},
			want: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelector(
					api.NewESFromMatchRequirements(
						matchLabels(appFooLabel, networkLabelGreen),
						networkRequirementBlueOrGreen,
					),
				),
				L3: []policyTypes.Selector{
					policyTypes.NewLabelSelector(
						api.NewESFromMatchRequirements(
							matchLabels(appBarLabel, networkLabelGreen),
							networkRequirementBlueOrGreen,
						),
					),
					policyTypes.NewLabelSelector(
						api.NewESFromMatchRequirements(
							matchLabels(appQuxLabel, networkLabelGreen),
							networkRequirementBlueOrGreen,
						),
					),
				},
			},
		},
		{
			name: "label source any is handled correctly",
			rule: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelector(
					api.NewESFromMatchRequirements(
						matchLabels(appFooLabel, networkLabelRed),
						networkRequirementBlueOrRed,
					),
				),
				L3: []policyTypes.Selector{
					policyTypes.NewLabelSelector(
						api.NewESFromMatchRequirements(
							matchLabels(appBarLabel),
							networkRequirementBlueOrRed,
						),
					),
					policyTypes.NewLabelSelectorFromLabels(appQuxLabel),
				},
			},
			want: &policyTypes.PolicyEntry{
				Subject: policyTypes.NewLabelSelector(
					api.NewESFromMatchRequirements(
						matchLabels(appFooLabel, networkLabelRed),
						networkRequirementBlueOrRed,
					),
				),
				L3: []policyTypes.Selector{
					// peer which already has any: requirement is unchanged
					policyTypes.NewLabelSelector(
						api.NewESFromMatchRequirements(
							matchLabels(appBarLabel),
							networkRequirementBlueOrRed,
						),
					),
					// peer without requirements inherits from subject
					policyTypes.NewLabelSelector(
						api.NewESFromMatchRequirements(
							matchLabels(appQuxLabel, networkLabelRed),
							networkRequirementBlueOrRed,
						),
					),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewriteRuleSelectors(tt.rule)
			require.Equal(t, tt.want, tt.rule)
		})
	}
}

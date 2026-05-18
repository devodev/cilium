//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package wafpolicy

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestReconcilerSetsAcceptedCondition(t *testing.T) {
	scheme := newTestWAFScheme(t)

	testCases := []struct {
		name           string
		policy         *isovalentv1alpha1.IsovalentWAFPolicy
		expectedStatus metav1.ConditionStatus
	}{
		{
			name: "valid policy",
			policy: &isovalentv1alpha1.IsovalentWAFPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "team-a",
					Name:      "policy1",
				},
				Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
					Targets: lbServiceTargets(&slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "api"},
					}),
					Enabled: true,
				},
			},
			expectedStatus: metav1.ConditionTrue,
		},
		{
			name: "invalid policy",
			policy: &isovalentv1alpha1.IsovalentWAFPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "team-a",
					Name:      "policy1",
				},
				Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
					Targets: lbServiceTargets(&slim_metav1.LabelSelector{
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
							Key:      "app",
							Operator: "InvalidOperator",
						}},
					}),
					Enabled: true,
				},
			},
			expectedStatus: metav1.ConditionFalse,
		},
		{
			name: "invalid inline rules",
			policy: &isovalentv1alpha1.IsovalentWAFPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "team-a",
					Name:      "policy1",
				},
				Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
					Targets: lbServiceTargets(&slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "api"},
					}),
					Enabled: true,
					Rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
						Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{
							Inline: `SecRule REQUEST_URI "@rx (" "id:1000,phase:1,deny"`,
						},
					},
				},
			},
			expectedStatus: metav1.ConditionFalse,
		},
		{
			name: "empty inline rules",
			policy: &isovalentv1alpha1.IsovalentWAFPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "team-a",
					Name:      "policy1",
				},
				Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
					Targets: lbServiceTargets(&slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "api"},
					}),
					Enabled: true,
					Rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
						Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{
							Inline: "\n\t \r\n",
						},
					},
				},
			},
			expectedStatus: metav1.ConditionFalse,
		},
		{
			name: "rejects policies that specify both managed and custom rules",
			policy: &isovalentv1alpha1.IsovalentWAFPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "team-a",
					Name:      "policy1",
				},
				Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
					Targets: lbServiceTargets(&slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "api"},
					}),
					Enabled: true,
					Rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
						Managed: &isovalentv1alpha1.IsovalentWAFManagedRules{
							Profile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
						},
						Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{
							Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
						},
					},
				},
			},
			expectedStatus: metav1.ConditionFalse,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler, k8sClient := newTestPolicyReconciler(t, scheme, tc.policy.DeepCopy())

			requireReconciledPolicy(t, reconciler, tc.policy)
			requireAcceptedConditionStatus(t, k8sClient, tc.policy, tc.expectedStatus)
		})
	}
}

func TestReconcilePolicyInlineRules(t *testing.T) {
	expectedInline, err := BuildInlineRules(`SecAction "id:1000,phase:1,pass,nolog"`)
	require.NoError(t, err)

	otherInline, err := BuildInlineRules(`SecAction "id:1001,phase:1,pass,nolog"`)
	require.NoError(t, err)

	scheme := newTestWAFScheme(t)

	testCases := []struct {
		name                    string
		policy                  *isovalentv1alpha1.IsovalentWAFPolicy
		inlineRulesData         map[string]string
		inlineRulesMetadata     map[string]string
		expectedInlineRulesData map[string]string
		expectedMetadataData    map[string]inlineMetadata
	}{
		{
			name:   "publishes desired hash and garbage collects stale entry",
			policy: newInlineBundlePolicy(),
			inlineRulesData: map[string]string{
				"stale": "stale",
			},
			inlineRulesMetadata: map[string]string{
				"stale": `{"policies":["team-a/policy-inline"]}`,
			},
			expectedInlineRulesData: map[string]string{
				expectedInline.HashKey: expectedInline.Inline,
			},
			expectedMetadataData: map[string]inlineMetadata{
				expectedInline.HashKey: {Policies: []string{"team-a/policy-inline"}},
			},
		},
		{
			name: "reuses existing desired hash and removes old hash reference",
			policy: &isovalentv1alpha1.IsovalentWAFPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "team-a",
					Name:      "policy-inline",
				},
				Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
					Rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
						Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{
							Inline: expectedInline.Inline,
						},
					},
				},
			},
			inlineRulesData: map[string]string{
				expectedInline.HashKey: expectedInline.Inline,
				otherInline.HashKey:    otherInline.Inline,
			},
			inlineRulesMetadata: map[string]string{
				expectedInline.HashKey: `{"policies":["team-b/policy-inline"]}`,
				otherInline.HashKey:    `{"policies":["team-a/policy-inline"]}`,
			},
			expectedInlineRulesData: map[string]string{
				expectedInline.HashKey: expectedInline.Inline,
			},
			expectedMetadataData: map[string]inlineMetadata{
				expectedInline.HashKey: {Policies: []string{"team-a/policy-inline", "team-b/policy-inline"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler, k8sClient := newTestReconcilerWithInlineBundleState(
				t,
				scheme,
				tc.inlineRulesData,
				tc.inlineRulesMetadata,
			)

			require.NoError(t, reconciler.reconcilePolicyInlineRules(t.Context(), tc.policy.Namespace+"/"+tc.policy.Name, tc.policy))
			requireInlineBundleState(t, k8sClient, tc.expectedInlineRulesData, tc.expectedMetadataData)
		})
	}
}

func newTestWAFScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(isovalentv1alpha1.AddToScheme(scheme))
	return scheme
}

func newTestPolicyReconciler(
	t *testing.T,
	scheme *runtime.Scheme,
	objects ...client.Object,
) (*reconciler, client.Client) {
	t.Helper()

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.IsovalentWAFPolicy{}).
		WithObjects(objects...).
		Build()

	return newReconciler(hivetest.Logger(t), k8sClient, k8sClient, "kube-system", ""), k8sClient
}

func newTestReconcilerWithInlineBundleState(
	t *testing.T,
	scheme *runtime.Scheme,
	inlineRules, inlineRulesMetadata map[string]string,
) (*reconciler, client.Client) {
	t.Helper()

	inlineRulesCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      DefaultInlineRulesCM,
			Labels:    configMapLabels(),
		},
		Data: combineInlineBundleData(inlineRulesMetadata, inlineRules),
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(inlineRulesCM).
		Build()

	return newReconciler(hivetest.Logger(t), k8sClient, k8sClient, "kube-system", ""), k8sClient
}

func requireReconciledPolicy(t *testing.T, reconciler *reconciler, policy *isovalentv1alpha1.IsovalentWAFPolicy) {
	t.Helper()

	_, err := reconciler.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: policy.Namespace,
			Name:      policy.Name,
		},
	})
	require.NoError(t, err, "unexpected reconciler error")
}

func requireAcceptedConditionStatus(
	t *testing.T,
	k8sClient client.Client,
	policy *isovalentv1alpha1.IsovalentWAFPolicy,
	expectedStatus metav1.ConditionStatus,
) {
	t.Helper()

	updatedPolicy := &isovalentv1alpha1.IsovalentWAFPolicy{}
	err := k8sClient.Get(t.Context(), client.ObjectKeyFromObject(policy), updatedPolicy)
	require.NoError(t, err, "unexpected update policy error")

	condition := updatedPolicy.GetStatusCondition(isovalentv1alpha1.ConditionTypeIsovalentWAFPolicyAccepted)
	require.NotNil(t, condition)
	require.Equal(t, expectedStatus, condition.Status)
}

func requireInlineBundleState(
	t *testing.T,
	k8sClient client.Client,
	expectedInlineRules map[string]string,
	expectedInlineRulesMetadata map[string]inlineMetadata,
) {
	t.Helper()

	updatedInlineCM := &corev1.ConfigMap{}
	err := k8sClient.Get(t.Context(), types.NamespacedName{
		Namespace: "kube-system",
		Name:      DefaultInlineRulesCM,
	}, updatedInlineCM)
	require.NoError(t, err)
	require.Equal(t, expectedInlineRules, extractInlineRules(updatedInlineCM.Data))

	for hashKey, expectedMetadata := range expectedInlineRulesMetadata {
		var actualMetadata inlineMetadata
		actualMetadataData := extractInlineMetadata(updatedInlineCM.Data)
		err = json.Unmarshal([]byte(actualMetadataData[hashKey]), &actualMetadata)
		require.NoError(t, err)
		require.Equal(t, expectedMetadata, actualMetadata)
	}
	require.Len(t, extractInlineMetadata(updatedInlineCM.Data), len(expectedInlineRulesMetadata))
}

func newInlineBundlePolicy() *isovalentv1alpha1.IsovalentWAFPolicy {
	return &isovalentv1alpha1.IsovalentWAFPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "team-a",
			Name:      "policy-inline",
		},
		Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
			Targets: lbServiceTargets(&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "api"},
			}),
			Enabled: true,
			Rules: &isovalentv1alpha1.IsovalentWAFPolicyRules{
				Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{
					Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
				},
			},
		},
	}
}

func lbServiceTargets(selector *slim_metav1.LabelSelector) []isovalentv1alpha1.IsovalentWAFPolicyTarget {
	return []isovalentv1alpha1.IsovalentWAFPolicyTarget{{
		APIGroup:      isovalentv1alpha1.CustomResourceDefinitionGroup,
		Kind:          isovalentv1alpha1.LBServiceKindDefinition,
		LabelSelector: selector,
	}}
}

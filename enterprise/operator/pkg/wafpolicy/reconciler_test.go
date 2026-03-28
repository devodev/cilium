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
	"testing"

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
	scheme := runtime.NewScheme()
	utilruntime.Must(isovalentv1alpha1.AddToScheme(scheme))

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
					Targets: isovalentv1alpha1.IsovalentWAFPolicyTargets{
						LBServices: &isovalentv1alpha1.IsovalentWAFPolicyLBServices{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
					},
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
					Targets: isovalentv1alpha1.IsovalentWAFPolicyTargets{
						LBServices: &isovalentv1alpha1.IsovalentWAFPolicyLBServices{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
									Key:      "app",
									Operator: "InvalidOperator",
								}},
							},
						},
					},
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
					Targets: isovalentv1alpha1.IsovalentWAFPolicyTargets{
						LBServices: &isovalentv1alpha1.IsovalentWAFPolicyLBServices{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
					},
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
					Targets: isovalentv1alpha1.IsovalentWAFPolicyTargets{
						LBServices: &isovalentv1alpha1.IsovalentWAFPolicyLBServices{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
					},
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
					Targets: isovalentv1alpha1.IsovalentWAFPolicyTargets{
						LBServices: &isovalentv1alpha1.IsovalentWAFPolicyLBServices{
							LabelSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "api"},
							},
						},
					},
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
			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&isovalentv1alpha1.IsovalentWAFPolicy{}).
				WithObjects(tc.policy.DeepCopy()).
				Build()

			reconciler := newReconciler(hivetest.Logger(t), k8sClient)

			_, err := reconciler.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: tc.policy.Namespace,
					Name:      tc.policy.Name,
				},
			})
			require.NoError(t, err, "unexpected reconciler error")

			updatedPolicy := &isovalentv1alpha1.IsovalentWAFPolicy{}
			err = k8sClient.Get(t.Context(), client.ObjectKeyFromObject(tc.policy), updatedPolicy)
			require.NoError(t, err, "unexpected update policy error")

			condition := updatedPolicy.GetStatusCondition(isovalentv1alpha1.ConditionTypeIsovalentWAFPolicyAccepted)
			require.NotNil(t, condition)
			require.Equal(t, tc.expectedStatus, condition.Status)
		})
	}
}

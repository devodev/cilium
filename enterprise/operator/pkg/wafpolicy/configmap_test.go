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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestConfigMapNeedsUpdate(t *testing.T) {
	testCases := []struct {
		name        string
		cm          *corev1.ConfigMap
		desiredData map[string]string
		expected    bool
	}{
		{
			name: "matching data and labels do not require update",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "kube-system",
					Name:      DefaultInlineRulesCM,
					Labels:    configMapLabels(),
				},
				Data: map[string]string{
					inlineRulePrefix + "hash-a": "inline-a",
				},
			},
			desiredData: map[string]string{
				inlineRulePrefix + "hash-a": "inline-a",
			},
			expected: false,
		},
		{
			name: "missing labels require update",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "kube-system",
					Name:      DefaultInlineRulesCM,
				},
				Data: map[string]string{
					inlineRulePrefix + "hash-a": "inline-a",
				},
			},
			desiredData: map[string]string{
				inlineRulePrefix + "hash-a": "inline-a",
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, configMapNeedsUpdate(tc.cm, tc.desiredData))
		})
	}
}

func TestConfigMapReconcileInlineBundleCM(t *testing.T) {
	firstInline, err := BuildInlineRules(`SecAction "id:1000,phase:1,pass,nolog"`)
	require.NoError(t, err)

	secondInline, err := BuildInlineRules(`SecAction "id:1001,phase:1,pass,nolog"`)
	require.NoError(t, err)

	testCases := []struct {
		name                   string
		objects                []client.Object
		operations             []configMapReconcileOp
		expectedInlineRules    map[string]string
		expectedInlineMetadata map[string]inlineMetadata
	}{
		{
			name: "creates and appends bundles across reconciles",
			operations: []configMapReconcileOp{
				{
					policyRef:      "team-a/policy-a",
					desiredHashKey: firstInline.HashKey,
					desiredInline:  firstInline.Inline,
				},
				{
					policyRef:      "team-b/policy-b",
					desiredHashKey: secondInline.HashKey,
					desiredInline:  secondInline.Inline,
				},
			},
			expectedInlineRules: map[string]string{
				firstInline.HashKey:  firstInline.Inline,
				secondInline.HashKey: secondInline.Inline,
			},
			expectedInlineMetadata: map[string]inlineMetadata{
				firstInline.HashKey:  {Policies: []string{"team-a/policy-a"}},
				secondInline.HashKey: {Policies: []string{"team-b/policy-b"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler, k8sClient := newConfigMapTestReconciler(t, tc.objects...)
			for _, op := range tc.operations {
				require.NoError(t, reconciler.reconcileInlineBundleCM(
					t.Context(),
					op.policyRef,
					op.desiredHashKey,
					op.desiredInline,
				))
			}
			requireInlineBundleConfigMapState(t, k8sClient, tc.expectedInlineRules, tc.expectedInlineMetadata)
		})
	}
}

type configMapReconcileOp struct {
	policyRef      string
	desiredHashKey string
	desiredInline  string
}

func newConfigMapTestReconciler(t *testing.T, objects ...client.Object) (*reconciler, client.Client) {
	t.Helper()

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		Build()

	return newReconciler(hivetest.Logger(t), k8sClient, k8sClient, "kube-system", ""), k8sClient
}

func requireInlineBundleConfigMapState(
	t *testing.T,
	k8sClient client.Client,
	expectedInlineRules map[string]string,
	expectedInlineMetadata map[string]inlineMetadata,
) {
	t.Helper()

	cm := &corev1.ConfigMap{}
	err := k8sClient.Get(t.Context(), types.NamespacedName{
		Namespace: "kube-system",
		Name:      DefaultInlineRulesCM,
	}, cm)
	require.NoError(t, err)
	require.Equal(t, configMapLabels(), cm.Labels)
	require.Equal(t, expectedInlineRules, extractInlineRules(cm.Data))
	requireInlineBundleMetadataData(t, cm.Data, expectedInlineMetadata)
}

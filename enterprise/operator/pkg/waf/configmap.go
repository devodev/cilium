//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package waf

import (
	"context"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// reconcileInlineBundleCM converges the shared ConfigMap to the desired inline
// bundle state for a single policy reconcile pass.
func (r *reconciler) reconcileInlineBundleCM(
	ctx context.Context,
	policyRef, desiredHashKey string,
	desiredInline string,
) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := r.getConfigMap(ctx, r.inlineRulesCM)
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				return err
			}

			desiredData, err := reconcileInlineBundleState(nil, policyRef, desiredHashKey, desiredInline)
			if err != nil {
				return err
			}
			if desiredData == nil {
				return nil
			}

			if err := r.client.Create(ctx, r.newManagedConfigMap(r.inlineRulesCM, desiredData)); err != nil {
				if k8serrors.IsAlreadyExists(err) {
					return k8serrors.NewConflict(corev1.Resource(corev1.ResourceConfigMaps.String()), r.inlineRulesCM, err)
				}
				return err
			}
			return nil
		}

		desiredData, err := reconcileInlineBundleState(cm.Data, policyRef, desiredHashKey, desiredInline)
		if err != nil {
			return err
		}
		if !configMapNeedsUpdate(cm, desiredData) {
			return nil
		}

		cm.Data = desiredData
		cm.Labels = configMapLabels()
		return r.client.Update(ctx, cm)
	})
	if err != nil {
		return fmt.Errorf("failed to reconcile inline WAF rules ConfigMap: %w", err)
	}

	r.logger.Debug(
		"WAF ConfigMap has been updated",
		logfields.ConfigMapName, client.ObjectKey{
			Namespace: r.namespace,
			Name:      r.inlineRulesCM,
		},
	)

	return nil
}

// removePolicyInlineRules removes every inline bundle reference contributed by
// the given policy and prunes bundles that become unreferenced.
func (r *reconciler) removePolicyInlineRules(ctx context.Context, policyRef string) error {
	var deletedHashes map[string]struct{}

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := r.getConfigMap(ctx, r.inlineRulesCM)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				deletedHashes = map[string]struct{}{}
				return nil
			}
			return err
		}

		desiredData, hashesToDelete, err := removePolicyInlineRulesFromState(cm.Data, policyRef)
		if err != nil {
			return err
		}
		deletedHashes = hashesToDelete
		if !configMapNeedsUpdate(cm, desiredData) {
			return nil
		}

		cm.Data = desiredData
		cm.Labels = configMapLabels()
		return r.client.Update(ctx, cm)
	})
	if err != nil {
		return fmt.Errorf("failed to reconcile WAF inline rules ConfigMap: %w", err)
	}

	r.logger.Debug(
		"WAF inline rules have been removed for policy",
		logfields.PolicyKey, policyRef,
		logfields.PolicyKeysDeleted, slices.Collect(maps.Keys(deletedHashes)),
	)

	return nil
}

func (r *reconciler) getConfigMap(ctx context.Context, name string) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.namespace,
			Name:      name,
		},
	}
	if err := r.cmReader.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		return nil, err
	}
	return cm, nil
}

func (r *reconciler) newManagedConfigMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.namespace,
			Name:      name,
			Labels:    configMapLabels(),
		},
		Data: normalizeConfigMapData(data),
	}
}

func configMapNeedsUpdate(cm *corev1.ConfigMap, desiredData map[string]string) bool {
	return !maps.Equal(cm.Data, desiredData) || !maps.Equal(cm.Labels, configMapLabels())
}

func configMapLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "waf-inline-rule-bundles",
		"app.kubernetes.io/managed-by": "cilium-operator",
		"app.kubernetes.io/part-of":    "cilium",
	}
}

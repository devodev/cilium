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
	"context"
	"fmt"
	"log/slog"
	"maps"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type reconciler struct {
	logger *slog.Logger
	client client.Client
	// ConfigMap reads must bypass the cached manager client. A cached Get would
	// lazily start a ConfigMap informer, which requires cluster-scoped list/watch
	// permissions that this reconciler does not need otherwise.
	cmReader      client.Reader
	namespace     string
	inlineRulesCM string
}

func newReconciler(logger *slog.Logger, client client.Client, cmReader client.Reader, namespace, inlineRulesCM string) *reconciler {
	if namespace == "" {
		namespace = "kube-system"
	}
	if inlineRulesCM == "" {
		inlineRulesCM = DefaultInlineRulesCM
	}

	return &reconciler{
		logger:        logger,
		client:        client,
		cmReader:      cmReader,
		namespace:     namespace,
		inlineRulesCM: inlineRulesCM,
	}
}

func (r *reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&isovalentv1alpha1.IsovalentWAFPolicy{}).
		Complete(r)
}

func (r *reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "IsovalentWAFPolicy",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Debug("Reconciling IsovalentWAFPolicy")
	policy := &isovalentv1alpha1.IsovalentWAFPolicy{}
	if err := r.client.Get(ctx, req.NamespacedName, policy); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get IsovalentWAFPolicy: %w", err))
		}

		scopedLog.Debug("IsovalentWAFPolicy not found - assuming it has been deleted")
		return controllerruntime.Success()
	}

	if policy.GetDeletionTimestamp() != nil {
		scopedLog.Debug("IsovalentWAFPolicy is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	validationErr := Validate(policy)
	if err := r.updateAcceptedCondition(ctx, policy, validationErr); err != nil {
		return controllerruntime.Fail(err)
	}

	if validationErr == nil {
		if err := r.publishInlineBundle(ctx, policy); err != nil {
			return controllerruntime.Fail(fmt.Errorf("failed to publish WAF inline bundle: %w", err))
		}
	}
	return controllerruntime.Success()
}

func (r *reconciler) updateAcceptedCondition(ctx context.Context, policy *isovalentv1alpha1.IsovalentWAFPolicy, validationErr error) error {
	condition := Condition(policy, validationErr)
	if !SetCondition(policy, condition) {
		return nil
	}
	if err := r.client.Status().Update(ctx, policy); err != nil {
		return fmt.Errorf("failed to update IsovalentWAFPolicy status: %w", err)
	}
	return nil
}

func (r *reconciler) publishInlineBundle(ctx context.Context, policy *isovalentv1alpha1.IsovalentWAFPolicy) error {
	entries, err := buildInlineBundleEntries(policy)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		r.logger.Debug("WAF policy does not contain custom inline rules")
		return nil
	}

	inlineCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.namespace,
			Name:      r.inlineRulesCM,
		},
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.cmReader.Get(ctx, client.ObjectKeyFromObject(inlineCM), inlineCM); err != nil {
			if !k8serrors.IsNotFound(err) {
				return err
			}

			applyInlineBundleData(inlineCM, entries)
			if err := r.client.Create(ctx, inlineCM); err != nil {
				if k8serrors.IsAlreadyExists(err) {
					return k8serrors.NewConflict(corev1.Resource("configmaps"), r.inlineRulesCM, err)
				}
				return err
			}
			return nil
		}

		applyInlineBundleData(inlineCM, entries)
		if err := r.client.Update(ctx, inlineCM); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update inline WAF bundle ConfigMap: %w", err)
	}

	r.logger.Debug(
		"WAF inline bundle ConfigMap has been updated",
		logfields.K8sNamespace, policy.Namespace,
		logfields.Name, policy.Name,
		logfields.ConfigMapName, client.ObjectKeyFromObject(inlineCM),
	)

	return nil
}

func buildInlineBundleEntries(policy *isovalentv1alpha1.IsovalentWAFPolicy) (map[string]string, error) {
	if policy == nil || policy.Spec.Rules == nil || policy.Spec.Rules.Custom == nil {
		return nil, nil
	}

	inlineRules, err := BuildInlineRules(policy.Spec.Rules.Custom.Inline)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		inlineRules.HashKey: inlineRules.Inline,
	}, nil
}

func applyInlineBundleData(cm *corev1.ConfigMap, entries map[string]string) {
	cm.Data = mergeInlineBundleData(cm.Data, entries)
	cm.Labels = map[string]string{
		"app.kubernetes.io/name":       "waf-runtime-rules",
		"app.kubernetes.io/managed-by": "cilium-operator",
		"app.kubernetes.io/part-of":    "cilium",
	}
}

func mergeInlineBundleData(existing, updates map[string]string) map[string]string {
	merged := make(map[string]string, len(existing)+len(updates))
	maps.Copy(merged, existing)
	maps.Copy(merged, updates)
	return merged
}

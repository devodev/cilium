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

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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
	policyRef := fmt.Sprintf("%s/%s", req.Namespace, req.Name)
	if err := r.client.Get(ctx, req.NamespacedName, policy); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get IsovalentWAFPolicy: %w", err))
		}

		scopedLog.Debug("IsovalentWAFPolicy not found - assuming it has been deleted")
		if err := r.removePolicyInlineRules(ctx, policyRef); err != nil {
			return controllerruntime.Fail(fmt.Errorf("failed to reconcile WAF inline rules for deleted policy: %w", err))
		}
		return controllerruntime.Success()
	}

	if policy.GetDeletionTimestamp() != nil {
		scopedLog.Debug("IsovalentWAFPolicy is marked for deletion - removing published inline rules")
		if err := r.removePolicyInlineRules(ctx, policyRef); err != nil {
			return controllerruntime.Fail(fmt.Errorf("failed to reconcile WAF inline rules for deleting policy: %w", err))
		}
		return controllerruntime.Success()
	}

	validationErr := Validate(policy)
	if err := r.reconcilePolicyStatus(ctx, policy, validationErr); err != nil {
		return controllerruntime.Fail(err)
	}
	if validationErr != nil {
		if err := r.removePolicyInlineRules(ctx, policyRef); err != nil {
			return controllerruntime.Fail(fmt.Errorf("failed to reconcile WAF inline rules for invalid policy: %w", err))
		}
		return controllerruntime.Success()
	}

	if err := r.reconcilePolicyInlineRules(ctx, policyRef, policy); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to reconcile WAF inline rules: %w", err))
	}
	return controllerruntime.Success()
}

func (r *reconciler) reconcilePolicyStatus(ctx context.Context, policy *isovalentv1alpha1.IsovalentWAFPolicy, validationErr error) error {
	condition := Condition(policy, validationErr)
	if !SetCondition(policy, condition) {
		return nil
	}
	if err := r.client.Status().Update(ctx, policy); err != nil {
		return fmt.Errorf("failed to update IsovalentWAFPolicy status: %w", err)
	}
	return nil
}

func (r *reconciler) reconcilePolicyInlineRules(ctx context.Context, policyRef string, policy *isovalentv1alpha1.IsovalentWAFPolicy) error {
	var desiredHashKey, desiredInline string
	if policy != nil && policy.Spec.Rules != nil && policy.Spec.Rules.Custom != nil {
		rules, err := BuildInlineRules(policy.Spec.Rules.Custom.Inline)
		if err != nil {
			return fmt.Errorf("failed to build WAF inline bundle data: %w", err)
		}
		desiredHashKey = rules.HashKey
		desiredInline = rules.Inline
	}

	if err := r.reconcileInlineBundleCM(ctx, policyRef, desiredHashKey, desiredInline); err != nil {
		return err
	}

	logAttrs := []any{
		logfields.K8sNamespace, policy.Namespace,
		logfields.Name, policy.Name,
		logfields.PolicyKey, policyRef,
	}
	if desiredHashKey != "" {
		logAttrs = append(logAttrs, logfields.PolicyKeysAdded, []string{desiredHashKey})
	}
	r.logger.Debug("WAF inline bundle ConfigMap has been reconciled", logAttrs...)
	return nil
}

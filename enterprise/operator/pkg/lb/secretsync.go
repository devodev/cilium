//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func enqueueTLSSecrets(_ client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Controller, "secrets",
			logfields.Resource, obj.GetName(),
		)

		lbService, ok := obj.(*isovalentv1alpha1.LBService)
		if !ok {
			return nil
		}

		var reqs []reconcile.Request

		allReferencedSecretNames := lbService.AllReferencedSecretNames()
		for _, secretName := range allReferencedSecretNames {
			s := types.NamespacedName{
				Namespace: lbService.Namespace,
				Name:      secretName,
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: s})
			scopedLog.Debug("Enqueued secret for LBService",
				logfields.Secret, s)
		}

		return reqs
	})
}

func isReferencedByLBService(ctx context.Context, c client.Client, logger *slog.Logger, secret *corev1.Secret) bool {
	return len(getLBServicesForSecret(ctx, c, logger, secret)) > 0
}

func getLBServicesForSecret(ctx context.Context, c client.Client, logger *slog.Logger, secret *corev1.Secret) []*isovalentv1alpha1.LBService {
	lbList := isovalentv1alpha1.LBServiceList{}

	listOps := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(lbServiceTlsSecretsIndexName, secret.GetName()),
		Namespace:     secret.GetNamespace(),
	}

	if err := c.List(ctx, &lbList, listOps); err != nil {
		if strings.Contains(err.Error(), "Index with name field:"+lbServiceTlsSecretsIndexName+" does not exist") {
			logger.Info("LBService TLS secret index not yet available, falling back to namespace scan")
			return getLBServicesForSecretWithoutIndex(ctx, c, logger, secret)
		}

		logger.Warn("Failed to list LBServices", logfields.Error, err)
		return nil
	}

	return lbServicesFromList(lbList)
}

func getLBServicesForSecretWithoutIndex(ctx context.Context, c client.Client, logger *slog.Logger, secret *corev1.Secret) []*isovalentv1alpha1.LBService {
	lbList := isovalentv1alpha1.LBServiceList{}

	// Secret sync can run before the LBService controller has registered its field indexes during startup.
	// Fall back to a namespace-local scan so secret sync still behaves correctly until the index is available.
	if err := c.List(ctx, &lbList, client.InNamespace(secret.GetNamespace())); err != nil {
		logger.Warn("Failed to list LBServices without index", logfields.Error, err)
		return nil
	}

	filtered := isovalentv1alpha1.LBServiceList{}
	for _, lbService := range lbList.Items {
		if slices.Contains(lbService.AllReferencedSecretNames(), secret.GetName()) {
			filtered.Items = append(filtered.Items, lbService)
		}
	}

	return lbServicesFromList(filtered)
}

func lbServicesFromList(lbList isovalentv1alpha1.LBServiceList) []*isovalentv1alpha1.LBService {
	result := []*isovalentv1alpha1.LBService{}

	for _, i := range lbList.Items {
		lbfe := i
		result = append(result, &lbfe)
	}

	return result
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package deployment

import (
	"context"
	"log/slog"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type GatewayClassReconciler struct {
	client.Client
	scheme *runtime.Scheme
	logger *slog.Logger
}

func NewGatewayClassReconciler(mgr ctrl.Manager, logger *slog.Logger) *GatewayClassReconciler {
	return &GatewayClassReconciler{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		logger: logger,
	}
}

func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("gateway-api-deployment-gatewayclass").
		For(&gatewayv1.GatewayClass{}, builder.WithPredicates(gatewayClassOwnedByController(controllerName))).
		Complete(r)
}

func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "GatewayClassDeployment",
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.DebugContext(ctx, "Reconciling GatewayClass")

	original := &gatewayv1.GatewayClass{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(err)
	}

	if original.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	updated := original.DeepCopy()
	r.setStatusAccepted(updated, true, "Valid GatewayClass", gatewayv1.GatewayClassReasonAccepted)
	if err := r.Client.Status().Patch(ctx, updated, client.MergeFrom(original)); err != nil {
		scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	return controllerruntime.Success()
}

func (r *GatewayClassReconciler) setStatusAccepted(gwc *gatewayv1.GatewayClass, accepted bool, msg string, reason gatewayv1.GatewayClassConditionReason) {
	status := metav1.ConditionFalse
	if accepted {
		status = metav1.ConditionTrue
	}

	gwc.Status.Conditions = helpers.MergeConditions(gwc.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: gwc.Generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

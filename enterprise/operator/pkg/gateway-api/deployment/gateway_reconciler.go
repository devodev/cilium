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
	"fmt"
	"log/slog"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	gatewayConditionDataplaneReady    = "io.cilium/DataplaneReady"
	gatewayConditionControlplaneReady = "io.cilium/ControlplaneReady"
)

// Gateway API resource attachment labels:
// https://gateway-api.sigs.k8s.io/geps/gep-1762/#resource-attachment
const (
	gatewayNameAttachmentLabel      = "gateway.networking.k8s.io/gateway-name"
	gatewayClassNameAttachmentLabel = "gateway.networking.k8s.io/gateway-class-name"
)

// Standard Kubernetes application labels:
// https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
const (
	appKubernetesNameLabel      = "app.kubernetes.io/name"
	appKubernetesComponentLabel = "app.kubernetes.io/component"
	appKubernetesPartOfLabel    = "app.kubernetes.io/part-of"
	appKubernetesManagedByLabel = "app.kubernetes.io/managed-by"
	appKubernetesInstanceLabel  = "app.kubernetes.io/instance"
)

const (
	gatewayDeploymentManagedBy   = "cilium-operator"
	gatewayDeploymentPartOf      = "cilium-gateway-api-deployment"
	gatewayControlplaneComponent = "controlplane"
	gatewayControlplaneAppName   = "cilium-gateway-controlplane"
	gatewayDataplaneComponent    = "dataplane"
	gatewayDataplaneAppName      = "cilium-gateway-dataplane"
)

const (
	dataplaneResourcePrefix    = "cilium-gwd-"
	controlplaneResourcePrefix = "cilium-gwc-"
)

const (
	bootstrapChecksumAnnotation = "io.cilium.gateway/bootstrap-config-checksum"
)

type GatewayReconciler struct {
	client       client.Client
	scheme       *runtime.Scheme
	logger       *slog.Logger
	config       Config
	daemonConfig *option.DaemonConfig
}

func NewGatewayReconciler(client client.Client, scheme *runtime.Scheme, logger *slog.Logger, config Config, daemonConfig *option.DaemonConfig) *GatewayReconciler {
	return &GatewayReconciler{
		client:       client,
		scheme:       scheme,
		logger:       logger,
		config:       config,
		daemonConfig: daemonConfig,
	}
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("gateway-api-deployment-gateway").
		For(&gatewayv1.Gateway{}, builder.WithPredicates(gatewayOwnedByController(context.Background(), r.client, r.logger))).
		Watches(
			&gatewayv1.GatewayClass{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueRequestForOwningGatewayClass),
			builder.WithPredicates(gatewayClassOwnedByController(controllerName)),
		).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Service{}).
		Complete(r)
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "Gateway",
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.DebugContext(ctx, "Reconciling Gateway")

	gw := &gatewayv1.Gateway{}
	if err := r.client.Get(ctx, req.NamespacedName, gw); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(fmt.Errorf("failed to get Gateway: %w", err))
	}

	if gw.GetDeletionTimestamp() != nil {
		if err := r.cleanupControlplaneResources(ctx, gw); err != nil {
			return controllerruntime.Fail(err)
		}
		return controllerruntime.Success()
	}

	namespace := &corev1.Namespace{}
	if err := r.client.Get(ctx, client.ObjectKey{Name: gw.GetNamespace()}, namespace); err != nil {
		if k8serrors.IsNotFound(err) {
			if cleanupErr := r.cleanupControlplaneResources(ctx, gw); cleanupErr != nil {
				return controllerruntime.Fail(cleanupErr)
			}
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(fmt.Errorf("failed to get Gateway namespace: %w", err))
	}

	if namespace.GetDeletionTimestamp() != nil {
		// Prevent subsequent errors due to namespace deletion.
		scopedLog.InfoContext(ctx, "Aborting reconciliation because namespace is being terminated")
		if cleanupErr := r.cleanupControlplaneResources(ctx, gw); cleanupErr != nil {
			return controllerruntime.Fail(cleanupErr)
		}
		return controllerruntime.Success()
	}

	gwc := &gatewayv1.GatewayClass{}
	if err := r.client.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		if k8serrors.IsNotFound(err) {
			original := gw.DeepCopy()
			r.removeCustomStatusConditions(gw)
			if cleanupErr := r.cleanupDataplaneResources(ctx, gw); cleanupErr != nil {
				return controllerruntime.Fail(cleanupErr)
			}
			if cleanupErr := r.cleanupControlplaneResources(ctx, gw); cleanupErr != nil {
				return controllerruntime.Fail(cleanupErr)
			}
			if statusErr := r.client.Status().Patch(ctx, gw, client.MergeFrom(original)); statusErr != nil {
				return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status after GatewayClass removal: %w", statusErr))
			}
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(fmt.Errorf("failed to get GatewayClass: %w", err))
	}

	if string(gwc.Spec.ControllerName) != controllerName {
		scopedLog.Debug("GatewayClass does not match the deployment controller")
		original := gw.DeepCopy()
		r.removeCustomStatusConditions(gw)
		if err := r.cleanupDataplaneResources(ctx, gw); err != nil {
			return controllerruntime.Fail(err)
		}
		if err := r.cleanupControlplaneResources(ctx, gw); err != nil {
			return controllerruntime.Fail(err)
		}
		if err := r.client.Status().Patch(ctx, gw, client.MergeFrom(original)); err != nil {
			return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status after GatewayClass handoff: %w", err))
		}
		return controllerruntime.Success()
	}

	original := gw.DeepCopy()
	if err := r.reconcileDataplaneResources(ctx, gw); err != nil {
		r.setStatusDataplaneReady(gw, metav1.ConditionFalse, "Failed to reconcile dataplane resources", string(gatewayv1.GatewayReasonPending))
		if statusErr := r.client.Status().Patch(ctx, gw, client.MergeFrom(original)); statusErr != nil {
			scopedLog.ErrorContext(ctx, "Failed to update Gateway status after dataplane reconcile error", logfields.Error, statusErr)
		}
		return controllerruntime.Fail(err)
	}
	if err := r.reconcileControlplaneResources(ctx, gw); err != nil {
		r.setStatusControlplaneReady(gw, metav1.ConditionFalse, "Failed to reconcile controlplane resources", string(gatewayv1.GatewayReasonPending))
		if statusErr := r.client.Status().Patch(ctx, gw, client.MergeFrom(original)); statusErr != nil {
			scopedLog.ErrorContext(ctx, "Failed to update Gateway status after controlplane reconcile error", logfields.Error, statusErr)
		}
		return controllerruntime.Fail(err)
	}

	dataplaneService := &corev1.Service{}
	if err := r.client.Get(ctx, client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, dataplaneService); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to get dataplane Service for Gateway status addresses: %w", err))
	}

	gw.Status.Addresses = gatewayStatusAddressesFromService(dataplaneService)
	r.setStatusDataplaneReady(gw, metav1.ConditionTrue, "Gateway dataplane resources are reconciled", string(gatewayv1.GatewayReasonReady))
	r.setStatusControlplaneReady(gw, metav1.ConditionTrue, "Gateway controlplane resources are reconciled", string(gatewayv1.GatewayReasonReady))
	if err := r.client.Status().Patch(ctx, gw, client.MergeFrom(original)); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *GatewayReconciler) enqueueRequestForOwningGatewayClass(ctx context.Context, obj client.Object) []reconcile.Request {
	gwc, ok := obj.(*gatewayv1.GatewayClass)
	if !ok {
		return nil
	}

	gwList := &gatewayv1.GatewayList{}
	if err := r.client.List(ctx, gwList); err != nil {
		r.logger.ErrorContext(ctx, "Unable to list Gateways", logfields.Error, err)
		return nil
	}

	requests := make([]reconcile.Request, 0, len(gwList.Items))
	for _, gw := range gwList.Items {
		if gw.Spec.GatewayClassName != gatewayv1.ObjectName(gwc.Name) {
			continue
		}

		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&gw),
		})
	}

	return requests
}

func (r *GatewayReconciler) setStatusDataplaneReady(gw *gatewayv1.Gateway, status metav1.ConditionStatus, msg string, reason string) {
	gw.Status.Conditions = helpers.MergeConditions(gw.Status.Conditions, metav1.Condition{
		Type:               gatewayConditionDataplaneReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: gw.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func (r *GatewayReconciler) setStatusControlplaneReady(gw *gatewayv1.Gateway, status metav1.ConditionStatus, msg string, reason string) {
	gw.Status.Conditions = helpers.MergeConditions(gw.Status.Conditions, metav1.Condition{
		Type:               gatewayConditionControlplaneReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: gw.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func (r *GatewayReconciler) removeCustomStatusConditions(gw *gatewayv1.Gateway) {
	filtered := gw.Status.Conditions[:0]
	for _, condition := range gw.Status.Conditions {
		switch condition.Type {
		case gatewayConditionDataplaneReady:
			continue
		case "io.cilium/ControlplaneReady":
			continue
		default:
			filtered = append(filtered, condition)
		}
	}
	gw.Status.Conditions = filtered
}

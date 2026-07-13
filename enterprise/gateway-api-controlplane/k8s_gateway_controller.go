//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayhelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	translation "github.com/cilium/cilium/operator/pkg/model/translation"
	gatewaytranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type gatewayReconciler struct {
	client            client.Client
	logger            *slog.Logger
	xdsMutator        XDSResourceMutator
	targetGateway     types.NamespacedName
	gatewayTranslator translation.Translator
}

type gatewayReconcilerParams struct {
	cell.In

	Logger     *slog.Logger
	Config     Config
	XDSMutator XDSResourceMutator
	CtrlMgr    ctrl.Manager
}

func registerGatewayController(params gatewayReconcilerParams) error {
	if params.Config.GatewayNamespace == "" || params.Config.GatewayName == "" {
		return fmt.Errorf("target Gateway is not configured")
	}

	gatewayReconciler := &gatewayReconciler{
		client:     params.CtrlMgr.GetClient(),
		logger:     params.Logger,
		xdsMutator: params.XDSMutator,
		targetGateway: types.NamespacedName{
			Namespace: params.Config.GatewayNamespace,
			Name:      params.Config.GatewayName,
		},
	}
	translationConfig := translation.Config{
		SecretsNamespace: gatewayReconciler.targetGateway.Namespace,
		HostNetworkConfig: translation.HostNetworkConfig{
			Enabled: true,
		},
		IPConfig: translation.IPConfig{
			IPv4Enabled: true,
			IPv6Enabled: false,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
			UseAppProtocol:     true,
		},
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	}
	cecTranslator := translation.NewCECTranslator(translationConfig)
	gatewayReconciler.gatewayTranslator = gatewaytranslation.NewTranslator(cecTranslator, translationConfig)
	if err := gatewayReconciler.setupWithManager(params.CtrlMgr); err != nil {
		return fmt.Errorf("failed to setup Gateway controller: %w", err)
	}
	gatewayReconciler.logger.Info(
		"Registered Gateway controller in manager",
		logfields.K8sNamespace, gatewayReconciler.targetGateway.Namespace,
		logfields.Gateway, gatewayReconciler.targetGateway.Name,
	)

	return nil
}

func (r *gatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.NamespacedName != r.targetGateway {
		return ctrl.Result{}, nil
	}

	scopedLogger := r.logger.With(
		logfieldController, "gateway-api-controlplane",
		logfields.Resource, req.String(),
	)
	scopedLogger.Debug("Reconciling Gateway")

	var gateway gatewayv1.Gateway
	if err := r.client.Get(ctx, req.NamespacedName, &gateway); err != nil {
		if client.IgnoreNotFound(err) == nil {
			scopedLogger.Info("Gateway not found, clearing xDS snapshot")
			return ctrl.Result{}, r.xdsMutator.ClearSnapshot(ctx, gatewayAsEnvoyClusterName(req.NamespacedName))
		}
		return ctrl.Result{}, err
	}

	// The controlplane relies on the operator-owned custom conditions to decide
	// whether this Gateway still belongs to the deployment-based implementation.
	// This avoids cluster-scoped reads of Namespaces and GatewayClasses from the
	// per-Gateway controlplane pod. The operator removes these custom conditions
	// on handoff, which triggers one last reconcile here via the Gateway update.
	if !ownsGateway(&gateway) {
		scopedLogger.Info("Gateway is no longer owned by the deployment controller, clearing xDS snapshot")
		if err := r.xdsMutator.ClearSnapshot(ctx, gatewayAsEnvoyClusterName(req.NamespacedName)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	original := gateway.DeepCopy()

	scopedLogger.Debug("Translating Gateway to xDS resources", logfields.Gateway, gateway.Name)
	resources, err := r.translateGatewayToXDSResources(ctx, scopedLogger, &gateway)
	if err != nil {
		r.setGatewayAccepted(&gateway, metav1.ConditionTrue, "Gateway is accepted by the controlplane", gatewayv1.GatewayReasonAccepted)
		r.setGatewayProgrammed(&gateway, metav1.ConditionFalse, "Unable to translate Gateway resources", gatewayv1.GatewayReasonListenersNotValid)
		_ = r.patchGatewayStatus(ctx, original, &gateway)
		return ctrl.Result{}, err
	}

	scopedLogger.Debug("Publishing Gateway xDS snapshot")
	if err := r.xdsMutator.UpdateSnapshot(ctx, gatewayAsEnvoyClusterNameObject(&gateway), resources); err != nil {
		r.setGatewayAccepted(&gateway, metav1.ConditionTrue, "Gateway is accepted by the controlplane", gatewayv1.GatewayReasonAccepted)
		r.setGatewayProgrammed(&gateway, metav1.ConditionFalse, "Unable to publish xDS snapshot", gatewayv1.GatewayReasonNoResources)
		_ = r.patchGatewayStatus(ctx, original, &gateway)
		return ctrl.Result{}, err
	}

	r.setGatewayAccepted(&gateway, metav1.ConditionTrue, "Gateway is accepted by the controlplane", gatewayv1.GatewayReasonAccepted)
	r.setGatewayProgrammed(&gateway, metav1.ConditionTrue, "Gateway is programmed by the controlplane", gatewayv1.GatewayReasonProgrammed)

	if err := r.patchGatewayStatus(ctx, original, &gateway); err != nil {
		return ctrl.Result{}, err
	}

	scopedLogger.Debug("Updated Gateway xDS snapshot")
	return ctrl.Result{}, nil
}

func (r *gatewayReconciler) patchGatewayStatus(ctx context.Context, original, gateway *gatewayv1.Gateway) error {
	return r.client.Status().Patch(ctx, gateway, client.MergeFrom(original))
}

func (r *gatewayReconciler) setGatewayAccepted(gateway *gatewayv1.Gateway, status metav1.ConditionStatus, message string, reason gatewayv1.GatewayConditionReason) {
	gateway.Status.Conditions = gatewayhelpers.MergeConditions(
		gateway.Status.Conditions,
		metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             status,
			Reason:             string(reason),
			Message:            message,
			ObservedGeneration: gateway.Generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	)
}

func (r *gatewayReconciler) setGatewayProgrammed(gateway *gatewayv1.Gateway, status metav1.ConditionStatus, message string, reason gatewayv1.GatewayConditionReason) {
	gateway.Status.Conditions = gatewayhelpers.MergeConditions(
		gateway.Status.Conditions,
		metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             status,
			Reason:             string(reason),
			Message:            message,
			ObservedGeneration: gateway.Generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	)
}

func (r *gatewayReconciler) setupWithManager(mgr ctrl.Manager) error {
	targetGatewayPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetNamespace() == r.targetGateway.Namespace && obj.GetName() == r.targetGateway.Name
	})

	// The per-Gateway controlplane intentionally uses coarse same-namespace
	// watches for now. Any change to a potentially relevant namespaced input
	// causes the target Gateway to reconcile, and finer-grained dependency
	// tracking can be added in a later stage.
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}, builder.WithPredicates(targetGatewayPredicate)).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&gatewayv1.TLSRoute{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&gatewayv1.GRPCRoute{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&gatewayv1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&gatewayv1.BackendTLSPolicy{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.enqueueTargetGateway)).
		Complete(r)
}

func (r *gatewayReconciler) enqueueTargetGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj.GetNamespace() != r.targetGateway.Namespace {
		return nil
	}
	return []reconcile.Request{{NamespacedName: r.targetGateway}}
}

func gatewayAsEnvoyClusterName(targetGateway types.NamespacedName) string {
	return targetGateway.Namespace + "/" + targetGateway.Name
}

func gatewayAsEnvoyClusterNameObject(gateway *gatewayv1.Gateway) string {
	return gateway.Namespace + "/" + gateway.Name
}

func ownsGateway(gateway *gatewayv1.Gateway) bool {
	for _, condition := range gateway.Status.Conditions {
		switch condition.Type {
		case "io.cilium/DataplaneReady":
			return true
		case "io.cilium/ControlplaneReady":
			return true
		}
	}

	return false
}

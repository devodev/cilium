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
	"net/http"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_accessloggers_file_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayhelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type gatewayReconciler struct {
	client        client.Client
	logger        *slog.Logger
	xdsMutator    XDSResourceMutator
	targetGateway types.NamespacedName
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
		logfields.Resource, req.NamespacedName.String(),
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
	resources, err := translateGatewayToXDSResources(&gateway)
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}, builder.WithPredicates(targetGatewayPredicate)).
		Complete(r)
}

// translateGatewayToXDSResources is a temporary test translation used to
// exercise the xDS controlplane wiring. It is not yet the intended full
// Gateway API to Envoy xDS translation.
func translateGatewayToXDSResources(gateway *gatewayv1.Gateway) (XDSResources, error) {
	listeners := make([]*envoy_config_listener_v3.Listener, 0, len(gateway.Spec.Listeners))
	routes := make([]*envoy_config_route_v3.RouteConfiguration, 0, len(gateway.Spec.Listeners))

	for _, listener := range gateway.Spec.Listeners {
		if listenerProtocol(listener.Protocol) != "http" {
			continue
		}

		routeName := xdsRouteName(gateway, listener.Name)

		httpConnectionManager, err := anypb.New(&envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{
			StatPrefix: routeName,
			RouteSpecifier: &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_Rds{
				Rds: &envoy_extensions_filters_network_http_connection_manager_v3.Rds{
					ConfigSource: &envoy_config_core_v3.ConfigSource{
						ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
						ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{
							Ads: &envoy_config_core_v3.AggregatedConfigSource{},
						},
					},
					RouteConfigName: routeName,
				},
			},
			AccessLog: []*envoy_config_accesslog_v3.AccessLog{
				{
					Name: "envoy.access_loggers.file",
					ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
						TypedConfig: mustAny(&envoy_extensions_accessloggers_file_v3.FileAccessLog{
							Path: "/dev/stdout",
						}),
					},
				},
			},
			HttpFilters: []*envoy_extensions_filters_network_http_connection_manager_v3.HttpFilter{
				{
					Name: "envoy.filters.http.router",
					ConfigType: &envoy_extensions_filters_network_http_connection_manager_v3.HttpFilter_TypedConfig{
						TypedConfig: mustAny(&envoy_extensions_filters_http_router_v3.Router{}),
					},
				},
			},
		})
		if err != nil {
			return XDSResources{}, fmt.Errorf("failed to marshal HTTP connection manager for listener %q: %w", listener.Name, err)
		}

		listeners = append(listeners, &envoy_config_listener_v3.Listener{
			Name: routeName,
			Address: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: uint32(listener.Port),
						},
					},
				},
			},
			FilterChains: []*envoy_config_listener_v3.FilterChain{
				{
					Filters: []*envoy_config_listener_v3.Filter{
						{
							Name: "envoy.filters.network.http_connection_manager",
							ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
								TypedConfig: httpConnectionManager,
							},
						},
					},
				},
			},
		})

		routes = append(routes, &envoy_config_route_v3.RouteConfiguration{
			Name: routeName,
			VirtualHosts: []*envoy_config_route_v3.VirtualHost{
				{
					Name:    routeName,
					Domains: []string{"*"},
					Routes: []*envoy_config_route_v3.Route{
						{
							Match: &envoy_config_route_v3.RouteMatch{
								PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
									Prefix: "/",
								},
							},
							Action: &envoy_config_route_v3.Route_DirectResponse{
								DirectResponse: &envoy_config_route_v3.DirectResponseAction{
									Status: http.StatusOK,
									Body: &envoy_config_core_v3.DataSource{
										Specifier: &envoy_config_core_v3.DataSource_InlineString{
											InlineString: fmt.Sprintf("gateway: %s/%s\n", gateway.Namespace, gateway.Name),
										},
									},
								},
							},
						},
					},
				},
			},
		})
	}

	return XDSResources{
		Listeners: listeners,
		Routes:    routes,
	}, nil
}

func listenerProtocol(protocol gatewayv1.ProtocolType) string {
	return strings.ToLower(string(protocol))
}

func xdsRouteName(gateway *gatewayv1.Gateway, listenerName gatewayv1.SectionName) string {
	parts := []string{gateway.Namespace, gateway.Name, string(listenerName)}
	return strings.Join(slices.DeleteFunc(parts, func(part string) bool { return part == "" }), "/")
}

func mustAny(message proto.Message) *anypb.Any {
	typedConfig, err := anypb.New(message)
	if err != nil {
		panic(err)
	}

	return typedConfig
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

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extension

import (
	"context"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_network_hcm_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type State any

type ResolveResult struct {
	State          State
	DeferReconcile bool
}

type Target struct {
	GroupKind      schema.GroupKind
	NamespacedName types.NamespacedName
	Labels         map[string]string
}

type HTTPFilter struct {
	// Lower values run first; equal values keep registration order.
	Order  int
	Filter *envoy_extensions_filters_network_hcm_v3.HttpFilter
}

type HTTPRoute struct {
	// Lower values run first; equal values keep registration order.
	Order int
	Route *envoy_config_route_v3.Route
}

type AccessLogField struct {
	Text []string
	JSON map[string]string
}

type HTTPExtension interface {
	Name() string
	Enabled() bool

	WatchNamespaceScoped() []client.Object

	Resolve(context.Context, Target) (ResolveResult, error)

	HTTPFilters(service types.NamespacedName, state State) ([]HTTPFilter, error)
	HTTPRoutes(service types.NamespacedName, state State) ([]HTTPRoute, error)
	AccessLogFields(State) []AccessLogField
}

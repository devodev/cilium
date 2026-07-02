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

	"github.com/cilium/hive/cell"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	lbextension "github.com/cilium/cilium/enterprise/operator/pkg/lb/extension"
	wafenvoy "github.com/cilium/cilium/enterprise/operator/pkg/waf/envoy"
	wafpolicy "github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type lbExtensionOut struct {
	cell.Out

	Extension lbextension.HTTPExtension `group:"lb-http-extensions"`
}

type lbExtension struct {
	resolver   *wafpolicy.Resolver
	translator *wafenvoy.Translator
}

func newLBExtension(resolver *wafpolicy.Resolver, translator *wafenvoy.Translator) lbExtensionOut {
	return lbExtensionOut{
		Extension: &lbExtension{
			resolver:   resolver,
			translator: translator,
		},
	}
}

func (e *lbExtension) Name() string {
	return "waf"
}

func (e *lbExtension) Enabled() bool {
	return e.resolver.Enabled()
}

func (e *lbExtension) WatchNamespaceScoped() []client.Object {
	return []client.Object{&isovalentv1alpha1.IsovalentWAFPolicy{}}
}

func (e *lbExtension) Resolve(ctx context.Context, target lbextension.Target) (lbextension.ResolveResult, error) {
	resolution, err := e.resolver.ResolveConfig(ctx, wafpolicy.PolicyTarget{
		GroupKind:      target.GroupKind,
		NamespacedName: target.NamespacedName,
		Labels:         target.Labels,
	})
	return lbextension.ResolveResult{
		State:          resolution.Config,
		DeferReconcile: resolution.DeferReconcile,
	}, err
}

func (e *lbExtension) HTTPFilters(service types.NamespacedName, state lbextension.State) ([]lbextension.HTTPFilter, error) {
	config, err := effectiveConfig(state)
	if err != nil {
		return nil, err
	}

	filter, err := e.translator.HTTPFilter(service.Name, service.Namespace, config)
	if err != nil {
		return nil, err
	}
	if filter == nil {
		return nil, nil
	}

	return []lbextension.HTTPFilter{{
		Order:  0,
		Filter: filter,
	}}, nil
}

func (e *lbExtension) HTTPRoutes(service types.NamespacedName, state lbextension.State) ([]lbextension.HTTPRoute, error) {
	config, err := effectiveConfig(state)
	if err != nil {
		return nil, err
	}

	route, err := e.translator.BlockRoute(service.Name, service.Namespace, config)
	if err != nil {
		return nil, err
	}
	if route == nil {
		return nil, nil
	}

	return []lbextension.HTTPRoute{{
		Order: 0,
		Route: route,
	}}, nil
}

func (e *lbExtension) AccessLogFields(state lbextension.State) []lbextension.AccessLogField {
	config, ok := state.(*wafpolicy.EffectiveConfig)
	if !ok || config == nil || !config.Enabled {
		return nil
	}

	return []lbextension.AccessLogField{{
		Text: []string{
			`http.req.x-waf-rule-id="%REQ(X-WAF-RULE-ID)%"`,
			`http.req.x-waf-original-path="%REQ(X-WAF-ORIGINAL-PATH)%"`,
			`http.resp.x-waf-rule-id="%RESP(X-WAF-RULE-ID)%"`,
		},
		JSON: map[string]string{
			"http.req.x-waf-rule-id":       "%REQ(X-WAF-RULE-ID)%",
			"http.req.x-waf-original-path": "%REQ(X-WAF-ORIGINAL-PATH)%",
			"http.resp.x-waf-rule-id":      "%RESP(X-WAF-RULE-ID)%",
		},
	}}
}

func effectiveConfig(state lbextension.State) (*wafpolicy.EffectiveConfig, error) {
	if state == nil {
		return nil, nil
	}

	config, ok := state.(*wafpolicy.EffectiveConfig)
	if !ok {
		return nil, fmt.Errorf("unexpected WAF extension state %T", state)
	}
	return config, nil
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package envoy

import (
	"encoding/json"
	"log/slog"

	xds_type_v3 "github.com/cncf/xds/go/xds/type/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_network_hcm_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// HTTPFilterName is the Envoy HTTP filter extension name for dynamic modules.
	HTTPFilterName = "envoy.filters.http.dynamic_modules"
	// HTTPFilterTypeURL identifies the DynamicModuleFilter typed config payload.
	HTTPFilterTypeURL = "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter"
	// DynamicModuleName is the registered dynamic module name Envoy resolves to the shared object.
	DynamicModuleName = "coraza_envoy_filter"
	// FilterName is the filter symbol exposed by the Coraza dynamic module.
	FilterName = "coraza_filter"
	// FilterConfigTypeURL identifies the string-valued Coraza filter config payload.
	FilterConfigTypeURL = "type.googleapis.com/google.protobuf.StringValue"
)

type Translator struct {
	logger  *slog.Logger
	builder ProxyConfigBuilder
}

func NewTranslator(logger *slog.Logger, builder ProxyConfigBuilder) *Translator {
	return &Translator{
		logger:  logger,
		builder: builder,
	}
}

// HTTPFilter builds the Coraza dynamic-module HTTP filter that inspects requests.
func (t *Translator) HTTPFilter(svcName, svcNs string, config *policy.EffectiveConfig) (*envoy_extensions_filters_network_hcm_v3.HttpFilter, error) {
	proxyConfig, err := t.proxyConfig(config)
	if err != nil {
		return nil, err
	}

	if proxyConfig == nil {
		t.logger.Debug(
			"Skipping WAF dynamic module filter",
			logfields.K8sNamespace, svcNs,
			logfields.Service, svcName,
		)
		return nil, nil
	}

	typedConfig, err := toHTTPFilterConfig(proxyConfig)
	if err != nil {
		return nil, err
	}

	return &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: HTTPFilterName,
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: typedConfig,
		},
	}, nil
}

// BlockRoute builds the synthetic direct-response route used for request-phase blocking.
func (t *Translator) BlockRoute(svcName, svcNs string, config *policy.EffectiveConfig) (*envoy_config_route_v3.Route, error) {
	proxyConfig, err := t.proxyConfig(config)
	if err != nil {
		t.logger.Error(
			"Failed to build WAF block route",
			logfields.Error, err,
			logfields.K8sNamespace, svcNs,
			logfields.Service, svcName,
		)
		return nil, err
	}

	if proxyConfig == nil {
		t.logger.Debug(
			"Skipping WAF block route",
			logfields.K8sNamespace, svcNs,
			logfields.Service, svcName,
		)
		return nil, nil
	}

	return &envoy_config_route_v3.Route{
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
				Path: proxyConfig.BlockPath,
			},
		},
		Action: &envoy_config_route_v3.Route_DirectResponse{
			DirectResponse: &envoy_config_route_v3.DirectResponseAction{
				Status: uint32(proxyConfig.ResponseBlockStatus),
				Body: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineString{
						InlineString: proxyConfig.ResponseBlockBody,
					},
				},
			},
		},
	}, nil
}

func (t *Translator) proxyConfig(config *policy.EffectiveConfig) (*ProxyConfig, error) {
	if config == nil {
		return nil, nil
	}

	return t.builder.Build(*config)
}

func toHTTPFilterConfig(config *ProxyConfig) (*anypb.Any, error) {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	filterStruct, err := structpb.NewStruct(map[string]any{
		"dynamic_module_config": map[string]any{
			"name": DynamicModuleName,
		},
		"filter_name": FilterName,
		"filter_config": map[string]any{
			"@type": FilterConfigTypeURL,
			"value": string(configJSON),
		},
	})
	if err != nil {
		return nil, err
	}

	return toAny(&xds_type_v3.TypedStruct{
		TypeUrl: HTTPFilterTypeURL,
		Value:   filterStruct,
	}), nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}

	return a
}

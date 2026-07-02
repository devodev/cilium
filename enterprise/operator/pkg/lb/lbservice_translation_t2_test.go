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
	"testing"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_accessloggers_file_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	envoy_extensions_accessloggers_stream_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	lbextension "github.com/cilium/cilium/enterprise/operator/pkg/lb/extension"
)

func TestDesiredEnvoyHTTPRouteConfigAddsExtensionRoutes(t *testing.T) {
	type expectedRoute struct {
		path                 string
		cluster              string
		directResponseStatus uint32
	}

	testCases := []struct {
		name           string
		httpExtensions []lbextension.HTTPExtension
		expectedRoutes []expectedRoute
	}{
		{
			name: "adds extension route before backend route",
			httpExtensions: []lbextension.HTTPExtension{
				&testHTTPRouteExtension{},
			},
			expectedRoutes: []expectedRoute{
				{path: "/__extension__", directResponseStatus: 418},
				{path: "/api/foo-insecure", cluster: "backend_cluster_app"},
			},
		},
		{
			name: "keeps backend route without extension route",
			expectedRoutes: []expectedRoute{
				{path: "/api/foo-insecure", cluster: "backend_cluster_app"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			translator := &lbServiceT2Translator{
				httpExtensions: tc.httpExtensions,
			}
			routeConfig, err := translator.desiredEnvoyHttpRouteConfig(newHTTPRouteExtensionModel())

			require.NoError(t, err)
			require.Len(t, routeConfig.VirtualHosts, 1)
			require.Len(t, routeConfig.VirtualHosts[0].Routes, len(tc.expectedRoutes))

			for i, expectedRoute := range tc.expectedRoutes {
				actualRoute := routeConfig.VirtualHosts[0].Routes[i]
				require.Equal(t, expectedRoute.path, actualRoute.GetMatch().GetPath())
				if expectedRoute.directResponseStatus != 0 {
					require.Equal(t, expectedRoute.directResponseStatus, actualRoute.GetDirectResponse().GetStatus())
					continue
				}
				require.Equal(t, expectedRoute.cluster, actualRoute.GetRoute().GetCluster())
			}
		})
	}
}

func TestDesiredEnvoyAccessLoggersAddsExtensionFields(t *testing.T) {
	model := &lbService{
		namespace: "default",
		name:      "demo",
		httpExtensionStates: map[string]lbextension.State{
			"access-log": struct{}{},
		},
	}

	testCases := []struct {
		name               string
		httpExtensions     []lbextension.HTTPExtension
		expectedTextFormat string
		expectedJSONFields map[string]any
	}{
		{
			name:               "adds extension fields",
			httpExtensions:     []lbextension.HTTPExtension{&testAccessLogExtension{}},
			expectedTextFormat: "service.name=\"demo\" ext.field=\"%REQ(X-EXT)%\"\n",
			expectedJSONFields: map[string]any{
				"service.name": "demo",
				"ext.field":    "%REQ(X-EXT)%",
			},
		},
		{
			name:               "keeps base fields without extension",
			expectedTextFormat: "service.name=\"demo\"\n",
			expectedJSONFields: map[string]any{
				"service.name": "demo",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			translator := &lbServiceT2Translator{
				config: reconcilerConfig{
					AccessLog: reconcilerAccesslogConfig{
						EnableStdOut: true,
						FilePath:     "/tmp/access.log",
					},
				},
				httpExtensions: tc.httpExtensions,
			}
			accessLoggers := translator.desiredEnvoyAccessLoggers(
				model,
				`service.name="%SERVICE_NAME%"`,
				`{"service.name":"%SERVICE_NAME%"}`,
				translator.accessLogFields(model),
			)

			require.Len(t, accessLoggers, 2)

			stdout := &envoy_extensions_accessloggers_stream_v3.StdoutAccessLog{}
			require.NoError(t, accessLoggers[0].GetTypedConfig().UnmarshalTo(stdout))
			require.Equal(t,
				tc.expectedTextFormat,
				stdout.GetLogFormat().GetTextFormatSource().GetInlineString(),
			)

			file := &envoy_extensions_accessloggers_file_v3.FileAccessLog{}
			require.NoError(t, accessLoggers[1].GetTypedConfig().UnmarshalTo(file))
			require.Equal(t, tc.expectedJSONFields, file.GetLogFormat().GetJsonFormat().AsMap())
		})
	}
}

func TestAppendTextAccessLogFields(t *testing.T) {
	testCases := []struct {
		name     string
		format   string
		fields   []lbextension.AccessLogField
		expected string
	}{
		{
			name:     "no fields trims base format",
			format:   ` service.name="%SERVICE_NAME%" `,
			expected: `service.name="%SERVICE_NAME%"`,
		},
		{
			name:   "appends single field",
			format: `service.name="%SERVICE_NAME%"`,
			fields: []lbextension.AccessLogField{{
				Text: []string{`ext.field="%REQ(X-EXT)%"`},
			}},
			expected: `service.name="%SERVICE_NAME%" ext.field="%REQ(X-EXT)%"`,
		},
		{
			name:   "appends multiple fields in order",
			format: `service.name="%SERVICE_NAME%"`,
			fields: []lbextension.AccessLogField{
				{Text: []string{`ext.a="%REQ(X-A)%"`, `ext.b="%REQ(X-B)%"`}},
				{Text: []string{`ext.c="%REQ(X-C)%"`}},
			},
			expected: `service.name="%SERVICE_NAME%" ext.a="%REQ(X-A)%" ext.b="%REQ(X-B)%" ext.c="%REQ(X-C)%"`,
		},
		{
			name: "uses field when base format is empty",
			fields: []lbextension.AccessLogField{{
				Text: []string{` ext.field="%REQ(X-EXT)%" `},
			}},
			expected: `ext.field="%REQ(X-EXT)%"`,
		},
		{
			name:   "skips empty text entries",
			format: `service.name="%SERVICE_NAME%"`,
			fields: []lbextension.AccessLogField{{
				Text: []string{"", " \t ", `ext.field="%REQ(X-EXT)%"`},
			}},
			expected: `service.name="%SERVICE_NAME%" ext.field="%REQ(X-EXT)%"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, appendTextAccessLogFields(tc.format, tc.fields))
		})
	}
}

func newHTTPRouteExtensionModel() *lbService {
	return &lbService{
		namespace: "default",
		name:      "extension-route",
		applications: lbApplications{
			httpProxy: &lbApplicationHTTPProxy{
				routes: map[string][]lbRouteHTTP{
					"insecure.acme.io": {
						{
							match: lbRouteHTTPMatch{
								path:     "/api/foo-insecure",
								pathType: routePathTypeExact,
							},
							backendRef: backendRef{name: "app"},
						},
					},
				},
			},
		},
		httpExtensionStates: map[string]lbextension.State{
			"route": struct{}{},
		},
	}
}

type testHTTPRouteExtension struct{}

func (e *testHTTPRouteExtension) Name() string {
	return "route"
}

func (e *testHTTPRouteExtension) Enabled() bool {
	return true
}

func (e *testHTTPRouteExtension) WatchNamespaceScoped() []client.Object {
	return nil
}

func (e *testHTTPRouteExtension) Resolve(context.Context, lbextension.Target) (lbextension.ResolveResult, error) {
	return lbextension.ResolveResult{}, nil
}

func (e *testHTTPRouteExtension) HTTPFilters(types.NamespacedName, lbextension.State) ([]lbextension.HTTPFilter, error) {
	return nil, nil
}

func (e *testHTTPRouteExtension) HTTPRoutes(types.NamespacedName, lbextension.State) ([]lbextension.HTTPRoute, error) {
	return []lbextension.HTTPRoute{{
		Route: &envoy_config_route_v3.Route{
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{Path: "/__extension__"},
			},
			Action: &envoy_config_route_v3.Route_DirectResponse{
				DirectResponse: &envoy_config_route_v3.DirectResponseAction{Status: 418},
			},
		},
	}}, nil
}

func (e *testHTTPRouteExtension) AccessLogFields(lbextension.State) []lbextension.AccessLogField {
	return nil
}

type testAccessLogExtension struct{}

func (e *testAccessLogExtension) Name() string {
	return "access-log"
}

func (e *testAccessLogExtension) Enabled() bool {
	return true
}

func (e *testAccessLogExtension) WatchNamespaceScoped() []client.Object {
	return nil
}

func (e *testAccessLogExtension) Resolve(context.Context, lbextension.Target) (lbextension.ResolveResult, error) {
	return lbextension.ResolveResult{}, nil
}

func (e *testAccessLogExtension) HTTPFilters(types.NamespacedName, lbextension.State) ([]lbextension.HTTPFilter, error) {
	return nil, nil
}

func (e *testAccessLogExtension) HTTPRoutes(types.NamespacedName, lbextension.State) ([]lbextension.HTTPRoute, error) {
	return nil, nil
}

func (e *testAccessLogExtension) AccessLogFields(lbextension.State) []lbextension.AccessLogField {
	return []lbextension.AccessLogField{{
		Text: []string{`ext.field="%REQ(X-EXT)%"`},
		JSON: map[string]string{"ext.field": "%REQ(X-EXT)%"},
	}}
}

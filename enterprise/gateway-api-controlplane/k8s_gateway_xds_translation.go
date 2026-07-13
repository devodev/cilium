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
	"maps"
	"slices"
	"strconv"
	"strings"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayhelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type translationInputs struct {
	HTTPRoutes         []gatewayv1.HTTPRoute
	TLSRoutes          []gatewayv1.TLSRoute
	GRPCRoutes         []gatewayv1.GRPCRoute
	ReferenceGrants    []gatewayv1.ReferenceGrant
	BackendTLSPolicies []gatewayv1.BackendTLSPolicy
	Services           []corev1.Service
	EndpointSlices     []discoveryv1.EndpointSlice
	Secrets            []corev1.Secret
	ConfigMaps         []corev1.ConfigMap
}

const (
	secretSourceKindSecret    = "Secret"
	secretSourceKindConfigMap = "ConfigMap"
)

func (r *gatewayReconciler) translateGatewayToXDSResources(
	ctx context.Context,
	logger *slog.Logger,
	gateway *gatewayv1.Gateway,
) (XDSResources, error) {
	rawInputs, err := r.loadTranslationInputs(ctx)
	if err != nil {
		return XDSResources{}, err
	}

	model := ingestion.GatewayAPI(logger, r.buildIngestionInput(gateway, rawInputs))

	cec, _, _, err := r.gatewayTranslator.Translate(model)
	if err != nil {
		return XDSResources{}, fmt.Errorf("failed to translate Gateway to shared Gateway API model resources: %w", err)
	}
	if cec == nil {
		return XDSResources{}, nil
	}

	resources, err := decodeCECResources(cec.Spec.Resources)
	if err != nil {
		return XDSResources{}, err
	}

	secretNames := gatherReferencedSecrets(model)
	secretData := indexSecrets(rawInputs.Secrets)
	configMapData := indexConfigMaps(rawInputs.ConfigMaps)

	if err := normalizeXDSResources(resources, secretNames); err != nil {
		return XDSResources{}, err
	}

	endpoints, err := buildEndpointAssignments(resources.Clusters, rawInputs.Services, rawInputs.EndpointSlices)
	if err != nil {
		return XDSResources{}, err
	}

	secrets, err := buildSecretResources(secretNames, secretData, configMapData)
	if err != nil {
		return XDSResources{}, err
	}

	resources.Endpoints = endpoints
	resources.Secrets = secrets

	logger.Debug(
		"Translated Gateway to xDS resources",
		logfields.Gateway, gateway.Name,
		logfieldListeners, len(resources.Listeners),
		logfieldRoutes, len(resources.Routes),
		logfieldClusters, len(resources.Clusters),
		logfieldEndpoints, len(resources.Endpoints),
		logfieldSecrets, len(resources.Secrets),
	)

	return resources, nil
}

func (r *gatewayReconciler) buildIngestionInput(gateway *gatewayv1.Gateway, rawInputs translationInputs) ingestion.Input {
	// The per-Gateway controlplane intentionally stays namespaced-only for now.
	// That means translation is currently limited to same-namespace inputs.
	return ingestion.Input{
		Gateway:             *gateway,
		HTTPRoutes:          rawInputs.HTTPRoutes,
		TLSRoutes:           rawInputs.TLSRoutes,
		GRPCRoutes:          rawInputs.GRPCRoutes,
		ReferenceGrants:     rawInputs.ReferenceGrants,
		Namespaces:          []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: r.targetGateway.Namespace}}},
		Services:            rawInputs.Services,
		BackendTLSPolicyMap: gatewayhelpers.BuildBackendTLSPolicyLookup(&gatewayv1.BackendTLSPolicyList{Items: rawInputs.BackendTLSPolicies}),
	}
}

// loadTranslationInputs intentionally gathers the full set of potentially
// relevant namespaced inputs for the target Gateway. This coarse same-namespace
// loading keeps the current implementation simple; later stages can narrow the
// input set once the dependency graph is modeled more explicitly.
func (r *gatewayReconciler) loadTranslationInputs(ctx context.Context) (translationInputs, error) {
	var out translationInputs
	namespace := r.targetGateway.Namespace

	// For now, list all candidate resources from the Gateway namespace and let
	// the downstream translation path decide which ones are actually consumed.
	for _, item := range []struct {
		list client.ObjectList
		dst  any
	}{
		{list: &gatewayv1.HTTPRouteList{}, dst: &out.HTTPRoutes},
		{list: &gatewayv1.TLSRouteList{}, dst: &out.TLSRoutes},
		{list: &gatewayv1.GRPCRouteList{}, dst: &out.GRPCRoutes},
		{list: &gatewayv1.ReferenceGrantList{}, dst: &out.ReferenceGrants},
		{list: &gatewayv1.BackendTLSPolicyList{}, dst: &out.BackendTLSPolicies},
		{list: &corev1.ServiceList{}, dst: &out.Services},
		{list: &discoveryv1.EndpointSliceList{}, dst: &out.EndpointSlices},
		{list: &corev1.SecretList{}, dst: &out.Secrets},
		{list: &corev1.ConfigMapList{}, dst: &out.ConfigMaps},
	} {
		if err := r.client.List(ctx, item.list, client.InNamespace(namespace)); err != nil {
			return translationInputs{}, fmt.Errorf("failed to list %T in namespace %q: %w", item.list, namespace, err)
		}

		switch list := item.list.(type) {
		case *gatewayv1.HTTPRouteList:
			*item.dst.(*[]gatewayv1.HTTPRoute) = list.Items
		case *gatewayv1.TLSRouteList:
			*item.dst.(*[]gatewayv1.TLSRoute) = list.Items
		case *gatewayv1.GRPCRouteList:
			*item.dst.(*[]gatewayv1.GRPCRoute) = list.Items
		case *gatewayv1.ReferenceGrantList:
			*item.dst.(*[]gatewayv1.ReferenceGrant) = list.Items
		case *gatewayv1.BackendTLSPolicyList:
			*item.dst.(*[]gatewayv1.BackendTLSPolicy) = list.Items
		case *corev1.ServiceList:
			*item.dst.(*[]corev1.Service) = list.Items
		case *discoveryv1.EndpointSliceList:
			*item.dst.(*[]discoveryv1.EndpointSlice) = list.Items
		case *corev1.SecretList:
			*item.dst.(*[]corev1.Secret) = list.Items
		case *corev1.ConfigMapList:
			*item.dst.(*[]corev1.ConfigMap) = list.Items
		default:
			return translationInputs{}, fmt.Errorf("unsupported translation input list type %T", item.list)
		}
	}

	return out, nil
}

func decodeCECResources(items []ciliumv2.XDSResource) (XDSResources, error) {
	var resources XDSResources

	for _, item := range items {
		message, err := item.UnmarshalNew()
		if err != nil {
			return XDSResources{}, fmt.Errorf("failed to decode translated xDS resource %q: %w", item.GetTypeUrl(), err)
		}

		switch resource := message.(type) {
		case *envoy_config_listener_v3.Listener:
			resources.Listeners = append(resources.Listeners, resource)
		case *envoy_config_route_v3.RouteConfiguration:
			resources.Routes = append(resources.Routes, resource)
		case *envoy_config_cluster_v3.Cluster:
			resources.Clusters = append(resources.Clusters, resource)
		case *envoy_config_endpoint_v3.ClusterLoadAssignment:
			resources.Endpoints = append(resources.Endpoints, resource)
		case *envoy_extensions_transport_sockets_tls_v3.Secret:
			resources.Secrets = append(resources.Secrets, resource)
		default:
			return XDSResources{}, fmt.Errorf("unsupported translated xDS resource type %T", message)
		}
	}

	return resources, nil
}

func normalizeXDSResources(resources XDSResources, secretNames map[string]secretSource) error {
	for _, listener := range resources.Listeners {
		for _, filterChain := range listener.FilterChains {
			normalizeTransportSocket(filterChain.TransportSocket, secretNames)
			for _, filter := range filterChain.Filters {
				tc := filter.GetTypedConfig()
				if tc == nil || tc.GetTypeUrl() != envoy.HttpConnectionManagerTypeURL {
					continue
				}

				message, err := tc.UnmarshalNew()
				if err != nil {
					continue
				}

				hcm, ok := message.(*envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager)
				if !ok {
					continue
				}

				if rds := hcm.GetRds(); rds != nil {
					rds.ConfigSource = standaloneADSConfigSource()
					filter.ConfigType = &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: mustAny(hcm),
					}
				}
			}
		}

		if listener.GetAddress() == nil || listener.GetAddress().GetSocketAddress() == nil {
			return fmt.Errorf("translated listener %q is missing a socket address", listener.Name)
		}

		if sa := listener.GetAddress().GetSocketAddress(); sa.Address == "" {
			sa.Address = "0.0.0.0"
		}
	}

	for _, cluster := range resources.Clusters {
		normalizeTransportSocket(cluster.TransportSocket, secretNames)

		if cluster.GetType() != envoy_config_cluster_v3.Cluster_EDS {
			continue
		}
		if cluster.EdsClusterConfig == nil {
			cluster.EdsClusterConfig = &envoy_config_cluster_v3.Cluster_EdsClusterConfig{}
		}
		cluster.EdsClusterConfig.EdsConfig = standaloneADSConfigSource()
	}

	return nil
}

type secretSource struct {
	kind      string
	namespace string
	name      string
}

func gatherReferencedSecrets(m *model.Model) map[string]secretSource {
	out := map[string]secretSource{}

	for _, listener := range m.HTTP {
		for _, secret := range listener.TLS {
			out[secret.Namespace+"/"+secret.Name] = secretSource{
				kind:      secretSourceKindSecret,
				namespace: secret.Namespace,
				name:      secret.Name,
			}
		}

		for _, route := range listener.Routes {
			for _, backend := range route.Backends {
				addBackendTLSSecretRef(out, backend)
			}
			for _, mirror := range route.RequestMirrors {
				if mirror != nil && mirror.Backend != nil {
					addBackendTLSSecretRef(out, *mirror.Backend)
				}
			}
			if route.ExternalAuth != nil {
				addBackendTLSSecretRef(out, route.ExternalAuth.Backend)
			}
		}
	}

	for _, listener := range m.TLSPassthrough {
		for _, route := range listener.Routes {
			for _, backend := range route.Backends {
				addBackendTLSSecretRef(out, backend)
			}
		}
	}

	return out
}

func addBackendTLSSecretRef(out map[string]secretSource, backend model.Backend) {
	if backend.TLS == nil || backend.TLS.CACertRef == nil {
		return
	}
	key := backend.TLS.CACertRef.Namespace + "/" + backend.TLS.CACertRef.Name
	out[key] = secretSource{
		kind:      backend.TLS.CACertRef.Kind,
		namespace: backend.TLS.CACertRef.Namespace,
		name:      backend.TLS.CACertRef.Name,
	}
}

func normalizeTransportSocket(ts *envoy_config_core_v3.TransportSocket, secretNames map[string]secretSource) {
	if ts == nil {
		return
	}
	tc := ts.GetTypedConfig()
	if tc == nil {
		return
	}

	message, err := tc.UnmarshalNew()
	if err != nil {
		return
	}

	switch tls := message.(type) {
	case *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext:
		if normalizeCommonTLSContext(tls.CommonTlsContext, secretNames) {
			ts.ConfigType = &envoy_config_core_v3.TransportSocket_TypedConfig{TypedConfig: mustAny(tls)}
		}
	case *envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext:
		if normalizeCommonTLSContext(tls.CommonTlsContext, secretNames) {
			ts.ConfigType = &envoy_config_core_v3.TransportSocket_TypedConfig{TypedConfig: mustAny(tls)}
		}
	}
}

func normalizeCommonTLSContext(tls *envoy_extensions_transport_sockets_tls_v3.CommonTlsContext, secretNames map[string]secretSource) bool {
	if tls == nil {
		return false
	}

	updated := false
	for _, sc := range tls.TlsCertificateSdsSecretConfigs {
		updated = normalizeSDSSecretConfig(sc, secretNames) || updated
	}
	if sc := tls.GetValidationContextSdsSecretConfig(); sc != nil {
		updated = normalizeSDSSecretConfig(sc, secretNames) || updated
	}
	if cvc := tls.GetCombinedValidationContext(); cvc != nil {
		if sc := cvc.GetValidationContextSdsSecretConfig(); sc != nil {
			updated = normalizeSDSSecretConfig(sc, secretNames) || updated
		}
	}

	return updated
}

func normalizeSDSSecretConfig(sc *envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig, secretNames map[string]secretSource) bool {
	if sc == nil {
		return false
	}

	updated := false
	if sc.SdsConfig == nil {
		sc.SdsConfig = standaloneADSConfigSource()
		updated = true
	}

	if src, ok := resolveTranslatedSecretName(sc.Name, secretNames); ok {
		directName := src.namespace + "/" + src.name
		if sc.Name != directName {
			sc.Name = directName
			updated = true
		}
	}

	return updated
}

func standaloneADSConfigSource() *envoy_config_core_v3.ConfigSource {
	return &envoy_config_core_v3.ConfigSource{
		ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
		ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{
			Ads: &envoy_config_core_v3.AggregatedConfigSource{},
		},
	}
}

func resolveTranslatedSecretName(name string, secretNames map[string]secretSource) (secretSource, bool) {
	if src, ok := secretNames[name]; ok {
		return src, true
	}

	slash := strings.IndexRune(name, '/')
	if slash < 0 || slash == len(name)-1 {
		return secretSource{}, false
	}

	suffix := name[slash+1:]
	for _, src := range secretNames {
		switch src.kind {
		case secretSourceKindSecret:
			if suffix == src.namespace+"-"+src.name {
				return src, true
			}
		case secretSourceKindConfigMap:
			if suffix == src.namespace+"-cfgmap-"+src.name {
				return src, true
			}
		}
	}

	return secretSource{}, false
}

func buildEndpointAssignments(
	clusters []*envoy_config_cluster_v3.Cluster,
	services []corev1.Service,
	slicesList []discoveryv1.EndpointSlice,
) ([]*envoy_config_endpoint_v3.ClusterLoadAssignment, error) {
	serviceByName := map[string]corev1.Service{}
	for _, svc := range services {
		serviceByName[svc.Namespace+"/"+svc.Name] = svc
	}

	var assignments []*envoy_config_endpoint_v3.ClusterLoadAssignment
	for _, cluster := range clusters {
		if cluster.GetType() != envoy_config_cluster_v3.Cluster_EDS || cluster.EdsClusterConfig == nil {
			continue
		}
		resourceName := edsResourceName(cluster)

		ns, name, portRef, err := parseClusterServiceName(cluster.EdsClusterConfig.ServiceName)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EDS service name for cluster %q: %w", cluster.Name, err)
		}

		svc, ok := serviceByName[ns+"/"+name]
		if !ok {
			assignments = append(assignments, &envoy_config_endpoint_v3.ClusterLoadAssignment{ClusterName: resourceName})
			continue
		}

		resolvedPort, err := resolveServicePort(svc, portRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve service port for cluster %q: %w", cluster.Name, err)
		}

		assignment := &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: resourceName,
		}

		for _, slice := range slicesList {
			if slice.Namespace != ns || slice.Labels[discoveryv1.LabelServiceName] != name {
				continue
			}

			matchPorts := slicesMatchingPort(slice.Ports, portRef, resolvedPort)
			if len(matchPorts) == 0 {
				continue
			}

			for _, endpoint := range slice.Endpoints {
				if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
					continue
				}

				for _, address := range endpoint.Addresses {
					for _, p := range matchPorts {
						assignment.Endpoints = append(assignment.Endpoints, &envoy_config_endpoint_v3.LocalityLbEndpoints{
							LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
								{
									HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
										Endpoint: &envoy_config_endpoint_v3.Endpoint{
											Address: &envoy_config_core_v3.Address{
												Address: &envoy_config_core_v3.Address_SocketAddress{
													SocketAddress: &envoy_config_core_v3.SocketAddress{
														Protocol: envoy_config_core_v3.SocketAddress_TCP,
														Address:  address,
														PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
															PortValue: uint32(*p.Port),
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
				}
			}
		}

		assignments = append(assignments, assignment)
	}

	slices.SortFunc(assignments, func(a, b *envoy_config_endpoint_v3.ClusterLoadAssignment) int {
		return strings.Compare(a.ClusterName, b.ClusterName)
	})

	return assignments, nil
}

func edsResourceName(cluster *envoy_config_cluster_v3.Cluster) string {
	if cluster.GetEdsClusterConfig().GetServiceName() != "" {
		return cluster.GetEdsClusterConfig().GetServiceName()
	}
	return cluster.Name
}

func parseClusterServiceName(serviceName string) (namespace string, name string, port string, err error) {
	slash := strings.IndexRune(serviceName, '/')
	colon := strings.LastIndexByte(serviceName, ':')
	if slash <= 0 || colon <= slash+1 || colon == len(serviceName)-1 {
		return "", "", "", fmt.Errorf("invalid service name %q", serviceName)
	}
	return serviceName[:slash], serviceName[slash+1 : colon], serviceName[colon+1:], nil
}

func resolveServicePort(svc corev1.Service, portRef string) (int32, error) {
	if portNum, err := strconv.ParseInt(portRef, 10, 32); err == nil {
		return int32(portNum), nil
	}

	for _, p := range svc.Spec.Ports {
		if p.Name == portRef {
			return p.Port, nil
		}
	}

	return 0, fmt.Errorf("port %q not found on Service %s/%s", portRef, svc.Namespace, svc.Name)
}

func slicesMatchingPort(ports []discoveryv1.EndpointPort, portRef string, resolvedPort int32) []discoveryv1.EndpointPort {
	var out []discoveryv1.EndpointPort
	for _, port := range ports {
		if port.Port == nil {
			continue
		}
		if port.Name != nil && *port.Name == portRef {
			out = append(out, port)
			continue
		}
		if int32(*port.Port) == resolvedPort {
			out = append(out, port)
		}
	}
	return out
}

func indexSecrets(secrets []corev1.Secret) map[string]corev1.Secret {
	out := make(map[string]corev1.Secret, len(secrets))
	for _, secret := range secrets {
		out[secret.Namespace+"/"+secret.Name] = secret
	}
	return out
}

func indexConfigMaps(configMaps []corev1.ConfigMap) map[string]corev1.ConfigMap {
	out := make(map[string]corev1.ConfigMap, len(configMaps))
	for _, configMap := range configMaps {
		out[configMap.Namespace+"/"+configMap.Name] = configMap
	}
	return out
}

func buildSecretResources(
	required map[string]secretSource,
	secrets map[string]corev1.Secret,
	configMaps map[string]corev1.ConfigMap,
) ([]*envoy_extensions_transport_sockets_tls_v3.Secret, error) {
	results := map[string]*envoy_extensions_transport_sockets_tls_v3.Secret{}

	for key, source := range required {
		switch source.kind {
		case secretSourceKindSecret:
			secret, ok := secrets[key]
			if !ok {
				return nil, fmt.Errorf("referenced Secret %s not found", key)
			}
			envoySecret, err := k8sSecretToEnvoySecret(secret)
			if err != nil {
				return nil, fmt.Errorf("failed to translate Secret %s for SDS: %w", key, err)
			}
			if envoySecret != nil {
				results[envoySecret.Name] = envoySecret
			}
		case secretSourceKindConfigMap:
			configMap, ok := configMaps[key]
			if !ok {
				return nil, fmt.Errorf("referenced ConfigMap %s not found", key)
			}
			envoySecret, err := configMapToEnvoySecret(configMap)
			if err != nil {
				return nil, fmt.Errorf("failed to translate ConfigMap %s for SDS: %w", key, err)
			}
			if envoySecret != nil {
				results[envoySecret.Name] = envoySecret
			}
		default:
			return nil, fmt.Errorf("unsupported secret source kind %q for %s", source.kind, key)
		}
	}

	orderedKeys := slices.Sorted(maps.Keys(results))
	out := make([]*envoy_extensions_transport_sockets_tls_v3.Secret, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		out = append(out, results[key])
	}
	return out, nil
}

func k8sSecretToEnvoySecret(secret corev1.Secret) (*envoy_extensions_transport_sockets_tls_v3.Secret, error) {
	name := secret.Namespace + "/" + secret.Name
	envoySecret := &envoy_extensions_transport_sockets_tls_v3.Secret{Name: name}

	switch {
	case len(secret.Data[corev1.TLSCertKey]) > 0 || len(secret.Data[corev1.TLSPrivateKeyKey]) > 0:
		envoySecret.Type = &envoy_extensions_transport_sockets_tls_v3.Secret_TlsCertificate{
			TlsCertificate: &envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
				CertificateChain: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{InlineBytes: secret.Data[corev1.TLSCertKey]},
				},
				PrivateKey: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{InlineBytes: secret.Data[corev1.TLSPrivateKeyKey]},
				},
			},
		}
	case len(secret.Data[corev1.ServiceAccountRootCAKey]) > 0:
		envoySecret.Type = &envoy_extensions_transport_sockets_tls_v3.Secret_ValidationContext{
			ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
				TrustedCa: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{InlineBytes: secret.Data[corev1.ServiceAccountRootCAKey]},
				},
			},
		}
	default:
		return nil, nil
	}

	return envoySecret, nil
}

func configMapToEnvoySecret(configMap corev1.ConfigMap) (*envoy_extensions_transport_sockets_tls_v3.Secret, error) {
	caData, ok := configMap.BinaryData[corev1.ServiceAccountRootCAKey]
	if !ok {
		if value, found := configMap.Data[corev1.ServiceAccountRootCAKey]; found {
			caData = []byte(value)
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("missing %q entry", corev1.ServiceAccountRootCAKey)
	}

	return &envoy_extensions_transport_sockets_tls_v3.Secret{
		Name: configMap.Namespace + "/" + configMap.Name,
		Type: &envoy_extensions_transport_sockets_tls_v3.Secret_ValidationContext{
			ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
				TrustedCa: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{InlineBytes: caData},
				},
			},
		},
	}, nil
}

func mustAny(message proto.Message) *anypb.Any {
	typedConfig, err := anypb.New(message)
	if err != nil {
		panic(err)
	}

	return typedConfig
}

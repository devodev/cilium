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
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	cilium_proxy_api "github.com/cilium/proxy/go/cilium/api"
	cncf_xds_core_v3 "github.com/cncf/xds/go/xds/core/v3"
	cncf_xds_matcher_v3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_accessloggers_file_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_extensions_accessloggers_stream_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	envoy_extensions_clusters_common_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
	envoy_extensions_clusters_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dns/v3"
	envoy_extensions_filters_http_basic_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/basic_auth/v3"
	envoy_extensions_filters_http_healthcheck_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/health_check/v3"
	envoy_extensions_filters_http_jwt_authn_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	envoy_extensions_filters_http_localratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	envoy_extensions_filters_http_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_filters_listener_proxy_protocol_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_extensions_filters_listener_tlsinspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_extensions_filters_network_hcm_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_localratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/local_ratelimit/v3"
	envoy_extensions_filters_network_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	envoy_extensions_filters_network_tcpproxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_extensions_filters_listener_udp_udpproxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/udp/udp_proxy/v3"
	envoy_extensions_network_dns_resolver_cares_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/network/dns_resolver/cares/v3"
	envoy_extensions_rbac_principals_mtlsauthenticated_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/rbac/principals/mtls_authenticated/v3"
	envoy_extensions_transportsockets_proxy_protocol_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/proxy_protocol/v3"
	envoy_extensions_transportsockets_rawbuffer_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/raw_buffer/v3"
	envoy_extensions_transportsockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafenvoy "github.com/cilium/cilium/enterprise/operator/pkg/waf/envoy"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	httpTypeHTTP  = "http"
	httpTypeHTTPS = "https"
)

type lbServiceT2Translator struct {
	logger        *slog.Logger
	config        reconcilerConfig
	wafTranslator *wafenvoy.Translator
}

func (r *lbServiceT2Translator) DesiredCiliumEnvoyConfig(model *lbService) (*ciliumv2.CiliumEnvoyConfig, error) {
	if (!model.vip.IPv4Assigned() && !model.vip.IPv6Assigned()) || !model.vip.bindStatus.serviceExists || !model.vip.bindStatus.bindSuccessful || model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		return nil, nil
	}

	envoyResources := []ciliumv2.XDSResource{}

	// Service (with route(s)) -> Envoy Listener(s) & Route(s)

	listeners, err := r.desiredEnvoyListeners(model)
	if err != nil {
		return nil, err
	}

	for _, l := range listeners {
		listenerXdsResource, err := r.toXdsResource(l, envoy.ListenerTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, listenerXdsResource)
	}

	routeConfigs, err := r.desiredEnvoyRouteConfigs(model)
	if err != nil {
		return nil, err
	}

	for _, rc := range routeConfigs {
		routeConfigXdsResource, err := r.toXdsResource(rc, envoy.RouteTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, routeConfigXdsResource)
	}

	// Backend(s)-> Envoy Cluster(s) & Envoy Endpoints (ClusterLoadAssignments)

	clusters := r.desiredEnvoyClusters(model)

	for _, c := range clusters {
		clusterXdsResource, err := r.toXdsResource(c, envoy.ClusterTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, clusterXdsResource)
	}

	loadAssignments := r.desiredEnvoyClusterLoadAssignments(model)

	for _, la := range loadAssignments {
		endpointXdsResource, err := r.toXdsResource(la, envoy.EndpointTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, endpointXdsResource)
	}

	// Include gRPC access logger cluster only if enabled globally AND not disabled per-service.
	if r.config.AccessLog.EnableGRPC && model.grpcAccessLogsEnabledForService() {
		accessLoggerCluster, err := r.desiredAccessLoggerCluster(model)
		if err != nil {
			return nil, err
		}
		accessLoggerClusterResource, err := r.toXdsResource(accessLoggerCluster, envoy.ClusterTypeURL)
		if err != nil {
			return nil, err
		}
		envoyResources = append(envoyResources, accessLoggerClusterResource)
	}

	t2NodeLabelselector, err := slim_metav1.ParseToLabelSelector(model.t2LabelSelector.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse T2 node label selector: %w", err)
	}

	return &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),

			// Explicitly instruct the CEC parsing to handle the CEC as N/S L7 loadbalancing.
			// This is mainly to change the source IP of the Envoy upstream connection to the
			// node-local "Ingress" IP so that Cilium NetworkPolicies with the special identity
			// "Ingress" can be defined and enforced.
			Annotations: map[string]string{
				annotation.CECUseOriginalSourceAddress: "false",
				annotation.CECIsL7LB:                   strconv.FormatBool(r.config.Policy.EnableCiliumPolicyFilters && model.enableCNPIntegration),
				annotation.CECInjectCiliumFilters:      strconv.FormatBool(r.config.Policy.EnableCiliumPolicyFilters && model.enableCNPIntegration),
			},
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{
			NodeSelector: t2NodeLabelselector,
			Resources:    envoyResources,
		},
	}, nil
}

func (r *lbServiceT2Translator) accessLoggerClusterName(model *lbService) string {
	return fmt.Sprintf("%s-%s-access-logger", model.namespace, model.name)
}

func (r *lbServiceT2Translator) accessLoggerClusterAddress(model *lbService) string {
	return fmt.Sprintf("namespace-logger.%s.svc.cluster.local", model.namespace)
}

func (r *lbServiceT2Translator) accessLoggerClusterPort(model *lbService) uint32 {
	return uint32(666)
}

func (r *lbServiceT2Translator) desiredAccessLoggerCluster(model *lbService) (*envoy_config_cluster_v3.Cluster, error) {
	return &envoy_config_cluster_v3.Cluster{
		Name:           r.accessLoggerClusterName(model),
		ConnectTimeout: &durationpb.Duration{Seconds: 3},
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_STRICT_DNS,
		},
		CommonLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig{
			// disabling panic mode (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/panic_threshold)
			HealthyPanicThreshold: &envoy_type_v3.Percent{Value: 0.0},
		},
		DnsLookupFamily: r.dnsLookupFamily(model),
		LbPolicy:        envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": r.toClusterHTTPProtocolOptions(lbBackendHTTPConfig{
				enableHTTP11: false,
				enableHTTP2:  true,
			}),
		},
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: r.accessLoggerClusterName(model),
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &envoy_config_endpoint_v3.Endpoint{
									Address: &envoy_config_core_v3.Address{
										Address: &envoy_config_core_v3.Address_SocketAddress{
											SocketAddress: &envoy_config_core_v3.SocketAddress{
												Protocol: envoy_config_core_v3.SocketAddress_TCP,
												Address:  r.accessLoggerClusterAddress(model),
												PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
													PortValue: r.accessLoggerClusterPort(model),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListeners(model *lbService) ([]*envoy_config_listener_v3.Listener, error) {
	listeners := []*envoy_config_listener_v3.Listener{}

	addresses := []string{}
	if model.vip.IPv4Assigned() {
		addresses = append(addresses, *model.vip.assignedIPv4)
	}
	if model.vip.IPv6Assigned() {
		addresses = append(addresses, *model.vip.assignedIPv6)
	}

	// In T2 health push mode, UDP services no longer need the dedicated TCP health-check
	// listener. Keeping it would emit a TCP listener without any filter chains, which Envoy
	// rejects with a NACK.
	if !model.isUDPProxy() || !r.config.T1T2HealthCheck.T2HCPushEnabled {
		tcpListener, err := r.desiredEnvoyTCPListener(model, addresses)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, tcpListener)
	}

	if model.isUDPProxy() {
		listeners = append(listeners, r.desiredEnvoyUDPListener(model, addresses))
	}

	return listeners, nil
}

func (r *lbServiceT2Translator) desiredEnvoyTCPListener(model *lbService, addresses []string) (*envoy_config_listener_v3.Listener, error) {
	var accessLoggers []*envoy_config_accesslog_v3.AccessLog

	if r.config.AccessLog.EnableTCP {
		accessLoggers = r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatTCP, r.config.AccessLog.JSONFormatTCP)
	}

	mainAddress, additionalAddresses := r.toAddresses(addresses, model.port, envoy_config_core_v3.SocketAddress_TCP)
	filterChains, err := r.desiredEnvoyListenerFilterChains(model)
	if err != nil {
		return nil, err
	}

	return &envoy_config_listener_v3.Listener{
		Name:                          "frontend_listener_tcp",
		Address:                       mainAddress,
		AdditionalAddresses:           additionalAddresses,
		ListenerFilters:               r.desiredEnvoyTCPListenerFilters(model),
		FilterChains:                  filterChains,
		AccessLog:                     accessLoggers,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(32768), // 32KiB
		StatPrefix:                    fmt.Sprintf("%s_%s", model.namespace, model.name),
		TrafficDirection:              envoy_config_core_v3.TrafficDirection_INBOUND,
	}, nil
}

func (*lbServiceT2Translator) toAddresses(addresses []string, port int32, protocol envoy_config_core_v3.SocketAddress_Protocol) (*envoy_config_core_v3.Address, []*envoy_config_listener_v3.AdditionalAddress) {
	mainAddress := &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_SocketAddress{
			SocketAddress: &envoy_config_core_v3.SocketAddress{
				Protocol: protocol,
				Address:  addresses[0],
				PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
					PortValue: uint32(port),
				},
			},
		},
	}
	additionalAddresses := []*envoy_config_listener_v3.AdditionalAddress{}

	for _, a := range addresses[1:] {
		additionalAddresses = append(additionalAddresses, &envoy_config_listener_v3.AdditionalAddress{
			Address: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: protocol,
						Address:  a,
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: uint32(port),
						},
					},
				},
			},
		})
	}

	return mainAddress, additionalAddresses
}

func (r *lbServiceT2Translator) desiredEnvoyUDPListener(model *lbService, addresses []string) *envoy_config_listener_v3.Listener {
	mainAddress, additionalAddresses := r.toAddresses(addresses, model.port, envoy_config_core_v3.SocketAddress_UDP)

	return &envoy_config_listener_v3.Listener{
		Name:                          "frontend_listener_udp",
		Address:                       mainAddress,
		AdditionalAddresses:           additionalAddresses,
		ListenerFilters:               r.desiredEnvoyUDPListenerFilters(model),
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(32768), // 32KiB
		StatPrefix:                    fmt.Sprintf("%s_%s", model.namespace, model.name),
		TrafficDirection:              envoy_config_core_v3.TrafficDirection_INBOUND,
	}
}

func (r *lbServiceT2Translator) desiredEnvoyTCPListenerFilters(model *lbService) []*envoy_config_listener_v3.ListenerFilter {
	listenerFilters := []*envoy_config_listener_v3.ListenerFilter{}

	// Don't add TLS inspector for TCP proxy to prevent some issues with certain protocols (e.g. mysql).
	// see https://github.com/envoyproxy/envoy/issues/21044
	if !model.isTCPProxy() {
		listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
			Name: "envoy.filters.listener.tls_inspector",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_listener_tlsinspector_v3.TlsInspector{}),
			},
		})
	}

	if model.proxyProtocolConfig != nil {
		// Without this filter, Envoy will not be able to parse the Proxy Protocol header
		// and return protocol error
		// Sample error log:
		// 	- application log: http/1.1 protocol error: INVALID_HEADER_NAME_CHARACTER
		//  - access log: http.resp.code.details="http1.codec_error"  response.flags="DPE" response.flags-long="DownstreamProtocolError"
		listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
			Name: "envoy.filters.listener.proxy_protocol",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: toAny(r.toProxyProtocolConfig(model.proxyProtocolConfig)),
			},
		})
	}

	if !(r.config.Policy.EnableCiliumPolicyFilters && model.enableCNPIntegration) {
		listenerFilters = append(listenerFilters, r.disabledBPFMetadataListenerFilter())
	}

	return listenerFilters
}

func (r *lbServiceT2Translator) desiredEnvoyUDPListenerFilters(model *lbService) []*envoy_config_listener_v3.ListenerFilter {
	listenerFilters := []*envoy_config_listener_v3.ListenerFilter{}

	if !(r.config.Policy.EnableCiliumPolicyFilters && model.enableCNPIntegration) {
		listenerFilters = append(listenerFilters, r.disabledBPFMetadataListenerFilter())
	}

	var accessLoggers []*envoy_config_accesslog_v3.AccessLog

	if r.config.AccessLog.EnableUDP {
		accessLoggers = r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatUDP, r.config.AccessLog.JSONFormatUDP)
	}

	listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
		Name: "envoy.filters.udp_listener.udp_proxy",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: toAny(&envoy_extensions_filters_listener_udp_udpproxy_v3.UdpProxyConfig{
				StatPrefix: "udp_proxy",
				RouteSpecifier: &envoy_extensions_filters_listener_udp_udpproxy_v3.UdpProxyConfig_Matcher{
					Matcher: &cncf_xds_matcher_v3.Matcher{
						OnNoMatch: &cncf_xds_matcher_v3.Matcher_OnMatch{
							OnMatch: &cncf_xds_matcher_v3.Matcher_OnMatch_Action{
								Action: &cncf_xds_core_v3.TypedExtensionConfig{
									Name: "envoy.udpproxy.route",
									TypedConfig: toAny(&envoy_extensions_filters_listener_udp_udpproxy_v3.Route{
										// prefix as qualifying a matcher tree upstream isn't implemented
										Cluster: fmt.Sprintf("%s/%s/%s", model.namespace, model.getOwningResourceName(), r.getClusterName(model.applications.udpProxy.routes[0].backendRef.name)),
									}),
								},
							},
						},
					},
				},
				HashPolicies:     r.toUDPProxyHashpolicy(model),
				AccessLog:        accessLoggers,
				AccessLogOptions: &envoy_extensions_filters_listener_udp_udpproxy_v3.UdpProxyConfig_UdpAccessLogOptions{},
			}),
		},
	})

	return listenerFilters
}

func (*lbServiceT2Translator) disabledBPFMetadataListenerFilter() *envoy_config_listener_v3.ListenerFilter {
	return &envoy_config_listener_v3.ListenerFilter{
		Name: "cilium.bpf_metadata",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: toAny(&cilium_proxy_api.BpfMetadata{
				// Disable BPF map lookups so external or selectorless backends do not
				// get the default CNP integration path auto-injected by the parser.
				BpfRoot: "",
			}),
		},
	}
}

func (r *lbServiceT2Translator) toUDPProxyHashpolicy(model *lbService) []*envoy_extensions_filters_listener_udp_udpproxy_v3.UdpProxyConfig_HashPolicy {
	hashPolicies := []*envoy_extensions_filters_listener_udp_udpproxy_v3.UdpProxyConfig_HashPolicy{}
	for _, route := range model.applications.udpProxy.routes {
		if route.persistentBackend != nil && route.persistentBackend.sourceIP {
			hashPolicies = append(hashPolicies, &envoy_extensions_filters_listener_udp_udpproxy_v3.UdpProxyConfig_HashPolicy{
				PolicySpecifier: &envoy_extensions_filters_listener_udp_udpproxy_v3.UdpProxyConfig_HashPolicy_SourceIp{
					SourceIp: true,
				},
			})
		}
	}

	return hashPolicies
}

func (r *lbServiceT2Translator) toProxyProtocolConfig(proxyProtocolConfig *lbServiceProxyProtocolConfig) *envoy_extensions_filters_listener_proxy_protocol_v3.ProxyProtocol {
	if proxyProtocolConfig == nil {
		return nil
	}

	var disallowedVersions []envoy_config_core_v3.ProxyProtocolConfig_Version
	for _, v := range proxyProtocolConfig.disallowedVersions {
		switch v {
		case proxyProtocolVersionV1:
			disallowedVersions = append(disallowedVersions, envoy_config_core_v3.ProxyProtocolConfig_V1)
		case proxyProtocolVersionV2:
			disallowedVersions = append(disallowedVersions, envoy_config_core_v3.ProxyProtocolConfig_V2)
		}
	}

	return &envoy_extensions_filters_listener_proxy_protocol_v3.ProxyProtocol{
		// This is to make sure that the listener will not be rejected other kinds of traffic
		AllowRequestsWithoutProxyProtocol: true,
		DisallowedVersions:                disallowedVersions,
		PassThroughTlvs: &envoy_config_core_v3.ProxyProtocolPassThroughTLVs{
			TlvType: proxyProtocolConfig.passThroughTLVs,
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerFilterChains(model *lbService) ([]*envoy_config_listener_v3.FilterChain, error) {
	filterChains := []*envoy_config_listener_v3.FilterChain{}

	if !r.config.T1T2HealthCheck.T2HCPushEnabled {
		healthCheckFilterChain := r.desiredEnvoyListenerHealthCheckHttpFilterChain(model)
		filterChains = append(filterChains, healthCheckFilterChain)
	}

	if model.applications.isHTTPProxyConfigured() {
		httpFilterChain, err := r.desiredEnvoyListenerHttpFilterChain(model)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, httpFilterChain)
	}

	if model.applications.isHTTPSProxyConfigured() {
		httpsFilterChain, err := r.desiredEnvoyListenerHttpsFilterChain(model)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, httpsFilterChain)
	}

	if model.applications.isTLSPassthroughConfigured() {
		tlsPassthroughFilterChains := r.desiredEnvoyListenerTLSPassthroughFilterChains(model)
		filterChains = append(filterChains, tlsPassthroughFilterChains...)
	}

	if model.applications.isTLSProxyConfigured() {
		tlsProxyFilterChains := r.desiredEnvoyListenerTLSProxyFilterChains(model)
		filterChains = append(filterChains, tlsProxyFilterChains...)
	}

	if model.applications.isT2TCPProxyConfigured() {
		tcpProxyFilterChains := r.desiredEnvoyListenerTCPProxyFilterChains(model)
		filterChains = append(filterChains, tcpProxyFilterChains...)
	}

	return filterChains, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHealthCheckHttpFilterChain(model *lbService) *envoy_config_listener_v3.FilterChain {
	networkFilters := []*envoy_config_listener_v3.Filter{}

	networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyListenerHealthCheckHTTPHCM(model)),
		},
	})

	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol:        "raw_buffer",
			DirectSourcePrefixRanges: r.t1NodeCIDRRanges(model),
		},
		Filters: networkFilters,
	}
}

func (r *lbServiceT2Translator) t1NodeCIDRRanges(model *lbService) []*envoy_config_core_v3.CidrRange {
	t1NodeCIDRs := []*envoy_config_core_v3.CidrRange{}
	for _, t1NodeIP := range model.t1NodeIPv4Addresses {
		t1NodeCIDRs = append(t1NodeCIDRs, &envoy_config_core_v3.CidrRange{
			AddressPrefix: t1NodeIP,
			PrefixLen:     wrapperspb.UInt32(32),
		})
	}
	for _, t1NodeIP := range model.t1NodeIPv6Addresses {
		t1NodeCIDRs = append(t1NodeCIDRs, &envoy_config_core_v3.CidrRange{
			AddressPrefix: t1NodeIP,
			PrefixLen:     wrapperspb.UInt32(128),
		})
	}

	return t1NodeCIDRs
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpFilterChain(model *lbService) (*envoy_config_listener_v3.FilterChain, error) {
	networkFilters := []*envoy_config_listener_v3.Filter{}

	if model.applications.getHTTPConnectionFiltering() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.rbac",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toHTTPNetworkRBACFilter(model.applications.getHTTPConnectionFiltering(), httpTypeHTTP, model.namespace, model.name)),
			},
		})
	}

	if model.applications.getHTTPConnectionRateLimits() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.local_ratelimit",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toNetworkRateLimitFilter(model.applications.getHTTPConnectionRateLimits(), model.namespace, model.name)),
			},
		})
	}

	httpHCM, err := r.desiredEnvoyListenerHTTPHCM(model)
	if err != nil {
		return nil, err
	}

	networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: toAny(httpHCM),
		},
	})

	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "raw_buffer",
		},
		Filters: networkFilters,
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHealthCheckHTTPHCM(model *lbService) *envoy_extensions_filters_network_hcm_v3.HttpConnectionManager {
	var accessLoggers []*envoy_config_accesslog_v3.AccessLog

	if r.config.AccessLog.EnableHC {
		accessLoggers = r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatHC, r.config.AccessLog.JSONFormatHC)
	}

	return &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager{
		ServerName:                   r.config.ServerName,
		AccessLog:                    accessLoggers,
		GenerateRequestId:            wrapperspb.Bool(true),
		PreserveExternalRequestId:    false,
		AlwaysSetRequestIdInResponse: false,
		StatPrefix:                   fmt.Sprintf("healthcheck_http_%s_%s", model.namespace, model.name),
		CodecType:                    envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_AUTO,
		NormalizePath:                wrapperspb.Bool(true),
		MergeSlashes:                 true,
		UseRemoteAddress:             wrapperspb.Bool(r.config.OriginalIPDetection.UseRemoteAddress),
		XffNumTrustedHops:            uint32(r.config.OriginalIPDetection.XffNumTrustedHops),
		StripMatchingHostPort:        true,
		HttpFilters:                  r.desiredEnvoyListenerHealthCheckHttpHTTPFilters(model),
		RouteSpecifier:               &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_RouteConfig{}, // no routes - but specifier required
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			HeadersWithUnderscoresAction: envoy_config_core_v3.HttpProtocolOptions_REJECT_REQUEST,
			MaxConnectionDuration:        durationpb.New(time.Hour),
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
			MaxConcurrentStreams:        wrapperspb.UInt32(100),
			InitialStreamWindowSize:     wrapperspb.UInt32(65535),
			InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHTTPHCM(model *lbService) (*envoy_extensions_filters_network_hcm_v3.HttpConnectionManager, error) {
	httpFilters, err := r.desiredEnvoyListenerHttpHTTPFilters(model)
	if err != nil {
		return nil, err
	}

	return &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager{
		ServerName:                   r.config.ServerName,
		AccessLog:                    r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatHTTP, r.config.AccessLog.JSONFormatHTTP),
		GenerateRequestId:            wrapperspb.Bool(r.config.RequestID.Generate),
		PreserveExternalRequestId:    r.config.RequestID.Preserve,
		AlwaysSetRequestIdInResponse: r.config.RequestID.Response,
		StatPrefix:                   fmt.Sprintf("http_%s_%s", model.namespace, model.name),
		CodecType:                    r.toCodecType(model.applications.getHTTPHTTPConfig()),
		NormalizePath:                wrapperspb.Bool(true),
		MergeSlashes:                 true,
		UseRemoteAddress:             wrapperspb.Bool(r.config.OriginalIPDetection.UseRemoteAddress),
		XffNumTrustedHops:            uint32(r.config.OriginalIPDetection.XffNumTrustedHops),
		StripMatchingHostPort:        true,
		HttpFilters:                  httpFilters,
		RouteSpecifier: &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_hcm_v3.Rds{
				RouteConfigName: "frontend_routeconfig_http",
			},
		},
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			HeadersWithUnderscoresAction: envoy_config_core_v3.HttpProtocolOptions_REJECT_REQUEST,
			MaxConnectionDuration:        durationpb.New(time.Hour),
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
			MaxConcurrentStreams:        wrapperspb.UInt32(100),
			InitialStreamWindowSize:     wrapperspb.UInt32(65535),
			InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
		},
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHealthCheckHttpHTTPFilters(model *lbService) []*envoy_extensions_filters_network_hcm_v3.HttpFilter {
	httpFilters := []*envoy_extensions_filters_network_hcm_v3.HttpFilter{}

	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.health_check",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredHealthCheckFilter(model)),
		},
	})

	// adding router as required terminal filter - even though it's not used in case of health checking (no passthrough mode)
	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyRouterFilter()),
		},
	})

	return httpFilters
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpHTTPFilters(model *lbService) ([]*envoy_extensions_filters_network_hcm_v3.HttpFilter, error) {
	httpFilters := []*envoy_extensions_filters_network_hcm_v3.HttpFilter{}

	wafFilter, err := r.wafTranslator.HTTPFilter(model.name, model.namespace, model.effectiveWAFConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build managed WAF HTTP filter: %w", err)
	}

	if wafFilter != nil {
		httpFilters = append(httpFilters, wafFilter)
	}

	if model.usesHTTPBasicAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.basic_auth",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_basic_auth_v3.BasicAuth{
					Users: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineString{
							InlineString: r.toHTPasswdString(model.applications.httpProxy.auth.basicAuth),
						},
					},
				}),
			},
		})
	}

	if model.usesHTTPJWTAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.jwt_authn",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(r.toJWTAuthentication(model.namespace, model.name, httpTypeHTTP, model.applications.httpProxy.auth.jwtAuth)),
			},
		})
	}

	if model.usesHTTPRequestFiltering() {
		// Only add the RBAC filter if there's at least one route that is using request filtering.
		// The RBAC filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.rbac",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_rbac_v3.RBAC{}),
			},
		})
	}

	if model.usesHTTPRequestRateLimiting() {
		// Only add the LocalRateLimit filter if there's at least one route that is using request rate limiting.
		// The filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.local_ratelimit",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit{
					StatPrefix: fmt.Sprintf("%s_%s", model.namespace, model.name), // required attribute
				}),
			},
		})
	}

	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyRouterFilter()),
		},
	})

	return httpFilters, nil
}

func (r *lbServiceT2Translator) toJWTAuthentication(namespace, name, httpType string, auth *lbServiceHTTPJWTAuth) *envoy_extensions_filters_http_jwt_authn_v3.JwtAuthentication {
	providers := map[string]*envoy_extensions_filters_http_jwt_authn_v3.JwtProvider{}
	providerNameRequirements := []*envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement{}
	for _, provider := range auth.providers {
		p := &envoy_extensions_filters_http_jwt_authn_v3.JwtProvider{
			// Forward JWT. The backend application suppose to use
			// JWT for their application specific logic.
			Forward: true,

			// put JWT payload into metadata for later use in RBAC
			PayloadInMetadata: "payload",
		}

		if provider.issuer != nil {
			p.Issuer = *provider.issuer
		}

		if len(provider.audiences) != 0 {
			p.Audiences = provider.audiences
		}

		if provider.localJWKS != nil {
			p.JwksSourceSpecifier = &envoy_extensions_filters_http_jwt_authn_v3.JwtProvider_LocalJwks{
				LocalJwks: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineString{
						InlineString: provider.localJWKS.jwksStr,
					},
				},
			}
		}

		if provider.remoteJWKS != nil {
			p.JwksSourceSpecifier = &envoy_extensions_filters_http_jwt_authn_v3.JwtProvider_RemoteJwks{
				RemoteJwks: &envoy_extensions_filters_http_jwt_authn_v3.RemoteJwks{
					HttpUri: &envoy_config_core_v3.HttpUri{
						Uri: provider.remoteJWKS.httpURI,
						HttpUpstreamType: &envoy_config_core_v3.HttpUri_Cluster{
							Cluster: r.jwksClusterNameQualified(namespace, name, httpType, provider.name),
						},
						// The long-enough timeout to fetch the JWKS from the remote store.
						// We can make this configurable as needed.
						Timeout: &durationpb.Duration{Seconds: 3},
					},
				},
			}
		}

		providers[provider.name] = p

		providerNameRequirements = append(providerNameRequirements, &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement{
			RequiresType: &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement_ProviderName{
				ProviderName: provider.name,
			},
		})
	}

	var requirement *envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement
	if len(providerNameRequirements) == 1 {
		// Envoy rejects the RequirementAny with a single entry. We
		// need to handle this case separately.
		requirement = providerNameRequirements[0]
	} else {
		requirement = &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement{
			RequiresType: &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement_RequiresAny{
				RequiresAny: &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirementOrList{
					Requirements: providerNameRequirements,
				},
			},
		}
	}

	return &envoy_extensions_filters_http_jwt_authn_v3.JwtAuthentication{
		Providers: providers,

		// Accept the request if any of the provider matches.
		Rules: []*envoy_extensions_filters_http_jwt_authn_v3.RequirementRule{
			{
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
						Prefix: "/",
					},
				},
				RequirementType: &envoy_extensions_filters_http_jwt_authn_v3.RequirementRule_Requires{
					Requires: requirement,
				},
			},
		},
	}
}

// Cilium appends namespace/name to the original Cluster name. However, the
// properties that refers the Cluster doesn't know about it.
func (r *lbServiceT2Translator) jwksClusterNameQualified(namespace, name, httpType, providerName string) string {
	return fmt.Sprintf("%s/%s/jwks_cluster_%s_%s", namespace, getOwningResourceName(name), httpType, providerName)
}

func (r *lbServiceT2Translator) jwksClusterName(httpType, providerName string) string {
	return fmt.Sprintf("jwks_cluster_%s_%s", httpType, providerName)
}

func (r *lbServiceT2Translator) toHTPasswdString(auth *lbServiceHTTPBasicAuth) string {
	htpasswd := strings.Builder{}
	for _, up := range auth.users {
		// Envoy only supports SHA1 hashed passwords as of today.
		hashed := sha1.Sum([]byte(up.password))
		b64Encoded := base64.StdEncoding.EncodeToString(hashed[:])
		htpasswd.WriteString(fmt.Sprintf("%s:{SHA}%s\n", up.username, b64Encoded))
	}
	return htpasswd.String()
}

func (r *lbServiceT2Translator) toHTTPSServerNames(model *lbService) []string {
	// get all HTTPS hostnames
	httpsDomainNames := []string{}

	if model.applications.httpsProxy != nil {
		httpsDomainNames = append(httpsDomainNames, slices.Collect(maps.Keys(model.applications.httpsProxy.routes))...)
	}

	// remove duplicates and raw '*' that is not allowed by Envoy
	serverNames := []string{}
	for _, dn := range httpsDomainNames {
		if dn == "*" {
			continue
		}

		serverNames = append(serverNames, dn)
	}

	slices.Sort(serverNames)
	return slices.Compact(serverNames)
}

func (r *lbServiceT2Translator) toCodecType(httpConfig *lbServiceHTTPConfig) envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_CodecType {
	if httpConfig == nil {
		return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_AUTO
	}

	if httpConfig.enableHTTP11 && !httpConfig.enableHTTP2 {
		return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_HTTP1
	}

	if httpConfig.enableHTTP2 && !httpConfig.enableHTTP11 {
		return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_HTTP2
	}

	return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_AUTO
}

func (r *lbServiceT2Translator) toAlpnProtocols(model *lbService) []string {
	if model.applications.httpsProxy == nil || model.applications.httpsProxy.httpConfig == nil {
		return nil
	}

	alpnProtocols := []string{}

	// Note: be aware that the order of ALPN protocols matters
	if model.applications.httpsProxy.httpConfig.enableHTTP2 {
		alpnProtocols = append(alpnProtocols, "h2")
	}

	if model.applications.httpsProxy.httpConfig.enableHTTP11 {
		alpnProtocols = append(alpnProtocols, "http/1.1")
	}

	return alpnProtocols
}

func (r *lbServiceT2Translator) toListenerTLSParams(model lbServiceTLSConfig) *envoy_extensions_transportsockets_tls_v3.TlsParameters {
	return &envoy_extensions_transportsockets_tls_v3.TlsParameters{
		TlsMinimumProtocolVersion: r.toTLSVersion(model.minTLSVersion),
		TlsMaximumProtocolVersion: r.toTLSVersion(model.maxTLSVersion),
		CipherSuites:              model.allowedCipherSuites,
		EcdhCurves:                model.allowedECDHCurves,
		SignatureAlgorithms:       model.allowedSignatureAlgorithms,
	}
}

func (r *lbServiceT2Translator) toClusterTLSParams(tlsConfig *lbBackendTLSConfig) *envoy_extensions_transportsockets_tls_v3.TlsParameters {
	return &envoy_extensions_transportsockets_tls_v3.TlsParameters{
		TlsMinimumProtocolVersion: r.toTLSVersion(tlsConfig.minTLSVersion),
		TlsMaximumProtocolVersion: r.toTLSVersion(tlsConfig.maxTLSVersion),
		CipherSuites:              tlsConfig.allowedCipherSuites,
		EcdhCurves:                tlsConfig.allowedECDHCurves,
		SignatureAlgorithms:       tlsConfig.allowedSignatureAlgorithms,
	}
}

func (r *lbServiceT2Translator) toTLSVersion(version string) envoy_extensions_transportsockets_tls_v3.TlsParameters_TlsProtocol {
	return envoy_extensions_transportsockets_tls_v3.TlsParameters_TlsProtocol(envoy_extensions_transportsockets_tls_v3.TlsParameters_TlsProtocol_value[version])
}

func (r *lbServiceT2Translator) toTLSServerNames(tlsHostNames []string) []string {
	// remove duplicates and raw '*' that is not allowed by Envoy
	serverNames := []string{}
	for _, dn := range tlsHostNames {
		if dn == "*" {
			continue
		}

		serverNames = append(serverNames, dn)
	}

	slices.Sort(serverNames)
	return slices.Compact(serverNames)
}

func (r *lbServiceT2Translator) toTLSCertificateSdsConfigs(namespace string, tlsConfig lbServiceTLSConfig) []*envoy_extensions_transportsockets_tls_v3.SdsSecretConfig {
	secrets := []*envoy_extensions_transportsockets_tls_v3.SdsSecretConfig{}

	for _, cs := range tlsConfig.certificateSecrets {
		secrets = append(secrets, &envoy_extensions_transportsockets_tls_v3.SdsSecretConfig{
			Name: fmt.Sprintf("%s/%s-%s", r.config.SecretsNamespace, namespace, cs),
		})
	}

	return secrets
}

func (r *lbServiceT2Translator) toTLSValidationContext(namespace string, model lbServiceTLSConfig) *envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext {
	if len(model.validationContext.trustedCASecretName) == 0 {
		return nil
	}

	defaultValidationContext := &envoy_extensions_transportsockets_tls_v3.CertificateValidationContext{}

	if len(model.validationContext.subjectAlternativeNames) > 0 {
		sanMatchers := []*envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher{}
		for _, san := range model.validationContext.subjectAlternativeNames {
			sanMatchers = append(sanMatchers, &envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher{
				SanType: envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_DNS,
				Matcher: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: san,
					},
				},
			})
		}
		defaultValidationContext.MatchTypedSubjectAltNames = sanMatchers
	}

	return &envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext{
		CombinedValidationContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedCertificateValidationContext{
			ValidationContextSdsSecretConfig: &envoy_extensions_transportsockets_tls_v3.SdsSecretConfig{
				Name: fmt.Sprintf("%s/%s-%s", r.config.SecretsNamespace, namespace, model.validationContext.trustedCASecretName),
			},
			DefaultValidationContext: defaultValidationContext,
		},
	}
}

func (r *lbServiceT2Translator) requiresClientCertificate(validationContext *envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext) *wrapperspb.BoolValue {
	if validationContext == nil {
		return nil
	}

	return wrapperspb.Bool(true)
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpsFilterChain(model *lbService) (*envoy_config_listener_v3.FilterChain, error) {
	validationContext := r.toTLSValidationContext(model.namespace, model.applications.httpsProxy.tlsConfig)

	networkFilters := []*envoy_config_listener_v3.Filter{}

	if model.applications.getHTTPSConnectionFiltering() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.rbac",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toHTTPNetworkRBACFilter(model.applications.getHTTPSConnectionFiltering(), httpTypeHTTPS, model.namespace, model.name)),
			},
		})
	}

	if model.applications.getHTTPSConnectionRateLimits() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.local_ratelimit",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toNetworkRateLimitFilter(model.applications.getHTTPSConnectionRateLimits(), model.namespace, model.name)),
			},
		})
	}

	httpsHCM, err := r.desiredEnvoyListenerHTTPSHCM(model)
	if err != nil {
		return nil, err
	}

	networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: toAny(httpsHCM),
		},
	})

	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "tls",
			ServerNames:       r.toHTTPSServerNames(model),
		},
		TransportSocket: &envoy_config_core_v3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.DownstreamTlsContext{
					// Upstream Envoy Secret Sync only supports setting the trusted CA without further verification data.
					// Therefore it's necessary to explicitly enable `require_client_certificate if the validation context isn't nil.
					//
					// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-certificatevalidationcontext
					// By default, a client certificate is optional, unless one of the additional options (require_client_certificate, verify_certificate_spki, verify_certificate_hash, or match_typed_subject_alt_names) is also specified.
					RequireClientCertificate: r.requiresClientCertificate(validationContext),
					CommonTlsContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: r.toTLSCertificateSdsConfigs(model.namespace, model.applications.httpsProxy.tlsConfig),
						ValidationContextType:          validationContext,
						AlpnProtocols:                  r.toAlpnProtocols(model),
						TlsParams:                      r.toListenerTLSParams(model.applications.httpsProxy.tlsConfig),
					},
				}),
			},
		},
		Filters: networkFilters,
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHTTPSHCM(model *lbService) (*envoy_extensions_filters_network_hcm_v3.HttpConnectionManager, error) {
	httpFilters, err := r.desiredEnvoyListenerHttpsHTTPFilters(model)
	if err != nil {
		return nil, err
	}

	return &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager{
		ServerName:                   r.config.ServerName,
		AccessLog:                    r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatHTTPS, r.config.AccessLog.JSONFormatHTTPS),
		GenerateRequestId:            wrapperspb.Bool(r.config.RequestID.Generate),
		PreserveExternalRequestId:    r.config.RequestID.Preserve,
		AlwaysSetRequestIdInResponse: r.config.RequestID.Response,
		StatPrefix:                   fmt.Sprintf("https_%s_%s", model.namespace, model.name),
		CodecType:                    r.toCodecType(model.applications.getHTTPSHTTPConfig()),
		NormalizePath:                wrapperspb.Bool(true),
		MergeSlashes:                 true,
		UseRemoteAddress:             wrapperspb.Bool(r.config.OriginalIPDetection.UseRemoteAddress),
		XffNumTrustedHops:            uint32(r.config.OriginalIPDetection.XffNumTrustedHops),
		StripMatchingHostPort:        true,
		HttpFilters:                  httpFilters,
		RouteSpecifier: &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_hcm_v3.Rds{
				RouteConfigName: "frontend_routeconfig_https",
			},
		},
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			HeadersWithUnderscoresAction: envoy_config_core_v3.HttpProtocolOptions_REJECT_REQUEST,
			MaxConnectionDuration:        durationpb.New(time.Hour),
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
			MaxConcurrentStreams:        wrapperspb.UInt32(100),
			InitialStreamWindowSize:     wrapperspb.UInt32(65535),
			InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
		},
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpsHTTPFilters(model *lbService) ([]*envoy_extensions_filters_network_hcm_v3.HttpFilter, error) {
	httpFilters := []*envoy_extensions_filters_network_hcm_v3.HttpFilter{}

	wafFilter, err := r.wafTranslator.HTTPFilter(model.name, model.namespace, model.effectiveWAFConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build managed WAF HTTPs filter: %w", err)
	}

	if wafFilter != nil {
		httpFilters = append(httpFilters, wafFilter)
	}

	if model.usesHTTPSBasicAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.basic_auth",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_basic_auth_v3.BasicAuth{
					Users: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineString{
							InlineString: r.toHTPasswdString(model.applications.httpsProxy.auth.basicAuth),
						},
					},
				}),
			},
		})
	}

	if model.usesHTTPSJWTAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.jwt_authn",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(r.toJWTAuthentication(model.namespace, model.name, httpTypeHTTPS, model.applications.httpsProxy.auth.jwtAuth)),
			},
		})
	}

	if model.usesHTTPSRequestFiltering() {
		// Only add the RBAC filter if there's at least one route that is using request filtering.
		// The RBAC filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.rbac",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_rbac_v3.RBAC{}),
			},
		})
	}

	if model.usesHTTPSRequestRateLimiting() {
		// Only add the LocalRateLimit filter if there's at least one route that is using request rate limiting.
		// The filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.local_ratelimit",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit{
					StatPrefix: fmt.Sprintf("%s_%s", model.namespace, model.name), // required attribute
				}),
			},
		})
	}

	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyRouterFilter()),
		},
	})

	return httpFilters, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListenerTLSPassthroughFilterChains(model *lbService) []*envoy_config_listener_v3.FilterChain {
	tlsPassthroughFilterChains := []*envoy_config_listener_v3.FilterChain{}

	if model.applications.tlsPassthrough == nil {
		return tlsPassthroughFilterChains
	}

	for i, tr := range model.applications.tlsPassthrough.routes {
		networkFilters := []*envoy_config_listener_v3.Filter{}

		if tr.connectionFiltering != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.rbac",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toTLSRouteRBACFilter(tr.connectionFiltering, model.namespace, model.name)),
				},
			})
		}

		if tr.rateLimits != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.local_ratelimit",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toNetworkRateLimitFilter(tr.rateLimits, model.namespace, model.name)),
				},
			})
		}

		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.tcp_proxy",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_network_tcpproxy_v3.TcpProxy{
					AccessLog:  r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatTLSPassthrough, r.config.AccessLog.JSONFormatTLSPassthrough),
					StatPrefix: fmt.Sprintf("tls_passthrough_%s_%s_%d", model.namespace, model.name, i),
					HashPolicy: r.toTCPProxyHashpolicyForTLS(tr.persistentBackend),
					ClusterSpecifier: &envoy_extensions_filters_network_tcpproxy_v3.TcpProxy_Cluster{
						Cluster: r.getClusterName(tr.backendRef.name),
					},
				}),
			},
		})

		f := &envoy_config_listener_v3.FilterChain{
			FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
				TransportProtocol: "tls",
				ServerNames:       r.toTLSServerNames(tr.match.hostNames),
			},
			Filters: networkFilters,
		}

		tlsPassthroughFilterChains = append(tlsPassthroughFilterChains, f)
	}

	return tlsPassthroughFilterChains
}

func (r *lbServiceT2Translator) desiredEnvoyListenerTLSProxyFilterChains(model *lbService) []*envoy_config_listener_v3.FilterChain {
	validationContext := r.toTLSValidationContext(model.namespace, model.applications.tlsProxy.tlsConfig)

	tlsProxyFilterChains := []*envoy_config_listener_v3.FilterChain{}
	for i, tr := range model.applications.tlsProxy.routes {
		networkFilters := []*envoy_config_listener_v3.Filter{}

		if tr.connectionFiltering != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.rbac",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toTLSRouteRBACFilter(tr.connectionFiltering, model.namespace, model.name)),
				},
			})
		}

		if tr.rateLimits != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.local_ratelimit",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toNetworkRateLimitFilter(tr.rateLimits, model.namespace, model.name)),
				},
			})
		}

		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.tcp_proxy",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_network_tcpproxy_v3.TcpProxy{
					AccessLog:  r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatTLS, r.config.AccessLog.JSONFormatTLS),
					StatPrefix: fmt.Sprintf("tls_proxy_%s_%s_%d", model.namespace, model.name, i),
					HashPolicy: r.toTCPProxyHashpolicyForTLS(tr.persistentBackend),
					ClusterSpecifier: &envoy_extensions_filters_network_tcpproxy_v3.TcpProxy_Cluster{
						Cluster: r.getClusterName(tr.backendRef.name),
					},
				}),
			},
		})

		f := &envoy_config_listener_v3.FilterChain{
			FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
				TransportProtocol: "tls",
				ServerNames:       r.toTLSServerNames(tr.match.hostNames),
			},
			TransportSocket: &envoy_config_core_v3.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.DownstreamTlsContext{
						// Upstream Envoy Secret Sync only supports setting the trusted CA without further verification data.
						// Therefore it's necessary to explicitly enable `require_client_certificate if the validation context isn't nil.
						//
						// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-certificatevalidationcontext
						// By default, a client certificate is optional, unless one of the additional options (require_client_certificate, verify_certificate_spki, verify_certificate_hash, or match_typed_subject_alt_names) is also specified.
						RequireClientCertificate: r.requiresClientCertificate(validationContext),
						CommonTlsContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext{
							TlsCertificateSdsSecretConfigs: r.toTLSCertificateSdsConfigs(model.namespace, model.applications.tlsProxy.tlsConfig),
							ValidationContextType:          validationContext,
							AlpnProtocols:                  r.toAlpnProtocols(model),
							TlsParams:                      r.toListenerTLSParams(model.applications.tlsProxy.tlsConfig),
						},
					}),
				},
			},
			Filters: networkFilters,
		}

		tlsProxyFilterChains = append(tlsProxyFilterChains, f)
	}

	return tlsProxyFilterChains
}

func (r *lbServiceT2Translator) desiredEnvoyListenerTCPProxyFilterChains(model *lbService) []*envoy_config_listener_v3.FilterChain {
	tcpProxyFilterChains := []*envoy_config_listener_v3.FilterChain{}
	for i, tr := range model.applications.tcpProxy.routes {
		networkFilters := []*envoy_config_listener_v3.Filter{}

		if tr.connectionFiltering != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.rbac",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toTCPRouteRBACFilter(tr.connectionFiltering, model.namespace, model.name)),
				},
			})
		}

		if tr.rateLimits != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.local_ratelimit",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toNetworkRateLimitFilter(tr.rateLimits, model.namespace, model.name)),
				},
			})
		}

		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.tcp_proxy",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_network_tcpproxy_v3.TcpProxy{
					AccessLog:  r.desiredEnvoyAccessLoggers(model, r.config.AccessLog.FormatTCP, r.config.AccessLog.JSONFormatTCP),
					StatPrefix: fmt.Sprintf("tcp_proxy_%s_%s_%d", model.namespace, model.name, i),
					HashPolicy: r.toTCPProxyHashpolicy(tr.persistentBackend),
					ClusterSpecifier: &envoy_extensions_filters_network_tcpproxy_v3.TcpProxy_Cluster{
						Cluster: r.getClusterName(tr.backendRef.name),
					},
				}),
			},
		})

		f := &envoy_config_listener_v3.FilterChain{
			FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
				TransportProtocol: "raw_buffer",
			},
			Filters: networkFilters,
		}

		tcpProxyFilterChains = append(tcpProxyFilterChains, f)
	}

	return tcpProxyFilterChains
}

func (r *lbServiceT2Translator) desiredEnvoyAccessLoggers(model *lbService, textFormatString string, jsonFormatString string) []*envoy_config_accesslog_v3.AccessLog {
	accessLoggers := []*envoy_config_accesslog_v3.AccessLog{}

	textFormatString = strings.ReplaceAll(textFormatString, "%SERVICE_NAMESPACE%", model.namespace)
	textFormatString = strings.ReplaceAll(textFormatString, "%SERVICE_NAME%", model.name)
	jsonFormatString = strings.ReplaceAll(jsonFormatString, "%SERVICE_NAMESPACE%", model.namespace)
	jsonFormatString = strings.ReplaceAll(jsonFormatString, "%SERVICE_NAME%", model.name)

	if r.config.AccessLog.EnableStdOut {
		accessLoggers = append(accessLoggers, &envoy_config_accesslog_v3.AccessLog{
			Name: "stdout",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_accessloggers_stream_v3.StdoutAccessLog{
					AccessLogFormat: &envoy_extensions_accessloggers_stream_v3.StdoutAccessLog_LogFormat{
						LogFormat: &envoy_config_core_v3.SubstitutionFormatString{
							Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
								TextFormatSource: &envoy_config_core_v3.DataSource{
									Specifier: &envoy_config_core_v3.DataSource_InlineString{
										InlineString: fmt.Sprintf("%s\n", textFormatString),
									},
								},
							},
						},
					},
				}),
			},
		})
	}

	if r.config.AccessLog.FilePath != "" {
		jsonFormatMap := map[string]any{}
		if err := json.Unmarshal([]byte(jsonFormatString), &jsonFormatMap); err != nil {
			r.logger.Error("Failed to unmarshal JSON accesslog format - skipping",
				logfields.Path, r.config.AccessLog.FilePath,
				logfields.Error, err)
			return accessLoggers
		}

		jsonFormatStruct, err := structpb.NewStruct(jsonFormatMap)
		if err != nil {
			r.logger.Error("Failed to create protobuf struct for JSON accesslog format - skipping",
				logfields.Path, r.config.AccessLog.FilePath,
				logfields.Error, err)
			return accessLoggers
		}

		accessLoggers = append(accessLoggers, &envoy_config_accesslog_v3.AccessLog{
			Name: "file",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_accessloggers_file_v3.FileAccessLog{
					Path: r.config.AccessLog.FilePath,
					AccessLogFormat: &envoy_extensions_accessloggers_file_v3.FileAccessLog_LogFormat{
						LogFormat: &envoy_config_core_v3.SubstitutionFormatString{
							Format: &envoy_config_core_v3.SubstitutionFormatString_JsonFormat{
								JsonFormat: jsonFormatStruct,
							},
							JsonFormatOptions: &envoy_config_core_v3.JsonFormatOptions{
								SortProperties: true,
							},
						},
					},
				}),
			},
		})
	}

	// Include gRPC access logger only if enabled globally AND not disabled per-service.
	if r.config.AccessLog.EnableGRPC && model.grpcAccessLogsEnabledForService() {
		accessLoggers = append(accessLoggers, &envoy_config_accesslog_v3.AccessLog{
			Name: "envoy.access_loggers.http_grpc",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_access_loggers_grpc_v3.HttpGrpcAccessLogConfig{
					CommonConfig: &envoy_extensions_access_loggers_grpc_v3.CommonGrpcAccessLogConfig{
						LogName: "ilb",
						GrpcService: &envoy_config_core_v3.GrpcService{
							TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
								EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
									// TODO: cleanup once upstream supports namespacing of accesslog cluster
									ClusterName: fmt.Sprintf("%s/%s/%s", model.namespace, model.getOwningResourceName(), r.accessLoggerClusterName(model)),
								},
							},
						},
					},
				}),
			},
		})
	}

	return accessLoggers
}

func (r *lbServiceT2Translator) desiredEnvoyRouteConfigs(model *lbService) ([]*envoy_config_route_v3.RouteConfiguration, error) {
	routeConfigs := []*envoy_config_route_v3.RouteConfiguration{}

	if model.applications.isHTTPProxyConfigured() {
		httpRouteConfig, err := r.desiredEnvoyHttpRouteConfig(model)
		if err != nil {
			return nil, err
		}
		routeConfigs = append(routeConfigs, httpRouteConfig)
	}

	if model.applications.isHTTPSProxyConfigured() {
		httpsRouteConfig, err := r.desiredEnvoyHttpsRouteConfig(model)
		if err != nil {
			return nil, err
		}
		routeConfigs = append(routeConfigs, httpsRouteConfig)

	}

	return routeConfigs, nil
}

func (r *lbServiceT2Translator) desiredEnvoyHttpRouteConfig(model *lbService) (*envoy_config_route_v3.RouteConfiguration, error) {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}
	if model.applications.httpProxy != nil {
		blockRoute, err := r.wafTranslator.BlockRoute(model.name, model.namespace, model.effectiveWAFConfig)
		if err != nil {
			return nil, err
		}

		virtualHosts = r.desiredEnvoyHttpRouteVirtualHosts(
			blockRoute,
			model.usesHTTPRequestFiltering(),
			model.usesHTTPRequestRateLimiting(),
			model.usesHTTPBasicAuth(),
			model.usesHTTPJWTAuth(),
			model.applications.httpProxy.routes,
			httpTypeHTTP,
			model.namespace,
			model.name,
		)
	}

	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_http",
		VirtualHosts: virtualHosts,
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyHttpsRouteConfig(model *lbService) (*envoy_config_route_v3.RouteConfiguration, error) {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}
	if model.applications.httpsProxy != nil {
		blockRoute, err := r.wafTranslator.BlockRoute(model.name, model.namespace, model.effectiveWAFConfig)
		if err != nil {
			return nil, err
		}

		virtualHosts = r.desiredEnvoyHttpRouteVirtualHosts(
			blockRoute,
			model.usesHTTPSRequestFiltering(),
			model.usesHTTPSRequestRateLimiting(),
			model.usesHTTPSBasicAuth(),
			model.usesHTTPSJWTAuth(),
			model.applications.httpsProxy.routes,
			httpTypeHTTPS,
			model.namespace,
			model.name,
		)
	}

	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_https",
		VirtualHosts: virtualHosts,
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyHttpRouteVirtualHosts(blockRoute *envoy_config_route_v3.Route, usesRequestFiltering bool, usesRateLimiting bool, usesBasicAuth bool, usesJWTAuth bool, modelRoutes map[string][]lbRouteHTTP, httpType string, namespace string, name string) []*envoy_config_route_v3.VirtualHost {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}

	routeHostNamesOrdered := slices.Sorted(maps.Keys(modelRoutes))

	for _, routeHostname := range routeHostNamesOrdered {
		envoyRoutes := []*envoy_config_route_v3.Route{}
		if blockRoute != nil {
			envoyRoutes = append(envoyRoutes, blockRoute)
		}

		for _, route := range modelRoutes[routeHostname] {
			tpfc := map[string]*anypb.Any{}
			if usesBasicAuth && route.auth != nil && route.auth.basicAuth != nil {
				tpfc["envoy.filters.http.basic_auth"] = toAny(r.toHTTPRouteBasicAuthFilter(route.auth.basicAuth))
			}
			if usesJWTAuth && route.auth != nil && route.auth.jwtAuth != nil {
				tpfc["envoy.filters.http.jwt_authn"] = toAny(r.toHTTPRouteJWTAuthFilter(route.auth.jwtAuth))
			}
			if usesRequestFiltering {
				tpfc["envoy.filters.http.rbac"] = toAny(r.toHTTPRouteRBACFilter(route.requestFiltering))
			}
			if usesRateLimiting {
				tpfc["envoy.filters.http.local_ratelimit"] = toAny(r.toHTTPRateLimitFilter(route.rateLimits, namespace, name))
			}

			envoyRoutes = append(envoyRoutes, &envoy_config_route_v3.Route{
				Match: r.toRouteMatch(route.match),
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						HashPolicy: r.toHTTPRouteHashpolicy(route.persistentBackend),
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: r.getClusterName(route.backendRef.name),
						},
					},
				},
				TypedPerFilterConfig: tpfc,
			})
		}

		cleanedHostName := strings.ReplaceAll(routeHostname, "*", "wildcard")
		cleanedHostName = strings.ReplaceAll(cleanedHostName, ".", "_")

		virtualHosts = append(virtualHosts,
			&envoy_config_route_v3.VirtualHost{
				Name:    fmt.Sprintf("frontend_virtualhost_%s_%s", httpType, cleanedHostName),
				Domains: []string{routeHostname},
				Routes:  envoyRoutes,
				RequestHeadersToRemove: []string{
					"x-envoy-internal",
					"x-envoy-external-address",
				},
				ResponseHeadersToRemove: []string{
					"x-envoy-upstream-service-time",
					"x-envoy-overloaded",
				},
			},
		)
	}

	return virtualHosts
}

func (r *lbServiceT2Translator) toRouteMatch(match lbRouteHTTPMatch) *envoy_config_route_v3.RouteMatch {
	switch match.pathType {
	case routePathTypePrefix:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: match.path,
			},
		}
	case routePathTypeExact:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
				Path: match.path,
			},
		}

	default:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: "/",
			},
		}
	}
}

func (r *lbServiceT2Translator) desiredEnvoyRouterFilter() *envoy_extensions_filters_http_router_v3.Router {
	return &envoy_extensions_filters_http_router_v3.Router{
		SuppressEnvoyHeaders: true,
	}
}

func (r *lbServiceT2Translator) desiredHealthCheckFilter(model *lbService) *envoy_extensions_filters_http_healthcheck_v3.HealthCheck {
	healthCheckFilterClusters := map[string]*envoy_type_v3.Percent{}

	minHealthyBackendPercentage := min(r.config.T1T2HealthCheck.T2ProbeMinHealthyBackendPercentage, 100)

	refBackendNamesSorted := slices.Sorted(maps.Keys(model.referencedBackends))

	for _, bn := range refBackendNamesSorted {
		healthCheckFilterClusters[r.getClusterName(bn)] = &envoy_type_v3.Percent{Value: float64(minHealthyBackendPercentage)}
	}

	healthCheckFilter := &envoy_extensions_filters_http_healthcheck_v3.HealthCheck{
		PassThroughMode:              &wrapperspb.BoolValue{Value: false},
		ClusterMinHealthyPercentages: healthCheckFilterClusters,
		Headers: []*envoy_config_route_v3.HeaderMatcher{
			{
				Name: ":path",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: r.config.T1T2HealthCheck.T1ProbeHttpPath,
						},
					},
				},
			},
			{
				Name: ":method",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: r.config.T1T2HealthCheck.T1ProbeHttpMethod,
						},
					},
				},
			},
			{
				Name: "user-agent",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Prefix{
							Prefix: r.config.T1T2HealthCheck.T1ProbeHttpUserAgentPrefix,
						},
					},
				},
			},
		},
	}

	return healthCheckFilter
}

func (r *lbServiceT2Translator) desiredEnvoyClusters(model *lbService) []*envoy_config_cluster_v3.Cluster {
	clusters := []*envoy_config_cluster_v3.Cluster{}

	refBackendNamesSorted := slices.Sorted(maps.Keys(model.referencedBackends))

	for _, bn := range refBackendNamesSorted {
		clusters = append(clusters, r.desiredEnvoyCluster(model, r.getClusterName(bn), model.referencedBackends[bn]))
	}

	clusters = append(clusters, r.desiredJWKSEnvoyClusters(model)...)

	return clusters
}

func (r *lbServiceT2Translator) desiredJWKSEnvoyClusters(model *lbService) []*envoy_config_cluster_v3.Cluster {
	clusters := []*envoy_config_cluster_v3.Cluster{}

	if model.usesHTTPJWTAuth() {
		for _, provider := range model.applications.httpProxy.auth.jwtAuth.providers {
			if cluster := r.desiredJWKSEnvoyCluster(model, httpTypeHTTP, provider); cluster != nil {
				clusters = append(clusters, cluster)
			}
		}
	}

	if model.usesHTTPSJWTAuth() {
		for _, provider := range model.applications.httpsProxy.auth.jwtAuth.providers {
			if cluster := r.desiredJWKSEnvoyCluster(model, httpTypeHTTPS, provider); cluster != nil {
				clusters = append(clusters, cluster)
			}
		}
	}

	return clusters
}

func (r *lbServiceT2Translator) desiredJWKSEnvoyCluster(model *lbService, httpType string, provider jwtProvider) *envoy_config_cluster_v3.Cluster {
	if provider.remoteJWKS == nil {
		return nil
	}

	uri, err := url.ParseRequestURI(provider.remoteJWKS.httpURI)
	if err != nil {
		// The API validation (format=uri) guarantees that the
		// given URI can be parsed with url.ParseRequestURI.
		// So, this shouldn't happen.
		r.logger.Error("BUG: Cannot parse JWKS URI",
			logfields.URL, provider.remoteJWKS.httpURI,
			logfields.Error, err,
		)
		return nil
	}

	var port uint32
	if uri.Port() == "" {
		// Port unspecified. Set default values.
		switch uri.Scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	} else {
		// port number is 16bit
		port64, err := strconv.ParseUint(uri.Port(), 10, 16)
		if err != nil {
			return nil
		}
		// Envoy takes port number as uint32
		port = uint32(port64)
	}

	var transportSocket *envoy_config_core_v3.TransportSocket
	if uri.Scheme == "https" {
		transportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.UpstreamTlsContext{}),
			},
		}
	}

	return &envoy_config_cluster_v3.Cluster{
		Name: r.jwksClusterName(httpType, provider.name),
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_STRICT_DNS,
		},
		DnsLookupFamily: r.dnsLookupFamily(model),
		TransportSocket: transportSocket,
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: r.jwksClusterName(httpType, provider.name),
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &envoy_config_endpoint_v3.Endpoint{
									Address: &envoy_config_core_v3.Address{
										Address: &envoy_config_core_v3.Address_SocketAddress{
											SocketAddress: &envoy_config_core_v3.SocketAddress{
												Address:       uri.Hostname(),
												PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: port},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *lbServiceT2Translator) dnsLookupFamily(model *lbService) envoy_config_cluster_v3.Cluster_DnsLookupFamily {
	switch {
	case r.config.IPFamilies.EnableIPv4 && r.config.IPFamilies.EnableIPv6:
		return envoy_config_cluster_v3.Cluster_AUTO
	case r.config.IPFamilies.EnableIPv4:
		return envoy_config_cluster_v3.Cluster_V4_ONLY
	case r.config.IPFamilies.EnableIPv6:
		return envoy_config_cluster_v3.Cluster_V6_ONLY
	}

	return envoy_config_cluster_v3.Cluster_V4_ONLY
}

func (r *lbServiceT2Translator) dnsLookupFamilyDNSExtension(model *lbService) envoy_extensions_clusters_common_dns_v3.DnsLookupFamily {
	switch {
	case r.config.IPFamilies.EnableIPv4 && r.config.IPFamilies.EnableIPv6:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_AUTO
	case r.config.IPFamilies.EnableIPv4:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_ONLY
	case r.config.IPFamilies.EnableIPv6:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V6_ONLY
	}

	return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_ONLY
}

func (r *lbServiceT2Translator) toHealthCheckTransportSocketMatches(healthCheckConfig lbBackendHealthCheckConfig) []*envoy_config_cluster_v3.Cluster_TransportSocketMatch {
	return []*envoy_config_cluster_v3.Cluster_TransportSocketMatch{
		{
			Name: "healthcheck",
			Match: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"type": structpb.NewStringValue("healthcheck"),
				},
			},
			TransportSocket: r.toTransportSocket(healthCheckConfig.tlsConfig, nil),
		},
	}
}

func (r *lbServiceT2Translator) toHealthCheckTransportSocketMatchCriteria(backend backend) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"type": structpb.NewStringValue("healthcheck"),
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyCluster(model *lbService, name string, b backend) *envoy_config_cluster_v3.Cluster {
	cluster := &envoy_config_cluster_v3.Cluster{
		Name: name,
		CommonLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig{
			// disabling panic mode (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/panic_threshold)
			HealthyPanicThreshold: &envoy_type_v3.Percent{Value: 0.0},
		},
		ConnectTimeout:         &durationpb.Duration{Seconds: int64(b.tcpConfig.connectTimeoutSeconds)},
		TransportSocketMatches: r.toHealthCheckTransportSocketMatches(b.healthCheckConfig),
		HealthChecks:           r.toClusterHealthChecks(b.healthCheckConfig, r.toHealthCheckTransportSocketMatchCriteria(b)),
		LbPolicy:               r.mapLbPolicy(b.lbAlgorithm.algorithm),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": r.toClusterHTTPProtocolOptions(b.httpConfig),
		},
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(32768), // 32KiB
		TransportSocket:               r.toTransportSocket(b.tlsConfig, b.proxyProtocol),
		IgnoreHealthOnHostRemoval:     true,
		TrackClusterStats: &envoy_config_cluster_v3.TrackClusterStats{
			TimeoutBudgets:       r.config.Metrics.ClusterTimeoutBudget,
			RequestResponseSizes: r.config.Metrics.ClusterAdditionalRequestResponse,
			PerEndpointStats:     r.config.Metrics.ClusterPerEndpoint,
		},
	}

	switch cluster.LbPolicy {
	case envoy_config_cluster_v3.Cluster_ROUND_ROBIN:
		cluster.LbConfig = r.toLbConfigRoundRobin()
	case envoy_config_cluster_v3.Cluster_LEAST_REQUEST:
		cluster.LbConfig = r.toLbConfigLeastRequest()
	case envoy_config_cluster_v3.Cluster_MAGLEV:
		cluster.LbConfig = r.toLbConfigMaglev(b.lbAlgorithm)
	}

	if localityConfigSpecifier := r.lookupLocalityConfigSpecifier(model); localityConfigSpecifier != nil {
		cluster.CommonLbConfig.LocalityConfigSpecifier = localityConfigSpecifier
	}

	switch b.typ {
	case lbBackendTypeHostname:
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_ClusterType{
			ClusterType: &envoy_config_cluster_v3.Cluster_CustomClusterType{
				Name: "envoy.clusters.dns",
				TypedConfig: toAny(&envoy_extensions_clusters_dns_v3.DnsCluster{
					DnsRefreshRate: &durationpb.Duration{Seconds: 10},
					DnsFailureRefreshRate: &envoy_extensions_clusters_dns_v3.DnsCluster_RefreshRate{
						BaseInterval: &durationpb.Duration{Seconds: 10},
						MaxInterval:  &durationpb.Duration{Seconds: 100},
					},
					RespectDnsTtl: true,
					TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
						Name:        "envoy.network.dns_resolver.cares",
						TypedConfig: toAny(r.toDNSResolverConfig(b)),
					},
					DnsLookupFamily:              r.dnsLookupFamilyDNSExtension(model),
					AllAddressesInSingleEndpoint: false, // strict dns
				}),
			},
		}

		// For STRICT_DNS cluster, we must specify endpoint inline in the cluster
		cluster.LoadAssignment = r.desiredEnvoyClusterLoadAssignment(name, b)

	default:
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_EDS,
		}
	}

	return cluster
}

func (r *lbServiceT2Translator) toDNSResolverConfig(b backend) *envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig {
	resolverConfig := &envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
		DnsResolverOptions: &envoy_config_core_v3.DnsResolverOptions{
			// For the sake of simplicity, we disable default search domain for now
			NoDefaultSearchDomain: true,
		},
	}

	if b.dnsResolverConfig != nil {
		for _, resolver := range b.dnsResolverConfig.resolvers {
			resolverConfig.Resolvers = append(resolverConfig.Resolvers, &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address: resolver.ip,
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: resolver.port,
						},
					},
				},
			})
		}
	}

	return resolverConfig
}

func (r *lbServiceT2Translator) toLbConfigRoundRobin() *envoy_config_cluster_v3.Cluster_RoundRobinLbConfig_ {
	return &envoy_config_cluster_v3.Cluster_RoundRobinLbConfig_{
		RoundRobinLbConfig: &envoy_config_cluster_v3.Cluster_RoundRobinLbConfig{},
	}
}

func (r *lbServiceT2Translator) toLbConfigLeastRequest() *envoy_config_cluster_v3.Cluster_LeastRequestLbConfig_ {
	return &envoy_config_cluster_v3.Cluster_LeastRequestLbConfig_{
		LeastRequestLbConfig: &envoy_config_cluster_v3.Cluster_LeastRequestLbConfig{},
	}
}

func (r *lbServiceT2Translator) toLbConfigMaglev(algorithmConfig lbBackendLBAlgorithm) *envoy_config_cluster_v3.Cluster_MaglevLbConfig_ {
	return &envoy_config_cluster_v3.Cluster_MaglevLbConfig_{
		MaglevLbConfig: &envoy_config_cluster_v3.Cluster_MaglevLbConfig{
			TableSize: wrapperspb.UInt64(uint64(algorithmConfig.consistentHashing.maglevTableSize)),
		},
	}
}

func (r *lbServiceT2Translator) rawTransportSocket() *envoy_config_core_v3.TransportSocket {
	return &envoy_config_core_v3.TransportSocket{
		Name: "envoy.transport_sockets.raw_buffer",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: toAny(&envoy_extensions_transportsockets_rawbuffer_v3.RawBuffer{}),
		},
	}
}

func (r *lbServiceT2Translator) wrapWithTLSTransport(tlsConfig *lbBackendTLSConfig) *envoy_config_core_v3.TransportSocket {
	if tlsConfig == nil {
		return r.rawTransportSocket()
	}

	return &envoy_config_core_v3.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.UpstreamTlsContext{
				CommonTlsContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext{
					TlsParams: r.toClusterTLSParams(tlsConfig),
				},
			}),
		},
	}
}

func (r *lbServiceT2Translator) wrapWithProxyProtocolTransport(ts *envoy_config_core_v3.TransportSocket, proxyProtocol *lbBackendProxyProtocolConfig) *envoy_config_core_v3.TransportSocket {
	if proxyProtocol == nil {
		return ts
	}

	ppUpstreamTransport := &envoy_extensions_transportsockets_proxy_protocol_v3.ProxyProtocolUpstreamTransport{}
	switch proxyProtocol.version {
	case proxyProtocolVersionV1:
		ppUpstreamTransport.Config = &envoy_config_core_v3.ProxyProtocolConfig{
			Version: envoy_config_core_v3.ProxyProtocolConfig_V1,
		}
	case proxyProtocolVersionV2:
		ppUpstreamTransport.Config = &envoy_config_core_v3.ProxyProtocolConfig{
			Version: envoy_config_core_v3.ProxyProtocolConfig_V2,
			PassThroughTlvs: &envoy_config_core_v3.ProxyProtocolPassThroughTLVs{
				TlvType: proxyProtocol.passthroughTLVs,
			},
		}
	}
	ppUpstreamTransport.TransportSocket = ts

	return &envoy_config_core_v3.TransportSocket{
		Name: "envoy.transport_sockets.proxy_protocol",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: toAny(ppUpstreamTransport),
		},
	}
}

func (r *lbServiceT2Translator) toTransportSocket(tlsConfig *lbBackendTLSConfig, proxyProtocol *lbBackendProxyProtocolConfig) *envoy_config_core_v3.TransportSocket {
	return r.wrapWithProxyProtocolTransport(r.wrapWithTLSTransport(tlsConfig), proxyProtocol)
}

func (r *lbServiceT2Translator) toClusterHTTPProtocolOptions(httpConfig lbBackendHTTPConfig) *anypb.Any {
	switch {
	case httpConfig.enableHTTP11 && !httpConfig.enableHTTP2:
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
				MaxConnectionDuration: durationpb.New(time.Hour),
			},
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			},
		})
	case httpConfig.enableHTTP2 && !httpConfig.enableHTTP11:
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
				MaxConnectionDuration: durationpb.New(time.Hour),
			},
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
				},
			},
		})
	default:
		// use HTTP1.1 if both protocol versions are enabled.
		// The reason is to prevent HTTP/2 issues due to backends that don't support H2C (HTTP2 without TLS).
		// Note: Once we support TLS re-encryption to the backend we can enable AutoConfig to make use of ALPN protocol negotiation.
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
				MaxConnectionDuration: durationpb.New(time.Hour),
			},
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			},
		})
	}
}

func (r *lbServiceT2Translator) toClusterHealthChecks(healthCheckConfig lbBackendHealthCheckConfig, hcTransportSocketMatchCriteria *structpb.Struct) []*envoy_config_core_v3.HealthCheck {
	healthCheck := &envoy_config_core_v3.HealthCheck{
		Interval:                     &durationpb.Duration{Seconds: int64(healthCheckConfig.intervalSeconds)},
		UnhealthyInterval:            &durationpb.Duration{Seconds: int64(healthCheckConfig.unhealthyIntervalSeconds)},
		UnhealthyEdgeInterval:        &durationpb.Duration{Seconds: int64(healthCheckConfig.unhealthyEdgeIntervalSeconds)},
		NoTrafficInterval:            &durationpb.Duration{Seconds: int64(healthCheckConfig.unhealthyEdgeIntervalSeconds)},
		Timeout:                      &durationpb.Duration{Seconds: int64(healthCheckConfig.timeoutSeconds)},
		HealthyThreshold:             &wrapperspb.UInt32Value{Value: uint32(healthCheckConfig.healthyThreshold)},
		UnhealthyThreshold:           &wrapperspb.UInt32Value{Value: uint32(healthCheckConfig.unhealthyThreshold)},
		TransportSocketMatchCriteria: hcTransportSocketMatchCriteria,
	}

	if r.config.T1T2HealthCheck.T2EnvoyHCEventLoggingEnabled {
		healthCheck.AlwaysLogHealthCheckFailures = true
		healthCheck.AlwaysLogHealthCheckSuccess = true
		healthCheck.EventLogger = []*envoy_config_core_v3.TypedExtensionConfig{
			{
				Name: "cilium.health_check.event_sink.pipe",
				TypedConfig: toAny(&cilium_proxy_api.HealthCheckEventPipeSink{
					Path: envoy.GetSocketDir(r.config.T1T2HealthCheck.T2EnvoyHCEventLoggingStateDir) + "/healthcheck_sink.sock",
				}),
			},
		}
	}

	switch {
	case healthCheckConfig.http != nil:
		healthCheck.HealthChecker = r.toClusterHealthCheckerHTTP(healthCheckConfig)
	case healthCheckConfig.tcp != nil:
		healthCheck.HealthChecker = r.toClusterHealthCheckerTCP(healthCheckConfig)
	default:
		return nil
	}
	return []*envoy_config_core_v3.HealthCheck{
		healthCheck,
	}
}

func (r *lbServiceT2Translator) toClusterHealthCheckerHTTP(healthCheckConfig lbBackendHealthCheckConfig) *envoy_config_core_v3.HealthCheck_HttpHealthCheck_ {
	check := &envoy_config_core_v3.HealthCheck_HttpHealthCheck_{
		HttpHealthCheck: &envoy_config_core_v3.HealthCheck_HttpHealthCheck{
			Host:             healthCheckConfig.http.host,
			Path:             healthCheckConfig.http.path,
			Method:           r.toHealthCheckHTTPMethod(healthCheckConfig.http.method),
			ExpectedStatuses: r.toHealthCheckHTTPStatusCodes(healthCheckConfig.http.healthyStatusCodes),
		},
	}

	if healthCheckConfig.http.send != nil {
		check.HttpHealthCheck.Send = r.toHealthPayload(healthCheckConfig.http.send)
	}

	if healthCheckConfig.http.receive != nil {
		check.HttpHealthCheck.ResponseBufferSize = wrapperspb.UInt64(0) // Match on entire response
		receive := []*envoy_config_core_v3.HealthCheck_Payload{}

		for _, p := range healthCheckConfig.http.receive {
			receive = append(receive, r.toHealthPayload(p))
		}

		check.HttpHealthCheck.Receive = receive
	}

	return check
}

func (r *lbServiceT2Translator) toHealthPayload(input *lbBackendHealthCheckPayload) *envoy_config_core_v3.HealthCheck_Payload {
	result := &envoy_config_core_v3.HealthCheck_Payload{}

	switch {
	case input.text != nil:
		result.Payload = &envoy_config_core_v3.HealthCheck_Payload_Text{
			Text: *input.text,
		}
	}

	return result
}

func (r *lbServiceT2Translator) toHealthCheckHTTPMethod(method lbBackendHealthCheckHTTPMethod) envoy_config_core_v3.RequestMethod {
	switch method {
	case lbBackendHealthCheckHTTPMethodGet:
		return envoy_config_core_v3.RequestMethod_GET
	case lbBackendHealthCheckHTTPMethodConnect:
		return envoy_config_core_v3.RequestMethod_CONNECT
	case lbBackendHealthCheckHTTPMethodDelete:
		return envoy_config_core_v3.RequestMethod_DELETE
	case lbBackendHealthCheckHTTPMethodHead:
		return envoy_config_core_v3.RequestMethod_HEAD
	case lbBackendHealthCheckHTTPMethodOptions:
		return envoy_config_core_v3.RequestMethod_OPTIONS
	case lbBackendHealthCheckHTTPMethodPatch:
		return envoy_config_core_v3.RequestMethod_PATCH
	case lbBackendHealthCheckHTTPMethodPost:
		return envoy_config_core_v3.RequestMethod_POST
	case lbBackendHealthCheckHTTPMethodPut:
		return envoy_config_core_v3.RequestMethod_PUT
	case lbBackendHealthCheckHTTPMethodTrace:
		return envoy_config_core_v3.RequestMethod_TRACE
	default:
		return envoy_config_core_v3.RequestMethod_GET
	}
}

func (r *lbServiceT2Translator) toHealthCheckHTTPStatusCodes(codes []lbBackendHealthCheckHTTPStatusRange) []*envoy_type_v3.Int64Range {
	result := []*envoy_type_v3.Int64Range{}

	for _, hchr := range codes {
		result = append(result, &envoy_type_v3.Int64Range{
			Start: int64(hchr.start),
			End:   int64(hchr.end),
		})
	}

	return result
}

func (r *lbServiceT2Translator) toClusterHealthCheckerTCP(healthCheckConfig lbBackendHealthCheckConfig) *envoy_config_core_v3.HealthCheck_TcpHealthCheck_ {
	check := &envoy_config_core_v3.HealthCheck_TcpHealthCheck_{
		TcpHealthCheck: &envoy_config_core_v3.HealthCheck_TcpHealthCheck{},
	}

	if healthCheckConfig.tcp.send != nil {
		check.TcpHealthCheck.Send = r.toHealthPayload(healthCheckConfig.tcp.send)
	}

	if healthCheckConfig.tcp.receive != nil {
		receive := []*envoy_config_core_v3.HealthCheck_Payload{}

		for _, p := range healthCheckConfig.tcp.receive {
			receive = append(receive, r.toHealthPayload(p))
		}

		check.TcpHealthCheck.Receive = receive
	}

	return check
}

func (r *lbServiceT2Translator) desiredEnvoyClusterLoadAssignments(model *lbService) []*envoy_config_endpoint_v3.ClusterLoadAssignment {
	loadAssignments := []*envoy_config_endpoint_v3.ClusterLoadAssignment{}

	if la := r.desiredEnvoyZoneAwarenessLoadAssignment(model); la != nil {
		loadAssignments = append(loadAssignments, la)
	}

	refBackendNamesSorted := slices.Sorted(maps.Keys(model.referencedBackends))

	for _, bn := range refBackendNamesSorted {
		// For STRICT_DNS cluster, we must specify endpoint inline in the cluster
		if b := model.referencedBackends[bn]; b.typ != lbBackendTypeHostname {
			loadAssignments = append(loadAssignments, r.desiredEnvoyClusterLoadAssignment(r.getClusterName(bn), b))
		}
	}

	return loadAssignments
}

// desiredEnvoyZoneAwarenessLoadAssignment builds the synthetic locality EDS
// resource ILB publishes for Envoy's internal locality cluster. Envoy uses this
// cluster only as a model of the per-zone T2 proxy population when evaluating
// zone-aware routing on T2; it is not used to open real upstream connections.
func (r *lbServiceT2Translator) desiredEnvoyZoneAwarenessLoadAssignment(model *lbService) *envoy_config_endpoint_v3.ClusterLoadAssignment {
	if model.zoneAwareMode != lbServiceZoneAwareModePreferSameZone && model.zoneAwareMode != lbServiceZoneAwareModeRequireSameZone {
		return nil
	}

	addresses := model.t2NodeIPv4Addresses
	addressZone := model.t2NodeIPv4Zones
	if len(addresses) == 0 {
		addresses = model.t2NodeIPv6Addresses
		addressZone = model.t2NodeIPv6Zones
	}

	zoneLbEndpoints := map[string][]*envoy_config_endpoint_v3.LbEndpoint{}
	for _, addr := range addresses {
		zone := addressZone[addr]
		if zone == "" || zone == lbServiceZoneUnknown {
			// The synthetic locality cluster must represent only T2 Envoys with a
			// usable local zone. Embedded Envoy locality requires
			// topology.kubernetes.io/zone and fails startup without it, so nodes
			// with unknown zone are intentionally excluded here.
			continue
		}
		zoneLbEndpoints[zone] = append(zoneLbEndpoints[zone], &envoy_config_endpoint_v3.LbEndpoint{
			LoadBalancingWeight: wrapperspb.UInt32(1),
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
				Endpoint: &envoy_config_endpoint_v3.Endpoint{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Address: addr,
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									// This synthetic locality cluster is used only to model the
									// per-zone T2 node population for Envoy's locality math. It is
									// not used to open real upstream connections, but SocketAddress
									// still requires PortSpecifier to be set, so provide a harmless
									// dummy port value.
									PortValue: 1,
								},
							},
						},
					},
				},
			},
		})
	}

	if len(zoneLbEndpoints) == 0 {
		// No zoned T2 Envoys are available, so there is no locality population
		// model to publish for zone-aware routing.
		return nil
	}

	localityLbEndpoints := make([]*envoy_config_endpoint_v3.LocalityLbEndpoints, 0, len(zoneLbEndpoints))
	for _, zone := range slices.Sorted(maps.Keys(zoneLbEndpoints)) {
		localityLbEndpoints = append(localityLbEndpoints, &envoy_config_endpoint_v3.LocalityLbEndpoints{
			Locality: &envoy_config_core_v3.Locality{
				Zone: zone,
			},
			LbEndpoints: zoneLbEndpoints[zone],
		})
	}

	return &envoy_config_endpoint_v3.ClusterLoadAssignment{
		ClusterName: envoy.LocalityClusterName,
		Endpoints:   localityLbEndpoints,
	}
}

// desiredEnvoyClusterLoadAssignment builds the real backend EDS resource for a
// single upstream cluster, grouping endpoints by zone when that metadata is
// available and preserving unknown-zone endpoints in a fallback bucket.
func (r *lbServiceT2Translator) desiredEnvoyClusterLoadAssignment(name string, b backend) *envoy_config_endpoint_v3.ClusterLoadAssignment {
	zoneLbEndpoints := map[string][]*envoy_config_endpoint_v3.LbEndpoint{}
	bareLbEndpoints := []*envoy_config_endpoint_v3.LbEndpoint{}

	for _, lbBackend := range b.lbBackends {
		var hcConfig *envoy_config_endpoint_v3.Endpoint_HealthCheckConfig
		if b.healthCheckConfig.port > 0 {
			hcConfig = &envoy_config_endpoint_v3.Endpoint_HealthCheckConfig{
				PortValue: b.healthCheckConfig.port,
			}
		}
		for _, a := range lbBackend.addresses {
			lbEndpoint := &envoy_config_endpoint_v3.LbEndpoint{
				LoadBalancingWeight: wrapperspb.UInt32(lbBackend.weight),
				HealthStatus:        r.toHealthStatus(lbBackend.status),
				HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{Endpoint: &envoy_config_endpoint_v3.Endpoint{
					Address: &envoy_config_core_v3.Address{Address: &envoy_config_core_v3.Address_SocketAddress{SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address:       a,
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: uint32(lbBackend.port)},
					}}},
					HealthCheckConfig: hcConfig,
				}},
			}

			if zone, ok := lbBackend.addressZones[a]; ok && zone != "" && zone != lbServiceZoneUnknown {
				zoneLbEndpoints[zone] = append(zoneLbEndpoints[zone], lbEndpoint)
				continue
			}
			bareLbEndpoints = append(bareLbEndpoints, lbEndpoint)
		}
	}

	localityLbEndpoints := make([]*envoy_config_endpoint_v3.LocalityLbEndpoints, 0, len(zoneLbEndpoints)+1)
	for _, zone := range slices.Sorted(maps.Keys(zoneLbEndpoints)) {
		localityLbEndpoints = append(localityLbEndpoints, &envoy_config_endpoint_v3.LocalityLbEndpoints{
			Locality: &envoy_config_core_v3.Locality{
				Zone: zone,
			},
			LbEndpoints: zoneLbEndpoints[zone],
		})
	}
	if len(bareLbEndpoints) > 0 || len(localityLbEndpoints) == 0 {
		localityLbEndpoints = append(localityLbEndpoints, &envoy_config_endpoint_v3.LocalityLbEndpoints{
			LbEndpoints: bareLbEndpoints,
		})
	}

	return &envoy_config_endpoint_v3.ClusterLoadAssignment{
		ClusterName: name,
		Endpoints:   localityLbEndpoints,
	}
}

func (r *lbServiceT2Translator) toHealthStatus(status lbBackendStatus) envoy_config_core_v3.HealthStatus {
	switch status {
	case lbBackendStatusDraining:
		return envoy_config_core_v3.HealthStatus_DRAINING
	default:
		return envoy_config_core_v3.HealthStatus_UNKNOWN
	}
}

func (r *lbServiceT2Translator) toHTTPRouteHashpolicy(persistentBackendConfig *lbRouteHTTPPersistentBackend) []*envoy_config_route_v3.RouteAction_HashPolicy {
	if persistentBackendConfig == nil {
		return nil
	}

	hashPolicy := []*envoy_config_route_v3.RouteAction_HashPolicy{}

	if persistentBackendConfig.sourceIP {
		hashPolicy = append(hashPolicy, &envoy_config_route_v3.RouteAction_HashPolicy{
			PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_ConnectionProperties_{
				ConnectionProperties: &envoy_config_route_v3.RouteAction_HashPolicy_ConnectionProperties{
					SourceIp: persistentBackendConfig.sourceIP,
				},
			},
		})
	}

	for _, c := range persistentBackendConfig.cookieNames {
		hashPolicy = append(hashPolicy, &envoy_config_route_v3.RouteAction_HashPolicy{
			PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_Cookie_{
				Cookie: &envoy_config_route_v3.RouteAction_HashPolicy_Cookie{
					Name: c,
				},
			},
		})
	}

	for _, h := range persistentBackendConfig.headerNames {
		hashPolicy = append(hashPolicy, &envoy_config_route_v3.RouteAction_HashPolicy{
			PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_Header_{
				Header: &envoy_config_route_v3.RouteAction_HashPolicy_Header{
					HeaderName: h,
				},
			},
		})
	}

	if len(hashPolicy) == 0 {
		return nil
	}

	return hashPolicy
}

func (r *lbServiceT2Translator) toTCPProxyHashpolicyForTLS(persistentBackendConfig *lbRouteTLSPersistentBackend) []*envoy_type_v3.HashPolicy {
	if persistentBackendConfig == nil {
		return nil
	}

	hashPolicy := []*envoy_type_v3.HashPolicy{}

	if persistentBackendConfig.sourceIP {
		hashPolicy = append(hashPolicy, &envoy_type_v3.HashPolicy{
			PolicySpecifier: &envoy_type_v3.HashPolicy_SourceIp_{SourceIp: &envoy_type_v3.HashPolicy_SourceIp{}},
		})
	}

	if len(hashPolicy) == 0 {
		return nil
	}

	return hashPolicy
}

func (r *lbServiceT2Translator) toTCPProxyHashpolicy(persistentBackendConfig *lbRouteTCPPersistentBackend) []*envoy_type_v3.HashPolicy {
	if persistentBackendConfig == nil {
		return nil
	}

	hashPolicy := []*envoy_type_v3.HashPolicy{}

	if persistentBackendConfig.sourceIP {
		hashPolicy = append(hashPolicy, &envoy_type_v3.HashPolicy{
			PolicySpecifier: &envoy_type_v3.HashPolicy_SourceIp_{SourceIp: &envoy_type_v3.HashPolicy_SourceIp{}},
		})
	}

	if len(hashPolicy) == 0 {
		return nil
	}

	return hashPolicy
}

func (r *lbServiceT2Translator) mapLbPolicy(lbAlgorithm lbAlgorithmType) envoy_config_cluster_v3.Cluster_LbPolicy {
	switch lbAlgorithm {
	case lbAlgorithmRoundRobin:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	case lbAlgorithmLeastRequest:
		return envoy_config_cluster_v3.Cluster_LEAST_REQUEST
	case lbAlgorithmConsistentHashing:
		return envoy_config_cluster_v3.Cluster_MAGLEV
	default:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	}
}

func (r *lbServiceT2Translator) toHTTPNetworkRBACFilter(config *lbServiceHTTPConnectionFiltering, httpType string, namespace string, name string) *envoy_extensions_filters_network_rbac_v3.RBAC {
	if config == nil {
		return nil
	}

	policies := map[string]*envoy_config_rbac_v3.Policy{}
	action := r.toRBACAction(config.ruleType)

	for i, rr := range config.rules {
		permissions := []*envoy_config_rbac_v3.Permission{}
		principals := []*envoy_config_rbac_v3.Principal{}

		if rr.sourceCIDR != nil {
			principals = append(principals, r.toRBACPrincipalRemoteIP(rr.sourceCIDR))
		}

		if len(principals) == 0 {
			principals = append(principals, r.toRBACPrincipalAny())
		}

		if len(permissions) == 0 {
			permissions = append(permissions, r.toRBACPermissionAny())
		}

		policies[fmt.Sprintf("rule-%d", i)] = &envoy_config_rbac_v3.Policy{
			Permissions: permissions,
			Principals:  principals,
		}
	}

	return &envoy_extensions_filters_network_rbac_v3.RBAC{
		StatPrefix: fmt.Sprintf("%s_%s_%s", httpType, namespace, name),
		Rules: &envoy_config_rbac_v3.RBAC{
			Action:   action,
			Policies: policies,
		},
	}
}

func (r *lbServiceT2Translator) toHTTPRouteRBACFilter(config *lbRouteHTTPRequestFiltering) *envoy_extensions_filters_http_rbac_v3.RBACPerRoute {
	action := envoy_config_rbac_v3.RBAC_DENY
	policies := map[string]*envoy_config_rbac_v3.Policy{}

	rules := []lbRouteHTTPRequestFilteringRule{}

	if config != nil {
		rules = config.rules
		action = r.toRBACAction(config.ruleType)
	}

	for i, rr := range rules {
		permissions := []*envoy_config_rbac_v3.Permission{}
		principals := []*envoy_config_rbac_v3.Principal{}

		if rr.sourceCIDR != nil {
			principals = append(principals, r.toRBACPrincipalRemoteIP(rr.sourceCIDR))
		}

		if rr.jwtClaims != nil {
			principals = append(principals, r.toRBACPrincipalJWTPayloadMetadata(rr.jwtClaims)...)
		}

		if rr.clientCertificateSANs != nil {
			principals = append(principals, r.toRBACPrincipalMTLSAuthenticated(rr.clientCertificateSANs)...)
		}

		if rr.hostname != nil {
			permissions = append(permissions, r.toRBACPermissionHostName(rr.hostname))
		}

		if rr.path != nil {
			permissions = append(permissions, r.toRBACPermissionHTTPPath(rr.path))
		}

		permissions = append(permissions, r.toRBACPermissionHTTPHeaders(rr.headers)...)

		if len(principals) > 0 {
			principals = []*envoy_config_rbac_v3.Principal{r.toRBACPrincipalAnd(principals...)}
		} else {
			principals = []*envoy_config_rbac_v3.Principal{r.toRBACPrincipalAny()}
		}

		if len(permissions) > 0 {
			permissions = []*envoy_config_rbac_v3.Permission{r.toRBACPermissionAnd(permissions...)}
		} else {
			permissions = []*envoy_config_rbac_v3.Permission{r.toRBACPermissionAny()}
		}

		policies[fmt.Sprintf("rule-%d", i)] = &envoy_config_rbac_v3.Policy{
			Permissions: permissions,
			Principals:  principals,
		}
	}

	return &envoy_extensions_filters_http_rbac_v3.RBACPerRoute{
		Rbac: &envoy_extensions_filters_http_rbac_v3.RBAC{
			Rules: &envoy_config_rbac_v3.RBAC{
				Action:   action,
				Policies: policies,
			},
		},
	}
}

func (r *lbServiceT2Translator) toTLSRouteRBACFilter(config *lbRouteTLSConnectionFiltering, namespace string, name string) *envoy_extensions_filters_network_rbac_v3.RBAC {
	if config == nil {
		return nil
	}

	policies := map[string]*envoy_config_rbac_v3.Policy{}
	action := r.toRBACAction(config.ruleType)

	for i, rr := range config.rules {
		permissions := []*envoy_config_rbac_v3.Permission{}
		principals := []*envoy_config_rbac_v3.Principal{}

		if rr.sourceCIDR != nil {
			principals = append(principals, r.toRBACPrincipalRemoteIP(rr.sourceCIDR))
		}

		if rr.clientCertificateSANs != nil {
			principals = append(principals, r.toRBACPrincipalMTLSAuthenticated(rr.clientCertificateSANs)...)
		}

		if rr.servername != nil {
			permissions = append(permissions, r.toRBACPermissionServerName(*rr.servername))
		}

		if len(principals) > 0 {
			principals = []*envoy_config_rbac_v3.Principal{r.toRBACPrincipalAnd(principals...)}
		} else {
			principals = []*envoy_config_rbac_v3.Principal{r.toRBACPrincipalAny()}
		}

		if len(permissions) > 0 {
			permissions = []*envoy_config_rbac_v3.Permission{r.toRBACPermissionAnd(permissions...)}
		} else {
			permissions = []*envoy_config_rbac_v3.Permission{r.toRBACPermissionAny()}
		}

		policies[fmt.Sprintf("rule-%d", i)] = &envoy_config_rbac_v3.Policy{
			Permissions: permissions,
			Principals:  principals,
		}
	}

	return &envoy_extensions_filters_network_rbac_v3.RBAC{
		StatPrefix: fmt.Sprintf("tls_%s_%s", namespace, name),
		Rules: &envoy_config_rbac_v3.RBAC{
			Action:   action,
			Policies: policies,
		},
	}
}

func (r *lbServiceT2Translator) toTCPRouteRBACFilter(config *lbRouteTCPConnectionFiltering, namespace string, name string) *envoy_extensions_filters_network_rbac_v3.RBAC {
	if config == nil {
		return nil
	}

	policies := map[string]*envoy_config_rbac_v3.Policy{}
	action := r.toRBACAction(config.ruleType)

	for i, rr := range config.rules {
		permissions := []*envoy_config_rbac_v3.Permission{}
		principals := []*envoy_config_rbac_v3.Principal{}

		if rr.sourceCIDR != nil {
			principals = append(principals, r.toRBACPrincipalRemoteIP(rr.sourceCIDR))
		}

		if len(principals) == 0 {
			principals = append(principals, r.toRBACPrincipalAny())
		}

		if len(permissions) == 0 {
			permissions = append(permissions, r.toRBACPermissionAny())
		}

		policies[fmt.Sprintf("rule-%d", i)] = &envoy_config_rbac_v3.Policy{
			Permissions: permissions,
			Principals:  principals,
		}
	}

	return &envoy_extensions_filters_network_rbac_v3.RBAC{
		StatPrefix: fmt.Sprintf("tcp_%s_%s", namespace, name),
		Rules: &envoy_config_rbac_v3.RBAC{
			Action:   action,
			Policies: policies,
		},
	}
}

func (r *lbServiceT2Translator) toRBACPrincipalRemoteIP(sourceCIDRRule *lbRouteRequestFilteringSourceCIDR) *envoy_config_rbac_v3.Principal {
	return &envoy_config_rbac_v3.Principal{
		Identifier: &envoy_config_rbac_v3.Principal_RemoteIp{
			RemoteIp: &envoy_config_core_v3.CidrRange{
				AddressPrefix: sourceCIDRRule.addressPrefix,
				PrefixLen:     wrapperspb.UInt32(uint32(sourceCIDRRule.prefixLen)),
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPrincipalJWTPayloadMetadata(jwtClaims []*lbRouteRequestFilteringJWTClaim) []*envoy_config_rbac_v3.Principal {
	principals := []*envoy_config_rbac_v3.Principal{}

	for _, claim := range jwtClaims {

		valueMatcher := &envoy_type_matcher_v3.ValueMatcher_StringMatch{
			StringMatch: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: nil,
				IgnoreCase:   false,
			},
		}

		switch claim.value.valueType {
		case filterJWTClaimTypeExact:
			valueMatcher.StringMatch.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: claim.value.value,
			}
		case filterJWTClaimTypePrefix:
			valueMatcher.StringMatch.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Prefix{
				Prefix: claim.value.value,
			}
		case filterJWTClaimTypeRegex:
			valueMatcher.StringMatch.MatchPattern = &envoy_type_matcher_v3.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
					Regex:      claim.value.value,
				},
			}
		}

		principals = append(principals, &envoy_config_rbac_v3.Principal{
			Identifier: &envoy_config_rbac_v3.Principal_SourcedMetadata{
				SourcedMetadata: &envoy_config_rbac_v3.SourcedMetadata{
					MetadataMatcher: &envoy_type_matcher_v3.MetadataMatcher{
						Filter: "envoy.filters.http.jwt_authn", // JWT Authentication HTTP filter writes JWT payloads into metadata
						Path: []*envoy_type_matcher_v3.MetadataMatcher_PathSegment{
							{
								Segment: &envoy_type_matcher_v3.MetadataMatcher_PathSegment_Key{
									Key: "payload",
								},
							},
							{
								Segment: &envoy_type_matcher_v3.MetadataMatcher_PathSegment_Key{
									Key: claim.name,
								},
							},
						},
						Value: &envoy_type_matcher_v3.ValueMatcher{
							MatchPattern: valueMatcher,
						},
						Invert: false,
					},
					MetadataSource: envoy_config_rbac_v3.MetadataSource_DYNAMIC,
				},
			},
		})
	}

	return principals
}

func (r *lbServiceT2Translator) toRBACPrincipalMTLSAuthenticated(clientCertificateSANs []*lbRouteRequestFilteringClientCertificateSAN) []*envoy_config_rbac_v3.Principal {
	principals := []*envoy_config_rbac_v3.Principal{}

	for _, san := range clientCertificateSANs {

		stringMatcher := &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: nil,
			IgnoreCase:   false,
		}

		switch san.value.valueType {
		case filterClientCertificateSANValueTypeExact:
			stringMatcher.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: san.value.value,
			}
		case filterClientCertificateSANValueTypePrefix:
			stringMatcher.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Prefix{
				Prefix: san.value.value,
			}
		case filterClientCertificateSANValueTypeRegex:
			stringMatcher.MatchPattern = &envoy_type_matcher_v3.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
					Regex:      san.value.value,
				},
			}
		}

		principals = append(principals, &envoy_config_rbac_v3.Principal{
			Identifier: &envoy_config_rbac_v3.Principal_Custom{
				Custom: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.rbac.principals.mtls_authenticated",
					TypedConfig: toAny(&envoy_extensions_rbac_principals_mtlsauthenticated_v3.Config{
						SanMatcher: &envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher{
							SanType: r.toSANType(san.sanType),
							Matcher: stringMatcher,
							Oid:     san.oid,
						},
						AnyValidatedClientCertificate: false,
					}),
				},
			},
		})
	}

	return principals
}

func (r *lbServiceT2Translator) toSANType(sanType string) envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_SanType {
	switch sanType {
	case "DNS":
		return envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_DNS
	case "URI":
		return envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_URI
	case "EMAIL":
		return envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_EMAIL
	case "IP_ADDRESS":
		return envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_IP_ADDRESS
	case "OTHER_NAME":
		return envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_OTHER_NAME
	default:
		return envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_OTHER_NAME
	}
}

func (r *lbServiceT2Translator) toRBACPermissionHostName(hostnameRule *lbRouteRequestFilteringHostName) *envoy_config_rbac_v3.Permission {
	headerPermRule := &envoy_config_rbac_v3.Permission_Header{
		Header: &envoy_config_route_v3.HeaderMatcher{
			Name: ":authority",
		},
	}

	switch hostnameRule.hostNameType {
	case filterHostnameTypeExact:
		headerPermRule.Header.HeaderMatchSpecifier = &envoy_config_route_v3.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
					Exact: hostnameRule.hostName,
				},
			},
		}
	case filterHostnameTypeSuffix:
		headerPermRule.Header.HeaderMatchSpecifier = &envoy_config_route_v3.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_Suffix{
					Suffix: hostnameRule.hostName,
				},
			},
		}
	}

	return &envoy_config_rbac_v3.Permission{
		Rule: headerPermRule,
	}
}

func (r *lbServiceT2Translator) toRBACPermissionHTTPPath(httpPathRule *lbRouteRequestFilteringHTTPPath) *envoy_config_rbac_v3.Permission {
	pathMatcherPermRule := &envoy_type_matcher_v3.PathMatcher_Path{
		Path: &envoy_type_matcher_v3.StringMatcher{},
	}

	switch httpPathRule.pathType {
	case filterPathTypeExact:
		pathMatcherPermRule.Path.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{
			Exact: httpPathRule.path,
		}
	case filterPathTypePrefix:
		pathMatcherPermRule.Path.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Prefix{
			Prefix: httpPathRule.path,
		}
	}

	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_UrlPath{
			UrlPath: &envoy_type_matcher_v3.PathMatcher{
				Rule: pathMatcherPermRule,
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionHTTPHeaders(httpHeaderRules []*lbRouteRequestFilteringHTTPHeader) []*envoy_config_rbac_v3.Permission {
	perms := []*envoy_config_rbac_v3.Permission{}

	for _, rule := range httpHeaderRules {
		perms = append(perms, r.toRBACPermissionHTTPHeader(rule))
	}

	return perms
}

func (r *lbServiceT2Translator) toRBACPermissionHTTPHeader(httpHeaderRule *lbRouteRequestFilteringHTTPHeader) *envoy_config_rbac_v3.Permission {
	headerMatcher := &envoy_config_route_v3.HeaderMatcher_StringMatch{
		StringMatch: &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: nil,
			IgnoreCase:   false,
		},
	}

	switch httpHeaderRule.value.valueType {
	case filterHeaderTypeExact:
		headerMatcher.StringMatch.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{
			Exact: httpHeaderRule.value.value,
		}
	case filterHeaderTypePrefix:
		headerMatcher.StringMatch.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Prefix{
			Prefix: httpHeaderRule.value.value,
		}
	case filterHeaderTypeRegex:
		headerMatcher.StringMatch.MatchPattern = &envoy_type_matcher_v3.StringMatcher_SafeRegex{
			SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
				EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
				Regex:      httpHeaderRule.value.value,
			},
		}
	}

	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_Header{
			Header: &envoy_config_route_v3.HeaderMatcher{
				Name:                      httpHeaderRule.name,
				HeaderMatchSpecifier:      headerMatcher,
				InvertMatch:               false,
				TreatMissingHeaderAsEmpty: false,
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionServerName(serverNameRule lbRouteRequestFilteringHostName) *envoy_config_rbac_v3.Permission {
	serverNameSM := &envoy_type_matcher_v3.StringMatcher{}

	switch serverNameRule.hostNameType {
	case filterHostnameTypeExact:
		serverNameSM.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{
			Exact: serverNameRule.hostName,
		}
	case filterHostnameTypeSuffix:
		serverNameSM.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Suffix{
			Suffix: serverNameRule.hostName,
		}
	}

	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_RequestedServerName{
			RequestedServerName: serverNameSM,
		},
	}
}

func (r *lbServiceT2Translator) toRBACPrincipalAnd(ids ...*envoy_config_rbac_v3.Principal) *envoy_config_rbac_v3.Principal {
	return &envoy_config_rbac_v3.Principal{
		Identifier: &envoy_config_rbac_v3.Principal_AndIds{
			AndIds: &envoy_config_rbac_v3.Principal_Set{
				Ids: ids,
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionAnd(rules ...*envoy_config_rbac_v3.Permission) *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_AndRules{
			AndRules: &envoy_config_rbac_v3.Permission_Set{
				Rules: rules,
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionAny() *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_Any{
			Any: true,
		},
	}
}

func (r *lbServiceT2Translator) toRBACPrincipalAny() *envoy_config_rbac_v3.Principal {
	return &envoy_config_rbac_v3.Principal{
		Identifier: &envoy_config_rbac_v3.Principal_Any{
			Any: true,
		},
	}
}

func (r *lbServiceT2Translator) toRBACAction(ruleType ruleTypeType) envoy_config_rbac_v3.RBAC_Action {
	switch ruleType {
	case ruleTypeAllow:
		return envoy_config_rbac_v3.RBAC_ALLOW
	case ruleTypeDeny:
		return envoy_config_rbac_v3.RBAC_DENY
	default:
		return envoy_config_rbac_v3.RBAC_DENY
	}
}

func (r *lbServiceT2Translator) toNetworkRateLimitFilter(config *lbServiceConnectionRateLimit, namespace string, name string) *envoy_extensions_filters_network_localratelimit_v3.LocalRateLimit {
	if config == nil {
		return nil
	}

	return &envoy_extensions_filters_network_localratelimit_v3.LocalRateLimit{
		StatPrefix: fmt.Sprintf("%s_%s", namespace, name),
		TokenBucket: &envoy_type_v3.TokenBucket{
			MaxTokens:     uint32(config.connections.limit),
			TokensPerFill: wrapperspb.UInt32(uint32(config.connections.limit)),
			FillInterval:  &durationpb.Duration{Seconds: int64(config.connections.timePeriodSeconds)},
		},
	}
}

func (r *lbServiceT2Translator) toHTTPRateLimitFilter(config *lbServiceRequestRateLimit, namespace string, name string) *envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit {
	// We have to provide a ratelimit configuration even if no config available.
	// This is required if the ratelimit is defined as HTTP filter.
	// Also setting to some random defaults (that meet the validation) -
	// the filter won't be enforced in this case.
	tokensPerFill := uint32(100)
	fillIntervalInSeconds := int64(60)
	percentageEnabled := uint32(0)

	if config != nil {
		tokensPerFill = uint32(config.requests.limit)
		fillIntervalInSeconds = int64(config.requests.timePeriodSeconds)
		percentageEnabled = 100
	}

	return &envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit{
		StatPrefix: fmt.Sprintf("%s_%s", namespace, name),
		TokenBucket: &envoy_type_v3.TokenBucket{
			MaxTokens:     tokensPerFill,
			TokensPerFill: wrapperspb.UInt32(tokensPerFill),
			FillInterval:  &durationpb.Duration{Seconds: fillIntervalInSeconds},
		},
		FilterEnabled: &envoy_config_core_v3.RuntimeFractionalPercent{
			DefaultValue: &envoy_type_v3.FractionalPercent{
				Numerator:   percentageEnabled,
				Denominator: envoy_type_v3.FractionalPercent_HUNDRED,
			},
		},
		FilterEnforced: &envoy_config_core_v3.RuntimeFractionalPercent{
			DefaultValue: &envoy_type_v3.FractionalPercent{
				Numerator:   percentageEnabled,
				Denominator: envoy_type_v3.FractionalPercent_HUNDRED,
			},
		},
	}
}

func (r *lbServiceT2Translator) toHTTPRouteBasicAuthFilter(config *lbRouteHTTPBasicAuth) *envoy_config_route_v3.FilterConfig {
	return &envoy_config_route_v3.FilterConfig{
		Disabled: config.disabled,
	}
}

func (r *lbServiceT2Translator) toHTTPRouteJWTAuthFilter(config *lbRouteHTTPJWTAuth) *envoy_extensions_filters_http_jwt_authn_v3.PerRouteConfig {
	return &envoy_extensions_filters_http_jwt_authn_v3.PerRouteConfig{
		RequirementSpecifier: &envoy_extensions_filters_http_jwt_authn_v3.PerRouteConfig_Disabled{
			Disabled: config.disabled,
		},
	}
}

func (r *lbServiceT2Translator) getClusterName(backendName string) string {
	return fmt.Sprintf("backend_cluster_%s", backendName)
}

func (r *lbServiceT2Translator) toXdsResource(m proto.Message, typeUrl string) (ciliumv2.XDSResource, error) {
	protoBytes, err := proto.Marshal(m)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: typeUrl,
			Value:   protoBytes,
		},
	}, nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}

	return a
}

func (r *lbServiceT2Translator) lookupLocalityConfigSpecifier(model *lbService) *envoy_config_cluster_v3.Cluster_CommonLbConfig_ZoneAwareLbConfig_ {
	switch model.zoneAwareMode {
	case lbServiceZoneAwareModePreferSameZone:
		return &envoy_config_cluster_v3.Cluster_CommonLbConfig_ZoneAwareLbConfig_{
			ZoneAwareLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig_ZoneAwareLbConfig{
				MinClusterSize: wrapperspb.UInt64(model.zoneAwareMinBackendCount),
			},
		}
	default:
		return nil
	}
}

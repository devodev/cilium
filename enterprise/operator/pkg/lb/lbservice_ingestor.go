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
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ingestor struct {
	logger                 *slog.Logger
	defaultT1LabelSelector slim_metav1.LabelSelector
	defaultT2LabelSelector slim_metav1.LabelSelector
}

func newIngestor(logger *slog.Logger, defaultT1LabelSelector slim_metav1.LabelSelector, defaultT2LabelSelector slim_metav1.LabelSelector) *ingestor {
	return &ingestor{
		logger:                 logger,
		defaultT1LabelSelector: defaultT1LabelSelector,
		defaultT2LabelSelector: defaultT2LabelSelector,
	}
}

func (r *ingestor) ingest(ctx context.Context, vip *isovalentv1alpha1.LBVIP, lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool, deployments []isovalentv1alpha1.LBDeployment, nodes []*slim_corev1.Node, t1Service *corev1.Service, referencedSecrets map[string]*corev1.Secret, referencedK8sServices []corev1.Service, referencedEndpointSlices []discoveryv1.EndpointSlice) (*lbService, error) {
	referencedBackends := r.toReferencedBackends(backends, referencedK8sServices, referencedEndpointSlices)

	t1LabelSelector, t2LabelSelector, err := r.getTierLabelSelectors(deployments)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve T1 & T2 node label selectors: %w", err)
	}

	t1NodeIPv4Addresses, t1NodeIPv6Addresses, t2NodeIPv4Addresses, t2NodeIPv6Addresses, err := r.loadT1AndT2NodeIPs(ctx, getIPFamily(vip), nodes, *t1LabelSelector, *t2LabelSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve T1 & T2 node ips: %w", err)
	}
	t2NodeIPv4Zones, t2NodeIPv6Zones := r.loadNodeAddressZonesByLabelSelector(getIPFamily(vip), nodes, *t2LabelSelector)

	return &lbService{
		namespace: lbsvc.Namespace,
		name:      lbsvc.Name,
		vip: lbVIP{
			name:         lbsvc.Spec.VIPRef.Name,
			ipFamily:     getIPFamily(vip),
			assignedIPv4: getAssignedIPv4(vip),
			assignedIPv6: getAssignedIPv6(vip),
			bindStatus:   getVIPBindStatus(t1Service),
		},
		zoneAwareMode:            r.resolveZoneAwareMode(lbsvc),
		zoneAwareMinBackendCount: r.resolveZoneAwareMinBackendCount(lbsvc),
		port:                     lbsvc.Spec.Port,
		proxyProtocolConfig:      r.toServiceProxyProtocolConfig(lbsvc.Spec.ProxyProtocolConfig),
		enableGRPCAccessLogs:     lbsvc.Spec.EnableGRPCAccessLogs,
		applications:             r.toApplications(lbsvc, referencedBackends, referencedSecrets),
		referencedBackends:       referencedBackends,
		t1NodeIPv4Addresses:      t1NodeIPv4Addresses,
		t1NodeIPv6Addresses:      t1NodeIPv6Addresses,
		t2NodeIPv4Addresses:      t2NodeIPv4Addresses,
		t2NodeIPv6Addresses:      t2NodeIPv6Addresses,
		t2NodeIPv4Zones:          t2NodeIPv4Zones,
		t2NodeIPv6Zones:          t2NodeIPv6Zones,
		t1LabelSelector:          *t1LabelSelector,
		t2LabelSelector:          *t2LabelSelector,
		enableCNPIntegration:     r.hasSelectorBasedK8sServiceBackends(backends, referencedK8sServices),
	}, nil
}

func (r *ingestor) getTierLabelSelectors(deployments []isovalentv1alpha1.LBDeployment) (*labels.Selector, *labels.Selector, error) {
	t1NodeLabelSelectors := []slim_metav1.LabelSelector{}
	t2NodeLabelSelectors := []slim_metav1.LabelSelector{}

	if len(deployments) > 0 {
		for _, a := range deployments {
			if a.Spec.Nodes.LabelSelectors != nil {
				t1NodeLabelSelectors = append(t1NodeLabelSelectors, a.Spec.Nodes.LabelSelectors.T1)
				t2NodeLabelSelectors = append(t2NodeLabelSelectors, a.Spec.Nodes.LabelSelectors.T2)
			}
		}
	}

	t1LS, err := r.getTierLabelSelector(r.defaultT1LabelSelector, t1NodeLabelSelectors)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get T1 label selector: %w", err)
	}

	t2LS, err := r.getTierLabelSelector(r.defaultT2LabelSelector, t2NodeLabelSelectors)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get T2 label selector: %w", err)
	}

	return t1LS, t2LS, nil
}

// getTierLabelSelector returns the relevant labelselector. This is either the combined labelselector of all labelselectors from an LBDeployment
// (all requirements merged) or the passed default labelselector.
func (r *ingestor) getTierLabelSelector(defaultLS slim_metav1.LabelSelector, deploymentLSList []slim_metav1.LabelSelector) (*labels.Selector, error) {
	defaultLabelSelector, err := slim_metav1.LabelSelectorAsSelector(&defaultLS)
	if err != nil {
		// this should never happen
		return nil, fmt.Errorf("failed to resolve default labelselector: %w", err)
	}

	if len(deploymentLSList) == 0 {
		return &defaultLabelSelector, nil
	}

	// combine the requirements of all labelselectors of LBDeployments
	combinedLabelSelector := labels.SelectorFromSet(nil) // empty label selector

	for _, ls := range deploymentLSList {
		deplLS, err := slim_metav1.LabelSelectorAsSelector(&ls)
		if err != nil {
			// In case of an error, fallback to the default labelselector. This should never be the case as this is already validated
			// by the LBDeployment reconciler.
			r.logger.Warn("Failed to parse node labelselector of LBDeployment - skipping")
			continue
		}

		reqs, _ := deplLS.Requirements()
		combinedLabelSelector = combinedLabelSelector.Add(reqs...)
	}

	return &combinedLabelSelector, nil
}

func (r *ingestor) loadT1AndT2NodeIPs(ctx context.Context, ipFamily ipFamily, nodes []*slim_corev1.Node, t1LabelSelector labels.Selector, t2LabelSelector labels.Selector) ([]string, []string, []string, []string, error) {
	t1NodeIPv4Addresses, t1NodeIPv6Addresses, err := r.loadNodeAddressesByLabelSelector(ctx, ipFamily, nodes, t1LabelSelector)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to retrieve T1 node ips: %w", err)
	}

	t2NodeIPv4Addresses, t2NodeIPv6Addresses, err := r.loadNodeAddressesByLabelSelector(ctx, ipFamily, nodes, t2LabelSelector)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to retrieve T2 node ips: %w", err)
	}

	return t1NodeIPv4Addresses, t1NodeIPv6Addresses, t2NodeIPv4Addresses, t2NodeIPv6Addresses, nil
}

func (r *ingestor) loadNodeAddressesByLabelSelector(ctx context.Context, ipFamily ipFamily, nodes []*slim_corev1.Node, selector labels.Selector) ([]string, []string, error) {
	nodeIPv4Addresses := []string{}
	nodeIPv6Addresses := []string{}

	forEachSelectedNodeInternalIP(r.logger, ipFamily, nodes, selector, func(_ *slim_corev1.Node, ip string, addr netip.Addr) {
		if addr.Is4() {
			nodeIPv4Addresses = append(nodeIPv4Addresses, ip)
		} else {
			nodeIPv6Addresses = append(nodeIPv6Addresses, ip)
		}
	})

	slices.Sort(nodeIPv4Addresses)
	slices.Sort(nodeIPv6Addresses)

	return nodeIPv4Addresses, nodeIPv6Addresses, nil
}

func (r *ingestor) loadNodeAddressZonesByLabelSelector(ipFamily ipFamily, nodes []*slim_corev1.Node, selector labels.Selector) (map[string]string, map[string]string) {
	nodeIPv4Zones := map[string]string{}
	nodeIPv6Zones := map[string]string{}
	forEachSelectedNodeInternalIP(r.logger, ipFamily, nodes, selector, func(cn *slim_corev1.Node, ip string, addr netip.Addr) {
		zone := resolveNodeZone(cn.Labels)
		if zone == lbServiceZoneUnknown {
			return
		}

		if addr.Is4() {
			nodeIPv4Zones[ip] = zone
		} else {
			nodeIPv6Zones[ip] = zone
		}
	})
	return nodeIPv4Zones, nodeIPv6Zones
}

func (*ingestor) resolveZoneAwareMode(lbsvc *isovalentv1alpha1.LBService) lbServiceZoneAwareModeType {
	if lbsvc.Spec.TrafficPolicy == nil || lbsvc.Spec.TrafficPolicy.ZoneAware == nil {
		return lbServiceZoneAwareModeDisabled
	}

	switch lbsvc.Spec.TrafficPolicy.ZoneAware.Mode {
	case isovalentv1alpha1.LBZoneAwareModePreferSameZone:
		return lbServiceZoneAwareModePreferSameZone
	case isovalentv1alpha1.LBZoneAwareModeRequireSameZone:
		return lbServiceZoneAwareModeRequireSameZone
	default:
		return lbServiceZoneAwareModeDisabled
	}
}

func (*ingestor) resolveZoneAwareMinBackendCount(lbsvc *isovalentv1alpha1.LBService) uint64 {
	if lbsvc.Spec.TrafficPolicy == nil || lbsvc.Spec.TrafficPolicy.ZoneAware == nil {
		return 0
	}

	if lbsvc.Spec.TrafficPolicy.ZoneAware.MinBackendCount == 0 {
		return 1
	}

	return lbsvc.Spec.TrafficPolicy.ZoneAware.MinBackendCount
}

func resolveNodeZone(nodeLabels map[string]string) string {
	if zone := nodeLabels[corev1.LabelTopologyZone]; zone != "" {
		return zone
	}
	return lbServiceZoneUnknown
}

func (*ingestor) toHTTPConfig(httpConfig *isovalentv1alpha1.LBServiceHTTPConfig) *lbServiceHTTPConfig {
	http11Enabled := true
	http2Enabled := true

	if httpConfig != nil && httpConfig.EnableHTTP11 != nil {
		http11Enabled = *httpConfig.EnableHTTP11
	}

	if httpConfig != nil && httpConfig.EnableHTTP2 != nil {
		http2Enabled = *httpConfig.EnableHTTP2
	}

	return &lbServiceHTTPConfig{
		enableHTTP11: http11Enabled,
		enableHTTP2:  http2Enabled,
	}
}

func (*ingestor) toTLSConfig(tlsConfig isovalentv1alpha1.LBServiceTLSConfig) lbServiceTLSConfig {
	certificateSecretNames := []string{}
	for _, c := range tlsConfig.Certificates {
		certificateSecretNames = append(certificateSecretNames, c.SecretRef.Name)
	}

	validationContextSecret := ""
	validationContextSubjectAlternativeNames := []string{}

	if tlsConfig.Validation != nil {
		validationContextSecret = tlsConfig.Validation.SecretRef.Name

		for _, san := range tlsConfig.Validation.SubjectAlternativeNames {
			validationContextSubjectAlternativeNames = append(validationContextSubjectAlternativeNames, san.Exact)
		}
	}

	minTLSVersion := ""
	if tlsConfig.MinTLSVersion != nil {
		minTLSVersion = string(*tlsConfig.MinTLSVersion)
	}

	maxTLSVersion := ""
	if tlsConfig.MaxTLSVersion != nil {
		maxTLSVersion = string(*tlsConfig.MaxTLSVersion)
	}

	allowedCipherSuites := []string{}
	for _, cs := range tlsConfig.AllowedCipherSuites {
		allowedCipherSuites = append(allowedCipherSuites, string(cs))
	}

	allowedECDHCurves := []string{}
	for _, ec := range tlsConfig.AllowedECDHCurves {
		allowedECDHCurves = append(allowedECDHCurves, string(ec))
	}

	allowedSignatureAlgorithms := []string{}
	for _, sa := range tlsConfig.AllowedSignatureAlgorithms {
		allowedSignatureAlgorithms = append(allowedSignatureAlgorithms, string(sa))
	}

	return lbServiceTLSConfig{
		certificateSecrets: certificateSecretNames,
		validationContext: lbServiceTLSConfigValidationContext{
			trustedCASecretName:     validationContextSecret,
			subjectAlternativeNames: validationContextSubjectAlternativeNames,
		},
		minTLSVersion:              minTLSVersion,
		maxTLSVersion:              maxTLSVersion,
		allowedCipherSuites:        allowedCipherSuites,
		allowedECDHCurves:          allowedECDHCurves,
		allowedSignatureAlgorithms: allowedSignatureAlgorithms,
	}
}

func (r *ingestor) toReferencedBackends(backends []*isovalentv1alpha1.LBBackendPool, referencedK8sServices []corev1.Service, referencedEndpointSlices []discoveryv1.EndpointSlice) map[string]backend {
	referencedBackends := map[string]backend{}

	for _, b := range backends {
		referencedBackends[b.Name] = backend{
			name:        b.Name,
			typ:         r.toBackendType(b.Spec.BackendType),
			lbBackends:  r.toBackends(b.Spec.BackendType, b.Spec.Backends, referencedK8sServices, referencedEndpointSlices),
			lbAlgorithm: r.toLBBackendAlgorithm(b.Spec.Loadbalancing),
			healthCheckConfig: lbBackendHealthCheckConfig{
				http:                         r.toHTTPHealthCheck(&b.Spec.HealthCheck),
				tcp:                          r.toTCPHealthCheck(&b.Spec.HealthCheck),
				tlsConfig:                    r.toBackendTLSConfig(b.Spec.HealthCheck.TLSConfig),
				intervalSeconds:              int(*b.Spec.HealthCheck.IntervalSeconds),
				timeoutSeconds:               int(*b.Spec.HealthCheck.TimeoutSeconds),
				healthyThreshold:             int(*b.Spec.HealthCheck.HealthyThreshold),
				unhealthyThreshold:           int(*b.Spec.HealthCheck.UnhealthyThreshold),
				unhealthyEdgeIntervalSeconds: int(*b.Spec.HealthCheck.IntervalSeconds),
				unhealthyIntervalSeconds:     int(*b.Spec.HealthCheck.IntervalSeconds),
				port:                         toHealthCheckPort(b.Spec.HealthCheck.Port),
			},
			tcpConfig:         r.toBackendTCPConfig(b.Spec.TCPConfig),
			tlsConfig:         r.toBackendTLSConfig(b.Spec.TLSConfig),
			httpConfig:        r.toBackendHTTPConfig(b.Spec.HTTPConfig),
			dnsResolverConfig: r.toDNSResolverConfig(b.Spec.DNSResolverConfig),
			proxyProtocol:     r.toBackendProxyProtocolConfig(b.Spec.ProxyProtocolConfig),
		}
	}

	return referencedBackends
}

func (*ingestor) hasSelectorBasedK8sServiceBackends(backends []*isovalentv1alpha1.LBBackendPool, referencedK8sServices []corev1.Service) bool {
	servicesByName := make(map[string]corev1.Service, len(referencedK8sServices))
	for _, svc := range referencedK8sServices {
		servicesByName[svc.Name] = svc
	}

	for _, backendPool := range backends {
		for _, backend := range backendPool.Spec.Backends {
			if backend.K8sServiceRef == nil {
				continue
			}

			svc, ok := servicesByName[backend.K8sServiceRef.Name]
			if !ok {
				continue
			}

			if len(svc.Spec.Selector) > 0 {
				return true
			}
		}
	}

	return false
}

func (r *ingestor) toApplications(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend, referencedSecrets map[string]*corev1.Secret) lbApplications {
	return lbApplications{
		httpProxy:      r.toApplicationHTTP(lbsvc, referencedBackends, referencedSecrets),
		httpsProxy:     r.toApplicationHTTPS(lbsvc, referencedBackends, referencedSecrets),
		tlsPassthrough: r.toApplicationTLSPassthrough(lbsvc, referencedBackends),
		tlsProxy:       r.toApplicationTLSProxy(lbsvc, referencedBackends),
		tcpProxy:       r.toApplicationTCPProxy(lbsvc, referencedBackends),
		udpProxy:       r.toApplicationUDPProxy(lbsvc, referencedBackends),
	}
}

func (r *ingestor) toApplicationHTTP(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend, referencedSecrets map[string]*corev1.Secret) *lbApplicationHTTPProxy {
	if lbsvc.Spec.Applications.HTTPProxy == nil {
		return nil
	}

	routes := map[string][]lbRouteHTTP{}

	for _, lr := range lbsvc.Spec.Applications.HTTPProxy.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		httpRoute := lbRouteHTTP{
			match: lbRouteHTTPMatch{
				pathType: pathType,
				path:     path,
			},
			backendRef:        backendRef{name: lr.BackendRef.Name},
			persistentBackend: r.toHTTPPersistentBackendConfig(lr.PersistentBackend),
			requestFiltering:  r.toHTTPRouteRequestFilteringConfig(lr.RequestFiltering),
			rateLimits:        r.toHTTPRouteRateLimits(lr.RateLimits),
			auth:              r.toHTTPRouteAuth(lr.Auth),
		}

		if lr.Match == nil || len(lr.Match.HostNames) == 0 {
			routes["*"] = append(routes["*"], httpRoute)
			continue
		}

		// assigning the route to all hostnames
		for _, h := range lr.Match.HostNames {
			routes[string(h)] = append(routes[string(h)], httpRoute)
		}
	}

	return &lbApplicationHTTPProxy{
		httpConfig:          r.toHTTPConfig(lbsvc.Spec.Applications.HTTPProxy.HTTPConfig),
		connectionFiltering: r.toHTTPConnectionFilteringConfig(lbsvc.Spec.Applications.HTTPProxy.ConnectionFiltering),
		rateLimits:          r.toHTTPRateLimits(lbsvc.Spec.Applications.HTTPProxy.RateLimits),
		auth:                r.toHTTPAuth(lbsvc.Spec.Applications.HTTPProxy.Auth, referencedSecrets),
		routes:              routes,
	}
}

func (r *ingestor) toApplicationHTTPS(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend, referencedSecrets map[string]*corev1.Secret) *lbApplicationHTTPSProxy {
	if lbsvc.Spec.Applications.HTTPSProxy == nil {
		return nil
	}

	routes := map[string][]lbRouteHTTP{}

	for _, lr := range lbsvc.Spec.Applications.HTTPSProxy.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		httpRoute := lbRouteHTTP{
			match: lbRouteHTTPMatch{
				pathType: pathType,
				path:     path,
			},
			backendRef:        backendRef{name: lr.BackendRef.Name},
			persistentBackend: r.toHTTPPersistentBackendConfig(lr.PersistentBackend),
			requestFiltering:  r.toHTTPSRouteRequestFilteringConfig(lr.RequestFiltering),
			rateLimits:        r.toHTTPRouteRateLimits(lr.RateLimits),
			auth:              r.toHTTPRouteAuth(lr.Auth),
		}

		if lr.Match == nil || len(lr.Match.HostNames) == 0 {
			routes["*"] = append(routes["*"], httpRoute)
			continue
		}

		// assigning the route to all hostnames
		for _, h := range lr.Match.HostNames {
			routes[string(h)] = append(routes[string(h)], httpRoute)
		}
	}

	return &lbApplicationHTTPSProxy{
		httpConfig:          r.toHTTPConfig(lbsvc.Spec.Applications.HTTPSProxy.HTTPConfig),
		tlsConfig:           r.toTLSConfig(lbsvc.Spec.Applications.HTTPSProxy.TLSConfig),
		connectionFiltering: r.toHTTPConnectionFilteringConfig(lbsvc.Spec.Applications.HTTPSProxy.ConnectionFiltering),
		rateLimits:          r.toHTTPRateLimits(lbsvc.Spec.Applications.HTTPSProxy.RateLimits),
		auth:                r.toHTTPAuth(lbsvc.Spec.Applications.HTTPSProxy.Auth, referencedSecrets),
		routes:              routes,
	}
}

func toPath(match *isovalentv1alpha1.LBServiceHTTPRouteMatch) (routePathTypeType, string) {
	pathType := routePathTypePrefix
	path := "/"

	if match != nil && match.Path != nil {
		if match.Path.Prefix != nil {
			pathType = routePathTypePrefix
			path = *match.Path.Prefix
		} else if match.Path.Exact != nil {
			pathType = routePathTypeExact
			path = *match.Path.Exact
		}
	}

	return pathType, path
}

func (r *ingestor) toApplicationTLSPassthrough(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationTLSPassthrough {
	if lbsvc.Spec.Applications.TLSPassthrough == nil {
		return nil
	}

	routes := []lbRouteTLSPassthrough{}

	for _, lr := range lbsvc.Spec.Applications.TLSPassthrough.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTLSPassthrough{
			match: lbRouteTLSPassthroughMatch{
				hostNames: r.toTLSPassthroughHostNames(lr.Match),
			},
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toTLSPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTLSRequestFilteringConfig(lr.ConnectionFiltering),
			rateLimits:          r.toTLSRateLimits(lr.RateLimits),
		})
	}

	return &lbApplicationTLSPassthrough{
		routes: routes,
	}
}

func (r *ingestor) toApplicationTLSProxy(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationTLSProxy {
	app := lbsvc.Spec.Applications.TLSProxy
	if app == nil {
		return nil
	}

	routes := []lbRouteTLSProxy{}
	for _, lr := range app.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTLSProxy{
			match: lbRouteTLSProxyMatch{
				hostNames: r.toTLSProxyHostNames(lr.Match),
			},
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toTLSPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTLSRequestFilteringConfig(lr.ConnectionFiltering),
			rateLimits:          r.toTLSRateLimits(lr.RateLimits),
		})
	}
	return &lbApplicationTLSProxy{
		tlsConfig: r.toTLSConfig(app.TLSConfig),
		routes:    routes,
	}
}

func (r *ingestor) toApplicationTCPProxy(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationTCPProxy {
	app := lbsvc.Spec.Applications.TCPProxy
	if app == nil {
		return nil
	}

	routes := []lbRouteTCPProxy{}
	for _, lr := range app.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTCPProxy{
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toTCPPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTCPRequestFilteringConfig(lr.ConnectionFiltering),
			rateLimits:          r.toTCPRateLimits(lr.RateLimits),
		})
	}

	tier := r.mapTCPProxyTierMode(lbsvc, app, referencedBackends)
	return &lbApplicationTCPProxy{
		tierMode: tier,
		fwdMode:  r.mapTCPProxyFwdMode(app, tier),
		routes:   routes,
	}
}

func (r *ingestor) toApplicationUDPProxy(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationUDPProxy {
	app := lbsvc.Spec.Applications.UDPProxy
	if app == nil {
		return nil
	}

	routes := []lbRouteUDPProxy{}
	for _, lr := range app.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteUDPProxy{
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toUDPPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toUDPRequestFilteringConfig(lr.ConnectionFiltering),
		})
	}

	tier := r.mapUDPProxyTierMode(lbsvc, app, referencedBackends)
	return &lbApplicationUDPProxy{
		tierMode: tier,
		fwdMode:  r.mapUDPProxyFwdMode(app, tier),
		routes:   routes,
	}
}

func (r *ingestor) toHTTPHealthCheck(hc *isovalentv1alpha1.HealthCheck) *lbBackendHealthCheckHTTPConfig {
	if hc.HTTP == nil {
		return nil
	}

	return &lbBackendHealthCheckHTTPConfig{
		host:               *hc.HTTP.Host,
		path:               *hc.HTTP.Path,
		method:             r.toHealthCheckHTTPMethod(hc.HTTP.Method),
		healthyStatusCodes: r.toHealthCheckHTTPStatusCodes(hc.HTTP.HealthyStatusCodes),
		send:               r.toHealthCheckPayload(hc.HTTP.Send),
		receive:            r.toHealthCheckPayloads(hc.HTTP.Receive),
	}
}

func (r *ingestor) toHealthCheckHTTPMethod(method *isovalentv1alpha1.HealthCheckHTTPMethod) lbBackendHealthCheckHTTPMethod {
	if method == nil {
		return lbBackendHealthCheckHTTPMethodGet
	}

	switch *method {
	case isovalentv1alpha1.HealthCheckHTTPMethodGet:
		return lbBackendHealthCheckHTTPMethodGet
	case isovalentv1alpha1.HealthCheckHTTPMethodConnect:
		return lbBackendHealthCheckHTTPMethodConnect
	case isovalentv1alpha1.HealthCheckHTTPMethodDelete:
		return lbBackendHealthCheckHTTPMethodDelete
	case isovalentv1alpha1.HealthCheckHTTPMethodHead:
		return lbBackendHealthCheckHTTPMethodHead
	case isovalentv1alpha1.HealthCheckHTTPMethodOptions:
		return lbBackendHealthCheckHTTPMethodOptions
	case isovalentv1alpha1.HealthCheckHTTPMethodPatch:
		return lbBackendHealthCheckHTTPMethodPatch
	case isovalentv1alpha1.HealthCheckHTTPMethodPost:
		return lbBackendHealthCheckHTTPMethodPost
	case isovalentv1alpha1.HealthCheckHTTPMethodPut:
		return lbBackendHealthCheckHTTPMethodPut
	case isovalentv1alpha1.HealthCheckHTTPMethodTrace:
		return lbBackendHealthCheckHTTPMethodTrace
	default:
		return lbBackendHealthCheckHTTPMethodGet
	}
}

func (r *ingestor) toHealthCheckPayloads(payload []*isovalentv1alpha1.HealthCheckPayload) []*lbBackendHealthCheckPayload {
	if payload == nil {
		return nil
	}

	result := []*lbBackendHealthCheckPayload{}

	for _, p := range payload {
		result = append(result, r.toHealthCheckPayload(p))
	}

	return result
}

func (r *ingestor) toHealthCheckPayload(payload *isovalentv1alpha1.HealthCheckPayload) *lbBackendHealthCheckPayload {
	if payload == nil {
		return nil
	}

	result := &lbBackendHealthCheckPayload{}

	switch {
	case payload.Text != nil:
		result.text = payload.Text
	}

	return result
}

var defaultHealthCheckStatusCodes = []lbBackendHealthCheckHTTPStatusRange{{
	start: 200,
	end:   201,
}}

func (r *ingestor) toHealthCheckHTTPStatusCodes(codes []*isovalentv1alpha1.HealthCheckHTTPStatusRange) []lbBackendHealthCheckHTTPStatusRange {
	if len(codes) == 0 {
		return defaultHealthCheckStatusCodes
	}

	result := []lbBackendHealthCheckHTTPStatusRange{}

	for _, hchr := range codes {
		result = append(result, lbBackendHealthCheckHTTPStatusRange{
			start: hchr.Start,
			end:   hchr.End,
		})
	}

	return result
}

func (r *ingestor) toTCPHealthCheck(hc *isovalentv1alpha1.HealthCheck) *lbBackendHealthCheckTCPConfig {
	if hc.TCP == nil {
		return nil
	}

	return &lbBackendHealthCheckTCPConfig{
		send:    r.toHealthCheckPayload(hc.TCP.Send),
		receive: r.toHealthCheckPayloads(hc.TCP.Receive),
	}
}

func (r *ingestor) toBackendType(backendType isovalentv1alpha1.BackendType) lbBackendType {
	switch backendType {
	case isovalentv1alpha1.BackendTypeIP:
		return lbBackendTypeIP
	case isovalentv1alpha1.BackendTypeHostname:
		return lbBackendTypeHostname
	default:
		return lbBackendTypeIP
	}
}

func (r *ingestor) toBackends(typ isovalentv1alpha1.BackendType, backends []isovalentv1alpha1.Backend, referencedK8sServices []corev1.Service, referencedEndpointSlices []discoveryv1.EndpointSlice) []lbBackend {
	ret := []lbBackend{}

	for _, backend := range backends {
		weight := uint32(1)
		if backend.Weight != nil {
			weight = *backend.Weight
		}

		status := lbBackendStatusHealthChecking
		if backend.Status != nil && *backend.Status == isovalentv1alpha1.BackendStatusDraining {
			status = lbBackendStatusDraining
		}

		backendPort := uint32(backend.Port)
		backendZone := backend.Zone
		addressZones := map[string]string{}

		addresses := []string{}
		switch typ {
		case isovalentv1alpha1.BackendTypeIP:
			addresses = append(addresses, *backend.IP)
		case isovalentv1alpha1.BackendTypeHostname:
			addresses = append(addresses, r.fixedHostname(*backend.Host))
		case isovalentv1alpha1.BackendTypeK8sService:
			// Ignore explicit backend zone metadata for in-cluster backends.
			// Their topology should come from EndpointSlice fields.
			backendZone = nil
			addresses, addressZones = r.getAddressesAndZonesFromEndpointSlices(referencedEndpointSlices, backend.K8sServiceRef.Name)
			backendPort = r.getBackendPortFromService(referencedK8sServices, referencedEndpointSlices, backend.K8sServiceRef.Name, backendPort)
		default:
			addresses = append(addresses, *backend.IP)
		}

		for _, a := range addresses {
			if _, ok := addressZones[a]; ok {
				continue
			}
			if backendZone != nil && *backendZone != "" {
				addressZones[a] = *backendZone
			} else {
				addressZones[a] = lbServiceZoneUnknown
			}
		}

		ret = append(ret, lbBackend{
			addresses:    addresses,
			addressZones: addressZones,
			port:         backendPort,
			weight:       weight,
			status:       status,
		})
	}

	return ret
}

func (r *ingestor) fixedHostname(address string) string {
	// FIXME: This is a workaround for the issue that no_default_search_domain
	// of Envoy is broken (https://github.com/envoyproxy/envoy/issues/33138).
	// This leads to the situation that the default search domain is mistakenly
	// appended to the hostname. This workaround is to append a dot to the hostname
	// make it fully qualified.
	if !strings.HasSuffix(address, ".") {
		address = address + "."
	}

	return address
}

func (r *ingestor) getAddressesAndZonesFromEndpointSlices(referencedEndpointSlices []discoveryv1.EndpointSlice, k8sServiceName string) ([]string, map[string]string) {
	ipAddressZones := map[string]string{}

	for _, es := range referencedEndpointSlices {
		if es.GetLabels()[discoveryv1.LabelServiceName] != k8sServiceName || (es.AddressType != discoveryv1.AddressTypeIPv4 && es.AddressType != discoveryv1.AddressTypeIPv6) {
			continue
		}

		for _, ep := range es.Endpoints {
			zone := lbServiceZoneUnknown
			if ep.Zone != nil && *ep.Zone != "" {
				zone = *ep.Zone
			} else if ep.DeprecatedTopology != nil {
				if z, ok := ep.DeprecatedTopology[corev1.LabelTopologyZone]; ok && z != "" {
					zone = z
				}
			}

			for _, addr := range ep.Addresses {
				// TODO: check conditions (kubelet healthchecks) ?
				if existing, ok := ipAddressZones[addr]; ok && existing != zone {
					r.logger.Warn("Conflicting zone metadata for backend endpoint address; falling back to unknown zone",
						logfields.ServiceName, k8sServiceName,
						logfields.Address, addr,
						logfields.Exists, existing,
						logfields.New, zone,
					)
					ipAddressZones[addr] = lbServiceZoneUnknown
					continue
				}
				ipAddressZones[addr] = zone
			}
		}
	}

	ipAddresses := make([]string, 0, len(ipAddressZones))
	for addr := range ipAddressZones {
		ipAddresses = append(ipAddresses, addr)
	}
	slices.Sort(ipAddresses)

	r.logger.Debug("Resolved addresses and zones from EndpointSlices",
		logfields.ServiceName, k8sServiceName,
		logfields.ResourceName, referencedEndpointSlices,
		logfields.PodIPs, ipAddresses,
		logfields.Zone, ipAddressZones,
	)

	return ipAddresses, ipAddressZones
}

// getBackendPortFromService translates the given service port to the target port (of the pod)
func (r *ingestor) getBackendPortFromService(referencedK8sServices []corev1.Service, referencedEndpointSlices []discoveryv1.EndpointSlice, k8sServiceName string, servicePort uint32) uint32 {
	for _, svc := range referencedK8sServices {
		if svc.Name == k8sServiceName {
			for _, sp := range svc.Spec.Ports {
				if sp.Port == int32(servicePort) {
					if sp.TargetPort.IntValue() != 0 {
						return uint32(sp.TargetPort.IntValue())
					}

					if sp.TargetPort.StrVal != "" {
						for _, es := range referencedEndpointSlices {
							if es.GetLabels()[discoveryv1.LabelServiceName] == k8sServiceName && es.AddressType == discoveryv1.AddressTypeIPv4 {
								for _, ep := range es.Ports {
									if ep.Name != nil && *ep.Name == sp.TargetPort.StrVal && ep.Port != nil && *ep.Port != 0 {
										return uint32(*ep.Port)
									}
								}
							}
						}
					}

				}
			}
		}
	}

	r.logger.Debug("No corresponding target port found. Falling back to use the service port.",
		logfields.ServiceName, k8sServiceName,
		logfields.Port, servicePort,
	)

	return servicePort
}

func (r *ingestor) toLBBackendAlgorithm(loadbalancing *isovalentv1alpha1.Loadbalancing) lbBackendLBAlgorithm {
	switch {
	case loadbalancing == nil:
		return lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin}
	case loadbalancing.Algorithm.RoundRobin != nil:
		return lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin}
	case loadbalancing.Algorithm.LeastRequest != nil:
		return lbBackendLBAlgorithm{algorithm: lbAlgorithmLeastRequest}
	case loadbalancing.Algorithm.ConsistentHashing != nil:
		maglevTableSize := uint32(65537)

		if loadbalancing.Algorithm.ConsistentHashing.Algorithm != nil && loadbalancing.Algorithm.ConsistentHashing.Algorithm.Maglev.TableSize != nil {
			desiredMaglevTableSize := *loadbalancing.Algorithm.ConsistentHashing.Algorithm.Maglev.TableSize
			if big.NewInt(int64(desiredMaglevTableSize)).ProbablyPrime(1) {
				maglevTableSize = desiredMaglevTableSize
			}
		}

		return lbBackendLBAlgorithm{
			algorithm: lbAlgorithmConsistentHashing,
			consistentHashing: &lbBackendLBAlgorithmConsistentHashing{
				maglevTableSize: maglevTableSize,
			},
		}
	}

	return lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin}
}

func (r *ingestor) toTLSPassthroughHostNames(match *isovalentv1alpha1.LBServiceTLSPassthroughRouteMatch) []string {
	if match == nil || len(match.HostNames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range match.HostNames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

func (r *ingestor) toTLSProxyHostNames(match *isovalentv1alpha1.LBServiceTLSRouteMatch) []string {
	if match == nil || len(match.HostNames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range match.HostNames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

// getAssignedIP evaluates and returns the actually assigned loadbalancer IP from the LBVIP resource.
// If there's no assigned loadbalancer IP assigned yet, nil is returned instead.
func getAssignedIPv4(vip *isovalentv1alpha1.LBVIP) *string {
	if vip != nil {
		return vip.Status.Addresses.IPv4
	}
	return nil
}

func getAssignedIPv6(vip *isovalentv1alpha1.LBVIP) *string {
	if vip != nil {
		return vip.Status.Addresses.IPv6
	}
	return nil
}

func getVIPBindStatus(t1Service *corev1.Service) lbVIPBindStatus {
	if t1Service == nil {
		return lbVIPBindStatus{
			serviceExists:  false,
			bindSuccessful: false,
		}
	}

	for _, cond := range t1Service.Status.Conditions {
		// Map LBIPAM conditions to LBVIP conditions
		if cond.Type == "cilium.io/IPAMRequestSatisfied" {
			switch cond.Status {
			case metav1.ConditionUnknown:
				return lbVIPBindStatus{
					serviceExists:  true,
					bindSuccessful: false,
					bindIssue:      "No LB IPAM condition present yet",
				}
			case metav1.ConditionTrue:
				return lbVIPBindStatus{
					serviceExists:  true,
					bindSuccessful: true,
				}
			case metav1.ConditionFalse:
				switch cond.Reason {
				case "already_allocated_incompatible_service":
					// Special handling for the case where an IP & port combination might
					// already be used by another service.
					return lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: false,
						bindIssue:      cond.Message,
					}
				default:
					// Pass through the message of LB IPAM.
					// Assuming users will file an issue if
					// they see this message. Most of these
					// cases should already be covered by LB IP
					// assignment to LBVIP service.
					return lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: false,
						bindIssue:      "Unexpected condition: " + cond.Message,
					}
				}
			}
		}
	}

	return lbVIPBindStatus{
		bindSuccessful: false,
		bindIssue:      "No LB IPAM condition present yet",
	}
}

func (*ingestor) toBackendTCPConfig(tcpConfig *isovalentv1alpha1.LBBackendTCPConfig) *lbBackendTCPConfig {
	connectTimeout := int32(5)
	if tcpConfig != nil && tcpConfig.ConnectTimeoutSeconds != nil {
		connectTimeout = *tcpConfig.ConnectTimeoutSeconds
	}

	return &lbBackendTCPConfig{
		connectTimeoutSeconds: connectTimeout,
	}
}

func (*ingestor) toBackendTLSConfig(tlsConfig *isovalentv1alpha1.LBBackendTLSConfig) *lbBackendTLSConfig {
	if tlsConfig == nil {
		return nil
	}

	minTLSVersion := ""
	if tlsConfig.MinTLSVersion != nil {
		minTLSVersion = string(*tlsConfig.MinTLSVersion)
	}

	maxTLSVersion := ""
	if tlsConfig.MaxTLSVersion != nil {
		maxTLSVersion = string(*tlsConfig.MaxTLSVersion)
	}

	allowedCipherSuites := []string{}
	for _, cs := range tlsConfig.AllowedCipherSuites {
		allowedCipherSuites = append(allowedCipherSuites, string(cs))
	}

	allowedECDHCurves := []string{}
	for _, ec := range tlsConfig.AllowedECDHCurves {
		allowedECDHCurves = append(allowedECDHCurves, string(ec))
	}

	allowedSignatureAlgorithms := []string{}
	for _, sa := range tlsConfig.AllowedSignatureAlgorithms {
		allowedSignatureAlgorithms = append(allowedSignatureAlgorithms, string(sa))
	}

	return &lbBackendTLSConfig{
		minTLSVersion:              minTLSVersion,
		maxTLSVersion:              maxTLSVersion,
		allowedCipherSuites:        allowedCipherSuites,
		allowedECDHCurves:          allowedECDHCurves,
		allowedSignatureAlgorithms: allowedSignatureAlgorithms,
	}
}

func (*ingestor) toBackendHTTPConfig(httpConfig *isovalentv1alpha1.LBBackendHTTPConfig) lbBackendHTTPConfig {
	http11Enabled := true
	http2Enabled := true

	if httpConfig != nil && httpConfig.EnableHTTP11 != nil {
		http11Enabled = *httpConfig.EnableHTTP11
	}

	if httpConfig != nil && httpConfig.EnableHTTP2 != nil {
		http2Enabled = *httpConfig.EnableHTTP2
	}

	return lbBackendHTTPConfig{
		enableHTTP11: http11Enabled,
		enableHTTP2:  http2Enabled,
	}
}

func (*ingestor) toHTTPPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend) *lbRouteHTTPPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	cookieNames := []string{}
	for _, c := range persistentBackendConfig.Cookies {
		cookieNames = append(cookieNames, c.Name)
	}

	headerNames := []string{}
	for _, h := range persistentBackendConfig.Headers {
		headerNames = append(headerNames, h.Name)
	}

	return &lbRouteHTTPPersistentBackend{
		sourceIP:    sourceIP,
		cookieNames: cookieNames,
		headerNames: headerNames,
	}
}

func (*ingestor) toTLSPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceTLSRoutePersistentBackend) *lbRouteTLSPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	return &lbRouteTLSPersistentBackend{
		sourceIP: sourceIP,
	}
}

func (r *ingestor) toHTTPConnectionFilteringConfig(config *isovalentv1alpha1.LBServiceHTTPConnectionFiltering) *lbServiceHTTPConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbServiceHTTPConnectionFilteringRule{}

	for _, ir := range config.Rules {
		rules = append(rules, lbServiceHTTPConnectionFilteringRule{
			sourceCIDR: r.toSourceCIDR(ir.SourceCIDR),
		})
	}

	return &lbServiceHTTPConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (*ingestor) toTCPPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceTCPRoutePersistentBackend) *lbRouteTCPPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	return &lbRouteTCPPersistentBackend{
		sourceIP: sourceIP,
	}
}

func (r *ingestor) toTCPRequestFilteringConfig(config *isovalentv1alpha1.LBServiceTCPRouteConnectionFiltering) *lbRouteTCPConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteTCPConnectionFilteringRule{}

	for _, ir := range config.Rules {
		rules = append(rules, lbRouteTCPConnectionFilteringRule{
			sourceCIDR: r.toSourceCIDR(ir.SourceCIDR),
		})
	}

	return &lbRouteTCPConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (*ingestor) toUDPPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceUDPRoutePersistentBackend) *lbRouteUDPPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	return &lbRouteUDPPersistentBackend{
		sourceIP: sourceIP,
	}
}

func (r *ingestor) toUDPRequestFilteringConfig(config *isovalentv1alpha1.LBServiceUDPRouteConnectionFiltering) *lbRouteUDPConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteUDPConnectionFilteringRule{}

	for _, ir := range config.Rules {
		rules = append(rules, lbRouteUDPConnectionFilteringRule{
			sourceCIDR: r.toSourceCIDR(ir.SourceCIDR),
		})
	}

	return &lbRouteUDPConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (r *ingestor) toHTTPRouteRequestFilteringConfig(config *isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering) *lbRouteHTTPRequestFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteHTTPRequestFilteringRule{}

	for _, ir := range config.Rules {
		rules = append(rules, lbRouteHTTPRequestFilteringRule{
			sourceCIDR: r.toSourceCIDR(ir.SourceCIDR),
			hostname:   r.toHTTPHostname(ir.HostName),
			path:       r.toHTTPPath(ir.Path),
			headers:    r.toHTTPHeaders(ir.Headers),
			jwtClaims:  r.toJWTClaims(ir.JWTClaims),
		})
	}

	return &lbRouteHTTPRequestFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (r *ingestor) toHTTPSRouteRequestFilteringConfig(config *isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering) *lbRouteHTTPRequestFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteHTTPRequestFilteringRule{}

	for _, ir := range config.Rules {
		rules = append(rules, lbRouteHTTPRequestFilteringRule{
			sourceCIDR:            r.toSourceCIDR(ir.SourceCIDR),
			hostname:              r.toHTTPHostname(ir.HostName),
			path:                  r.toHTTPPath(ir.Path),
			headers:               r.toHTTPHeaders(ir.Headers),
			jwtClaims:             r.toJWTClaims(ir.JWTClaims),
			clientCertificateSANs: r.toClientCertificateSAN(ir.ClientCertificateSANs),
		})
	}

	return &lbRouteHTTPRequestFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (*ingestor) toHTTPHostname(httpHostName *isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname) *lbRouteRequestFilteringHostName {
	if httpHostName == nil {
		return nil
	}

	var hostName string
	var hostNameType filterHostnameTypeType

	if httpHostName.Exact != nil {
		hostName = *httpHostName.Exact
		hostNameType = filterHostnameTypeExact
	} else if httpHostName.Suffix != nil {
		hostName = *httpHostName.Suffix
		hostNameType = filterHostnameTypeSuffix
	}

	return &lbRouteRequestFilteringHostName{
		hostName:     hostName,
		hostNameType: hostNameType,
	}
}

func (*ingestor) toHTTPPath(httpPath *isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath) *lbRouteRequestFilteringHTTPPath {
	if httpPath == nil {
		return nil
	}

	var p string
	var pType filterPathTypeType

	if httpPath.Exact != nil {
		p = *httpPath.Exact
		pType = filterPathTypeExact
	} else if httpPath.Prefix != nil {
		p = *httpPath.Prefix
		pType = filterPathTypePrefix
	}

	return &lbRouteRequestFilteringHTTPPath{
		path:     p,
		pathType: pType,
	}
}

func (*ingestor) toHTTPHeaders(httpHeaders []*isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader) []*lbRouteRequestFilteringHTTPHeader {
	headers := []*lbRouteRequestFilteringHTTPHeader{}

	for _, h := range httpHeaders {
		var v string
		var vType filterHeaderTypeType

		if h.Value.Exact != nil {
			v = *h.Value.Exact
			vType = filterHeaderTypeExact
		} else if h.Value.Prefix != nil {
			v = *h.Value.Prefix
			vType = filterHeaderTypePrefix
		} else if h.Value.Regex != nil {
			v = *h.Value.Regex
			vType = filterHeaderTypeRegex
		}

		headers = append(headers, &lbRouteRequestFilteringHTTPHeader{
			name: h.Name,
			value: lbRouteRequestFilteringHTTPHeaderValue{
				value:     v,
				valueType: vType,
			},
		})
	}

	return headers
}

func (r *ingestor) toJWTClaims(claims []*isovalentv1alpha1.LBServiceRequestFilteringRuleJWTClaim) []*lbRouteRequestFilteringJWTClaim {
	jwtClaims := []*lbRouteRequestFilteringJWTClaim{}

	for _, claim := range claims {
		var v string
		var vType filterJWTClaimTypeType

		if claim.Value.Exact != nil {
			v = *claim.Value.Exact
			vType = filterJWTClaimTypeExact
		} else if claim.Value.Prefix != nil {
			v = *claim.Value.Prefix
			vType = filterJWTClaimTypePrefix
		} else if claim.Value.Regex != nil {
			v = *claim.Value.Regex
			vType = filterJWTClaimTypeRegex
		}

		jwtClaims = append(jwtClaims, &lbRouteRequestFilteringJWTClaim{
			name: claim.Name,
			value: lbRouteRequestFilteringJWTClaimValue{
				value:     v,
				valueType: vType,
			},
		})
	}

	return jwtClaims
}

func (r *ingestor) toClientCertificateSAN(sans []*isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSAN) []*lbRouteRequestFilteringClientCertificateSAN {
	clientCertificateSANs := []*lbRouteRequestFilteringClientCertificateSAN{}

	for _, san := range sans {
		oid := ""
		if san.OID != nil {
			oid = *san.OID
		}
		var v string
		var vType filterClientCertificateSANValueType

		if san.Value.Exact != nil {
			v = *san.Value.Exact
			vType = filterClientCertificateSANValueTypeExact
		} else if san.Value.Prefix != nil {
			v = *san.Value.Prefix
			vType = filterClientCertificateSANValueTypePrefix
		} else if san.Value.Regex != nil {
			v = *san.Value.Regex
			vType = filterClientCertificateSANValueTypeRegex
		}

		clientCertificateSANs = append(clientCertificateSANs, &lbRouteRequestFilteringClientCertificateSAN{
			sanType: string(san.Type),
			oid:     oid,
			value: lbRouteRequestFilteringClientCertificateSANValue{
				value:     v,
				valueType: vType,
			},
		})
	}

	return clientCertificateSANs
}

func (r *ingestor) toSourceCIDR(inputSourceCIDR *isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR) *lbRouteRequestFilteringSourceCIDR {
	if inputSourceCIDR == nil {
		return nil
	}

	_, ipNet, err := net.ParseCIDR(inputSourceCIDR.CIDR)
	if err != nil {
		// return nil as this should already be covered by CRD field validation
		return nil
	}

	prefixLen, _ := ipNet.Mask.Size()

	return &lbRouteRequestFilteringSourceCIDR{
		addressPrefix: ipNet.IP.String(),
		prefixLen:     uint32(prefixLen),
	}
}

func (r *ingestor) toTLSRequestFilteringConfig(config *isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering) *lbRouteTLSConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteTLSConnectionFilteringRule{}

	for _, ir := range config.Rules {
		rules = append(rules, lbRouteTLSConnectionFilteringRule{
			sourceCIDR:            r.toSourceCIDR(ir.SourceCIDR),
			clientCertificateSANs: r.toClientCertificateSAN(ir.ClientCertificateSANs),
			servername:            r.toTLSServerName(ir),
		})
	}

	return &lbRouteTLSConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (*ingestor) toTLSServerName(ir isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule) *lbRouteRequestFilteringHostName {
	if ir.ServerName == nil {
		return nil
	}

	var serverName string
	var serverNameType filterHostnameTypeType

	if ir.ServerName.Exact != nil {
		serverName = *ir.ServerName.Exact
		serverNameType = filterHostnameTypeExact
	} else if ir.ServerName.Suffix != nil {
		serverName = *ir.ServerName.Suffix
		serverNameType = filterHostnameTypeSuffix
	}

	return &lbRouteRequestFilteringHostName{
		hostName:     serverName,
		hostNameType: serverNameType,
	}
}

func (*ingestor) mapRuleType(ruleType isovalentv1alpha1.RequestFilteringRuleType) ruleTypeType {
	switch ruleType {
	case isovalentv1alpha1.RequestFilteringRuleTypeAllow:
		return ruleTypeAllow
	case isovalentv1alpha1.RequestFilteringRuleTypeDeny:
		return ruleTypeDeny
	}

	return ruleTypeDeny
}

func (*ingestor) toHTTPRateLimits(rateLimits *isovalentv1alpha1.LBServiceHTTPRateLimits) *lbServiceConnectionRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceConnectionRateLimit{
		connections: lbServiceRateLimit{
			limit:             rateLimits.Connections.Limit,
			timePeriodSeconds: rateLimits.Connections.TimePeriodSeconds,
		},
	}
}

func (*ingestor) toHTTPRouteRateLimits(rateLimits *isovalentv1alpha1.LBServiceHTTPRouteRateLimits) *lbServiceRequestRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceRequestRateLimit{
		requests: lbServiceRateLimit{
			limit:             rateLimits.Requests.Limit,
			timePeriodSeconds: rateLimits.Requests.TimePeriodSeconds,
		},
	}
}

func (*ingestor) toTLSRateLimits(rateLimits *isovalentv1alpha1.LBServiceTLSRouteRateLimits) *lbServiceConnectionRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceConnectionRateLimit{
		connections: lbServiceRateLimit{
			limit:             rateLimits.Connections.Limit,
			timePeriodSeconds: rateLimits.Connections.TimePeriodSeconds,
		},
	}
}

func (*ingestor) toTCPRateLimits(rateLimits *isovalentv1alpha1.LBServiceTCPRouteRateLimits) *lbServiceConnectionRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceConnectionRateLimit{
		connections: lbServiceRateLimit{
			limit:             rateLimits.Connections.Limit,
			timePeriodSeconds: rateLimits.Connections.TimePeriodSeconds,
		},
	}
}

func (r *ingestor) mapTCPProxyTierMode(lbsvc *isovalentv1alpha1.LBService, app *isovalentv1alpha1.LBServiceApplicationTCPProxy, referencedBackends map[string]backend) tierModeType {
	forceDeploymentMode := isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto

	if app.ForceDeploymentMode != nil {
		forceDeploymentMode = *app.ForceDeploymentMode
	}

	switch forceDeploymentMode {
	case isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto:
		return r.evaluateTCPProxyAutoTierMode(lbsvc, app, referencedBackends)
	case isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1:
		return tierModeT1
	case isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2:
		return tierModeT2
	default:
		return r.evaluateTCPProxyAutoTierMode(lbsvc, app, referencedBackends)
	}
}

func (r *ingestor) backendPortsAreTheSame(lbBackends []lbBackend) bool {
	port := uint32(0)

	for _, be := range lbBackends {
		if port == 0 {
			port = be.port
		}
		if port != be.port {
			return false
		}
	}

	return true
}

func (r *ingestor) evaluateProxyAutoForwardingMode(tier tierModeType) fwdModeType {
	switch tier {
	case tierModeT1:
		return fwdModeSNAT
	case tierModeT2:
		return fwdModeDSR
	default:
		return fwdModeDSR
	}
}

func (r *ingestor) mapTCPProxyFwdMode(app *isovalentv1alpha1.LBServiceApplicationTCPProxy, tier tierModeType) fwdModeType {
	forceForwardingMode := isovalentv1alpha1.LBTCPProxyForceForwardingModeAuto

	if app.ForceForwardingMode != nil {
		forceForwardingMode = *app.ForceForwardingMode
	}

	switch forceForwardingMode {
	case isovalentv1alpha1.LBTCPProxyForceForwardingModeAuto:
		return r.evaluateProxyAutoForwardingMode(tier)
	case isovalentv1alpha1.LBTCPProxyForceForwardingModeSNAT:
		return fwdModeSNAT
	case isovalentv1alpha1.LBTCPProxyForceForwardingModeDSR:
		return fwdModeDSR
	default:
		return r.evaluateProxyAutoForwardingMode(tier)
	}
}

func (r *ingestor) mapUDPProxyFwdMode(app *isovalentv1alpha1.LBServiceApplicationUDPProxy, tier tierModeType) fwdModeType {
	forceForwardingMode := isovalentv1alpha1.LBUDPProxyForceForwardingModeAuto

	if app.ForceForwardingMode != nil {
		forceForwardingMode = *app.ForceForwardingMode
	}

	switch forceForwardingMode {
	case isovalentv1alpha1.LBUDPProxyForceForwardingModeAuto:
		return r.evaluateProxyAutoForwardingMode(tier)
	case isovalentv1alpha1.LBUDPProxyForceForwardingModeSNAT:
		return fwdModeSNAT
	case isovalentv1alpha1.LBUDPProxyForceForwardingModeDSR:
		return fwdModeDSR
	default:
		return r.evaluateProxyAutoForwardingMode(tier)
	}
}

func (r *ingestor) evaluateTCPProxyAutoTierMode(lbsvc *isovalentv1alpha1.LBService, app *isovalentv1alpha1.LBServiceApplicationTCPProxy, referencedBackends map[string]backend) tierModeType {
	ipv4Service := lbsvc.Status.Addresses.IPv4 != nil
	ipv6Service := lbsvc.Status.Addresses.IPv6 != nil

	for _, v := range referencedBackends {
		// Cilium Agent health checking doesn't support changing the host header of a HTTP health check request
		if v.healthCheckConfig.http != nil && v.healthCheckConfig.http.host != "lb" {
			return tierModeT2
		}

		// Cilium Agent health checking doesn't support custom payload (sending and validating response)
		if (v.healthCheckConfig.http != nil && (v.healthCheckConfig.http.send != nil || len(v.healthCheckConfig.http.receive) > 0)) ||
			(v.healthCheckConfig.tcp != nil && (v.healthCheckConfig.tcp.send != nil || len(v.healthCheckConfig.tcp.receive) > 0)) {
			return tierModeT2
		}

		// Cilium Agent health checking doesn't support custom HTTP method & status codes
		if v.healthCheckConfig.http != nil && (!slices.Equal(v.healthCheckConfig.http.healthyStatusCodes, defaultHealthCheckStatusCodes) || v.healthCheckConfig.http.method != lbBackendHealthCheckHTTPMethodGet) {
			return tierModeT2
		}

		// Cilium Agent health checking doesn't support TLS unless it's HTTP health checks.
		if v.healthCheckConfig.tlsConfig != nil && v.healthCheckConfig.http == nil {
			return tierModeT2
		}

		// T1-only cant have different IP family on the frontend & backend side
		if v.typ == lbBackendTypeIP {
			atLeastOneIPv4 := false
			atLeastOneIPv6 := false

			for _, lb := range v.lbBackends {
				for _, lba := range lb.addresses {
					if net.ParseIP(lba).To4() == nil {
						atLeastOneIPv6 = true
					} else {
						atLeastOneIPv4 = true
					}
				}
			}

			if (ipv4Service && !atLeastOneIPv4) || (ipv6Service && !atLeastOneIPv6) {
				return tierModeT2
			}
		}
	}

	for _, ar := range app.Routes {
		if ar.RateLimits != nil || referencedBackends[ar.BackendRef.Name].typ == lbBackendTypeHostname {
			return tierModeT2
		}

		// backends with different ports aren't supported by t1-only mode
		if !r.backendPortsAreTheSame(referencedBackends[ar.BackendRef.Name].lbBackends) {
			return tierModeT2
		}
	}

	return tierModeT1
}

func (r *ingestor) mapUDPProxyTierMode(lbsvc *isovalentv1alpha1.LBService, app *isovalentv1alpha1.LBServiceApplicationUDPProxy, referencedBackends map[string]backend) tierModeType {
	forceDeploymentMode := isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto

	if app.ForceDeploymentMode != nil {
		forceDeploymentMode = *app.ForceDeploymentMode
	}

	switch forceDeploymentMode {
	case isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto:
		return r.evaluateUDPProxyAutoTierMode(lbsvc, app, referencedBackends)
	case isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1:
		return tierModeT1
	case isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2:
		return tierModeT2
	default:
		return r.evaluateUDPProxyAutoTierMode(lbsvc, app, referencedBackends)
	}
}

func (r *ingestor) evaluateUDPProxyAutoTierMode(lbsvc *isovalentv1alpha1.LBService, app *isovalentv1alpha1.LBServiceApplicationUDPProxy, referencedBackends map[string]backend) tierModeType {
	ipv4Service := lbsvc.Status.Addresses.IPv4 != nil
	ipv6Service := lbsvc.Status.Addresses.IPv6 != nil

	for _, v := range referencedBackends {
		// Cilium Agent health checking doesn't support changing the host header of a HTTP health check request
		if v.healthCheckConfig.http != nil && v.healthCheckConfig.http.host != "lb" {
			return tierModeT2
		}

		// Cilium Agent health checking doesn't support custom payload (sending and validating response)
		if (v.healthCheckConfig.http != nil && (v.healthCheckConfig.http.send != nil || len(v.healthCheckConfig.http.receive) > 0)) ||
			(v.healthCheckConfig.tcp != nil && (v.healthCheckConfig.tcp.send != nil || len(v.healthCheckConfig.tcp.receive) > 0)) {
			return tierModeT2
		}

		// Cilium Agent health checking doesn't support custom HTTP method & status codes

		if v.healthCheckConfig.http != nil && (!slices.Equal(v.healthCheckConfig.http.healthyStatusCodes, defaultHealthCheckStatusCodes) || v.healthCheckConfig.http.method != lbBackendHealthCheckHTTPMethodGet) {
			return tierModeT2
		}

		// Cilium Agent health checking doesn't support TLS unless it's HTTP health checks.
		if v.healthCheckConfig.tlsConfig != nil && v.healthCheckConfig.http == nil {
			return tierModeT2
		}

		// T1-only cant have different IP family on the frontend & backend side
		if v.typ == lbBackendTypeIP {
			atLeastOneIPv4 := false
			atLeastOneIPv6 := false

			for _, lb := range v.lbBackends {
				for _, lba := range lb.addresses {
					if net.ParseIP(lba).To4() == nil {
						atLeastOneIPv6 = true
					} else {
						atLeastOneIPv4 = true
					}
				}
			}

			if (ipv4Service && !atLeastOneIPv4) || (ipv6Service && !atLeastOneIPv6) {
				return tierModeT2
			}
		}
	}

	for _, ar := range app.Routes {
		if referencedBackends[ar.BackendRef.Name].typ == lbBackendTypeHostname {
			return tierModeT2
		}

		// backends with different ports aren't supported by t1-only mode
		if !r.backendPortsAreTheSame(referencedBackends[ar.BackendRef.Name].lbBackends) {
			return tierModeT2
		}
	}

	return tierModeT1
}

func (r *ingestor) toDNSResolverConfig(config *isovalentv1alpha1.DNSResolverConfig) *lbBackendDNSResolverConfig {
	if config == nil {
		return nil
	}

	ret := &lbBackendDNSResolverConfig{
		resolvers: []lbBackendDNSResolver{},
	}

	for _, resolver := range config.Resolvers {
		ret.resolvers = append(ret.resolvers, lbBackendDNSResolver{
			ip:   resolver.IP,
			port: resolver.Port,
		})
	}

	return ret
}

func (r *ingestor) toHTTPAuth(auth *isovalentv1alpha1.LBServiceHTTPAuth, referencedSecrets map[string]*corev1.Secret) *lbServiceHTTPAuth {
	if auth == nil {
		return nil
	}
	return &lbServiceHTTPAuth{
		basicAuth: r.toHTTPBasicAuth(auth.Basic, referencedSecrets),
		jwtAuth:   r.toHTTPJWTAuth(auth.JWT, referencedSecrets),
	}
}

func (r *ingestor) toHTTPBasicAuth(basicAuth *isovalentv1alpha1.LBServiceHTTPBasicAuth, referencedSecrets map[string]*corev1.Secret) *lbServiceHTTPBasicAuth {
	if basicAuth == nil {
		return nil
	}

	ba := &lbServiceHTTPBasicAuth{
		users: []lbServiceUserPassword{},
	}

	secret, ok := referencedSecrets[basicAuth.Users.SecretRef.Name]
	if !ok {
		return nil
	}

	// Extract clear text credentials from secret
	for username, password := range secret.Data {
		ba.users = append(ba.users, lbServiceUserPassword{
			username: username,
			password: password,
		})
	}

	// Sort by username for deterministic output
	slices.SortStableFunc(ba.users, func(a, b lbServiceUserPassword) int {
		return strings.Compare(a.username, b.username)
	})

	return ba
}

func (r *ingestor) toHTTPJWTAuth(jwtAuth *isovalentv1alpha1.LBServiceHTTPJWTAuth, referencedSecrets map[string]*corev1.Secret) *lbServiceHTTPJWTAuth {
	if jwtAuth == nil {
		return nil
	}

	ja := &lbServiceHTTPJWTAuth{
		providers: []jwtProvider{},
	}

	for _, provider := range jwtAuth.Providers {
		p := jwtProvider{
			name:      provider.Name,
			issuer:    provider.Issuer,
			audiences: provider.Audiences,
		}
		switch {
		case provider.JWKS.SecretRef != nil:
			secret, ok := referencedSecrets[provider.JWKS.SecretRef.Name]
			if !ok {
				continue
			}

			jwksStr, ok := secret.Data[isovalentv1alpha1.LBServiceJWKSSecretKey]
			if !ok {
				continue
			}

			p.localJWKS = &localJWKS{
				jwksStr: string(jwksStr),
			}
		case provider.JWKS.HTTPURI != nil:
			p.remoteJWKS = &remoteJWKS{
				httpURI: provider.JWKS.HTTPURI.URI,
			}
		}
		ja.providers = append(ja.providers, p)
	}

	return ja
}

func (r *ingestor) toHTTPRouteAuth(auth *isovalentv1alpha1.LBServiceHTTPRouteAuth) *lbRouteHTTPAuth {
	if auth == nil {
		return nil
	}

	return &lbRouteHTTPAuth{
		basicAuth: r.toHTTPRouteBasicAuth(auth.Basic),
		jwtAuth:   r.toHTTPRouteJWTAuth(auth.JWT),
	}
}

func (r *ingestor) toHTTPRouteBasicAuth(basicAuth *isovalentv1alpha1.LBServiceHTTPRouteBasicAuth) *lbRouteHTTPBasicAuth {
	if basicAuth == nil {
		return nil
	}
	return &lbRouteHTTPBasicAuth{
		disabled: basicAuth.Disabled,
	}
}

func (r *ingestor) toServiceProxyProtocolConfig(protocol *isovalentv1alpha1.LBServiceProxyProtocolConfig) *lbServiceProxyProtocolConfig {
	if protocol == nil {
		return nil
	}

	var dVersions []int
	for _, v := range protocol.DisallowedVersions {
		dVersions = append(dVersions, int(v))
	}

	var tlvs []uint32
	for _, tlv := range protocol.PassthroughTLVs {
		tlvs = append(tlvs, uint32(tlv))
	}

	return &lbServiceProxyProtocolConfig{
		disallowedVersions: dVersions,
		passThroughTLVs:    tlvs,
	}
}

func (r *ingestor) toBackendProxyProtocolConfig(protocol *isovalentv1alpha1.LBBackendPoolProxyProtocolConfig) *lbBackendProxyProtocolConfig {
	if protocol == nil {
		return nil
	}

	var tlvs []uint32
	for _, tlv := range protocol.PassthroughTLVs {
		tlvs = append(tlvs, uint32(tlv))
	}

	return &lbBackendProxyProtocolConfig{
		version:         int(protocol.Version),
		passthroughTLVs: tlvs,
	}
}

func (r *ingestor) toHTTPRouteJWTAuth(jwtAuth *isovalentv1alpha1.LBServiceHTTPRouteJWTAuth) *lbRouteHTTPJWTAuth {
	if jwtAuth == nil {
		return nil
	}
	return &lbRouteHTTPJWTAuth{
		disabled: jwtAuth.Disabled,
	}
}

func forEachSelectedNodeInternalIP(logger *slog.Logger, ipFamily ipFamily, nodes []*slim_corev1.Node, selector labels.Selector, fn func(node *slim_corev1.Node, ip string, addr netip.Addr)) {
	for _, cn := range nodes {
		if !selector.Matches(labels.Set(cn.Labels)) {
			continue
		}

		hasInternalIP := false
		for _, addr := range cn.Status.Addresses {
			if addr.Type != slim_corev1.NodeInternalIP {
				continue
			}

			parsedAddr, err := netip.ParseAddr(addr.Address)
			if err != nil {
				logger.Debug("invalid node IP",
					logfields.NodeName, cn.Name,
					logfields.Error, err,
				)
				continue
			}

			if parsedAddr.Is4() && (ipFamily == ipFamilyV4 || ipFamily == ipFamilyDual) {
				hasInternalIP = true
				fn(cn, addr.Address, parsedAddr)
			} else if parsedAddr.Is6() && !parsedAddr.Is4In6() && (ipFamily == ipFamilyV6 || ipFamily == ipFamilyDual) {
				hasInternalIP = true
				fn(cn, addr.Address, parsedAddr)
			}
		}

		if !hasInternalIP {
			logger.Warn("Could not find InternalIP for CiliumNode",
				logfields.Resource, cn.Name,
			)
		}
	}
}

func toHealthCheckPort(port *int32) uint32 {
	if port != nil {
		return uint32(*port)
	}
	return 0
}

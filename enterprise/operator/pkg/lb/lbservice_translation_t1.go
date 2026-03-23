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
	"crypto/sha256"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type lbServiceT1Translator struct {
	logger *slog.Logger
	config reconcilerConfig
}

func (r *lbServiceT1Translator) toServicePort(model *lbService) corev1.ServicePort {
	if model.isUDPProxy() {
		return corev1.ServicePort{
			Name:     strings.ToLower(string(corev1.ProtocolUDP)),
			Protocol: corev1.ProtocolUDP,
			Port:     model.port,
		}
	}

	return corev1.ServicePort{
		Name:     strings.ToLower(string(corev1.ProtocolTCP)),
		Protocol: corev1.ProtocolTCP,
		Port:     model.port,
	}
}

func (r *lbServiceT1Translator) DesiredService(model *lbService) *corev1.Service {
	if !model.vip.IPv4Assigned() && !model.vip.IPv6Assigned() {
		return nil
	}

	annotations := map[string]string{
		ossannotation.ServiceNodeSelectorExposure: model.t1LabelSelector.String(),
	}

	// Set the assigned IP address of the LBVIP as LB IPAM annotation.
	// This way we treat the Service of the LBVIP as the main leader from an
	// LB IPAM perspective. This way, when switching the LBVIP, the IP gets changed
	// correctly
	annotations[ossannotation.LBIPAMIPsKey] = buildLBIPAMIPString(model.vip.assignedIPv4, model.vip.assignedIPv6)

	// Set the sharing key (LBVIP name)
	annotations[ossannotation.LBIPAMSharingKey] = model.vip.name

	// BGP
	annotations[annotation.ServiceHealthBGPAdvertiseThreshold] = "1"

	// Expose only LoadBalancer service
	annotations[ossannotation.ServiceTypeExposure] = string(corev1.ServiceTypeLoadBalancer)

	// T1 -> {T2 | Backend} forwarding mode
	annotations[ossannotation.ServiceForwardingMode] = r.getServiceForwardingMode(model)

	// T1 -> T2 loadbalancing algorithm
	annotations[ossannotation.ServiceLoadBalancingAlgorithm] = r.getServiceLoadBalancingAlgorithm(model)

	// T1 -> {T2 | Backend} health checking
	maps.Copy(annotations, r.getHealthCheckAnnotations(model))

	if !model.isTCPProxyT1OnlyMode() && !model.isUDPProxyT1OnlyMode() {
		// T1 -> T2 delegation: If T2 is on the same node, just push the packet up to
		// T2 instead of IPIP encapsulation
		annotations[ossannotation.ServiceProxyDelegation] = string(loadbalancer.SVCProxyDelegationDelegateIfLocal)
	}

	// T1-only connectionfiltering
	var lbSourceRanges []string = nil

	if model.isTCPProxyT1OnlyMode() || model.isUDPProxy() /* t1 & t1&t2 for UDP !! */ {
		lbSourceRanges = r.getServiceLoadBalancingT1SourceRanges(model)
		if len(lbSourceRanges) > 0 {
			annotations[ossannotation.ServiceSourceRangesPolicy] = r.getServiceLoadBalancingT1SourceRangesPolicy(model)
		}
	}

	annotations["loadbalancer.isovalent.com/type"] = "t1"

	// write T1 node ips as hash to annotation. This way a reconciliation of the K8s Service gets enforced if any of the Node labels change
	h := sha256.New()
	_, _ = h.Write([]byte(strings.Join(append(model.t1NodeIPv4Addresses, model.t1NodeIPv6Addresses...), "")))
	annotations["loadbalancer.isovalent.com/t1-nodes-hash"] = fmt.Sprintf("%x", h.Sum(nil))

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
			Labels: map[string]string{
				"loadbalancer.isovalent.com/vip-name": model.vip.name,
			},
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeLoadBalancer,
			AllocateLoadBalancerNodePorts: ptr.To(false),
			IPFamilies:                    getServiceIPFamilies(model.vip.ipFamily),
			IPFamilyPolicy:                getServiceIPFamilyPolicy(model.vip.ipFamily),
			Ports:                         []corev1.ServicePort{r.toServicePort(model)},
			LoadBalancerSourceRanges:      lbSourceRanges,
			SessionAffinity:               r.getServiceSessionAffinity(model),
			TrafficDistribution:           lookupTrafficDistribution(model.zoneAwareMode),
		},
	}
}

func (r *lbServiceT1Translator) getHealthCheckAnnotations(model *lbService) map[string]string {
	annotations := map[string]string{}

	switch {
	case !model.isTCPProxyT1OnlyMode() && !model.isUDPProxyT1OnlyMode():
		if r.config.T1T2HealthCheck.T2HCPushEnabled {
			return annotations
		}

		// In T1&T2 deployment mode, T1 service is configured to perform T1->T2 health checking using
		// hardcoded, globally configurable and calculated values (based on the backend configs)
		annotations[annotation.ServiceHealthProbeInterval] = fmt.Sprintf("%ds", r.getT1T2HealthCheckIntervalSeconds(model))
		annotations[annotation.ServiceHealthProbeTimeout] = fmt.Sprintf("%ds", r.config.T1T2HealthCheck.T1ProbeTimeoutSeconds)
		annotations[annotation.ServiceHealthThresholdHealthy] = "1"
		annotations[annotation.ServiceHealthThresholdUnhealthy] = "1"
		annotations[annotation.ServiceHealthQuarantineTimeout] = fmt.Sprintf("%ds", r.config.T1T2HealthCheck.T1ProbeTimeoutSeconds)

		// The presence of these annotations will enable HTTP-based health checking from T1 to T2 nodes
		annotations[annotation.ServiceHealthHTTPPath] = r.config.T1T2HealthCheck.T1ProbeHttpPath
		annotations[annotation.ServiceHealthHTTPMethod] = r.config.T1T2HealthCheck.T1ProbeHttpMethod

	default:
		// In T1-only deployment mode, T1 service is configured to perform the actual L4 health checking to the backends (T1->Backend).
		// (connect for TCP, ICMP/Payload-based for UDP)
		annotations[annotation.ServiceHealthProbeInterval] = fmt.Sprintf("%ds", r.getT1OnlyHealthCheckIntervalSeconds(model))
		annotations[annotation.ServiceHealthProbeTimeout] = fmt.Sprintf("%ds", r.getT1OnlyHealthCheckTimeoutSeconds(model))
		annotations[annotation.ServiceHealthThresholdHealthy] = strconv.Itoa(r.getT1OnlyHealthCheckThresholdHealthy(model))
		annotations[annotation.ServiceHealthThresholdUnhealthy] = strconv.Itoa(r.getT1OnlyHealthCheckThresholdUnhealthy(model))
		annotations[annotation.ServiceHealthQuarantineTimeout] = fmt.Sprintf("%ds", r.config.T1T2HealthCheck.T1ProbeTimeoutSeconds)
		if port := r.getT1OnlyHealthCheckPort(model); port > 0 {
			annotations[annotation.ServiceHealthProbePort] = strconv.FormatUint(uint64(port), 10)
		}

		if httpPath := r.getT1OnlyHealthCheckHTTPPath(model); httpPath != "" {
			annotations[annotation.ServiceHealthHTTPPath] = httpPath
			annotations[annotation.ServiceHealthHTTPMethod] = "GET"

			// If backend health check wants TLS, set https scheme + optional host
			if r.getT1OnlyHealthCheckUseHTTPS(model) {
				annotations[annotation.ServiceHealthHTTPScheme] = "https"
			}
			if host := r.getT1OnlyHealthCheckHTTPHost(model); host != "" {
				annotations[annotation.ServiceHealthHTTPHost] = host
			}
		}
	}

	return annotations
}

func (r *lbServiceT1Translator) getT1T2HealthCheckIntervalSeconds(model *lbService) int {
	shortestInterval := 0

	for _, b := range model.referencedBackends {
		if shortestInterval == 0 || b.healthCheckConfig.intervalSeconds < shortestInterval {
			shortestInterval = b.healthCheckConfig.intervalSeconds
		}
	}

	hcInterval := shortestInterval
	if shortestInterval > 1 {
		// Use half of shortest interval as health check interval
		hcInterval = shortestInterval / 2
	}

	return hcInterval
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckIntervalSeconds(model *lbService) int {
	for _, b := range model.referencedBackends {
		// return value of first backend, because T1-only (TCP & UDP) backends can only reference one backend
		return b.healthCheckConfig.intervalSeconds // no support for unhealthy interval
	}

	return 15
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckTimeoutSeconds(model *lbService) int {
	for _, b := range model.referencedBackends {
		// return value of first backend, because T1-only (TCP & UDP) backends can only reference one backend
		return b.healthCheckConfig.timeoutSeconds
	}

	return 5
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckThresholdHealthy(model *lbService) int {
	for _, b := range model.referencedBackends {
		// return value of first backend, because T1-only (TCP & UDP) backends can only reference one backend
		return b.healthCheckConfig.healthyThreshold
	}

	return 1
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckThresholdUnhealthy(model *lbService) int {
	for _, b := range model.referencedBackends {
		// return value of first backend, because T1-only (TCP & UDP) backends can only reference one backend
		return b.healthCheckConfig.unhealthyThreshold
	}

	return 1
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckPort(model *lbService) uint32 {
	for _, b := range model.referencedBackends {
		// return value of first backend, because T1-only (TCP & UDP) backends can only reference one backend
		return b.healthCheckConfig.port
	}

	return 0
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckHTTPPath(model *lbService) string {
	for _, b := range model.referencedBackends {
		// return value of first backend, because T1-only (TCP & UDP) backends can only reference one backend
		if b.healthCheckConfig.http != nil {
			return b.healthCheckConfig.http.path
		}
	}

	return ""
}

func (r *lbServiceT1Translator) endpointSubsetsFromT2Nodes(model *lbService, ipv6 bool) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	prot := corev1.ProtocolTCP
	if model.isUDPProxy() {
		prot = corev1.ProtocolUDP
	}

	addresses := model.t2NodeIPv4Addresses
	zones := model.t2NodeIPv4Zones
	if ipv6 {
		addresses = model.t2NodeIPv6Addresses
		zones = model.t2NodeIPv6Zones
	}

	return addressesAndZonesToEndpoints(addresses, zones),
		[]discoveryv1.EndpointPort{
			{
				Name:     ptr.To(strings.ToLower(string(prot))),
				Protocol: ptr.To(prot),
				Port:     ptr.To(int32(model.port)),
			},
		}
}

func (r *lbServiceT1Translator) tcpEndpointSubsetsFromBackends(model *lbService, ipv6 bool) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	backendRefs := collectBackendRefs(
		model.applications.tcpProxy.routes,
		func(tr lbRouteTCPProxy) backendRef { return tr.backendRef },
	)
	return endpointSubsetsFromBackends(r.logger, model, backendRefs, ipv6, corev1.ProtocolTCP)
}

func (r *lbServiceT1Translator) udpEndpointSubsetsFromBackends(model *lbService, ipv6 bool) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	backendRefs := collectBackendRefs(
		model.applications.udpProxy.routes,
		func(tr lbRouteUDPProxy) backendRef { return tr.backendRef },
	)
	return endpointSubsetsFromBackends(r.logger, model, backendRefs, ipv6, corev1.ProtocolUDP)
}

func (r *lbServiceT1Translator) DesiredEndpointSlice(model *lbService, ipv6 bool) *discoveryv1.EndpointSlice {
	if (!ipv6 && !model.vip.IPv4Assigned()) || ipv6 && !model.vip.IPv6Assigned() {
		return nil
	}

	endpoints, ports := r.getEndpointSliceInfo(model, ipv6)
	if !hasAddresses(endpoints) {
		// Prevent failure during creation/update of EndpointSlice without addresses
		// ... is invalid: endpoints[0].addresses: Required value: must contain at least 1 address
		return nil
	}

	addressType := discoveryv1.AddressTypeIPv4
	midfix := ""
	if ipv6 {
		addressType = discoveryv1.AddressTypeIPv6
		midfix = endpointSliceIPv6Midfix
	}

	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceNameWithMidfix(midfix),
			Labels: map[string]string{
				discoveryv1.LabelServiceName: model.getOwningResourceName(),
				discoveryv1.LabelManagedBy:   "ilb",
			},
		},
		AddressType: addressType,
		Endpoints:   endpoints,
		Ports:       ports,
	}
}

func hasAddresses(endpoints []discoveryv1.Endpoint) bool {
	for _, e := range endpoints {
		if len(e.Addresses) > 0 {
			return true
		}
	}

	return false
}

func (r *lbServiceT1Translator) getEndpointSliceInfo(model *lbService, ipv6 bool) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	if model.isTCPProxyT1OnlyMode() {
		return r.tcpEndpointSubsetsFromBackends(model, ipv6)
	} else if model.isUDPProxyT1OnlyMode() {
		return r.udpEndpointSubsetsFromBackends(model, ipv6)
	} else {
		return r.endpointSubsetsFromT2Nodes(model, ipv6)
	}
}

func (r *lbServiceT1Translator) getServiceForwardingMode(model *lbService) string {
	if model.isTCPProxyT1OnlyWithDSR() || model.isUDPProxyT1OnlyWithDSR() {
		return string(loadbalancer.SVCForwardingModeDSR)
	}

	if model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		return string(loadbalancer.SVCForwardingModeSNAT)
	}

	return string(loadbalancer.SVCForwardingModeDSR)
}

func (r *lbServiceT1Translator) getServiceLoadBalancingAlgorithm(model *lbService) string {
	if model.isTCPProxyT1OnlyWithDSR() || model.isUDPProxyT1OnlyWithDSR() {
		return "maglev"
	}

	if model.isTCPProxyT1OnlyMode() && !model.usesTCPProxyPersistentBackendsWithSourceIP() {
		return "random"
	}

	// Note: UDPProxy with deployment mode T1-only uses maglev to provide UDP "session" support.
	return "maglev"
}

func (r *lbServiceT1Translator) getServiceLoadBalancingT1SourceRanges(model *lbService) []string {
	switch {
	case model.isTCPProxy():
		for _, tr := range model.applications.tcpProxy.routes {
			if tr.connectionFiltering != nil {
				lbSourceRanges := []string{}
				for _, cfr := range tr.connectionFiltering.rules {
					if cfr.sourceCIDR != nil {
						lbSourceRanges = append(lbSourceRanges, fmt.Sprintf("%s/%d", cfr.sourceCIDR.addressPrefix, cfr.sourceCIDR.prefixLen))
					}
				}

				// Only one TCPProxy route allowed for the time being
				return lbSourceRanges
			}
		}
	case model.isUDPProxy():
		for _, tr := range model.applications.udpProxy.routes {
			if tr.connectionFiltering != nil {
				lbSourceRanges := []string{}
				for _, cfr := range tr.connectionFiltering.rules {
					if cfr.sourceCIDR != nil {
						lbSourceRanges = append(lbSourceRanges, fmt.Sprintf("%s/%d", cfr.sourceCIDR.addressPrefix, cfr.sourceCIDR.prefixLen))
					}
				}

				// Only one UDPProxy route allowed for the time being
				return lbSourceRanges
			}
		}
	}

	return nil
}

func (r *lbServiceT1Translator) getServiceLoadBalancingT1SourceRangesPolicy(model *lbService) string {
	switch {
	case model.isTCPProxy():
		for _, tr := range model.applications.tcpProxy.routes {
			if tr.connectionFiltering != nil {
				policy := "allow"
				if tr.connectionFiltering.ruleType == ruleTypeDeny {
					policy = "deny"
				}

				// Only one TCPProxy route allowed for the time being
				return policy
			}
		}
	case model.isUDPProxy():
		for _, tr := range model.applications.udpProxy.routes {
			if tr.connectionFiltering != nil {
				policy := "allow"
				if tr.connectionFiltering.ruleType == ruleTypeDeny {
					policy = "deny"
				}

				// Only one UDPProxy route allowed for the time being
				return policy
			}
		}
	}

	return ""
}

func (r *lbServiceT1Translator) getServiceSessionAffinity(model *lbService) corev1.ServiceAffinity {
	if !model.isTCPProxyT1OnlyMode() && !model.isUDPProxyT1OnlyMode() {
		return corev1.ServiceAffinityNone
	}

	if model.usesTCPProxyPersistentBackendsWithSourceIP() || model.usesUDPProxyPersistentBackendsWithSourceIP() {
		return corev1.ServiceAffinityClientIP
	}

	return corev1.ServiceAffinityNone
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckUseHTTPS(model *lbService) bool {
	for _, b := range model.referencedBackends {
		return b.healthCheckConfig.tlsConfig != nil
	}
	return false
}

func (r *lbServiceT1Translator) getT1OnlyHealthCheckHTTPHost(model *lbService) string {
	for _, b := range model.referencedBackends {
		return b.healthCheckConfig.http.host
	}
	return ""
}

func addressesAndZonesToEndpoints(addresses []string, zones map[string]string) []discoveryv1.Endpoint {
	zoneAddrs := map[string][]string{}
	bareAddrs := []string{}
	for _, a := range addresses {
		if zone := zones[a]; zone != "" && zone != lbServiceZoneUnknown {
			zoneAddrs[zone] = append(zoneAddrs[zone], a)
			continue
		}
		bareAddrs = append(bareAddrs, a)
	}

	return groupedAddressesToEndpoints(zoneAddrs, bareAddrs)
}

func collectBackendRefs[T any](routes []T, toRef func(route T) backendRef) []backendRef {
	refs := make([]backendRef, 0, len(routes))
	for _, route := range routes {
		refs = append(refs, toRef(route))
	}
	return refs
}

func endpointSubsetsFromBackends(logger *slog.Logger, model *lbService, backendRefs []backendRef, ipv6 bool, protocol corev1.Protocol) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	zoneAddrs := map[string][]string{}
	bareAddrs := []string{}
	port := uint32(0)

	for _, ref := range backendRefs {
		backend, ok := model.referencedBackends[ref.name]
		if !ok {
			continue
		}
		for _, b := range backend.lbBackends {
			if port == 0 {
				port = b.port
			}
			if port != b.port {
				logger.Debug("Skipping incompatible backend",
					logfields.Resource, types.NamespacedName{Namespace: model.namespace, Name: model.name},
					logfields.Address, b.addresses,
					logfields.Port, b.port,
					logfields.Reason, "T1-only service does not support backends with different ports")
				continue
			}
			for _, ba := range b.addresses {
				isIPv4 := net.ParseIP(ba).To4() != nil
				if isIPv4 != ipv6 {
					if zone := b.addressZones[ba]; zone != "" && zone != lbServiceZoneUnknown {
						zoneAddrs[zone] = append(zoneAddrs[zone], ba)
					} else {
						bareAddrs = append(bareAddrs, ba)
					}
				}
			}
		}
	}

	if len(zoneAddrs)+len(bareAddrs) == 0 {
		return nil, nil
	}

	return groupedAddressesToEndpoints(zoneAddrs, bareAddrs),
		[]discoveryv1.EndpointPort{
			{
				Name:     ptr.To(strings.ToLower(string(protocol))),
				Protocol: ptr.To(protocol),
				Port:     ptr.To(int32(port)),
			},
		}
}

func groupedAddressesToEndpoints(zoneAddrs map[string][]string, bareAddrs []string) []discoveryv1.Endpoint {
	endpoints := []discoveryv1.Endpoint{}
	for _, zone := range sortedKeys(zoneAddrs) {
		endpoints = append(endpoints, discoveryv1.Endpoint{
			Addresses: zoneAddrs[zone],
			Zone:      ptr.To(zone),
			Hints: &discoveryv1.EndpointHints{
				ForZones: []discoveryv1.ForZone{{Name: zone}},
			},
		})
	}
	if len(bareAddrs) > 0 || len(endpoints) == 0 {
		endpoints = append(endpoints, discoveryv1.Endpoint{
			Addresses: bareAddrs,
		})
	}
	return endpoints
}

func lookupTrafficDistribution(mode lbServiceZoneAwareModeType) *string {
	switch mode {
	case lbServiceZoneAwareModePreferSameZone:
		return ptr.To(corev1.ServiceTrafficDistributionPreferClose)
	default:
		return nil
	}
}

func sortedKeys(m map[string][]string) []string {
	return slices.Sorted(maps.Keys(m))
}

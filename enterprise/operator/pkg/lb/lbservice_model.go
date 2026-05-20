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
	wafpolicy "github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/shortener"
)

// TODO: validation method
// - tcp route -> only one route allowed
// - http and tls routes -> validate for overlapping hostnames? (with wildcards...)

type lbService struct {
	namespace                string
	name                     string
	vip                      lbVIP
	zoneAwareMode            lbServiceZoneAwareModeType
	zoneAwareMinBackendCount uint64
	port                     int32
	proxyProtocolConfig      *lbServiceProxyProtocolConfig
	enableGRPCAccessLogs     *bool
	applications             lbApplications
	referencedBackends       map[string]backend
	t1NodeIPv4Addresses      []string
	t1NodeIPv6Addresses      []string
	t2NodeIPv4Addresses      []string
	t2NodeIPv6Addresses      []string
	t2NodeIPv4Zones          map[string]string
	t2NodeIPv6Zones          map[string]string
	t1LabelSelector          labels.Selector
	t2LabelSelector          labels.Selector
	enableCNPIntegration     bool
	effectiveWAFConfig       *wafpolicy.EffectiveConfig
}

type lbServiceZoneAwareModeType string

const (
	lbServiceZoneAwareModeDisabled        lbServiceZoneAwareModeType = "disabled"
	lbServiceZoneAwareModePreferSameZone  lbServiceZoneAwareModeType = "preferSameZone"
	lbServiceZoneAwareModeRequireSameZone lbServiceZoneAwareModeType = "requireSameZone"
)

const lbServiceZoneUnknown = "unknown"

type lbVIP struct {
	name         string
	ipFamily     ipFamily
	assignedIPv4 *string
	assignedIPv6 *string
	bindStatus   lbVIPBindStatus
}

type ipFamily string

const (
	ipFamilyV4   ipFamily = "ipv4"
	ipFamilyV6   ipFamily = "ipv6"
	ipFamilyDual ipFamily = "dual"
)

type lbServiceProxyProtocolConfig struct {
	disallowedVersions []int
	passThroughTLVs    []uint32
}

type lbVIPBindStatus struct {
	serviceExists  bool
	bindSuccessful bool
	bindIssue      string
}

func (r lbVIP) IPv4Assigned() bool {
	return r.assignedIPv4 != nil
}

func (r lbVIP) IPv6Assigned() bool {
	return r.assignedIPv6 != nil
}

func (r lbVIP) IPv4SupportedByIPFamily() bool {
	return r.ipFamily == ipFamilyDual || r.ipFamily == ipFamilyV4
}

func (r lbVIP) IPv6SupportedByIPFamily() bool {
	return r.ipFamily == ipFamilyDual || r.ipFamily == ipFamilyV6
}

// grpcAccessLogsEnabledForService reports whether gRPC access logging is enabled for this service.
// Returns true if unset (nil), meaning the global setting applies.
func (r lbService) grpcAccessLogsEnabledForService() bool {
	if r.enableGRPCAccessLogs == nil {
		return true
	}
	return *r.enableGRPCAccessLogs
}

func (r lbService) getOwningResourceName() string {
	return getOwningResourceName(r.name)
}

func (r lbService) getOwningResourceNameWithMidfix(midfix string) string {
	return getOwningResourceNameWithMidfix(r.name, midfix)
}

func (r lbService) usesT2() bool {
	return !r.isTCPProxyT1OnlyMode() && !r.isUDPProxyT1OnlyMode()
}

func (r lbService) t2NodeZones() map[string]struct{} {
	zones := map[string]struct{}{}
	for _, zone := range r.t2NodeIPv4Zones {
		if zone == "" || zone == lbServiceZoneUnknown {
			continue
		}
		zones[zone] = struct{}{}
	}
	for _, zone := range r.t2NodeIPv6Zones {
		if zone == "" || zone == lbServiceZoneUnknown {
			continue
		}
		zones[zone] = struct{}{}
	}
	return zones
}

func (r lbService) hasBackendInT2NodeZone() bool {
	if !r.usesT2() {
		return false
	}

	t2Zones := r.t2NodeZones()
	if len(t2Zones) == 0 {
		return false
	}

	for _, be := range r.referencedBackends {
		for _, lbBe := range be.lbBackends {
			for _, zone := range lbBe.addressZones {
				if _, ok := t2Zones[zone]; ok {
					return true
				}
			}
		}
	}
	return false
}

func getOwningResourceName(parentName string) string {
	name := "lbfe-" + parentName

	// shorten to be below the max name length of k8s resources even after prefixing
	return shortener.ShortenK8sResourceName(name)
}

func getOwningResourceNameWithMidfix(parentName string, midfix string) string {
	name := "lbfe-" + midfix + parentName

	// shorten to be below the max name length of k8s resources even after prefixing
	return shortener.ShortenK8sResourceName(name)
}

type lbServiceHTTPConfig struct {
	enableHTTP11 bool
	enableHTTP2  bool
}

type lbServiceTLSConfig struct {
	certificateSecrets         []string
	validationContext          lbServiceTLSConfigValidationContext
	minTLSVersion              string
	maxTLSVersion              string
	allowedCipherSuites        []string
	allowedECDHCurves          []string
	allowedSignatureAlgorithms []string
}

type lbServiceTLSConfigValidationContext struct {
	trustedCASecretName     string
	subjectAlternativeNames []string
}

type lbApplications struct {
	httpProxy      *lbApplicationHTTPProxy
	httpsProxy     *lbApplicationHTTPSProxy
	tlsPassthrough *lbApplicationTLSPassthrough
	tlsProxy       *lbApplicationTLSProxy
	tcpProxy       *lbApplicationTCPProxy
	udpProxy       *lbApplicationUDPProxy
}

func (r lbApplications) isHTTPProxyConfigured() bool {
	return r.httpProxy != nil
}

func (r lbApplications) isHTTPSProxyConfigured() bool {
	return r.httpsProxy != nil
}

func (r lbApplications) isTLSPassthroughConfigured() bool {
	return r.tlsPassthrough != nil
}

func (r lbApplications) isTLSProxyConfigured() bool {
	return r.tlsProxy != nil
}

func (r lbApplications) isT2TCPProxyConfigured() bool {
	return r.tcpProxy != nil && r.tcpProxy.tierMode == tierModeT2
}

func (r lbService) usesHTTPRequestFiltering() bool {
	a := r.applications

	if a.httpProxy != nil {
		for _, routes := range a.httpProxy.routes {
			for _, ar := range routes {
				if ar.requestFiltering != nil {
					return true
				}
			}
		}
	}

	return false
}

func (r lbService) usesHTTPSRequestFiltering() bool {
	a := r.applications

	if a.httpsProxy != nil {
		for _, routes := range a.httpsProxy.routes {
			for _, ar := range routes {
				if ar.requestFiltering != nil {
					return true
				}
			}
		}
	}

	return false
}

func (r lbService) usesHTTPRequestRateLimiting() bool {
	a := r.applications

	if a.httpProxy != nil {
		for _, routes := range a.httpProxy.routes {
			for _, ar := range routes {
				if ar.rateLimits != nil {
					return true
				}
			}
		}
	}

	return false
}

func (r lbService) usesHTTPSRequestRateLimiting() bool {
	a := r.applications

	if a.httpsProxy != nil {
		for _, routes := range a.httpsProxy.routes {
			for _, ar := range routes {
				if ar.rateLimits != nil {
					return true
				}
			}
		}
	}

	return false
}

func (r lbService) usesHTTPBasicAuth() bool {
	return r.applications.httpProxy != nil &&
		r.applications.httpProxy.auth != nil &&
		r.applications.httpProxy.auth.basicAuth != nil
}

func (r lbService) usesHTTPSBasicAuth() bool {
	return r.applications.httpsProxy != nil &&
		r.applications.httpsProxy.auth != nil &&
		r.applications.httpsProxy.auth.basicAuth != nil
}

func (r lbService) usesHTTPJWTAuth() bool {
	return r.applications.httpProxy != nil &&
		r.applications.httpProxy.auth != nil &&
		r.applications.httpProxy.auth.jwtAuth != nil
}

func (r lbService) usesHTTPSJWTAuth() bool {
	return r.applications.httpsProxy != nil &&
		r.applications.httpsProxy.auth != nil &&
		r.applications.httpsProxy.auth.jwtAuth != nil
}

func (r lbApplications) getHTTPHTTPConfig() *lbServiceHTTPConfig {
	if r.httpProxy == nil {
		return nil
	}

	return r.httpProxy.httpConfig
}

func (r lbApplications) getHTTPSHTTPConfig() *lbServiceHTTPConfig {
	if r.httpsProxy == nil {
		return nil
	}

	return r.httpsProxy.httpConfig
}

func (r lbApplications) getHTTPConnectionFiltering() *lbServiceHTTPConnectionFiltering {
	if r.httpProxy == nil {
		return nil
	}

	return r.httpProxy.connectionFiltering
}

func (r lbApplications) getHTTPSConnectionFiltering() *lbServiceHTTPConnectionFiltering {
	if r.httpsProxy == nil {
		return nil
	}

	return r.httpsProxy.connectionFiltering
}

func (r lbApplications) getHTTPConnectionRateLimits() *lbServiceConnectionRateLimit {
	if r.httpProxy == nil {
		return nil
	}

	return r.httpProxy.rateLimits
}

func (r lbApplications) getHTTPSConnectionRateLimits() *lbServiceConnectionRateLimit {
	if r.httpsProxy == nil {
		return nil
	}

	return r.httpsProxy.rateLimits
}

func (r *lbService) usesTCPProxyPersistentBackendsWithSourceIP() bool {
	if r.applications.tcpProxy == nil {
		return false
	}

	for _, route := range r.applications.tcpProxy.routes {
		if route.persistentBackend != nil && route.persistentBackend.sourceIP {
			return true
		}
	}

	return false
}

func (r *lbService) usesUDPProxyPersistentBackendsWithSourceIP() bool {
	if r.applications.udpProxy == nil {
		return false
	}

	for _, route := range r.applications.udpProxy.routes {
		if route.persistentBackend != nil && route.persistentBackend.sourceIP {
			return true
		}
	}

	return false
}

type lbApplicationHTTPProxy struct {
	httpConfig          *lbServiceHTTPConfig
	connectionFiltering *lbServiceHTTPConnectionFiltering
	rateLimits          *lbServiceConnectionRateLimit
	auth                *lbServiceHTTPAuth
	routes              map[string][]lbRouteHTTP
}

type lbApplicationHTTPSProxy struct {
	httpConfig          *lbServiceHTTPConfig
	tlsConfig           lbServiceTLSConfig
	connectionFiltering *lbServiceHTTPConnectionFiltering
	rateLimits          *lbServiceConnectionRateLimit
	auth                *lbServiceHTTPAuth
	routes              map[string][]lbRouteHTTP
}

type lbApplicationTLSPassthrough struct {
	routes []lbRouteTLSPassthrough
}

type lbApplicationTLSProxy struct {
	tlsConfig lbServiceTLSConfig
	routes    []lbRouteTLSProxy
}

type tierModeType int

const (
	tierModeT1 tierModeType = iota
	tierModeT2
)

type fwdModeType int

const (
	fwdModeSNAT fwdModeType = iota
	fwdModeDSR
)

type lbApplicationTCPProxy struct {
	tierMode tierModeType
	fwdMode  fwdModeType
	routes   []lbRouteTCPProxy
}

func (r lbService) isTCPProxy() bool {
	return r.applications.tcpProxy != nil
}

func (r lbService) isTCPProxyT1OnlyMode() bool {
	return r.applications.tcpProxy != nil && r.applications.tcpProxy.tierMode == tierModeT1
}

func (r lbService) isTCPProxyT1OnlyWithDSR() bool {
	return r.applications.tcpProxy != nil && r.applications.tcpProxy.tierMode == tierModeT1 && r.applications.tcpProxy.fwdMode == fwdModeDSR
}

type lbApplicationUDPProxy struct {
	tierMode tierModeType
	fwdMode  fwdModeType
	routes   []lbRouteUDPProxy
}

func (r lbService) isUDPProxy() bool {
	return r.applications.udpProxy != nil
}

func (r lbService) isUDPProxyT1OnlyMode() bool {
	return r.applications.udpProxy != nil && r.applications.udpProxy.tierMode == tierModeT1
}

func (r lbService) isUDPProxyT1OnlyWithDSR() bool {
	return r.applications.udpProxy != nil && r.applications.udpProxy.tierMode == tierModeT1 && r.applications.udpProxy.fwdMode == fwdModeDSR
}

type lbRouteHTTP struct {
	match             lbRouteHTTPMatch
	backendRef        backendRef
	persistentBackend *lbRouteHTTPPersistentBackend
	requestFiltering  *lbRouteHTTPRequestFiltering
	rateLimits        *lbServiceRequestRateLimit
	auth              *lbRouteHTTPAuth
}

type lbRouteHTTPMatch struct {
	path     string
	pathType routePathTypeType
}

type routePathTypeType int

const (
	routePathTypePrefix routePathTypeType = iota
	routePathTypeExact
)

type lbRouteHTTPPersistentBackend struct {
	sourceIP    bool
	cookieNames []string
	headerNames []string
}

type ruleTypeType int

const (
	ruleTypeAllow ruleTypeType = iota
	ruleTypeDeny
)

type lbServiceHTTPConnectionFiltering struct {
	ruleType ruleTypeType
	rules    []lbServiceHTTPConnectionFilteringRule
}

type lbServiceHTTPConnectionFilteringRule struct {
	sourceCIDR *lbRouteRequestFilteringSourceCIDR
}

type lbRouteHTTPRequestFiltering struct {
	ruleType ruleTypeType
	rules    []lbRouteHTTPRequestFilteringRule
}

type lbRouteHTTPRequestFilteringRule struct {
	sourceCIDR            *lbRouteRequestFilteringSourceCIDR
	hostname              *lbRouteRequestFilteringHostName
	path                  *lbRouteRequestFilteringHTTPPath
	headers               []*lbRouteRequestFilteringHTTPHeader
	jwtClaims             []*lbRouteRequestFilteringJWTClaim
	clientCertificateSANs []*lbRouteRequestFilteringClientCertificateSAN // only populated in case of HTTPS
}

type lbRouteRequestFilteringSourceCIDR struct {
	addressPrefix string
	prefixLen     uint32
}

type lbRouteRequestFilteringClientCertificateSAN struct {
	sanType string
	oid     string
	value   lbRouteRequestFilteringClientCertificateSANValue
}

type lbRouteRequestFilteringClientCertificateSANValue struct {
	value     string
	valueType filterClientCertificateSANValueType
}

type filterClientCertificateSANValueType int

const (
	filterClientCertificateSANValueTypePrefix filterClientCertificateSANValueType = iota
	filterClientCertificateSANValueTypeExact
	filterClientCertificateSANValueTypeRegex
)

type lbRouteRequestFilteringHostName struct {
	hostName     string
	hostNameType filterHostnameTypeType
}

type filterHostnameTypeType int

const (
	filterHostnameTypeSuffix filterHostnameTypeType = iota
	filterHostnameTypeExact
)

type lbRouteRequestFilteringHTTPPath struct {
	path     string
	pathType filterPathTypeType
}

type filterPathTypeType int

const (
	filterPathTypePrefix filterPathTypeType = iota
	filterPathTypeExact
)

type lbRouteRequestFilteringHTTPHeader struct {
	name  string
	value lbRouteRequestFilteringHTTPHeaderValue
}

type lbRouteRequestFilteringHTTPHeaderValue struct {
	value     string
	valueType filterHeaderTypeType
}

type filterHeaderTypeType int

const (
	filterHeaderTypePrefix filterHeaderTypeType = iota
	filterHeaderTypeExact
	filterHeaderTypeRegex
)

type lbRouteRequestFilteringJWTClaim struct {
	name  string
	value lbRouteRequestFilteringJWTClaimValue
}

type lbRouteRequestFilteringJWTClaimValue struct {
	value     string
	valueType filterJWTClaimTypeType
}

type filterJWTClaimTypeType int

const (
	filterJWTClaimTypePrefix filterJWTClaimTypeType = iota
	filterJWTClaimTypeExact
	filterJWTClaimTypeRegex
)

type lbRouteTLSPassthrough struct {
	match               lbRouteTLSPassthroughMatch
	backendRef          backendRef
	persistentBackend   *lbRouteTLSPersistentBackend
	connectionFiltering *lbRouteTLSConnectionFiltering
	rateLimits          *lbServiceConnectionRateLimit
}

type lbRouteTLSPassthroughMatch struct {
	hostNames []string
}

type lbRouteTLSPersistentBackend struct {
	sourceIP bool
}

type lbRouteTLSConnectionFiltering struct {
	ruleType ruleTypeType
	rules    []lbRouteTLSConnectionFilteringRule
}

type lbRouteTLSConnectionFilteringRule struct {
	sourceCIDR            *lbRouteRequestFilteringSourceCIDR
	clientCertificateSANs []*lbRouteRequestFilteringClientCertificateSAN
	servername            *lbRouteRequestFilteringHostName
}

type lbRouteTLSProxy struct {
	match               lbRouteTLSProxyMatch
	backendRef          backendRef
	persistentBackend   *lbRouteTLSPersistentBackend
	connectionFiltering *lbRouteTLSConnectionFiltering
	rateLimits          *lbServiceConnectionRateLimit
}

type lbRouteTLSProxyMatch struct {
	hostNames []string
}

type backendRef struct {
	name string
}

type lbServiceRequestRateLimit struct {
	requests lbServiceRateLimit
}

type lbServiceConnectionRateLimit struct {
	connections lbServiceRateLimit
}

type lbServiceRateLimit struct {
	limit             uint
	timePeriodSeconds uint
}

type lbRouteTCPProxy struct {
	backendRef          backendRef
	persistentBackend   *lbRouteTCPPersistentBackend
	connectionFiltering *lbRouteTCPConnectionFiltering
	rateLimits          *lbServiceConnectionRateLimit
}

type lbRouteTCPPersistentBackend struct {
	sourceIP bool
}

type lbRouteTCPConnectionFiltering struct {
	ruleType ruleTypeType
	rules    []lbRouteTCPConnectionFilteringRule
}

type lbRouteTCPConnectionFilteringRule struct {
	sourceCIDR *lbRouteRequestFilteringSourceCIDR
}

type lbRouteUDPProxy struct {
	backendRef          backendRef
	persistentBackend   *lbRouteUDPPersistentBackend
	connectionFiltering *lbRouteUDPConnectionFiltering
}

type lbRouteUDPPersistentBackend struct {
	sourceIP bool
}

type lbRouteUDPConnectionFiltering struct {
	ruleType ruleTypeType
	rules    []lbRouteUDPConnectionFilteringRule
}

type lbRouteUDPConnectionFilteringRule struct {
	sourceCIDR *lbRouteRequestFilteringSourceCIDR
}

type lbServiceHTTPAuth struct {
	basicAuth *lbServiceHTTPBasicAuth
	jwtAuth   *lbServiceHTTPJWTAuth
}

type lbServiceHTTPBasicAuth struct {
	users []lbServiceUserPassword
}

type lbServiceHTTPJWTAuth struct {
	providers []jwtProvider
}

type jwtProvider struct {
	name       string
	issuer     *string
	audiences  []string
	localJWKS  *localJWKS
	remoteJWKS *remoteJWKS
}

type localJWKS struct {
	jwksStr string
}

type remoteJWKS struct {
	httpURI string
}

type lbServiceUserPassword struct {
	username string
	password []byte
}

type lbRouteHTTPAuth struct {
	basicAuth *lbRouteHTTPBasicAuth
	jwtAuth   *lbRouteHTTPJWTAuth
}

type lbRouteHTTPBasicAuth struct {
	disabled bool
}

type lbRouteHTTPJWTAuth struct {
	disabled bool
}

type backend struct {
	name              string
	typ               lbBackendType
	lbBackends        []lbBackend
	lbAlgorithm       lbBackendLBAlgorithm
	healthCheckConfig lbBackendHealthCheckConfig
	tcpConfig         *lbBackendTCPConfig
	tlsConfig         *lbBackendTLSConfig
	httpConfig        lbBackendHTTPConfig
	proxyProtocol     *lbBackendProxyProtocolConfig
	dnsResolverConfig *lbBackendDNSResolverConfig
}

type lbBackendType int

const (
	lbBackendTypeIP lbBackendType = iota
	lbBackendTypeHostname
)

type lbBackend struct {
	addresses    []string
	addressZones map[string]string
	port         uint32
	weight       uint32
	status       lbBackendStatus
}

type lbBackendStatus int

const (
	lbBackendStatusHealthChecking lbBackendStatus = iota
	lbBackendStatusDraining
)

type lbBackendLBAlgorithm struct {
	algorithm         lbAlgorithmType
	consistentHashing *lbBackendLBAlgorithmConsistentHashing
}

type lbBackendLBAlgorithmConsistentHashing struct {
	maglevTableSize uint32
}

type lbAlgorithmType int

const (
	lbAlgorithmRoundRobin lbAlgorithmType = iota
	lbAlgorithmLeastRequest
	lbAlgorithmConsistentHashing
)

type lbBackendHealthCheckConfig struct {
	http                         *lbBackendHealthCheckHTTPConfig
	tcp                          *lbBackendHealthCheckTCPConfig
	tlsConfig                    *lbBackendTLSConfig
	intervalSeconds              int
	timeoutSeconds               int
	healthyThreshold             int
	unhealthyThreshold           int
	unhealthyEdgeIntervalSeconds int
	unhealthyIntervalSeconds     int
	port                         uint32
}

type lbBackendHealthCheckHTTPConfig struct {
	host               string
	path               string
	method             lbBackendHealthCheckHTTPMethod
	healthyStatusCodes []lbBackendHealthCheckHTTPStatusRange
	send               *lbBackendHealthCheckPayload
	receive            []*lbBackendHealthCheckPayload
}

type lbBackendHealthCheckPayload struct {
	text *string
}

type lbBackendHealthCheckHTTPMethod int

const (
	lbBackendHealthCheckHTTPMethodGet lbBackendHealthCheckHTTPMethod = iota
	lbBackendHealthCheckHTTPMethodHead
	lbBackendHealthCheckHTTPMethodPost
	lbBackendHealthCheckHTTPMethodPut
	lbBackendHealthCheckHTTPMethodDelete
	lbBackendHealthCheckHTTPMethodConnect
	lbBackendHealthCheckHTTPMethodOptions
	lbBackendHealthCheckHTTPMethodTrace
	lbBackendHealthCheckHTTPMethodPatch
)

type lbBackendHealthCheckHTTPStatusRange struct {
	start uint
	end   uint
}

type lbBackendHealthCheckTCPConfig struct {
	send    *lbBackendHealthCheckPayload
	receive []*lbBackendHealthCheckPayload
}

type lbBackendTCPConfig struct {
	connectTimeoutSeconds int32
}

type lbBackendTLSConfig struct {
	minTLSVersion              string
	maxTLSVersion              string
	allowedCipherSuites        []string
	allowedECDHCurves          []string
	allowedSignatureAlgorithms []string
}

const (
	proxyProtocolVersionV1 = 1
	proxyProtocolVersionV2 = 2
)

type lbBackendProxyProtocolConfig struct {
	version         int
	passthroughTLVs []uint32
}

type lbBackendHTTPConfig struct {
	enableHTTP11 bool
	enableHTTP2  bool
}

type lbBackendDNSResolverConfig struct {
	resolvers []lbBackendDNSResolver
}

type lbBackendDNSResolver struct {
	ip   string
	port uint32
}

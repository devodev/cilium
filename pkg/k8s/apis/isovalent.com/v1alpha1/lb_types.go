// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbservice",path="lbservices",scope="Namespaced",shortName={lbsvc}
// +kubebuilder:printcolumn:JSONPath=".spec.vipRef.name",name="VIP Reference",type=string
// +kubebuilder:printcolumn:JSONPath=".status.addresses.ipv4",name="VIP IPv4",type=string
// +kubebuilder:printcolumn:JSONPath=".status.addresses.ipv6",name="VIP IPv6",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.port",name="Port",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.trafficPolicy.zoneAware.mode",name="Zone Aware",type=string
// +kubebuilder:printcolumn:JSONPath=".status.status",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LBService defines a Service frontend of the Isovalent Load Balancer.
// It's assigned to a LBVIP and and load balances traffic to one or multiple
// LBBackendPool's.
type LBService struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec LBServiceSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status LBServiceStatus `json:"status,omitempty"`
}

type LBServiceSpec struct {
	// The reference to the LBVIP resource that the LBService should be
	// associated with. The referred LBVIP must exist in the same namespace
	// as the service. Multiple LBServices can refer to the same LBVIP to
	// share the same VIP, but the port must be different.
	//
	// +kubebuilder:validation:Required
	VIPRef LBServiceVIPRef `json:"vipRef"`

	// The port that this service should listen on.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Enable PROXY protocol on this service. It can be enabled together
	// with TLS. If unspecified, PROXY protocol will be disabled.
	//
	// +kubebuilder:validation:Optional
	ProxyProtocolConfig *LBServiceProxyProtocolConfig `json:"proxyProtocolConfig,omitempty"`

	// Enable gRPC access logging for this service. When the global
	// gRPC access logging is enabled, this field can be used to
	// disable gRPC access logging for this specific service.
	// If unspecified, the global setting is used.
	//
	// +kubebuilder:validation:Optional
	EnableGRPCAccessLogs *bool `json:"enableGRPCAccessLogs,omitempty"`

	// The configuration for the applications that running on the port.
	// While the name is plural, only one application can be specified
	// currently.
	//
	// +kubebuilder:validation:Required
	Applications LBServiceApplications `json:"applications"`

	// The configuration for traffic policy behavior, such as zone-aware
	// routing. If unspecified, traffic policy will be disabled.
	//
	// +kubebuilder:validation:Optional
	TrafficPolicy *LBTrafficPolicy `json:"trafficPolicy,omitempty"`
}

func (r LBServiceSpec) ConfiguresTCPT1OnlyOrAuto() bool {
	return r.Applications.TCPProxy != nil &&
		(r.Applications.TCPProxy.ForceDeploymentMode == nil ||
			slices.Contains([]LBTCPProxyForceDeploymentModeType{LBTCPProxyForceDeploymentModeAuto, LBTCPProxyForceDeploymentModeT1}, *r.Applications.TCPProxy.ForceDeploymentMode))
}

func (r LBServiceSpec) ConfiguresUDPT1OnlyOrAuto() bool {
	return r.Applications.UDPProxy != nil &&
		(r.Applications.UDPProxy.ForceDeploymentMode == nil ||
			slices.Contains([]LBUDPProxyForceDeploymentModeType{LBUDPProxyForceDeploymentModeAuto, LBUDPProxyForceDeploymentModeT1}, *r.Applications.UDPProxy.ForceDeploymentMode))
}

type LBServiceProxyProtocolConfig struct {
	// The list of versions of the PROXY protocol, which will be rejected.
	// If not specified, all versions are allowed.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	DisallowedVersions []LBProxyProtocolVersion `json:"disallowedVersions,omitempty"`

	// This config controls which TLVs can be passed to filter state if it is Proxy Protocol
	// V2 header. If there is no setting for this field, no TLVs will be passed through.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	PassthroughTLVs []LBProxyProtocolTLV `json:"passthroughTLVs,omitempty"`
}

type LBServiceApplications struct {
	// Defining this stanza enables HTTPProxy application that proxies the
	// HTTP traffic to the backends over TCP connection.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	HTTPProxy *LBServiceApplicationHTTPProxy `json:"httpProxy,omitempty"`

	// Defining this stanza enables HTTPSProxy application that proxies the
	// HTTPS traffic to the backends over TLS and TCP connections.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	HTTPSProxy *LBServiceApplicationHTTPSProxy `json:"httpsProxy,omitempty"`

	// Defining this stanza enables TLSPassthrough application that proxies
	// the TLS traffic without terminating the TLS connection.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	TLSPassthrough *LBServiceApplicationTLSPassthrough `json:"tlsPassthrough,omitempty"`

	// Defining this stanza enables TLSProxy application that proxies the
	// TLS traffic to the backends by terminating the TLS.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	TLSProxy *LBServiceApplicationTLSProxy `json:"tlsProxy,omitempty"`

	// Defining this stanza enables TCPProxy application that proxies the
	// TCP traffic to the backends by terminating the TCP.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	TCPProxy *LBServiceApplicationTCPProxy `json:"tcpProxy,omitempty"`

	// Defining this stanza enables UDPProxy application that proxies the
	// UDP traffic to the backends by terminating the UDP.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	UDPProxy *LBServiceApplicationUDPProxy `json:"udpProxy,omitempty"`
}

// +kubebuilder:validation:XValidation:message="Application-wide and per-route auth type must be matched",rule="!has(self.auth) || (has(self.auth.basic) && self.routes.all(r, !has(r.auth) || has(r.auth.basic))) || (has(self.auth.jwt)   && self.routes.all(r, !has(r.auth) || has(r.auth.jwt)))"
type LBServiceApplicationHTTPProxy struct {
	// The application-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBServiceHTTPConfig `json:"httpConfig,omitempty"`

	// The optional connection filtering configuration for all HTTP connections.
	// It defines the connection attributes that should be obtained to decide
	// whether connections should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	ConnectionFiltering *LBServiceHTTPConnectionFiltering `json:"connectionFiltering,omitempty"`

	// Optional global rate limit configuration for the HTTP proxy application.
	// Currently, this is only a local rate limit (enforced on each LB node individually).
	//
	// +kubebuilder:validation:Optional
	RateLimits *LBServiceHTTPRateLimits `json:"rateLimits,omitempty"`

	// Optional HTTP authN/authZ configuration for the HTTP proxy application.
	//
	// +kubebuilder:validation:Optional
	Auth *LBServiceHTTPAuth `json:"auth,omitempty"`

	// The HTTP routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceHTTPRoute `json:"routes"`
}

// +kubebuilder:validation:XValidation:message="Application-wide and per-route auth type must be matched",rule="!has(self.auth) || (has(self.auth.basic) && self.routes.all(r, !has(r.auth) || has(r.auth.basic))) || (has(self.auth.jwt)   && self.routes.all(r, !has(r.auth) || has(r.auth.jwt)))"
type LBServiceApplicationHTTPSProxy struct {
	// The application-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBServiceHTTPConfig `json:"httpConfig,omitempty"`

	// The application-wide TLS configuration.
	//
	// +kubebuilder:validation:Required
	TLSConfig LBServiceTLSConfig `json:"tlsConfig"`

	// The optional connection filtering configuration for all HTTPS connections.
	// It defines the connection attributes that should be obtained to decide
	// whether connections should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	ConnectionFiltering *LBServiceHTTPConnectionFiltering `json:"connectionFiltering,omitempty"`

	// Optional global rate limit configuration for the HTTPS proxy application.
	// Currently, this is only a local rate limit (enforced on each LB node individually).
	//
	// +kubebuilder:validation:Optional
	RateLimits *LBServiceHTTPRateLimits `json:"rateLimits,omitempty"`

	// Optional HTTP authN/authZ configuration for the HTTPS proxy application.
	//
	// +kubebuilder:validation:Optional
	Auth *LBServiceHTTPAuth `json:"auth,omitempty"`

	// The HTTP routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceHTTPSRoute `json:"routes"`
}

type LBServiceHTTPConfig struct {
	// Setting this to true enables HTTP/1.1.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	EnableHTTP11 *bool `json:"enableHTTP11,omitempty"`

	// Setting this to true enables HTTP2.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	EnableHTTP2 *bool `json:"enableHTTP2,omitempty"`
}

type LBServiceHTTPAuth struct {
	// The basic authentication configuration.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	Basic *LBServiceHTTPBasicAuth `json:"basic,omitempty"`

	// The jwt authentication configuration.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	JWT *LBServiceHTTPJWTAuth `json:"jwt,omitempty"`
}

type LBServiceHTTPRouteAuth struct {
	// The per-route basic authentication configuration.
	//
	// +kubebuilder:validation:Optional
	Basic *LBServiceHTTPRouteBasicAuth `json:"basic,omitempty"`

	// The per-route JWT authentication configuration.
	//
	// +kubebuilder:validation:Optional
	JWT *LBServiceHTTPRouteJWTAuth `json:"jwt,omitempty"`
}

type LBServiceHTTPBasicAuth struct {
	// Users for the basic authentication.
	//
	// +kubebuilder:validation:Required
	Users LBServiceHTTPBasicAuthUser `json:"users"`
}

type LBServiceHTTPRouteBasicAuth struct {
	// Disables the basic authentication for this route.
	//
	// +kubebuilder:validation:Required
	Disabled bool `json:"disabled"`
}

type LBServiceHTTPJWTAuth struct {
	// The list of JWT authentication providers. At least one provider must
	// be specified.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=name
	Providers []LBServiceHTTPJWTProvider `json:"providers"`
}

type LBServiceHTTPRouteJWTAuth struct {
	// Disables the JWT authentication for this route.
	//
	// +kubebuilder:validation:Required
	Disabled bool `json:"disabled"`
}

type LBServiceHTTPJWTProvider struct {
	// The name of the provider.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// An expected issuer (iss) of the JWT. If specified, it has to match
	// the iss claim in the JWT. Otherwise, the iss field is not checked.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Issuer *string `json:"issuer,omitempty"`

	// List of expected audiences. If specified, one of the audience has to
	// match the aud claim in the JWT. Otherwise, the aud field is not
	// checked.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=8
	Audiences []string `json:"audiences,omitempty"`

	// The JWT authentication configuration.
	//
	// +kubebuilder:validation:Required
	JWKS LBServiceHTTPJWTAuthJWKS `json:"jwks"`
}

// +kubebuilder:validation:XValidation:message="Either secretRef or httpURI must be specified",rule="(has(self.secretRef)?1:0)+(has(self.httpURI)?1:0)==1"
type LBServiceHTTPJWTAuthJWKS struct {
	// The reference to the k8s Secret contains JWKS. The Secret must be an
	// Opaque Secret with "jwks" key and base64-encoded JWKS string as a
	// value.
	//
	// +kubebuilder:validation:Optional
	SecretRef *LBServiceSecretRef `json:"secretRef,omitempty"`

	// Get JWKS from remote server with HTTP.
	//
	// +kubebuilder:validation:Optional
	HTTPURI *LBServiceHTTPURI `json:"httpURI,omitempty"`
}

const (
	LBServiceJWKSSecretKey = "jwks"
)

type LBServiceHTTPURI struct {
	// The remote HTTP URI. The scheme must be http or https.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=uri
	// +kubebuilder:validation:XValidation:message="The scheme must be http or https",rule="self.startsWith('http') || self.startsWith('https')"
	URI string `json:"uri,omitempty"`
}

type LBServiceHTTPBasicAuthUser struct {
	// The reference to the k8s secret that contains the username and
	// password for the basic authentication. This must be a k8s secret of
	// type Opaque with the username as a key and the password as a value.
	// A single secret can contain multiple username-password pairs.
	//
	// +kubebuilder:validation:Required
	SecretRef LBServiceSecretRef `json:"secretRef"`
}

type LBServiceApplicationTLSPassthrough struct {
	// The TLS passthrough routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceTLSPassthroughRoute `json:"routes"`
}

type LBServiceApplicationTLSProxy struct {
	// The application-wide TLS configuration.
	//
	// +kubebuilder:validation:Required
	TLSConfig LBServiceTLSConfig `json:"tlsConfig"`

	// The TLS proxy routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceTLSRoute `json:"routes"`
}

type LBServiceTLSConfig struct {
	// The list of certificates that the service uses.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Certificates []LBServiceTLSCertificate `json:"certificates"`

	// Optional certificate verification.
	//
	// +kubebuilder:validation:Optional
	Validation *LBTLSValidationConfig `json:"validation,omitempty"`

	// Minimum TLS version.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	MinTLSVersion *LBTLSProtocolVersion `json:"minTLSVersion,omitempty"`

	// Maximum TLS version.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	MaxTLSVersion *LBTLSProtocolVersion `json:"maxTLSVersion,omitempty"`

	// Allowed TLS cipher suites.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedCipherSuites []LBTLSCipherSuite `json:"allowedCipherSuites,omitempty"`

	// Allowed ECDH Curves.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedECDHCurves []LBTLSECDHCurve `json:"allowedECDHCurves,omitempty"`

	// Allowed signature algorithms. The list is ordered by preference.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedSignatureAlgorithms []LBTLSSignatureAlgorithm `json:"allowedSignatureAlgorithms,omitempty"`
}

type LBTLSValidationConfig struct {
	// The k8s secret that contains the trusted CA in the secret data field `ca.crt`.
	//
	// +kubebuilder:validation:Required
	SecretRef LBServiceSecretRef `json:"secretRef"`

	// Allowed subject alternative names
	//
	// +kubebuilder:validation:Optional
	SubjectAlternativeNames []LBTLSValidationConfigSAN `json:"subjectAlternativeNames,omitempty"`
}

type LBTLSValidationConfigSAN struct {
	// Exact matching. The SAN must be exactly the same as the value.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Exact string `json:"exact"`
}

type LBServiceSecretRef struct {
	// The name of the K8s Secret resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// +kubebuilder:validation:XValidation:message="Force deployment mode t1-only isn't compatible with rate limits", rule="(!has(self.forceDeploymentMode) || self.forceDeploymentMode == 'auto' || self.forceDeploymentMode == 't1-t2' || self.routes.all(x, !has(x.rateLimits)) )"
type LBServiceApplicationTCPProxy struct {
	// Enforces specific implementation to be used to realize
	// TCPProxy application. This configuration should be used
	// only when there's a performance issue or bugs in the
	// implementation chosen by the default "auto" option.
	//
	// Following options are available:
	//
	// auto    : The LB controller automatically chooses the most
	//           efficient implementation for given configuration.
	//
	// t1-only : Enforces TCPProxy to be realized in T1 nodes only.
	//           If there is any LBService or LBBackendPool configuration
	//           incompatible with T1 capability, an error will be
	//           reported.
	//
	// t1-t2   : Enforces TCPProxy to be realized in T1 and T2 nodes
	//           even if it can be fully realized in T1 nodes only.
	//
	// Optional, Default: auto
	//
	// +kubebuilder:validation:Optional
	ForceDeploymentMode *LBTCPProxyForceDeploymentModeType `json:"forceDeploymentMode,omitempty"`

	// Enforces a specific forwarding mode for the "t1-only" deployed
	// TCPProxy application. This configuration should be used
	// only when the infrastructure can handle the forwarding mode,
	// for example, it can terminate DSR.
	//
	// Following options are available:
	//
	// auto : The LB controller automatically chooses the most
	//        suitable implementation for given configuration.
	//
	// snat : Enforces TCPProxy to be realized via SNAT for the
	//        T1-only LBService. This means reply traffic comes back
	//        to the load balancer for reverse translation. There
	//        are no further infrastructure requirements to handle
	//        such traffic.
	//
	// dsr  : Enforces TCPProxy to be realized via DSR for the
	//        T1-only LBService. This means reply traffic does not
	//        come back to the load balancer and the backends reply
	//        directly back to the client. This is more efficient
	//        than the "snat" option, however, the infrastructure
	//        must handle tunnel termination at the backend side
	//        for the encapsulated original request.
	//
	// Optional, Default: auto
	//
	// +kubebuilder:validation:Optional
	ForceForwardingMode *LBTCPProxyForceForwardingModeType `json:"forceForwardingMode,omitempty"`

	// The TCP proxy routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	Routes []LBServiceTCPRoute `json:"routes"`
}

type LBServiceTCPRoute struct {
	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this TCP route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceTCPRoutePersistentBackend `json:"persistentBackend,omitempty"`

	// The optional connection filtering configuration for this TCP route.
	// It defines the connection attributes that should be obtained to decide
	// whether connections should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	ConnectionFiltering *LBServiceTCPRouteConnectionFiltering `json:"connectionFiltering,omitempty"`

	// Optional per-route rate limit configuration.
	// Currently, this is only a local rate limit (enforced on each LB node individually).
	//
	// +kubebuilder:validation:Optional
	RateLimits *LBServiceTCPRouteRateLimits `json:"rateLimits,omitempty"`
}

type LBServiceTCPRoutePersistentBackend struct {
	// Whether requests from the same source IP should be sent to
	// the same backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceIP *bool `json:"sourceIP,omitempty"`
}

type LBServiceTCPRouteConnectionFiltering struct {
	// The type of the rules.
	//
	// +kubebuilder:validation:Required
	RuleType RequestFilteringRuleType `json:"ruleType"`

	// Configure the rules that should be used for the TCP route.
	// Each rule needs to define at least one property to filter on.
	// The properties of each entry are logically ANDed.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	Rules []LBServiceTCPRouteRequestFilteringRule `json:"rules,omitempty"`
}

type LBServiceTCPRouteRequestFilteringRule struct {
	// Source CIDR based matching. This allows for matching a specific or a range of IPv4 or IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceCIDR *LBServiceRequestFilteringRuleSourceCIDR `json:"sourceCIDR,omitempty"`
}

// +kubebuilder:validation:Enum=auto;t1-only;t1-t2
type LBTCPProxyForceDeploymentModeType string

const (
	LBTCPProxyForceDeploymentModeAuto LBTCPProxyForceDeploymentModeType = "auto"
	LBTCPProxyForceDeploymentModeT1   LBTCPProxyForceDeploymentModeType = "t1-only"
	LBTCPProxyForceDeploymentModeT2   LBTCPProxyForceDeploymentModeType = "t1-t2"
)

// +kubebuilder:validation:Enum=auto;snat;dsr
type LBTCPProxyForceForwardingModeType string

const (
	LBTCPProxyForceForwardingModeAuto LBTCPProxyForceForwardingModeType = "auto"
	LBTCPProxyForceForwardingModeSNAT LBTCPProxyForceForwardingModeType = "snat"
	LBTCPProxyForceForwardingModeDSR  LBTCPProxyForceForwardingModeType = "dsr"
)

type LBServiceApplicationUDPProxy struct {
	// Enforces specific implementation to be used to realize
	// UDPProxy application. This configuration should be used
	// only when there's a performance issue or bugs in the
	// implementation chosen by the default "auto" option.
	//
	// Following options are available:
	//
	// auto    : The LB controller automatically chooses the most
	//           efficient implementation for given configuration.
	//
	// t1-only : Enforces UDPProxy to be realized in T1 nodes only.
	//           If there is any LBService or LBBackendPool configuration
	//           incompatible with T1 capability, an error will be
	//           reported.
	//
	// t1-t2   : Enforces UDPProxy to be realized in T1 and T2 nodes
	//           even if it can be fully realized in T1 nodes only.
	//
	// Optional, Default: auto
	//
	// +kubebuilder:validation:Optional
	ForceDeploymentMode *LBUDPProxyForceDeploymentModeType `json:"forceDeploymentMode,omitempty"`

	// Enforces a specific forwarding mode for the "t1-only" deployed
	// UDPProxy application. This configuration should be used
	// only when the infrastructure can handle the forwarding mode,
	// for example, it can terminate DSR.
	//
	// Following options are available:
	//
	// auto : The LB controller automatically chooses the most
	//        suitable implementation for given configuration.
	//
	// snat : Enforces UDPProxy to be realized via SNAT for the
	//        T1-only LBService. This means reply traffic comes back
	//        to the load balancer for reverse translation. There
	//        are no further infrastructure requirements to handle
	//        such traffic.
	//
	// dsr  : Enforces UDPProxy to be realized via DSR for the
	//        T1-only LBService. This means reply traffic does not
	//        come back to the load balancer and the backends reply
	//        directly back to the client. This is more efficient
	//        than the "snat" option, however, the infrastructure
	//        must handle tunnel termination at the backend side
	//        for the encapsulated original request.
	//
	// Optional, Default: auto
	//
	// +kubebuilder:validation:Optional
	ForceForwardingMode *LBUDPProxyForceForwardingModeType `json:"forceForwardingMode,omitempty"`

	// The UDP proxy routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	Routes []LBServiceUDPRoute `json:"routes"`
}

type LBServiceUDPRoute struct {
	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this UDP route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceUDPRoutePersistentBackend `json:"persistentBackend,omitempty"`

	// The optional connection filtering configuration for this UDP route.
	// It defines the connection attributes that should be obtained to decide
	// whether connections should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	ConnectionFiltering *LBServiceUDPRouteConnectionFiltering `json:"connectionFiltering,omitempty"`
}

// +kubebuilder:validation:Enum=auto;t1-only;t1-t2
type LBUDPProxyForceDeploymentModeType string

const (
	LBUDPProxyForceDeploymentModeAuto LBUDPProxyForceDeploymentModeType = "auto"
	LBUDPProxyForceDeploymentModeT1   LBUDPProxyForceDeploymentModeType = "t1-only"
	LBUDPProxyForceDeploymentModeT2   LBUDPProxyForceDeploymentModeType = "t1-t2"
)

// +kubebuilder:validation:Enum=auto;snat;dsr
type LBUDPProxyForceForwardingModeType string

const (
	LBUDPProxyForceForwardingModeAuto LBUDPProxyForceForwardingModeType = "auto"
	LBUDPProxyForceForwardingModeSNAT LBUDPProxyForceForwardingModeType = "snat"
	LBUDPProxyForceForwardingModeDSR  LBUDPProxyForceForwardingModeType = "dsr"
)

type LBServiceUDPRoutePersistentBackend struct {
	// Whether requests from the same source IP should be sent to
	// the same backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceIP *bool `json:"sourceIP,omitempty"`
}

type LBServiceUDPRouteConnectionFiltering struct {
	// The type of the rules.
	//
	// +kubebuilder:validation:Required
	RuleType RequestFilteringRuleType `json:"ruleType"`

	// Configure the rules that should be used for the UDP route.
	// Each rule needs to define at least one property to filter on.
	// The properties of each entry are logically ANDed.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	Rules []LBServiceUDPRouteRequestFilteringRule `json:"rules,omitempty"`
}

type LBServiceUDPRouteRequestFilteringRule struct {
	// Source CIDR based matching. This allows for matching a specific or a range of IPv4 or IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceCIDR *LBServiceRequestFilteringRuleSourceCIDR `json:"sourceCIDR,omitempty"`
}

// +kubebuilder:validation:Enum=TLSv1_0;TLSv1_1;TLSv1_2;TLSv1_3
type LBTLSProtocolVersion string

// +kubebuilder:validation:MinLength=1
type LBTLSCipherSuite string

// +kubebuilder:validation:MinLength=1
type LBTLSECDHCurve string

// +kubebuilder:validation:MinLength=1
type LBTLSSignatureAlgorithm string

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type LBServiceHostName string

// +kubebuilder:validation:Enum=1;2
type LBProxyProtocolVersion int

const (
	LBProxyProtocolVersion1 LBProxyProtocolVersion = 1
	LBProxyProtocolVersion2 LBProxyProtocolVersion = 2
)

type LBProxyProtocolTLV int

type LBServiceTLSCertificate struct {
	// Reference to K8s secret in the same namespace that contains
	// the certificate and the private key that the service uses.
	//
	// The secret type must be kubernetes.io/tls and the
	// format must follow the spec.
	//
	// https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets
	// +kubebuilder:validation:Required
	SecretRef LBServiceSecretRef `json:"secretRef"`
}

type LBServiceHTTPRoute struct {
	// The HTTP route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBServiceHTTPRouteMatch `json:"match,omitempty"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this HTTP route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceHTTPRoutePersistentBackend `json:"persistentBackend,omitempty"`

	// The optional request filtering configuration for this HTTP route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	RequestFiltering *LBServiceHTTPRouteRequestFiltering `json:"requestFiltering,omitempty"`

	// Optional per-route rate limit configuration.
	// Currently, this is only a local rate limit (enforced on each LB node individually).
	//
	// +kubebuilder:validation:Optional
	RateLimits *LBServiceHTTPRouteRateLimits `json:"rateLimits,omitempty"`

	// Optional per-route authN/authZ configuration.
	//
	// +kubebuilder:validation:Optional
	Auth *LBServiceHTTPRouteAuth `json:"auth,omitempty"`
}

type LBServiceHTTPSRoute struct {
	// The HTTP route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBServiceHTTPRouteMatch `json:"match,omitempty"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this HTTP route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceHTTPRoutePersistentBackend `json:"persistentBackend,omitempty"`

	// The optional request filtering configuration for this HTTP route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	RequestFiltering *LBServiceHTTPSRouteRequestFiltering `json:"requestFiltering,omitempty"`

	// Optional per-route rate limit configuration.
	// Currently, this is only a local rate limit (enforced on each LB node individually).
	//
	// +kubebuilder:validation:Optional
	RateLimits *LBServiceHTTPRouteRateLimits `json:"rateLimits,omitempty"`

	// Optional per-route authN/authZ configuration.
	//
	// +kubebuilder:validation:Optional
	Auth *LBServiceHTTPRouteAuth `json:"auth,omitempty"`
}

type LBServiceHTTPRoutePersistentBackend struct {
	// Whether requests from the same source IP should be sent to
	// the same backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceIP *bool `json:"sourceIP,omitempty"`

	// List of cookies for which requests are sent to the same backend if they match.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Cookies []LBServiceHTTPRoutePersistentBackendCookie `json:"cookies,omitempty"`

	// List of headers for which requests are sent to the same backend if they match.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Headers []LBServiceHTTPRoutePersistentBackendHeader `json:"headers,omitempty"`
}

type LBServiceHTTPRoutePersistentBackendCookie struct {
	// The name of the cookie that will be used to obtain the hash key.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type LBServiceHTTPRoutePersistentBackendHeader struct {
	// The name of the header that will be used to obtain the hash key.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// +kubebuilder:validation:Enum=Allow;Deny
type RequestFilteringRuleType string

const (
	// Allow rules
	RequestFilteringRuleTypeAllow RequestFilteringRuleType = "Allow"
	// Deny rules
	RequestFilteringRuleTypeDeny RequestFilteringRuleType = "Deny"
)

type LBServiceHTTPConnectionFiltering struct {
	// The type of the rules.
	//
	// +kubebuilder:validation:Required
	RuleType RequestFilteringRuleType `json:"ruleType"`

	// Configure the rules that should be used for the HTTP application.
	// Each rule needs to define at least one property to filter on.
	// The properties of each entry are logically ANDed.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	Rules []LBServiceHTTPConnectionFilteringRule `json:"rules,omitempty"`
}

type LBServiceHTTPConnectionFilteringRule struct {
	// Source CIDR based matching. This allows for matching a specific or a range of IPv4 or IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceCIDR *LBServiceRequestFilteringRuleSourceCIDR `json:"sourceCIDR,omitempty"`
}

type LBServiceHTTPRouteRequestFiltering struct {
	// The type of the rules.
	//
	// +kubebuilder:validation:Required
	RuleType RequestFilteringRuleType `json:"ruleType"`

	// Configure the rules that should be used for the HTTP route.
	// Each rule needs to define at least one property to filter on.
	// The properties of each entry are logically ANDed.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	Rules []LBServiceHTTPRouteRequestFilteringRule `json:"rules,omitempty"`
}

type LBServiceHTTPSRouteRequestFiltering struct {
	// The type of the rules.
	//
	// +kubebuilder:validation:Required
	RuleType RequestFilteringRuleType `json:"ruleType"`

	// Configure the rules that should be used for the HTTP route.
	// Each rule needs to define at least one property to filter on.
	// The properties of each entry are logically ANDed.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	Rules []LBServiceHTTPSRouteRequestFilteringRule `json:"rules,omitempty"`
}

type LBServiceHTTPRateLimits struct {
	// Rate limiting on connection basis.
	// It is applied and enforced when the connection is established.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Connections *LBServiceRateLimit `json:"connections"`
}

type LBServiceHTTPRouteRateLimits struct {
	// Configure max allowed requests for the HTTP route.
	// It is applied and enforced before routing the HTTP request.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Requests *LBServiceRateLimit `json:"requests"`
}

type LBServiceTLSRouteRateLimits struct {
	// Configure max allowed connections for the TLS route.
	// It is applied and enforced when the connection is established.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Connections *LBServiceRateLimit `json:"connections"`
}

type LBServiceTCPRouteRateLimits struct {
	// Configure max allowed connections for the TCP route.
	// It is applied and enforced when the connection is established.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Connections *LBServiceRateLimit `json:"connections"`
}

type LBServiceRateLimit struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Required
	Limit uint `json:"limit"`

	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Required
	TimePeriodSeconds uint `json:"timePeriodSeconds"`
}

type LBServiceHTTPRouteRequestFilteringRule struct {
	// Source CIDR based matching. This allows for matching a specific or a range of IPv4 or IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceCIDR *LBServiceRequestFilteringRuleSourceCIDR `json:"sourceCIDR,omitempty"`

	// Host-based matching. Only one of exact or suffix match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	HostName *LBServiceRequestFilteringRuleHTTPHostname `json:"hostName,omitempty"`

	// Path-based matching. Only one of exact or suffix match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Path *LBServiceRequestFilteringRuleHTTPPath `json:"path,omitempty"`

	// Header-based matching. Only one of exact, suffix or regex match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Headers []*LBServiceRequestFilteringRuleHTTPHeader `json:"headers,omitempty"`

	// JWT claim based matching. Only one of exact, suffix or regex match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	JWTClaims []*LBServiceRequestFilteringRuleJWTClaim `json:"jwtClaims,omitempty"`
}

type LBServiceHTTPSRouteRequestFilteringRule struct {
	// Source CIDR based matching. This allows for matching a specific or a range of IPv4 or IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceCIDR *LBServiceRequestFilteringRuleSourceCIDR `json:"sourceCIDR,omitempty"`

	// Client certificate SAN based matching. Only one of exact, suffix or regex match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	ClientCertificateSANs []*LBServiceRequestFilteringRuleClientCertificateSAN `json:"clientCertificateSANs,omitempty"`

	// Host-based matching. Only one of exact or suffix match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	HostName *LBServiceRequestFilteringRuleHTTPHostname `json:"hostName,omitempty"`

	// Path-based matching. Only one of exact or suffix match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Path *LBServiceRequestFilteringRuleHTTPPath `json:"path,omitempty"`

	// Header-based matching. Only one of exact, suffix or regex match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	Headers []*LBServiceRequestFilteringRuleHTTPHeader `json:"headers,omitempty"`

	// JWT claim based matching. Only one of exact, suffix or regex match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	JWTClaims []*LBServiceRequestFilteringRuleJWTClaim `json:"jwtClaims,omitempty"`
}

type LBServiceRequestFilteringRuleSourceCIDR struct {
	// CIDR of the source.
	// This must be in CIDR notation and use a /32 to express
	// a single host.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Format=cidr
	CIDR string `json:"cidr"`
}

type LBServiceRequestFilteringRuleHTTPHostname struct {
	// Exact matching. The hostname must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Exact *string `json:"exact,omitempty"`

	// Suffix matching. The hostname must end with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Suffix *string `json:"suffix,omitempty"`
}

type LBServiceRequestFilteringRuleHTTPPath struct {
	// Exact matching. The path must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Exact *string `json:"exact,omitempty"`

	// Prefix matching. The path must start with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Prefix *string `json:"prefix,omitempty"`
}

type LBServiceRequestFilteringRuleHTTPHeader struct {
	// Name of the header.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Value of the header.
	//
	// +kubebuilder:validation:Required
	Value LBServiceRequestFilteringRuleHTTPHeaderValue `json:"value"`
}

type LBServiceRequestFilteringRuleHTTPHeaderValue struct {
	// Exact matching. The value must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Exact *string `json:"exact,omitempty"`

	// Prefix matching. The value must start with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Prefix *string `json:"prefix,omitempty"`

	// Regex matching. The value must match the regex value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Regex *string `json:"regex,omitempty"`
}

type LBServiceRequestFilteringRuleJWTClaim struct {
	// Name of the JWT claim.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Value of the JWT claim.
	//
	// +kubebuilder:validation:Required
	Value LBServiceRequestFilteringRuleJWTClaimValue `json:"value"`
}

type LBServiceRequestFilteringRuleJWTClaimValue struct {
	// Exact matching. The value must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Exact *string `json:"exact,omitempty"`

	// Prefix matching. The value must start with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Prefix *string `json:"prefix,omitempty"`

	// Regex matching. The value must match the regex value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Regex *string `json:"regex,omitempty"`
}

// +kubebuilder:validation:XValidation:message="OID needs to be set for SAN type OTHER_NAME",rule="(self.type != 'OTHER_NAME' || has(self.oid))"
type LBServiceRequestFilteringRuleClientCertificateSAN struct {
	// Type of the SAN.
	//
	// +kubebuilder:validation:Required
	Type LBServiceRequestFilteringRuleClientCertificateSANType `json:"type"`

	// OID Value which is required if OTHER_NAME SAN type is used.
	// For example, UPN OID is 1.3.6.1.4.1.311.20.2.3
	// (Reference: http://oid-info.com/get/1.3.6.1.4.1.311.20.2.3).
	//
	// If set for SAN types other than OTHER_NAME, it will be ignored.
	// +kubebuilder:validation:Optional
	OID *string `json:"oid,omitempty"`

	// Value of the SAN.
	//
	// +kubebuilder:validation:Required
	Value LBServiceRequestFilteringRuleClientCertificateSANValue `json:"value"`
}

// +kubebuilder:validation:Enum=DNS;URI;EMAIL;IP_ADDRESS;OTHER_NAME
type LBServiceRequestFilteringRuleClientCertificateSANType string

const (
	LBServiceRequestFilteringRuleClientCertificateSANTypeDNS       LBServiceRequestFilteringRuleClientCertificateSANType = "DNS"
	LBServiceRequestFilteringRuleClientCertificateSANTypeURI       LBServiceRequestFilteringRuleClientCertificateSANType = "URI"
	LBServiceRequestFilteringRuleClientCertificateSANTypeEMAIL     LBServiceRequestFilteringRuleClientCertificateSANType = "EMAIL"
	LBServiceRequestFilteringRuleClientCertificateSANTypeIPADDRESS LBServiceRequestFilteringRuleClientCertificateSANType = "IP_ADDRESS"
	LBServiceRequestFilteringRuleClientCertificateSANTypeOTHERNAME LBServiceRequestFilteringRuleClientCertificateSANType = "OTHER_NAME"
)

type LBServiceRequestFilteringRuleClientCertificateSANValue struct {
	// Exact matching. The value must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Exact *string `json:"exact,omitempty"`

	// Prefix matching. The value must start with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Prefix *string `json:"prefix,omitempty"`

	// Regex matching. The value must match the regex value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Regex *string `json:"regex,omitempty"`
}

type LBServiceHTTPRouteMatch struct {
	// The list of host names that the route should match. The host name is
	// the value of the Host header in the HTTP request for plain-text
	// HTTP. When TLS is enabled, the host name must match both the SNI and
	// the Host header. The following formats are supported:
	//
	// - Exact domain names: www.example.com
	// - Suffix domain wildcards: *.example.com
	// - Special wildcard: * matching any domain
	//
	// Omitting this field is identical to specifying a wildcard "*".
	//
	// +kubebuilder:validation:Optional
	HostNames []LBServiceHostName `json:"hostNames,omitempty"`

	// The path matching criteria. When omitted, the route matches all
	// paths.
	//
	// +kubebuilder:validation:Optional
	Path *LBServiceHTTPPath `json:"path,omitempty"`
}

type LBServiceHTTPPath struct {
	// Exact matching. The path must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Exact *string `json:"exact,omitempty"`

	// Prefix matching. The path must start with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Prefix *string `json:"prefix,omitempty"`
}

type LBServiceTLSPassthroughRoute struct {
	// The TLS route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBServiceTLSPassthroughRouteMatch `json:"match"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this TLS passthrough route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceTLSRoutePersistentBackend `json:"persistentBackend,omitempty"`

	// The optional connection filtering configuration for this TLS passthrough route.
	// It defines the connection attributes that should be obtained to decide
	// whether connections should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	ConnectionFiltering *LBServiceTLSRouteConnectionFiltering `json:"connectionFiltering,omitempty"`

	// Optional per-route rate limit configuration.
	// Currently, this is only a local rate limit (enforced on each LB node individually).
	//
	// +kubebuilder:validation:Optional
	RateLimits *LBServiceTLSRouteRateLimits `json:"rateLimits,omitempty"`
}

type LBServiceTLSRoute struct {
	// The TLS route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBServiceTLSRouteMatch `json:"match"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this TLS proxy route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceTLSRoutePersistentBackend `json:"persistentBackend,omitempty"`

	// The optional connection filtering configuration for this TLS proxy route.
	// It defines the connection attributes that should be obtained to decide
	// whether connections should be denied or allowed.
	//
	// +kubebuilder:validation:Optional
	ConnectionFiltering *LBServiceTLSRouteConnectionFiltering `json:"connectionFiltering,omitempty"`

	// Optional per-route rate limit configuration.
	// Currently, this is only a local rate limit (enforced on each LB node individually).
	//
	// +kubebuilder:validation:Optional
	RateLimits *LBServiceTLSRouteRateLimits `json:"rateLimits,omitempty"`
}

type LBServiceTLSPassthroughRouteMatch struct {
	// The list of host names that the route should match. The host name
	// must match the SNI. The following formats are supported:
	//
	// - Exact domain names: www.example.com
	// - Suffix domain wildcards: *.example.com
	// - Special wildcard: * matching any domain
	//
	// Omitting this field is identical to specifying a wildcard "*".
	//
	// +kubebuilder:validation:Optional
	HostNames []LBServiceHostName `json:"hostNames,omitempty"`
}

type LBServiceTLSRouteMatch struct {
	// The list of host names that the route should match. The host name
	// must match the SNI. The following formats are supported:
	//
	// - Exact domain names: www.example.com
	// - Suffix domain wildcards: *.example.com
	// - Special wildcard: * matching any domain
	//
	// Omitting this field is identical to specifying a wildcard "*".
	//
	// +kubebuilder:validation:Optional
	HostNames []LBServiceHostName `json:"hostNames,omitempty"`
}

type LBServiceTLSRoutePersistentBackend struct {
	// Whether requests from the same source IP should be sent to
	// the same backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceIP *bool `json:"sourceIP,omitempty"`
}

type LBServiceTLSRouteConnectionFiltering struct {
	// The type of the rules.
	//
	// +kubebuilder:validation:Required
	RuleType RequestFilteringRuleType `json:"ruleType"`

	// Configure the rules that should be used for the TLS route.
	// Each rule needs to define at least one property to filter on.
	// The properties of each entry are logically ANDed.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	Rules []LBServiceTLSRouteRequestFilteringRule `json:"rules,omitempty"`
}

type LBServiceTLSRouteRequestFilteringRule struct {
	// Source CIDR based matching. This allows for matching a specific or a range of IPv4 or IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	SourceCIDR *LBServiceRequestFilteringRuleSourceCIDR `json:"sourceCIDR,omitempty"`

	// Client certificate SAN based matching. Only one of exact, suffix or regex match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	ClientCertificateSANs []*LBServiceRequestFilteringRuleClientCertificateSAN `json:"clientCertificateSANs,omitempty"`

	// Servername-based matching. Only one of exact or suffix match can be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	ServerName *LBServiceRequestFilteringRuleTLSServername `json:"serverName,omitempty"`
}

type LBServiceRequestFilteringRuleTLSServername struct {
	// Exact matching. The servername must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Exact *string `json:"exact,omitempty"`

	// Suffix matching. The servername must end with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:OneOf
	Suffix *string `json:"suffix,omitempty"`
}

type LBServiceVIPRef struct {
	// The name of the LBVIP resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBServiceBackendRef struct {
	// The name of the LBBackendPool resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBServiceVIPAddresses struct {
	// IPv4 VIP assigned to the LBService.
	//
	// +kubebuilder:validation:Optional
	IPv4 *string `json:"ipv4,omitempty"`

	// IPv6 VIP assigned to the LBService.
	//
	// +kubebuilder:validation:Optional
	IPv6 *string `json:"ipv6,omitempty"`
}

type LBServiceStatus struct {
	// Allocated addresses for the LBService. The value is copied from the
	// LBVIP's status that the service refers to. This field exists for
	// the cosmetic purpose of showing the VIP in the kubectl output. You
	// should use LBVIP's status field as the source of truth.
	//
	// +kubebuilder:validation:Required
	Addresses LBServiceVIPAddresses `json:"addresses"`

	// Contains additional status information for the configured applications.
	// While the name is plural, only one application can be specified
	// currently.
	//
	// +kubebuilder:validation:Required
	Applications LBServiceApplicationsStatus `json:"applications"`

	// Contains K8s services that are referenced by all referenced
	// LBBackendPools.
	//
	// +kubebuilder:validation:Optional
	K8sServiceRefs []LBBackendPoolK8sServiceRef `json:"k8sServiceRefs,omitempty"`

	// The current conditions of the LBService.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Status of the resource.
	//
	// +kubebuilder:validation:Required
	Status LBResourceStatus `json:"status"`
}

func (r LBServiceStatus) IsEvaluatedTCPT1Only() bool {
	return r.Applications.TCPProxy != nil &&
		r.Applications.TCPProxy.DeploymentMode != nil &&
		*r.Applications.TCPProxy.DeploymentMode == LBTCPProxyDeploymentModeTypeT1Only
}

func (r LBServiceStatus) IsEvaluatedUDPT1Only() bool {
	return r.Applications.UDPProxy != nil &&
		r.Applications.UDPProxy.DeploymentMode != nil &&
		*r.Applications.UDPProxy.DeploymentMode == LBUDPProxyDeploymentModeTypeT1Only
}

type LBServiceApplicationsStatus struct {
	// Status information of the TCPProxy application.
	TCPProxy *LBServiceApplicationTCPProxyStatus `json:"tcpProxy,omitempty"`

	// Status information of the UDPProxy application.
	UDPProxy *LBServiceApplicationUDPProxyStatus `json:"udpProxy,omitempty"`
}

type LBServiceApplicationTCPProxyStatus struct {
	// The applied deployment mode of the TCPProxy application.
	//
	// This depends on the configured forceDeploymentMode on the TCPProxy application.
	// This is especially important for the mode `auto` where the actual
	// deployment mode is evaluated based on other configuration / enabled
	// features.
	DeploymentMode *LBTCPProxyDeploymentModeType `json:"deploymentMode,omitempty"`

	// The applied forwarding mode of the TCPProxy application.
	//
	// This depends on the configured forceForwardingMode on the TCPProxy application.
	// This is especially important for the mode `auto` where the actual
	// forwarding mode is evaluated based on other configuration / enabled
	// features.
	ForwardingMode *LBTCPProxyForwardingModeType `json:"forwardingMode,omitempty"`
}

// +kubebuilder:validation:Enum=t1-only;t1-t2
type LBTCPProxyDeploymentModeType string

const (
	LBTCPProxyDeploymentModeTypeT1Only LBTCPProxyDeploymentModeType = "t1-only"
	LBTCPProxyDeploymentModeTypeT1T2   LBTCPProxyDeploymentModeType = "t1-t2"
)

// +kubebuilder:validation:Enum=snat;dsr
type LBTCPProxyForwardingModeType string

const (
	LBTCPProxyForwardingModeSNAT LBTCPProxyForwardingModeType = "snat"
	LBTCPProxyForwardingModeDSR  LBTCPProxyForwardingModeType = "dsr"
)

type LBServiceApplicationUDPProxyStatus struct {
	// The applied deployment mode of the UDPProxy application.
	//
	// This depends on the configured forceDeploymentMode on the UDPProxy application.
	// This is especially important for the mode `auto` where the actual
	// deployment mode is evaluated based on other configuration / enabled
	// features.
	DeploymentMode *LBUDPProxyDeploymentModeType `json:"deploymentMode,omitempty"`

	// The applied forwarding mode of the UDPProxy application.
	//
	// This depends on the configured forceForwardingMode on the UDPProxy application.
	// This is especially important for the mode `auto` where the actual
	// forwarding mode is evaluated based on other configuration / enabled
	// features.
	ForwardingMode *LBUDPProxyForwardingModeType `json:"forwardingMode,omitempty"`
}

// +kubebuilder:validation:Enum=t1-only;t1-t2
type LBUDPProxyDeploymentModeType string

const (
	LBUDPProxyDeploymentModeTypeT1Only LBUDPProxyDeploymentModeType = "t1-only"
	LBUDPProxyDeploymentModeTypeT1T2   LBUDPProxyDeploymentModeType = "t1-t2"
)

// +kubebuilder:validation:Enum=snat;dsr
type LBUDPProxyForwardingModeType string

const (
	LBUDPProxyForwardingModeSNAT LBUDPProxyForwardingModeType = "snat"
	LBUDPProxyForwardingModeDSR  LBUDPProxyForwardingModeType = "dsr"
)

const (
	ConditionTypeServiceValid       = "lb.cilium.io/ServiceValid"
	ConditionTypeIPAssigned         = "lb.cilium.io/IPAssigned"
	ConditionTypeLBDeploymentsUsed  = "lb.cilium.io/LBDeploymentsUsed"
	ConditionTypeNodesAssigned      = "lb.cilium.io/NodesAssigned"
	ConditionTypeVIPExist           = "lb.cilium.io/VIPExist"
	ConditionTypeBackendsExist      = "lb.cilium.io/BackendsExist"
	ConditionTypeBackendsCompatible = "lb.cilium.io/BackendsCompatible"
	ConditionTypeSecretsExist       = "lb.cilium.io/SecretsExist"
	ConditionTypeSecretsCompatible  = "lb.cilium.io/SecretsCompatible"
	ConditionTypeK8sServiceExist    = "lb.cilium.io/K8sServiceExist"
	ConditionTypeEPSlicesExist      = "lb.cilium.io/EndpointSliceExist"
)

const (
	ServiceValidReasonValid                 = "ServiceValid"
	ServiceValidReasonInvalidJWTAuthMissing = "ServiceInvalidJWTAuthMissing"
)

const (
	IPAssignedConditionReasonIPFailure  = "IPFailure"
	IPAssignedConditionReasonIPPending  = "IPPending"
	IPAssignedConditionReasonIPAssigned = "IPAssigned"
)

const (
	LBDeploymentUsedConditionReasonNoLBDeploymentsUsed = "NoLBDeploymentsUsed"
	LBDeploymentUsedConditionReasonLBDeploymentsUsed   = "LBDeploymentsUsed"
)

const (
	NodesAssignedConditionReasonNodesAssigned   = "NodesAssigned"
	NodesAssignedConditionReasonNoNodesAssigned = "NoNodesAssigned"
)

const (
	VIPExistConditionReasonVIPExists  = "VIPExists"
	VIPExistConditionReasonVIPMissing = "VIPMissing"
)

const (
	BackendsExistConditionReasonAllBackendsExist = "AllBackendsExist"
	BackendsExistConditionReasonMissingBackends  = "MissingBackends"
)

const (
	BackendsCompatibleConditionReasonAllBackendsCompatible = "AllBackendsCompatible"
	BackendsCompatibleConditionReasonIncompatibleBackends  = "IncompatibleBackends"
)

const (
	SecretsExistConditionReasonAllSecretsExist = "AllSecretsExist"
	SecretsExistConditionReasonMissingSecrets  = "MissingSecrets"
)

const (
	SecretsCompatibleConditionReasonAllSecretsCompatible = "AllSecretsCompatible"
	SecretsCompatibleConditionReasonIncompatibleSecrets  = "IncompatibleSecrets"
)

const (
	ConditionTypeIPAddressAllocated = "lb.cilium.io/AddressAllocated"
	ConditionTypeIPFamily           = "lb.cilium.io/IPFamily"
)

const (
	IPAddressAllocatedConditionReasonIPv4AddressNotAllocated   = "IPv4AddressNotAllocated"
	IPAddressAllocatedConditionReasonIPv6AddressNotAllocated   = "IPv6AddressNotAllocated"
	IPAddressAllocatedConditionReasonAddressAlreadyInUse       = "AddressAlreadyInUse"
	IPAddressAllocatedConditionReasonAddressNoAvailableAddress = "NoAvailableAddress"
	IPAddressAllocatedConditionReasonAddressNoPool             = "NoPool"
)

const (
	IPFamilyValid   = "IPFamilyValid"
	IPFamilyInvalid = "IPFamilyInvalid"
)

const (
	K8sServiceExistConditionReasonAllK8sServicesExist = "AllK8sServicesExist"
	K8sServiceExistConditionReasonMissingK8sServices  = "MissingK8sServices"
)

const (
	EPSlicesExistConditionReasonAllEndpointSlicesExist = "AllEndpointSlicesExist"
	EPSlicesExistConditionReasonMissingEndpointSlices  = "MissingEndpointSlices"
)

func (r *LBService) AllReferencedSecretNames() []string {
	secretNames := []string{}

	secretNames = append(secretNames, r.AllReferencedTLSCertificateSecretNames()...)
	secretNames = append(secretNames, r.AllReferencedTLSCACertValidationSecretNames()...)
	secretNames = append(secretNames, r.AllReferencedBasicAuthSecretNames()...)
	secretNames = append(secretNames, r.AllReferencedJWTAuthSecretNames()...)

	slices.Sort(secretNames)
	return slices.Compact(secretNames)
}

func (r *LBService) AllReferencedTLSCertificateSecretNames() []string {
	secretNames := []string{}

	if r.Spec.Applications.HTTPSProxy != nil {
		for _, c := range r.Spec.Applications.HTTPSProxy.TLSConfig.Certificates {
			secretNames = append(secretNames, c.SecretRef.Name)
		}
	}

	if r.Spec.Applications.TLSProxy != nil {
		for _, c := range r.Spec.Applications.TLSProxy.TLSConfig.Certificates {
			secretNames = append(secretNames, c.SecretRef.Name)
		}
	}

	slices.Sort(secretNames)
	return slices.Compact(secretNames)
}

func (r *LBService) AllReferencedTLSCACertValidationSecretNames() []string {
	secretNames := []string{}

	if r.Spec.Applications.HTTPSProxy != nil {
		if r.Spec.Applications.HTTPSProxy.TLSConfig.Validation != nil {
			secretNames = append(secretNames, r.Spec.Applications.HTTPSProxy.TLSConfig.Validation.SecretRef.Name)
		}
	}

	if r.Spec.Applications.TLSProxy != nil {
		if r.Spec.Applications.TLSProxy.TLSConfig.Validation != nil {
			secretNames = append(secretNames, r.Spec.Applications.TLSProxy.TLSConfig.Validation.SecretRef.Name)
		}
	}

	slices.Sort(secretNames)
	return slices.Compact(secretNames)
}

func (r *LBService) AllReferencedBasicAuthSecretNames() []string {
	secretNames := []string{}

	if r.Spec.Applications.HTTPProxy != nil &&
		r.Spec.Applications.HTTPProxy.Auth != nil &&
		r.Spec.Applications.HTTPProxy.Auth.Basic != nil {
		secretNames = append(secretNames, r.Spec.Applications.HTTPProxy.Auth.Basic.Users.SecretRef.Name)
	}

	if r.Spec.Applications.HTTPSProxy != nil &&
		r.Spec.Applications.HTTPSProxy.Auth != nil &&
		r.Spec.Applications.HTTPSProxy.Auth.Basic != nil {
		secretNames = append(secretNames, r.Spec.Applications.HTTPSProxy.Auth.Basic.Users.SecretRef.Name)
	}

	slices.Sort(secretNames)
	return slices.Compact(secretNames)
}

func (r *LBService) AllReferencedJWTAuthSecretNames() []string {
	secretNames := []string{}

	if r.Spec.Applications.HTTPProxy != nil &&
		r.Spec.Applications.HTTPProxy.Auth != nil &&
		r.Spec.Applications.HTTPProxy.Auth.JWT != nil {
		for _, provider := range r.Spec.Applications.HTTPProxy.Auth.JWT.Providers {
			if provider.JWKS.SecretRef == nil {
				continue
			}
			secretNames = append(secretNames, provider.JWKS.SecretRef.Name)
		}
	}

	if r.Spec.Applications.HTTPSProxy != nil &&
		r.Spec.Applications.HTTPSProxy.Auth != nil &&
		r.Spec.Applications.HTTPSProxy.Auth.JWT != nil {
		for _, provider := range r.Spec.Applications.HTTPSProxy.Auth.JWT.Providers {
			if provider.JWKS.SecretRef == nil {
				continue
			}
			secretNames = append(secretNames, provider.JWKS.SecretRef.Name)
		}
	}

	slices.Sort(secretNames)
	return slices.Compact(secretNames)
}

func (r *LBService) AllReferencedBackendNames() []string {
	backends := []string{}

	if r.Spec.Applications.HTTPProxy != nil {
		for _, lr := range r.Spec.Applications.HTTPProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if r.Spec.Applications.HTTPSProxy != nil {
		for _, lr := range r.Spec.Applications.HTTPSProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if r.Spec.Applications.TLSPassthrough != nil {
		for _, lr := range r.Spec.Applications.TLSPassthrough.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if r.Spec.Applications.TLSProxy != nil {
		for _, lr := range r.Spec.Applications.TLSProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if r.Spec.Applications.TCPProxy != nil {
		for _, lr := range r.Spec.Applications.TCPProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if r.Spec.Applications.UDPProxy != nil {
		for _, lr := range r.Spec.Applications.UDPProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}

	slices.Sort(backends)
	return slices.Compact(backends)
}

func (r *LBService) AllReferencedVIPNames() []string {
	vips := []string{}

	if r.Spec.VIPRef.Name != "" {
		vips = append(vips, r.Spec.VIPRef.Name)
	}

	slices.Sort(vips)
	return slices.Compact(vips)
}

func (r *LBService) AllReferencedK8sServiceNames() []string {
	k8sServiceNames := []string{}

	for _, s := range r.Status.K8sServiceRefs {
		k8sServiceNames = append(k8sServiceNames, s.Name)
	}

	slices.Sort(k8sServiceNames)
	return slices.Compact(k8sServiceNames)
}

func (r *LBService) UpsertStatusCondition(conditionType string, condition metav1.Condition) {
	conditionExists := false
	for i, c := range r.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				// transition -> update condition
				r.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		r.Status.Conditions = append(r.Status.Conditions, condition)
	}
}

func (r *LBService) GetStatusCondition(conditionType string) *metav1.Condition {
	for _, c := range r.Status.Conditions {
		if c.Type == conditionType {
			return &c
		}
	}
	return nil
}

func (r *LBService) UpdateResourceStatus() {
	resourceStatus := LBResourceStatusOK

	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			resourceStatus = LBResourceStatusConditionNotMet
			break
		}
	}

	r.Status.Status = resourceStatus
}

func (r *LBService) AllStatusConditionsMet() bool {
	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			return false
		}
	}

	return true
}

type LBTrafficPolicy struct {
	// The zone-aware routing configuration for this service.
	//
	// +kubebuilder:validation:Optional
	ZoneAware *LBZoneAware `json:"zoneAware,omitempty"`
}

type LBZoneAware struct {
	// Configures zone-aware routing for this service. When enabled,
	// backend selection prefers or requires endpoints in the same
	// zone as the traffic source, depending on the selected mode.
	//
	// Following options are available:
	//
	// preferSameZone : Prefer backends in the same zone, but fall back to
	//                  other zones if none are available.
	//
	// requireSameZone : Only use backends in the same zone. If no compatible
	//                  backends exist, an error will be reported.
	//
	// +kubebuilder:validation:Required
	Mode LBZoneAwareModeType `json:"mode"`

	// Sets the minimum backend count threshold for this service.
	// Defaults to 1.
	//
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	MinBackendCount uint64 `json:"minBackendCount"`
}

// +kubebuilder:validation:Enum=preferSameZone;requireSameZone
type LBZoneAwareModeType string

const (
	LBZoneAwareModePreferSameZone  LBZoneAwareModeType = "preferSameZone"
	LBZoneAwareModeRequireSameZone LBZoneAwareModeType = "requireSameZone"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBServiceList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBService `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbbackendpool",path="lbbackendpools",scope="Namespaced",shortName={lbbep}
// +kubebuilder:printcolumn:JSONPath=".spec.backendType",name="Type",type=string
// +kubebuilder:printcolumn:JSONPath=".status.status",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LBBackendPool defines a pool of backends of the Isovalent Load Balancer
// where traffic can be load balanced to.
// Backends of a pool can either be defined as IPs, hostnames or references to K8s Service's.
type LBBackendPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec LBBackendPoolSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status LBBackendPoolStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:message="Backend format must match to the backendType",rule="( (self.backendType == 'IP' && self.backends.all(b, has(b.ip))) || (self.backendType == 'Hostname' && self.backends.all(b, has(b.host))) || (self.backendType == 'K8sService' && self.backends.all(b, has(b.k8sServiceRef))) )"
// +kubebuilder:validation:XValidation:message="Exactly one of ip, host or k8sServiceRef must be specified on the backend",rule="!( (self.backends.exists(b, has(b.ip) && has(b.host))) || (self.backends.exists(b, has(b.ip) && has(b.k8sServiceRef))) || (self.backends.exists(b, has(b.host) && has(b.k8sServiceRef))) || (self.backends.exists(b, !has(b.ip) && !has(b.host) && !has(b.k8sServiceRef))) )"
// +kubebuilder:validation:XValidation:message="Custom resolver configuration is only valid when backendType is Hostname",rule="(self.backendType == 'Hostname' || !has(self.dnsResolverConfig))"
type LBBackendPoolSpec struct {
	// Type of the backends. Either IP, Hostname or K8sService.
	// If IP is specified, backends must be specified by IP address.
	// If Hostname is specified, backends must be specified by host name.
	// If K8sService is specified, backends must be specified by a reference to a K8s Service.
	//
	// For K8sService type, if a zone-aware traffic policy is enabled and
	// two in-cluster Endpoints share the same IP but are labeled with different
	// zones, the zone "unknown" will be used.
	//
	// +kubebuilder:validation:Required
	BackendType BackendType `json:"backendType"`

	// The list of backends included in the pool.
	//
	// +kubebuilder:validation:Required
	Backends []Backend `json:"backends"`

	// The custom DNS resolver configuration. Only valid when the
	// backendType is Hostname.
	//
	// +kubebuilder:validation:Optional
	DNSResolverConfig *DNSResolverConfig `json:"dnsResolverConfig,omitempty"`

	// The pool-wide health check configuration.
	//
	// +kubebuilder:validation:Required
	HealthCheck HealthCheck `json:"healthCheck"`

	// The pool-wide loadbalancing configuration.
	//
	// +kubebuilder:validation:Optional
	Loadbalancing *Loadbalancing `json:"loadbalancing,omitempty"`

	// The pool-wide TCP configuration.
	//
	// +kubebuilder:validation:Optional
	TCPConfig *LBBackendTCPConfig `json:"tcpConfig,omitempty"`

	// PROXY protocol on this backend pool.
	//
	// +kubebuilder:validation:Optional
	ProxyProtocolConfig *LBBackendPoolProxyProtocolConfig `json:"proxyProtocolConfig,omitempty"`

	// The pool-wide TLS configuration.
	//
	// +kubebuilder:validation:Optional
	TLSConfig *LBBackendTLSConfig `json:"tlsConfig,omitempty"`

	// The pool-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBBackendHTTPConfig `json:"httpConfig,omitempty"`
}

// +kubebuilder:validation:Enum=IP;Hostname;K8sService
type BackendType string

const (
	BackendTypeIP         BackendType = "IP"
	BackendTypeHostname   BackendType = "Hostname"
	BackendTypeK8sService BackendType = "K8sService"
)

type DNSResolverConfig struct {
	// DNS resolvers to use for resolving host names. At least one resolver
	// must be specified. When specified, the LB uses the specified
	// resolvers and the default system resolvers are not used.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=ip
	// +listMapKey=port
	Resolvers []DNSResolver `json:"resolvers"`
}

type DNSResolver struct {
	// The IP address of the DNS resolver.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ip
	IP string `json:"ip"`

	// The port of the DNS resolver.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port uint32 `json:"port,omitempty"`
}

type LBBackendTCPConfig struct {
	// The connect timeout for the connections.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	ConnectTimeoutSeconds *int32 `json:"connectTimeoutSeconds,omitempty"`
}

type LBBackendTLSConfig struct {
	// Minimum TLS version.
	//
	// +kubebuilder:validation:Optional
	MinTLSVersion *LBTLSProtocolVersion `json:"minTLSVersion,omitempty"`

	// Maximum TLS version.
	//
	// +kubebuilder:validation:Optional
	MaxTLSVersion *LBTLSProtocolVersion `json:"maxTLSVersion,omitempty"`

	// Allowed TLS cipher suites.
	//
	// +kubebuilder:validation:Optional
	AllowedCipherSuites []LBTLSCipherSuite `json:"allowedCipherSuites,omitempty"`

	// Allowed ECDH Curves.
	//
	// +kubebuilder:validation:Optional
	AllowedECDHCurves []LBTLSECDHCurve `json:"allowedECDHCurves,omitempty"`

	// Allowed signature algorithms. The list is ordered by preference.
	//
	// +kubebuilder:validation:Optional
	AllowedSignatureAlgorithms []LBTLSSignatureAlgorithm `json:"allowedSignatureAlgorithms,omitempty"`
}

type LBBackendPoolProxyProtocolConfig struct {
	// The version of the PROXY protocol (e.g. 1 or 2)
	// +kubebuilder:validation:Required
	Version LBProxyProtocolVersion `json:"version,omitempty"`

	// The list of TLVs to be passed through.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	PassthroughTLVs []LBProxyProtocolTLV `json:"passthroughTLVs,omitempty"`
}

type LBBackendHTTPConfig struct {
	// Setting this to true enables HTTP/1.1.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP11 *bool `json:"enableHTTP11,omitempty"`

	// Setting this to true enables HTTP2.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP2 *bool `json:"enableHTTP2,omitempty"`
}

type Backend struct {
	// The IP address of the backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ip
	IP *string `json:"ip,omitempty"`

	// The hostname of the backend. It must be a valid hostname.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=hostname
	Host *string `json:"host,omitempty"`

	// The reference to the K8s Service resource that should act as backend.
	// The referred K8s Service must exist in the same namespace
	// as the LBBackendPool.
	//
	// +kubebuilder:validation:Optional
	K8sServiceRef *LBBackendPoolK8sServiceRef `json:"k8sServiceRef,omitempty"`

	// The port that the backend listens on.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// The weight of that backend. Used by loadbalancing algorithms.
	//
	// The weight for a backend is divided by the sum
	// of the weights of all backends in the backendpool
	// to produce a percentage of traffic for the backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	Weight *uint32 `json:"weight,omitempty"`

	// The zone of the backend used for zone-aware routing decisions.
	// Needs to be configured if the referencing LBService configures
	// zone-awareness. If backend is in-cluster, it will be ignored.
	//
	// +kubebuilder:validation:Optional
	Zone *string `json:"zone,omitempty"`

	// The status of that backend.
	//
	// If not defined, active health checking is used to determione the
	// status of the backend.
	//
	// +kubebuilder:validation:Optional
	Status *BackendStatus `json:"status,omitempty"`
}

type LBBackendPoolK8sServiceRef struct {
	// The name of the K8s Service resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// +kubebuilder:validation:Enum=Draining
type BackendStatus string

const (
	// Connection draining in progress. Existing connections remain open until terminated
	BackendStatusDraining BackendStatus = "Draining"
)

type HealthCheck struct {
	// The interval between health check probes.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=1
	IntervalSeconds *int32 `json:"intervalSeconds,omitempty"`

	// The timeout for each health check probe.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// The number of consecutive successful health check probes required
	// before considering the backend healthy.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	HealthyThreshold *int32 `json:"healthyThreshold,omitempty"`

	// The number of consecutive failed health check probes required before
	// considering the backend unhealthy.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	UnhealthyThreshold *int32 `json:"unhealthyThreshold,omitempty"`

	// The health check TLS configuration.
	//
	// If not defined, no TLS is used for health checking.
	//
	// +kubebuilder:validation:Optional
	TLSConfig *LBBackendTLSConfig `json:"tlsConfig,omitempty"`

	// The HTTP health check configuration. Exactly one of http or tcp must
	// be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	HTTP *HealthCheckHTTP `json:"http,omitempty"`

	// The TCP health check configuration. Exactly one of http or tcp must
	// be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	TCP *HealthCheckTCP `json:"tcp,omitempty"`

	// The port to use in the health checking probe. When
	// omitted, the probe uses the port that the backend listens on.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`
}

func (r *HealthCheck) ConfiguresPayload() bool {
	if (r.HTTP != nil && (r.HTTP.Send != nil || len(r.HTTP.Receive) > 0)) ||
		(r.TCP != nil && (r.TCP.Send != nil || len(r.TCP.Receive) > 0)) {
		return true
	}

	return false
}

func (r *HealthCheck) ConfiguresHTTPMethodOrStatusCodes() bool {
	if r.HTTP != nil && (len(r.HTTP.HealthyStatusCodes) > 0 || (r.HTTP.Method != nil && *r.HTTP.Method != HealthCheckHTTPMethodGet)) {
		return true
	}

	return false
}

type HealthCheckHTTP struct {
	// The host name to use in the HTTP health checking probe. When
	// omitted, the probe uses "lb".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=lb
	// +kubebuilder:validation:MinLength=1
	Host *string `json:"host,omitempty"`

	// The path to use in the HTTP health checking probe. When omitted, the
	// probe uses "/healthz".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=/healthz
	// +kubebuilder:validation:MinLength=1
	Path *string `json:"path,omitempty"`

	// The method to use in the HTTP health checking probe. When omitted, the
	// probe uses "GET".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=GET
	Method *HealthCheckHTTPMethod `json:"method,omitempty"`

	// The list of healthy status code ranges to use in the HTTP health checking probe. When omitted, the
	// probe uses "200" (OK).
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	HealthyStatusCodes []*HealthCheckHTTPStatusRange `json:"healthyStatusCodes,omitempty"`

	// Send configures HTTP specific payload to use in the HTTP health checking probe.
	// If specified, the method should support a request body (POST, PUT, PATCH, etc.).
	//
	// +kubebuilder:validation:Optional
	Send *HealthCheckPayload `json:"send,omitempty"`

	// Expected payloads to match when checking the response in the HTTP health checking probe.
	//
	// +kubebuilder:validation:Optional
	Receive []*HealthCheckPayload `json:"receive,omitempty"`
}

type HealthCheckPayload struct {
	// Text contains the hex encoded payload.
	//
	// +kubebuilder:validation:OneOf
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Text *string `json:"text,omitempty"`
}

// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;DELETE;CONNECT;OPTIONS;TRACE;PATCH
type HealthCheckHTTPMethod string

const (
	HealthCheckHTTPMethodGet     HealthCheckHTTPMethod = "GET"
	HealthCheckHTTPMethodHead    HealthCheckHTTPMethod = "HEAD"
	HealthCheckHTTPMethodPost    HealthCheckHTTPMethod = "POST"
	HealthCheckHTTPMethodPut     HealthCheckHTTPMethod = "PUT"
	HealthCheckHTTPMethodDelete  HealthCheckHTTPMethod = "DELETE"
	HealthCheckHTTPMethodConnect HealthCheckHTTPMethod = "CONNECT"
	HealthCheckHTTPMethodOptions HealthCheckHTTPMethod = "OPTIONS"
	HealthCheckHTTPMethodTrace   HealthCheckHTTPMethod = "TRACE"
	HealthCheckHTTPMethodPatch   HealthCheckHTTPMethod = "PATCH"
)

type HealthCheckHTTPStatusRange struct {
	// Start of the range (inclusive)
	//
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=600
	Start uint `json:"start"`

	// End of the range (exclusive)
	//
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=600
	End uint `json:"end"`
}

// +kubebuilder:validation:XValidation:message="Receive must be configured if send is defined.",rule="!has(self.send) || has(self.receive)"
type HealthCheckTCP struct {
	// Send configures TCP specific payload to use in the TCP health checking probe.
	// Note: Only works if receive (response payload validation) is configured too.
	//
	// +kubebuilder:validation:Optional
	Send *HealthCheckPayload `json:"send,omitempty"`

	// Expected payloads to match when checking the response in the TCP health checking probe.
	//
	// +kubebuilder:validation:Optional
	Receive []*HealthCheckPayload `json:"receive,omitempty"`
}

type Loadbalancing struct {
	// LB algorithm configuration.
	//
	// +kubebuilder:validation:Required
	Algorithm LoadbalancingAlgorithm `json:"algorithm"`
}

type LoadbalancingAlgorithm struct {
	// The round robin algorithm configuration. Exactly one of roundRobin, leastRequest or consistentHashing must be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	RoundRobin *LoadbalancingAlgorithmRoundRobin `json:"roundRobin,omitempty"`

	// The least request algorithm configuration. Exactly one of roundRobin, leastRequest or consistentHashing must be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	LeastRequest *LoadbalancingAlgorithmLeastRequest `json:"leastRequest,omitempty"`

	// The consistent hashing algorithm configuration. Exactly one of roundRobin, leastRequest or consistentHashing must be specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	ConsistentHashing *LoadbalancingAlgorithmConsistentHashing `json:"consistentHashing,omitempty"`
}

type LoadbalancingAlgorithmRoundRobin struct{}

type LoadbalancingAlgorithmLeastRequest struct{}

type LoadbalancingAlgorithmConsistentHashing struct {
	// Consistent hashing algorithm configuration.
	//
	// +kubebuilder:validation:Optional
	Algorithm *LoadbalancingConsistentHashingAlgorithm `json:"algorithm,omitempty"`
}

type LoadbalancingConsistentHashingAlgorithm struct {
	// The maglev configuration.
	//
	// +kubebuilder:validation:Required
	Maglev LoadbalancingConsistentHashingAlgorithmMaglev `json:"maglev"`
}

type LoadbalancingConsistentHashingAlgorithmMaglev struct {
	// The table size for Maglev hashing. Maglev aims for "minimal disruption" rather than an absolute guarantee.
	// Minimal disruption means that when the set of upstream hosts change, a connection will likely be sent to the same
	// upstream as it was before. Increasing the table size reduces the amount of disruption.
	// The table size must be prime number limited to 5000011. If it is not specified, the default is 65537.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=5000011
	TableSize *uint32 `json:"tableSize"`
}

type LBBackendPoolStatus struct {
	// The current conditions of the LBBackendPool.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Status of the resource.
	//
	// +kubebuilder:validation:Required
	Status LBResourceStatus `json:"status"`
}

const (
	ConditionTypeBackendAccepted = "lb.cilium.io/Accepted"
)

const (
	BackendAcceptedConditionReasonValid   = "Valid"
	BackendAcceptedConditionReasonInvalid = "Invalid"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBBackendPoolList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBBackendPool `json:"items"`
}

func (r *LBBackendPool) AllReferencedK8sServiceNames() []string {
	k8sServices := []string{}

	if r.Spec.BackendType != BackendTypeK8sService {
		return k8sServices
	}

	for _, b := range r.Spec.Backends {
		if b.K8sServiceRef != nil && b.K8sServiceRef.Name != "" {
			k8sServices = append(k8sServices, b.K8sServiceRef.Name)
		}
	}

	slices.Sort(k8sServices)
	return slices.Compact(k8sServices)
}

func (r *LBBackendPool) UpsertStatusCondition(conditionType string, condition metav1.Condition) {
	conditionExists := false
	for i, c := range r.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				// transition -> update condition
				r.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		r.Status.Conditions = append(r.Status.Conditions, condition)
	}
}

func (r *LBBackendPool) GetStatusCondition(conditionType string) *metav1.Condition {
	for _, c := range r.Status.Conditions {
		if c.Type == conditionType {
			return &c
		}
	}
	return nil
}

func (r *LBBackendPool) UpdateResourceStatus() {
	resourceStatus := LBResourceStatusOK

	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			resourceStatus = LBResourceStatusConditionNotMet
			break
		}
	}

	r.Status.Status = resourceStatus
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbvip",path="lbvips",scope="Namespaced",shortName={lbvip}
// +kubebuilder:printcolumn:JSONPath=".status.addresses.ipv4",name="IPv4",type=string
// +kubebuilder:printcolumn:JSONPath=".status.addresses.ipv6",name="IPv6",type=string
// +kubebuilder:printcolumn:JSONPath=".status.status",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LBVIP defines a virtual IP of the Isovalent Load Balancer.
// Multiple LBService's with different ports can reference it.
type LBVIP struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec LBVIPSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status LBVIPStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:message="For addressFamily dual only no or all (IPv4 & IPv6) IPs can be requested",rule="!has(self.addressFamily) || self.addressFamily != 'dual' || (has(self.ipv4Request) == has(self.ipv6Request))"
// +kubebuilder:validation:XValidation:message="IPv4 can only be requested for addressFamily ipv4 or dual",rule="!has(self.ipv4Request) || (!has(self.addressFamily) || self.addressFamily == 'dual' || self.addressFamily == 'ipv4')"
// +kubebuilder:validation:XValidation:message="IPv6 can only be requested for addressFamily ipv6 or dual",rule="!has(self.ipv6Request) || (has(self.addressFamily) && (self.addressFamily == 'dual' || self.addressFamily == 'ipv6'))"
type LBVIPSpec struct {
	// AddressFamily defines the IP address families that should be handled by this VIP.
	// For address family 'dual' an IP pool with free IPs for IPv4 and IPv6 must be configured.
	//
	// If not defined, the default is ipv4.
	//
	// +kubebuilder:validation:Optional
	AddressFamily *AddressFamily `json:"addressFamily,omitempty"`

	// Desired IPv4 VIP. If the address is unspecified, and the address
	// family is IPv4 or Dual, then it tries to allocate available VIP from
	// the pool. If address is specified, it tries to allocate specified
	// VIP from the pool.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	IPv4Request *string `json:"ipv4Request,omitempty"`

	// Desired IPv6 VIP. If the address is unspecified, and the address
	// family is IPv6 or Dual, then it tries to allocate available VIP from
	// the pool. If address is specified, it tries to allocate specified
	// VIP from the pool.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv6
	IPv6Request *string `json:"ipv6Request,omitempty"`
}

// +kubebuilder:validation:Enum=ipv4;ipv6;dual
type AddressFamily string

const (
	AddressFamilyIPv4 AddressFamily = "ipv4"
	AddressFamilyIPv6 AddressFamily = "ipv6"
	AddressFamilyDual AddressFamily = "dual"
)

type LBVIPStatus struct {
	// The current conditions of the LBVIP.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Status of the resource.
	//
	// +kubebuilder:validation:Required
	Status LBResourceStatus `json:"status"`

	// Allocated addresses
	//
	// +kubebuilder:validation:Required
	Addresses LBVIPAddresses `json:"addresses"`
}

type LBVIPAddresses struct {
	// The allocated IPv4 VIP.
	//
	// +kubebuilder:validation:Optional
	IPv4 *string `json:"ipv4,omitempty"`

	// The allocated IPv6 VIP.
	//
	// +kubebuilder:validation:Optional
	IPv6 *string `json:"ipv6,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBVIPList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBVIP `json:"items"`
}

func (r *LBVIP) UpsertStatusCondition(conditionType string, condition metav1.Condition) {
	conditionExists := false
	for i, c := range r.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				// transition -> update condition
				r.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		r.Status.Conditions = append(r.Status.Conditions, condition)
	}
}

func (r *LBVIP) UpdateResourceStatus() {
	resourceStatus := LBResourceStatusOK

	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			resourceStatus = LBResourceStatusConditionNotMet
			break
		}
	}

	r.Status.Status = resourceStatus
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbdeployment",path="lbdeployments",scope="Namespaced",shortName={lbdeployment}
// +kubebuilder:printcolumn:JSONPath=".status.status",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LBDeployment defines advanced LBService deployment options that allow
// to customize the assignment of LBService's to Isovalent Load Balancer nodes
// (K8s Nodes).
type LBDeployment struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec LBDeploymentSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status LBDeploymentStatus `json:"status,omitempty"`
}

type LBDeploymentSpec struct {
	// Services selects the LBServices that should be
	// handled by this deployment.
	//
	// +kubebuilder:validation:Required
	Services LBDeploymentServices `json:"services"`

	// Nodes defines the T1 & T2 nodes that should be used to execute
	// T1 respective T2 functionality for thee selected LBServices.
	//
	// +kubebuilder:validation:Required
	Nodes LBDeploymentNodes `json:"nodes"`
}

type LBDeploymentServices struct {
	// LabelSelector is a label selector that selects the LBServices within the same namespace.
	//
	// Note: An empty label selector (neither MatchLabels nor MatchExpressions defined) matches all LBServices in the same namespace.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	LabelSelector *slim_metav1.LabelSelector `json:"labelSelector,omitempty"`
}

type LBDeploymentNodes struct {
	// LabelSelectors selects the T1 & T2 nodes with k8s label selectors.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	LabelSelectors *LBDeploymentNodesLabelSelectors `json:"labelSelectors,omitempty"`
}

type LBDeploymentNodesLabelSelectors struct {
	// T1 is a label selector that determines on which nodes
	// T1 functionality should be executed for the selected LBServices.
	//
	// Note: An empty label selector (neither MatchLabels nor MatchExpressions defined) matches all nodes.
	//
	// +kubebuilder:validation:Required
	T1 slim_metav1.LabelSelector `json:"t1"`

	// T2 is a label selector that determines on which nodes
	// T2 functionality should be executed for the selected LBServices.
	//
	// Note: An empty label selector (neither MatchLabels nor MatchExpressions defined) matches all nodes.
	//
	// +kubebuilder:validation:Required
	T2 slim_metav1.LabelSelector `json:"t2"`
}

type LBDeploymentStatus struct {
	// The current conditions of the LBDeployment.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Status of the resource.
	//
	// +kubebuilder:validation:Required
	Status LBResourceStatus `json:"status"`
}

const (
	ConditionTypeDeploymentAccepted = "lb.cilium.io/Accepted"
)

const (
	DeploymentAcceptedConditionReasonValid   = "Valid"
	DeploymentAcceptedConditionReasonInvalid = "Invalid"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBDeploymentList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBDeployment `json:"items"`
}

func (r *LBDeployment) GetStatusCondition(conditionType string) *metav1.Condition {
	for _, c := range r.Status.Conditions {
		if c.Type == conditionType {
			return &c
		}
	}
	return nil
}

func (r *LBDeployment) UpsertStatusCondition(conditionType string, condition metav1.Condition) {
	conditionExists := false
	for i, c := range r.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				// transition -> update condition
				r.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		r.Status.Conditions = append(r.Status.Conditions, condition)
	}
}

func (r *LBDeployment) UpdateResourceStatus() {
	resourceStatus := LBResourceStatusOK

	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			resourceStatus = LBResourceStatusConditionNotMet
			break
		}
	}

	r.Status.Status = resourceStatus
}

// +kubebuilder:validation:Enum=OK;ConditionNotMet
type LBResourceStatus string

const (
	// Status OK: everytying is OK
	LBResourceStatusOK LBResourceStatus = "OK"
	// Status ConditionNotMet: At least one condition isn't met
	LBResourceStatusConditionNotMet LBResourceStatus = "ConditionNotMet"
)

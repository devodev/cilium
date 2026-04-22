//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"encoding/hex"
	"maps"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	ossannotation "github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func LbIPPoolV2Alpha1(name string, namespaceName string, ipBlock string) *ciliumv2alpha1.CiliumLoadBalancerIPPool {
	return &ciliumv2alpha1.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: ciliumv2alpha1.CiliumLoadBalancerIPPoolSpec{
			Blocks: []ciliumv2alpha1.CiliumLoadBalancerIPPoolIPBlock{
				{
					Cidr: ciliumv2alpha1.IPv4orIPv6CIDR(ipBlock),
				},
			},
			// Only include services from test namespace
			ServiceSelector: &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{
						Key:      "io.kubernetes.service.namespace",
						Operator: slim_metav1.LabelSelectorOpIn,
						Values:   []string{namespaceName},
					},
				},
			},
		},
	}
}

func LbIPPool(name string, namespaceName string, ipBlocks ...string) *ciliumv2.CiliumLoadBalancerIPPool {
	pool := &ciliumv2.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{TestResourceLabelName: "true"},
		},
		Spec: ciliumv2.CiliumLoadBalancerIPPoolSpec{
			Blocks: []ciliumv2.CiliumLoadBalancerIPPoolIPBlock{},
			// Only include services from test namespace
			ServiceSelector: &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{
						Key:      "io.kubernetes.service.namespace",
						Operator: slim_metav1.LabelSelectorOpIn,
						Values:   []string{namespaceName},
					},
				},
			},
		},
	}

	for _, ipb := range ipBlocks {
		pool.Spec.Blocks = append(pool.Spec.Blocks, ciliumv2.CiliumLoadBalancerIPPoolIPBlock{
			Cidr: ciliumv2.IPv4orIPv6CIDR(ipb),
		},
		)
	}

	return pool
}

type httpApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy)

func withHttpRoute(backendRef string, opts ...httpApplicationRouteOption) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		route := &isovalentv1alpha1.LBServiceHTTPRoute{
			Match: &isovalentv1alpha1.LBServiceHTTPRouteMatch{},
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: backendRef,
			},
		}

		for _, opt := range opts {
			opt(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type httpApplicationRouteOption func(o *isovalentv1alpha1.LBServiceHTTPRoute)

func withHttpHostname(hostname string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Match.HostNames = []isovalentv1alpha1.LBServiceHostName{isovalentv1alpha1.LBServiceHostName(hostname)}
	}
}

func withHttpPath(path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Match.Path = &isovalentv1alpha1.LBServiceHTTPPath{
			Exact: &path,
		}
	}
}

func withHttpBackendPersistenceBySourceIP() httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.PersistentBackend = &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{
			SourceIP: ptr.To(true),
		}
	}
}

func withHttpBackendPersistenceByCookie(cookieName string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.PersistentBackend = &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{
			Cookies: []isovalentv1alpha1.LBServiceHTTPRoutePersistentBackendCookie{
				{
					Name: cookieName,
				},
			},
		}
	}
}

func withHttpConnectionFilteringDenyBySourceIP(sourceCIDR string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpConnectionFilteringAllowBySourceIP(sourceCIDR string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpsConnectionFilteringDenyBySourceIP(sourceCIDR string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpsConnectionFilteringAllowBySourceIP(sourceCIDR string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

type httpsApplicationRouteOption func(o *isovalentv1alpha1.LBServiceHTTPSRoute)

func withHttpsHostname(hostname string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.Match.HostNames = []isovalentv1alpha1.LBServiceHostName{isovalentv1alpha1.LBServiceHostName(hostname)}
	}
}

func withHttpsPath(path string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.Match.Path = &isovalentv1alpha1.LBServiceHTTPPath{
			Exact: &path,
		}
	}
}

func withTCPProxyConnectionFilteringDenyBySourceIP(sourceCIDR string) tcpRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTCPRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTCPRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceTCPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTCPProxyConnectionFilteringAllowBySourceIP(sourceCIDR string) tcpRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTCPRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTCPRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceTCPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTCPProxyConnectionRateLimiting(limit uint, timePeriodSeconds uint) tcpRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTCPRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceTCPRouteRateLimits{
			Connections: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withTCPProxyBackendPersistenceBySourceIP() tcpRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTCPRoute) {
		o.PersistentBackend = &isovalentv1alpha1.LBServiceTCPRoutePersistentBackend{
			SourceIP: ptr.To(true),
		}
	}
}

func withTLSPassthroughConnectionFilteringDenyBySourceIP(sourceCIDR string) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTLSPassthroughConnectionFilteringAllowBySourceIP(sourceCIDR string) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTLSProxyConnectionFilteringDenyBySourceIP(sourceCIDR string) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTLSProxyConnectionFilteringAllowBySourceIP(sourceCIDR string) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyByExactPath(path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyByPrefixPath(path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Prefix: &path,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyByExactHostname(hostname string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyBySuffixHostname(hostname string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Suffix: &hostname,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyBySourceIP(sourceCIDR string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringAllowBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringAllowByExactHeader(headers map[string]string) httpApplicationRouteOption {
	headerRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{}

	for k, v := range headers {
		headerRules = append(headerRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeaderValue{
				Exact: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					Headers: headerRules,
				},
			},
		}
	}
}

func withHttpRequestFilteringAllowByPrefixHeader(headers map[string]string) httpApplicationRouteOption {
	headerRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{}

	for k, v := range headers {
		headerRules = append(headerRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeaderValue{
				Prefix: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					Headers: headerRules,
				},
			},
		}
	}
}

func withHttpRequestFilteringAllowByRegexHeader(headers map[string]string) httpApplicationRouteOption {
	headerRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{}

	for k, v := range headers {
		headerRules = append(headerRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeaderValue{
				Regex: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					Headers: headerRules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringDenyByExactPath(path string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpsRequestFilteringDenyByPrefixPath(path string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Prefix: &path,
					},
				},
			},
		}
	}
}

func withHttpsRequestFilteringDenyByExactHostname(hostname string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
				},
			},
		}
	}
}

func withHttpsRequestFilteringDenyBySuffixHostname(hostname string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Suffix: &hostname,
					},
				},
			},
		}
	}
}

func withHttpsRequestFilteringDenyBySourceIP(sourceCIDR string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpsRequestFilteringDenyBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByExactHeader(headers map[string]string) httpsApplicationRouteOption {
	headerRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{}

	for k, v := range headers {
		headerRules = append(headerRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeaderValue{
				Exact: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					Headers: headerRules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByPrefixHeader(headers map[string]string) httpsApplicationRouteOption {
	headerRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{}

	for k, v := range headers {
		headerRules = append(headerRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeaderValue{
				Prefix: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					Headers: headerRules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByRegexHeader(headers map[string]string) httpsApplicationRouteOption {
	headerRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{}

	for k, v := range headers {
		headerRules = append(headerRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeader{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHeaderValue{
				Regex: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					Headers: headerRules,
				},
			},
		}
	}
}

func withHttpRequestFilteringAllowByExactJWTClaim(jwtClaims map[string]string) httpApplicationRouteOption {
	jwtClaimRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleJWTClaim{}

	for k, v := range jwtClaims {
		jwtClaimRules = append(jwtClaimRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleJWTClaim{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleJWTClaimValue{
				Regex: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					JWTClaims: jwtClaimRules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByExactJWTClaim(jwtClaims map[string]string) httpsApplicationRouteOption {
	jwtClaimRules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleJWTClaim{}

	for k, v := range jwtClaims {
		jwtClaimRules = append(jwtClaimRules, &isovalentv1alpha1.LBServiceRequestFilteringRuleJWTClaim{
			Name: k,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleJWTClaimValue{
				Regex: &v,
			},
		})
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					JWTClaims: jwtClaimRules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByExactClientCertSANDNS(dns string) httpsApplicationRouteOption {
	rules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSAN{
		{
			Type: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANTypeDNS,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANValue{
				Exact: &dns,
			},
		},
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					ClientCertificateSANs: rules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByExactClientCertSANIP(ip string) httpsApplicationRouteOption {
	rules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSAN{
		{
			Type: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANTypeIPADDRESS,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANValue{
				Exact: &ip,
			},
		},
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					ClientCertificateSANs: rules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByExactClientCertSANURI(uri string) httpsApplicationRouteOption {
	rules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSAN{
		{
			Type: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANTypeURI,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANValue{
				Exact: &uri,
			},
		},
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					ClientCertificateSANs: rules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByExactClientCertSANEmail(email string) httpsApplicationRouteOption {
	rules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSAN{
		{
			Type: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANTypeEMAIL,
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANValue{
				Exact: &email,
			},
		},
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					ClientCertificateSANs: rules,
				},
			},
		}
	}
}

func withHttpsRequestFilteringAllowByExactClientCertSANOtherNameUPN(upn string) httpsApplicationRouteOption {
	rules := []*isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSAN{
		{
			Type: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANTypeOTHERNAME,
			OID:  ptr.To("1.3.6.1.4.1.311.20.2.3"),
			Value: isovalentv1alpha1.LBServiceRequestFilteringRuleClientCertificateSANValue{
				Exact: &upn,
			},
		},
	}

	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPSRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPSRouteRequestFilteringRule{
				{
					ClientCertificateSANs: rules,
				},
			},
		}
	}
}

func withHttpConnectionRateLimiting(limit uint, timePeriodSeconds uint) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.RateLimits = &isovalentv1alpha1.LBServiceHTTPRateLimits{
			Connections: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withHttpRequestRateLimiting(limit uint, timePeriodSeconds uint) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceHTTPRouteRateLimits{
			Requests: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withHttpsRequestRateLimiting(limit uint, timePeriodSeconds uint) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceHTTPRouteRateLimits{
			Requests: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withHttpBasicAuth(secretRef string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			Basic: &isovalentv1alpha1.LBServiceHTTPBasicAuth{
				Users: isovalentv1alpha1.LBServiceHTTPBasicAuthUser{
					SecretRef: isovalentv1alpha1.LBServiceSecretRef{
						Name: secretRef,
					},
				},
			},
		}
	}
}

func withHttpRouteBasicAuth(disabled bool) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPRouteAuth{
			Basic: &isovalentv1alpha1.LBServiceHTTPRouteBasicAuth{
				Disabled: disabled,
			},
		}
	}
}

func withHttpsRouteBasicAuth(disabled bool) httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPRouteAuth{
			Basic: &isovalentv1alpha1.LBServiceHTTPRouteBasicAuth{
				Disabled: disabled,
			},
		}
	}
}

func withHttpJWTAuth(opts ...httpJWTAuthOption) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			JWT: &isovalentv1alpha1.LBServiceHTTPJWTAuth{
				Providers: []isovalentv1alpha1.LBServiceHTTPJWTProvider{},
			},
		}
		for _, opt := range opts {
			opt(o.Auth.JWT)
		}
	}
}

type httpJWTAuthOption func(o *isovalentv1alpha1.LBServiceHTTPJWTAuth)

func withJWTProviderWithLocalJWKS(name string, issuer *string, audiences []string, jwksSecretRef string) httpJWTAuthOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPJWTAuth) {
		o.Providers = append(o.Providers, isovalentv1alpha1.LBServiceHTTPJWTProvider{
			Name:      name,
			Issuer:    issuer,
			Audiences: audiences,
			JWKS: isovalentv1alpha1.LBServiceHTTPJWTAuthJWKS{
				SecretRef: &isovalentv1alpha1.LBServiceSecretRef{
					Name: jwksSecretRef,
				},
			},
		})
	}
}

func withJWTProviderWithRemoteJWKS(name string, issuer *string, audiences []string, uri string) httpJWTAuthOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPJWTAuth) {
		o.Providers = append(o.Providers, isovalentv1alpha1.LBServiceHTTPJWTProvider{
			Name:      name,
			Issuer:    issuer,
			Audiences: audiences,
			JWKS: isovalentv1alpha1.LBServiceHTTPJWTAuthJWKS{
				HTTPURI: &isovalentv1alpha1.LBServiceHTTPURI{
					URI: uri,
				},
			},
		})
	}
}

func withHttpRouteJWTAuthDisabled() httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPRouteAuth{
			JWT: &isovalentv1alpha1.LBServiceHTTPRouteJWTAuth{
				Disabled: true,
			},
		}
	}
}

func withHttpsRouteJWTAuthDisabled() httpsApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPSRoute) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPRouteAuth{
			JWT: &isovalentv1alpha1.LBServiceHTTPRouteJWTAuth{
				Disabled: true,
			},
		}
	}
}

type serviceOption func(o *isovalentv1alpha1.LBService)

func withLabels(labels map[string]string) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		if o.Labels == nil {
			o.Labels = map[string]string{}
		}

		maps.Copy(o.Labels, labels)
	}
}

func withVIPRef(vipName string) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.VIPRef = isovalentv1alpha1.LBServiceVIPRef{
			Name: vipName,
		}
	}
}

func withPort(port int32) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.Port = port
	}
}

func withHTTPProxyApplication(opts ...httpApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		obj := isovalentv1alpha1.LBServiceApplications{
			HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
				Routes: []isovalentv1alpha1.LBServiceHTTPRoute{},
			},
		}

		for _, o := range opts {
			o(obj.HTTPProxy)
		}

		o.Spec.Applications = obj
	}
}

func withProxyProtocol(disallowedVersion []int, tlvs []int) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		var dv []isovalentv1alpha1.LBProxyProtocolVersion
		for _, v := range disallowedVersion {
			dv = append(dv, isovalentv1alpha1.LBProxyProtocolVersion(v))
		}

		var pTLVs []isovalentv1alpha1.LBProxyProtocolTLV
		for _, tlv := range tlvs {
			pTLVs = append(pTLVs, isovalentv1alpha1.LBProxyProtocolTLV(tlv))
		}
		o.Spec.ProxyProtocolConfig = &isovalentv1alpha1.LBServiceProxyProtocolConfig{
			DisallowedVersions: dv,
			PassthroughTLVs:    pTLVs,
		}
	}
}

type httpsApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy)

func withHttpsRoute(backendRef string, opts ...httpsApplicationRouteOption) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		route := &isovalentv1alpha1.LBServiceHTTPSRoute{
			Match: &isovalentv1alpha1.LBServiceHTTPRouteMatch{},
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: backendRef,
			},
		}

		for _, opt := range opts {
			opt(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

func withCertificate(secretRefName string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.TLSConfig.Certificates = append(o.TLSConfig.Certificates, isovalentv1alpha1.LBServiceTLSCertificate{
			SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: secretRefName},
		})
	}
}

func withClientCertificateValidation(secretRefName string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.TLSConfig.Validation = &isovalentv1alpha1.LBTLSValidationConfig{
			SecretRef: isovalentv1alpha1.LBServiceSecretRef{
				Name: secretRefName,
			},
		}
	}
}

func withHTTPSH2(h2Enabled bool) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.HTTPConfig.EnableHTTP2 = &h2Enabled
	}
}

func withHTTPSH11(h11Enabled bool) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.HTTPConfig.EnableHTTP11 = &h11Enabled
	}
}

func withHTTPSProxyApplication(opts ...httpsApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		obj := isovalentv1alpha1.LBServiceApplications{
			HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
				TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
					Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{},
				},
				HTTPConfig: &isovalentv1alpha1.LBServiceHTTPConfig{
					EnableHTTP11: ptr.To(true),
					EnableHTTP2:  ptr.To(true),
				},
				Routes: []isovalentv1alpha1.LBServiceHTTPSRoute{},
			},
		}

		for _, o := range opts {
			o(obj.HTTPSProxy)
		}

		o.Spec.Applications = obj
	}
}

func withHttpsBasicAuth(secretRef string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			Basic: &isovalentv1alpha1.LBServiceHTTPBasicAuth{
				Users: isovalentv1alpha1.LBServiceHTTPBasicAuthUser{
					SecretRef: isovalentv1alpha1.LBServiceSecretRef{
						Name: secretRef,
					},
				},
			},
		}
	}
}

func withHttpsJWTAuth(opts ...httpJWTAuthOption) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			JWT: &isovalentv1alpha1.LBServiceHTTPJWTAuth{
				Providers: []isovalentv1alpha1.LBServiceHTTPJWTProvider{},
			},
		}
		for _, opt := range opts {
			opt(o.Auth.JWT)
		}
	}
}

func withTLSPassthroughApplication(opts ...tlsPassthroughApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		app := &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{}

		for _, opt := range opts {
			opt(app)
		}

		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			TLSPassthrough: app,
		}
	}
}

type tlsPassthroughApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationTLSPassthrough)

func withTLSProxyApplication(opts ...tlsProxyApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		app := &isovalentv1alpha1.LBServiceApplicationTLSProxy{}

		for _, o := range opts {
			o(app)
		}

		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			TLSProxy: app,
		}
	}
}

type tlsProxyApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationTLSProxy)

func withTLSPassthroughRoute(backendRef string, opts ...tlsPassthroughRouteOption) tlsPassthroughApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTLSPassthrough) {
		route := &isovalentv1alpha1.LBServiceTLSPassthroughRoute{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
			Match:      &isovalentv1alpha1.LBServiceTLSPassthroughRouteMatch{},
		}

		for _, o := range opts {
			o(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type tlsPassthroughRouteOption func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute)

func withTLSPassthroughHostname(hostname string) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.Match.HostNames = []isovalentv1alpha1.LBServiceHostName{
			isovalentv1alpha1.LBServiceHostName(hostname),
		}
	}
}

func withTLSPassthroughConnectionRateLimiting(limit uint, timePeriodSeconds uint) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceTLSRouteRateLimits{
			Connections: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withTLSCertificate(secretName string) tlsProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTLSProxy) {
		o.TLSConfig = isovalentv1alpha1.LBServiceTLSConfig{
			Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
				{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: secretName}},
			},
		}
	}
}

func withTLSProxyRoute(backendRef string, opts ...tlsRouteOption) tlsProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTLSProxy) {
		route := &isovalentv1alpha1.LBServiceTLSRoute{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
			Match:      &isovalentv1alpha1.LBServiceTLSRouteMatch{},
		}

		for _, o := range opts {
			o(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type tlsRouteOption func(o *isovalentv1alpha1.LBServiceTLSRoute)

func withHostname(hostname string) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.Match.HostNames = []isovalentv1alpha1.LBServiceHostName{
			isovalentv1alpha1.LBServiceHostName(hostname),
		}
	}
}

func withTLSProxyConnectionRateLimiting(limit uint, timePeriodSeconds uint) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceTLSRouteRateLimits{
			Connections: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withTCPProxyApplication(opts ...tcpProxyApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		app := &isovalentv1alpha1.LBServiceApplicationTCPProxy{}

		for _, o := range opts {
			o(app)
		}

		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			TCPProxy: app,
		}
	}
}

type trafficPolicyOption func(o *isovalentv1alpha1.LBTrafficPolicy)

func withTrafficPolicy(opts ...trafficPolicyOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		policy := &isovalentv1alpha1.LBTrafficPolicy{}

		for _, o := range opts {
			o(policy)
		}

		o.Spec.TrafficPolicy = policy
	}
}

type zoneAware func(o *isovalentv1alpha1.LBZoneAware)

func withZoneAware(opts ...zoneAware) trafficPolicyOption {
	return func(o *isovalentv1alpha1.LBTrafficPolicy) {
		zone := &isovalentv1alpha1.LBZoneAware{
			MinBackendCount: 1,
		}

		for _, o := range opts {
			o(zone)
		}

		o.ZoneAware = zone
	}
}

func withMinBackendCount(count uint64) zoneAware {
	return func(o *isovalentv1alpha1.LBZoneAware) {
		o.MinBackendCount = count
	}
}

func withPreferSameZone() zoneAware {
	return func(o *isovalentv1alpha1.LBZoneAware) {
		o.Mode = isovalentv1alpha1.LBZoneAwareModePreferSameZone
	}
}

func withRequireSameZone() zoneAware {
	return func(o *isovalentv1alpha1.LBZoneAware) {
		o.Mode = isovalentv1alpha1.LBZoneAwareModeRequireSameZone
	}
}

type tcpProxyApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationTCPProxy)

func withTCPForceDeploymentMode(forceDeploymentMode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) tcpProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTCPProxy) {
		o.ForceDeploymentMode = &forceDeploymentMode
	}
}

func withTCPProxyRoute(backendRef string, opts ...tcpRouteOption) tcpProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTCPProxy) {
		route := &isovalentv1alpha1.LBServiceTCPRoute{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
		}

		for _, o := range opts {
			o(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type tcpRouteOption func(o *isovalentv1alpha1.LBServiceTCPRoute)

type udpRouteOption func(o *isovalentv1alpha1.LBServiceUDPRoute)

type udpProxyApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationUDPProxy)

func withUDPProxyApplication(opts ...udpProxyApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		app := &isovalentv1alpha1.LBServiceApplicationUDPProxy{}

		for _, o := range opts {
			o(app)
		}

		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			UDPProxy: app,
		}
	}
}

func withUDPForceDeploymentMode(forceDeploymentMode isovalentv1alpha1.LBUDPProxyForceDeploymentModeType) udpProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationUDPProxy) {
		o.ForceDeploymentMode = &forceDeploymentMode
	}
}

func withUDPProxyBackendPersistenceBySourceIP() udpRouteOption {
	return func(o *isovalentv1alpha1.LBServiceUDPRoute) {
		o.PersistentBackend = &isovalentv1alpha1.LBServiceUDPRoutePersistentBackend{
			SourceIP: ptr.To(true),
		}
	}
}

func withUDPProxyRoute(backendRef string, opts ...udpRouteOption) udpProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationUDPProxy) {
		route := &isovalentv1alpha1.LBServiceUDPRoute{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
		}

		for _, o := range opts {
			o(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

func withUDPProxyConnectionFilteringDenyBySourceIP(sourceCIDR string) udpRouteOption {
	return func(o *isovalentv1alpha1.LBServiceUDPRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceUDPRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceUDPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withUDPProxyConnectionFilteringAllowBySourceIP(sourceCIDR string) udpRouteOption {
	return func(o *isovalentv1alpha1.LBServiceUDPRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceUDPRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceUDPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func lbService(name string, opts ...serviceOption) *isovalentv1alpha1.LBService {
	svc := &isovalentv1alpha1.LBService{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBServiceSpec{
			VIPRef: isovalentv1alpha1.LBServiceVIPRef{
				// use VIP with same name by default
				Name: name,
			},
			Port: 80,
		},
	}

	for _, o := range opts {
		o(svc)
	}

	return svc
}

type backendPoolOption func(o *isovalentv1alpha1.LBBackendPool)

func withIPBackend(ip string, port uint32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.BackendType = isovalentv1alpha1.BackendTypeIP
		o.Spec.Backends = append(o.Spec.Backends, isovalentv1alpha1.Backend{
			IP:     ptr.To(ip),
			Port:   int32(port),
			Weight: ptr.To[uint32](1),
		})
	}
}

func withIPBackendAndZone(ip string, port uint32, zone string) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.BackendType = isovalentv1alpha1.BackendTypeIP
		o.Spec.Backends = append(o.Spec.Backends, isovalentv1alpha1.Backend{
			IP:     ptr.To(ip),
			Port:   int32(port),
			Weight: ptr.To[uint32](1),
			Zone:   &zone,
		})
	}
}

func withHostnameBackend(hostname string, port int32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.BackendType = isovalentv1alpha1.BackendTypeHostname
		o.Spec.Backends = append(o.Spec.Backends, isovalentv1alpha1.Backend{
			Host:   ptr.To(hostname),
			Port:   port,
			Weight: ptr.To[uint32](1),
		})
	}
}

func withK8sServiceBackend(serviceName string, servicePort uint32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.BackendType = isovalentv1alpha1.BackendTypeK8sService
		o.Spec.Backends = append(o.Spec.Backends, isovalentv1alpha1.Backend{
			K8sServiceRef: &isovalentv1alpha1.LBBackendPoolK8sServiceRef{
				Name: serviceName,
			},
			Port:   int32(servicePort),
			Weight: ptr.To[uint32](1),
		})
	}
}

func withConsistentHashing() backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.Loadbalancing = &isovalentv1alpha1.Loadbalancing{
			Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
				ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{},
			},
		}
	}
}

func withDNSResolver(ip string, port uint32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		if o.Spec.DNSResolverConfig == nil {
			o.Spec.DNSResolverConfig = &isovalentv1alpha1.DNSResolverConfig{
				Resolvers: []isovalentv1alpha1.DNSResolver{},
			}
		}
		o.Spec.DNSResolverConfig.Resolvers = append(o.Spec.DNSResolverConfig.Resolvers, isovalentv1alpha1.DNSResolver{
			IP:   ip,
			Port: port,
		})
	}
}

func withBackendTLS() backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.TLSConfig = &isovalentv1alpha1.LBBackendTLSConfig{}
	}
}

func withHealthCheckPort(port int32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		if port != 0 {
			o.Spec.HealthCheck.Port = &port
		}
	}
}

func withHealthCheckTLS() backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.HealthCheck.TLSConfig = &isovalentv1alpha1.LBBackendTLSConfig{}
	}
}

func withTCPHealthCheck(sendPayload *string, receivePayload *string) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.HealthCheck = isovalentv1alpha1.HealthCheck{
			IntervalSeconds: ptr.To[int32](5),
			TCP:             &isovalentv1alpha1.HealthCheckTCP{},
		}

		if sendPayload != nil && receivePayload != nil {
			sendPayloadHex := hex.EncodeToString([]byte(*sendPayload))
			receivePayloadHex := hex.EncodeToString([]byte(*receivePayload))

			o.Spec.HealthCheck.TCP.Send = &isovalentv1alpha1.HealthCheckPayload{
				Text: &sendPayloadHex,
			}

			o.Spec.HealthCheck.TCP.Receive = append(o.Spec.HealthCheck.TCP.Receive, &isovalentv1alpha1.HealthCheckPayload{
				Text: &receivePayloadHex,
			})
		}
	}
}

func withProxyProtocolConfig(version int, tlvs []int) backendPoolOption {
	temp := make([]isovalentv1alpha1.LBProxyProtocolTLV, len(tlvs))
	for i, tlv := range tlvs {
		temp[i] = isovalentv1alpha1.LBProxyProtocolTLV(tlv)
	}
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.ProxyProtocolConfig = &isovalentv1alpha1.LBBackendPoolProxyProtocolConfig{
			Version:         isovalentv1alpha1.LBProxyProtocolVersion(version),
			PassthroughTLVs: temp,
		}
	}
}

func lbBackendPool(name string, opts ...backendPoolOption) *isovalentv1alpha1.LBBackendPool {
	pool := &isovalentv1alpha1.LBBackendPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBBackendPoolSpec{
			HealthCheck: isovalentv1alpha1.HealthCheck{
				IntervalSeconds: ptr.To[int32](15),
				HTTP: &isovalentv1alpha1.HealthCheckHTTP{
					Path: ptr.To("/health"),
				},
			},
			Backends: []isovalentv1alpha1.Backend{},
		},
	}

	for _, o := range opts {
		o(pool)
	}

	return pool
}

type vipOption func(o *isovalentv1alpha1.LBVIP)

func withRequestedIPv4(ipv4 string) vipOption {
	return func(o *isovalentv1alpha1.LBVIP) {
		o.Spec.IPv4Request = &ipv4
	}
}

func withAddressFamily(family isovalentv1alpha1.AddressFamily) vipOption {
	return func(o *isovalentv1alpha1.LBVIP) {
		o.Spec.AddressFamily = &family
	}
}

func lbVIP(name string, opts ...vipOption) *isovalentv1alpha1.LBVIP {
	obj := &isovalentv1alpha1.LBVIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBVIPSpec{},
	}

	for _, o := range opts {
		o(obj)
	}

	return obj
}

func bgpClusterConfig(name string) *isovalentv1.IsovalentBGPClusterConfig {
	obj := &isovalentv1.IsovalentBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{TestResourceLabelName: "true"},
		},
		Spec: isovalentv1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{
						Key:      ossannotation.ServiceNodeExposure,
						Operator: slim_metav1.LabelSelectorOpIn,
						Values: []string{
							"t1",
							"t1-t2",
						},
					},
				},
			},
			BGPInstances: []isovalentv1.IsovalentBGPInstance{
				{
					Name:     "t1",
					LocalASN: ptr.To[int64](ciliumASN),
				},
			},
		},
	}

	return obj
}

func tlsSecret(namespace, name string, key, cert []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.key": key,
			"tls.crt": cert,
		},
	}
}

func caSecret(namespace, name string, cert []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": cert,
		},
	}
}

func lbDeployment(name string, opts ...deploymentOption) *isovalentv1alpha1.LBDeployment {
	svc := &isovalentv1alpha1.LBDeployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBDeploymentSpec{
			Services: isovalentv1alpha1.LBDeploymentServices{
				LabelSelector: &slim_metav1.LabelSelector{},
			},
			Nodes: isovalentv1alpha1.LBDeploymentNodes{
				LabelSelectors: &isovalentv1alpha1.LBDeploymentNodesLabelSelectors{
					T1: slim_metav1.LabelSelector{},
					T2: slim_metav1.LabelSelector{},
				},
			},
		},
	}

	for _, o := range opts {
		o(svc)
	}

	return svc
}

type deploymentOption func(o *isovalentv1alpha1.LBDeployment)

func withT1Nodes(t1NodeLabelSelector string) deploymentOption {
	return func(o *isovalentv1alpha1.LBDeployment) {
		ls, err := slim_metav1.ParseToLabelSelector(t1NodeLabelSelector)
		if err != nil {
			panic(err)
		}

		o.Spec.Nodes.LabelSelectors.T1 = *ls
	}
}

func WithServiceSelector(serviceLabelSelector string) deploymentOption {
	return func(o *isovalentv1alpha1.LBDeployment) {
		ls, err := slim_metav1.ParseToLabelSelector(serviceLabelSelector)
		if err != nil {
			panic(err)
		}

		o.Spec.Services.LabelSelector = ls
	}
}

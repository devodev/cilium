/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "conntrack.h"
#include "conntrack_map.h"
#include "trace.h"

#pragma once

/*
 * cilium_privnet_{ct4,ct6,ct_any4,ct_any6}_global are map of conntrack maps that
 * contains the connection tracking information of untranslated privnet flows.
 * Since IPs between different private networks can overlap, there is one
 * conntrack map per private network.
 */

 struct per_privnet_ct_map6_inner_map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ct_entry);
	__uint(max_entries, CT_MAP_SIZE_TCP);
	__uint(map_flags, LRU_MEM_FLAVOR);
 #ifndef BPF_TEST
 };
 #else
 } per_cluster_ct_tcp6_100 __section_maps_btf,
   per_cluster_ct_any6_100 __section_maps_btf;
 #endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map6_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct6_global __section_maps_btf;
#else
} cilium_privnet_ct6_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_tcp6_100,
	},
};
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map6_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct_any6_global __section_maps_btf;
#else
} cilium_privnet_ct_any6_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_any6_100,
	},
};
#endif

static __always_inline void *
privnet_get_ct_map6(const struct ipv6_ct_tuple *tuple, __u32 network_id)
{
	if (network_id != 0) {
		if (tuple->nexthdr == IPPROTO_TCP)
			return map_lookup_elem(&cilium_privnet_ct6_global, &network_id);

		return map_lookup_elem(&cilium_privnet_ct_any6_global, &network_id);
	}

	/* return default network CT map */
	return get_ct_map6(tuple);
}

static __always_inline void *
privnet_get_ct_any_map6(__u32 network_id)
{
	if (network_id != 0)
		return map_lookup_elem(&cilium_privnet_ct_any6_global, &network_id);

	/* return default network CT map */
	return &cilium_ct_any6_global;
}

 struct per_privnet_ct_map4_inner_map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ct_entry);
	__uint(max_entries, CT_MAP_SIZE_TCP);
	__uint(map_flags, LRU_MEM_FLAVOR);
 #ifndef BPF_TEST
 };
 #else
 } per_cluster_ct_tcp4_100 __section_maps_btf,
   per_cluster_ct_any4_100 __section_maps_btf;
 #endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map4_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct4_global __section_maps_btf;
#else
} cilium_privnet_ct4_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_tcp4_100,
	},
};
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map4_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct_any4_global __section_maps_btf;
#else
} cilium_privnet_ct_any4_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_any4_100,
	},
};
#endif

static __always_inline void *
privnet_get_ct_map4(const struct ipv4_ct_tuple *tuple, __u32 network_id)
{
	if (network_id != 0) {
		if (tuple->nexthdr == IPPROTO_TCP)
			return map_lookup_elem(&cilium_privnet_ct4_global, &network_id);

		return map_lookup_elem(&cilium_privnet_ct_any4_global, &network_id);
	}

	/* return default network CT map */
	return get_ct_map4(tuple);
}

static __always_inline void *
privnet_get_ct_any_map4(__u32 network_id)
{
	if (network_id != 0)
		return map_lookup_elem(&cilium_privnet_ct_any4_global, &network_id);

	/* return default network CT map */
	return &cilium_ct_any4_global;
}

static __always_inline int
privnet_ct_unknown_flow_ingress_ipv4(const struct __ctx_buff *ctx,
				     const struct iphdr *ip4,
				     const union v4addr *orig_dip,
				     __u32 network_id,
				     struct trace_ctx *trace)
{
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *ct_map, *ct_map_any;
	__u32 monitor = 0;
	int l4_off;
	int ct_ret;
	int ret;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	tuple.nexthdr = ip4->protocol;
	tuple.saddr = ip4->saddr;
	tuple.daddr = orig_dip->be32;

	ct_map = privnet_get_ct_map4(&tuple, network_id);
	ct_map_any = privnet_get_ct_any_map4(network_id);
	if (unlikely(!ct_map || !ct_map_any))
		return DROP_EP_NOT_READY;

	ct_ret = ct_lookup4(ct_map, &tuple, ctx, ip4, l4_off,
			    CT_INGRESS, SCOPE_BIDIR, &ct_state, &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	if (ct_ret == CT_NEW) {
		struct ct_state ct_state_new = {};

		ret = ct_create4(ct_map, ct_map_any, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, NULL);
		if (IS_ERR(ret))
			return ret;
	}

	return CTX_ACT_OK;
}

static __always_inline int
privnet_ct_unknown_flow_ingress_ipv6(const struct __ctx_buff *ctx,
				     const struct ipv6hdr *ip6,
				     const union v6addr *orig_dip,
				     __u32 network_id,
				     struct trace_ctx *trace)
{
	struct ipv6_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	void *ct_map, *ct_map_any;
	fraginfo_t fraginfo;
	__u32 monitor = 0;
	int hdrlen;
	int l4_off;
	int ct_ret;
	int ret;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, orig_dip);

	ct_map = privnet_get_ct_map6(&tuple, network_id);
	ct_map_any = privnet_get_ct_any_map6(network_id);
	if (unlikely(!ct_map || !ct_map_any))
		return DROP_EP_NOT_READY;

	ct_ret = ct_lookup6(ct_map, &tuple, ctx, ip6, fraginfo, l4_off,
			    CT_INGRESS, SCOPE_BIDIR, &ct_state, &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	if (ct_ret == CT_NEW) {
		struct ct_state ct_state_new = {};

		ret = ct_create6(get_ct_map6(&tuple), &cilium_ct_any6_global, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, NULL);
		if (IS_ERR(ret))
			return ret;
	}

	return CTX_ACT_OK;
}

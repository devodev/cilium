/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/overloadable.h"
#include "lib/enterprise_vrf.h"

struct egress_gw_ha_policy_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32 saddr;
	__u32 daddr;
};

#define EGRESS_GW_HA_MAX_GATEWAY_NODES 64

struct egress_gw_ha_policy_entry_v2 {
	/* Size is the number of IPs set in the gateway_ips field (i.e. the number of
	 * gateways configured for the policy).
	 */
	__u32 size;
	__be32 egress_ip;
	__be32 gateway_ips[EGRESS_GW_HA_MAX_GATEWAY_NODES];
	__u32 egress_ifindex;
};

struct egress_gw_ha_ct_entry {
	__be32 gateway_ip;
};

struct egress_gw_standalone_key {
	__be32 endpoint_ip;
};

struct egress_gw_standalone_entry {
	__be32 sec_identity;
	__be32 tunnel_endpoint;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key);
	__type(value, struct egress_gw_ha_policy_entry_v2);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_GW_HA_POLICY_MAP_V2_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_egress_gw_ha_policy_v4_v2 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct egress_gw_ha_ct_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_GW_HA_CT_MAP_SIZE);
} cilium_egress_gw_ha_ct_v4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct egress_gw_standalone_key);
	__type(value, struct egress_gw_standalone_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_GW_STANDALONE_MAP_SIZE);
} cilium_egress_gw_standalone_v4 __section_maps_btf;

#ifdef ENABLE_EGRESS_GATEWAY_COMMON

#ifdef ENABLE_EGRESS_GATEWAY_HA
static __always_inline const struct egress_gw_ha_policy_entry_v2 *
lookup_ip4_egress_gw_ha_policy_v2(__be32 saddr, __be32 daddr)
{
	struct egress_gw_ha_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&cilium_egress_gw_ha_policy_v4_v2, &key);
}

static __always_inline const struct egress_gw_ha_ct_entry *
lookup_ip4_egress_ct(struct ipv4_ct_tuple *ct_key)
{
	return map_lookup_elem(&cilium_egress_gw_ha_ct_v4, ct_key);
}

#ifdef ENABLE_EGRESS_GATEWAY_STANDALONE
static __always_inline const struct egress_gw_standalone_entry *
lookup_ip4_segw(__be32 addr)
{
	struct egress_gw_standalone_key segw_key = { .endpoint_ip = addr };

	return map_lookup_elem(&cilium_egress_gw_standalone_v4, &segw_key);
}
#endif /* ENABLE_EGRESS_GATEWAY_STANDALONE */

static __always_inline
void update_egress_gw_ha_ct_entry(struct ipv4_ct_tuple *ct_key, __be32 gateway)
{
	struct egress_gw_ha_ct_entry egress_ct = {
		.gateway_ip = gateway
	};

	map_update_elem(&cilium_egress_gw_ha_ct_v4, ct_key, &egress_ct, 0);
}

static __always_inline
__be32 pick_egress_gateway(const struct egress_gw_ha_policy_entry_v2 *policy)
{
	unsigned int index = get_prandom_u32() % policy->size;

	/* Just being extra defensive here while keeping the verifier happy.
	 * Userspace should always guarantee the invariant:
	 *     policy->size < EGRESS_GW_HA_MAX_GATEWAY_NODES"
	 */
	index %= EGRESS_GW_HA_MAX_GATEWAY_NODES;

	return policy->gateway_ips[index];
}

/* egress_gw_ha_policy_entry_is_excluded_cidr returns true if the given policy
 * entry represents an excluded CIDR.
 *
 * Excluded CIDRs are expressed with policy entries with a single gateway IP set
 * to the special EGRESS_GATEWAY_EXCLUDED_CIDR IPv4 (0.0.0.1)
 */
static __always_inline
bool egress_gw_ha_policy_entry_is_excluded_cidr(const struct egress_gw_ha_policy_entry_v2 *policy)
{
	return policy->size == 1 &&
		policy->gateway_ips[0] == EGRESS_GATEWAY_EXCLUDED_CIDR;
}
#endif /* ENABLE_EGRESS_GATEWAY_HA */

static __always_inline int
egress_gw_ha_request_needs_redirect(struct ipv4_ct_tuple *rtuple __maybe_unused,
				    __be32 *gateway_ip __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY_HA) && !defined(ENABLE_EGRESS_GATEWAY_STANDALONE)
	const struct egress_gw_ha_policy_entry_v2 *egress_gw_policy;
	const struct egress_gw_ha_ct_entry *egress_ct;
	struct ipv4_ct_tuple ct_key;

	/* The first iteration of egress_gw_ha_request_needs_redirect() would
	 * receive the full IPv4 header as parameter, extract the source and
	 * destination IPs and ports, and build the IPv4 tuple for the ct_key
	 * from that.
	 * To avoid rebuilding this tuple and having to deal with fragmentation,
	 * this function now receives the IPv4 tuple from handle_ipv4_from_lxc().
	 *
	 * As this is a CT tuple which has been already flipped by ct_lookup4(),
	 * for backward compatibility with the existing entries in the egressgw
	 * CT map, we need to flip its addresses back (ports were already
	 * flipped _before_ the call to ct_lookup4(), so after being flipped
	 * again they are now in the correct order).
	 *
	 * Moreover, clear the tuple's flags as in the first iteration it wasn't
	 * used.
	 */
	memcpy(&ct_key, rtuple, sizeof(ct_key));
	ipv4_ct_tuple_swap_addrs(&ct_key);
	ct_key.flags = 0;

	egress_ct = lookup_ip4_egress_ct(&ct_key);
	if (egress_ct) {
		/* If there's an entry, extract the IP of the gateway node from
		 * the egress_ct struct and forward the packet to the gateway
		 */
		*gateway_ip = egress_ct->gateway_ip;
		return CTX_ACT_REDIRECT;
	}

	/* Lookup the (src IP, dst IP) tuple in the the egress policy map */
	egress_gw_policy = lookup_ip4_egress_gw_ha_policy_v2(ipv4_ct_reverse_tuple_saddr(rtuple),
							     ipv4_ct_reverse_tuple_daddr(rtuple));
	if (!egress_gw_policy)
		return CTX_ACT_OK;

	if (!egress_gw_policy->size) {
		/* If no gateway is found, drop the packet. */
		return DROP_NO_EGRESS_GATEWAY;
	}

	/* If this is an excluded CIDR, skip redirection */
	if (egress_gw_ha_policy_entry_is_excluded_cidr(egress_gw_policy))
		return CTX_ACT_OK;

	/* Otherwise encap and redirect the packet to egress gateway
	 * node through a tunnel.
	 */
	*gateway_ip = pick_egress_gateway(egress_gw_policy);

	/* And add an egress CT entry to pin the selected gateway node
	 * for the connection
	 */
	update_egress_gw_ha_ct_entry(&ct_key, *gateway_ip);
	return CTX_ACT_REDIRECT;
#else
	return CTX_ACT_OK;
#endif /* ENABLE_EGRESS_GATEWAY_HA && !ENABLE_EGRESS_GATEWAY_STANDALONE*/
}

static __always_inline
bool egress_gw_ha_snat_needed(__be32 saddr __maybe_unused,
			      __be32 daddr __maybe_unused,
			      __be32 *snat_addr __maybe_unused,
			      __u32 *egress_ifindex __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY_HA)
	const struct egress_gw_ha_policy_entry_v2 *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_ha_policy_v2(saddr, daddr);
	if (!egress_gw_policy)
		return false;

	*egress_ifindex = egress_gw_policy->egress_ifindex;

	/* If this is an excluded CIDR, skip SNAT */
	if (egress_gw_ha_policy_entry_is_excluded_cidr(egress_gw_policy))
		return false;

	*snat_addr = egress_gw_policy->egress_ip;
	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY_HA */
}

static __always_inline bool
egress_gw_ha_reply_matches_policy(struct iphdr *ip4 __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY_HA)
	const struct egress_gw_ha_policy_entry_v2 *egress_gw_policy_v2;

	/* Find a matching policy by looking up the reverse address tuple: */
	egress_gw_policy_v2 = lookup_ip4_egress_gw_ha_policy_v2(ip4->daddr, ip4->saddr);
	if (!egress_gw_policy_v2)
		return false;

	/* If this is an excluded CIDR, skip redirection */
	if (egress_gw_ha_policy_entry_is_excluded_cidr(egress_gw_policy_v2))
		return false;

	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY_HA */
}

static __always_inline
int cee_egress_gw_standalone_map_update(struct __ctx_buff *ctx __maybe_unused,
					__be32 saddr __maybe_unused,
					__u32 src_sec_identity __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY_STANDALONE)
	struct bpf_tunnel_key tunnel_key = {};
	struct egress_gw_standalone_key segw_key = { .endpoint_ip = saddr };
	struct egress_gw_standalone_entry segw_value = {};
	__u32 key_size = TUNNEL_KEY_WITHOUT_SRC_IP;

	if (unlikely(ctx_get_tunnel_key(ctx, &tunnel_key, key_size, 0) < 0))
		return DROP_NO_TUNNEL_KEY;

	segw_value.tunnel_endpoint = bpf_htonl(tunnel_key.remote_ipv4);
	segw_value.sec_identity = src_sec_identity;
	if (unlikely(map_update_elem(&cilium_egress_gw_standalone_v4, &segw_key,
				     &segw_value, BPF_ANY) != 0))
		return DROP_WRITE_ERROR;
#endif /* ENABLE_EGRESS_GATEWAY_STANDALONE */

	return CTX_ACT_OK;
}

static __always_inline
__u32 cee_egress_gw_vrf_get(__u32 tbid)
{
#if defined(ENABLE_EGRESS_GATEWAY_HA) && !defined(ENABLE_EGRESS_GATEWAY_STANDALONE)
	return enterprise_vrf_map_get((vrf_id)tbid);
#endif

	return tbid;
}

#endif /* ENABLE_EGRESS_GATEWAY_COMMON */

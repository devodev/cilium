/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_config.h"
#include "lib/enterprise_vxlan.h"

#define ENCRYPTION_POLICY_FULL_PREFIX						\
  (8 * (sizeof(struct encryption_policy_key) - sizeof(struct bpf_lpm_trie_key)))

struct encryption_policy_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32		src_sec_identity;
	__u32		dst_sec_identity;
	__be16		protocol; /* 16 bits are wasteful, but ran into prefix lookup issues due to struct packing, byte padding */
	__be16		port;
};

struct encryption_policy_entry {
	__u8	encrypt:1,
			pad:7;
	__u8	prefix_len;
};

 #ifndef ENCRYPTION_POLICY_MAP_SIZE
 #define ENCRYPTION_POLICY_MAP_SIZE 16384
 #endif

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct encryption_policy_key);
	__type(value, struct encryption_policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, ENCRYPTION_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_encryption_policy_map __section_maps_btf;

DECLARE_ENTERPRISE_CONFIG(bool, encryption_policy_fallback_encrypt,
			  "True if encryption policy default action is encrypt.")

#ifdef ENABLE_ENCRYPTION_POLICY

#include "lib/wireguard.h"

/* encrypt_flow_lookup checks if the current packet needs encryption by looking
 * up policy entries for both flow directions. It always performs both lookups
 * and picks the result from whichever matched at a longer (more specific)
 * prefix. On equal prefix length, encrypt takes precedence (security-first).
 */
static __always_inline bool
encrypt_flow_lookup(__u32 src_id, __be16 src_port, __u32 dst_id, __be16 dst_port, __u8 proto) {
	const struct encryption_policy_entry *fwd, *rev;
	struct encryption_policy_key key = {
		.lpm_key = { ENCRYPTION_POLICY_FULL_PREFIX, {} },
		.src_sec_identity = src_id,
		.dst_sec_identity = dst_id,
		.protocol = proto,
		.port = dst_port,
	};

	/* forward direction: (src_id, dst_id, dst_port, proto) */
	fwd = map_lookup_elem(&cilium_encryption_policy_map, &key);

	/* A full-prefix encrypt match cannot be overridden by the reverse
	 * lookup: no entry can be more specific, and on equal prefix length
	 * encrypt wins. Skip the second lookup.
	 */
	if (fwd && fwd->prefix_len == ENCRYPTION_POLICY_FULL_PREFIX && fwd->encrypt)
		return true;

	/* reverse direction: (dst_id, src_id, src_port, proto) */
	key.src_sec_identity = dst_id;
	key.dst_sec_identity = src_id;
	key.port = src_port;

	rev = map_lookup_elem(&cilium_encryption_policy_map, &key);

	if (fwd && rev) {
		if (fwd->prefix_len > rev->prefix_len)
			return fwd->encrypt;
		if (rev->prefix_len > fwd->prefix_len)
			return rev->encrypt;
		/* equal prefix: encrypt wins */
		return fwd->encrypt || rev->encrypt;
	}
	if (fwd)
		return fwd->encrypt;
	if (rev)
		return rev->encrypt;

	return CONFIG(encryption_policy_fallback_encrypt);
}

static __always_inline int
encrypt_get_l4_info_ipv6(const struct __ctx_buff *ctx, const struct ipv6hdr *ip6,
			 __u8 *l4_proto, __u32 *l4_off)
{
	__u32 ipv6_off;

	*l4_proto = ip6->nexthdr;
	ipv6_off = ipv6_hdrlen(ctx, l4_proto);
	if (ipv6_off < 0)
		return ipv6_off;

	*l4_off = ETH_HLEN + ipv6_off;
	return 0;
}

static __always_inline void
encrypt_get_l4_info_ipv4(const struct iphdr *ip4, __u8 *l4_proto, __u32 *l4_off)
{
	*l4_proto = ip4->protocol;
	*l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
}

static __always_inline int
encrypt_handle_vxlan_inner_packet(const struct __ctx_buff *ctx __maybe_unused,
				  void *data, void *data_end, __u32 *l4_off, __u8 *l4_proto,
				  const struct remote_endpoint_info __maybe_unused **dst)
{
	struct ipv6hdr __maybe_unused *inner_ip6;
	struct iphdr __maybe_unused *inner_ip4;
	__u16 inner_l3_proto;
	__u32 __maybe_unused inner_l3_off;
	__u32 __maybe_unused ipv6_off;
	fraginfo_t __maybe_unused fraginfo;
	int ret;

	inner_l3_proto = vxlan_get_inner_proto(data, data_end, *l4_off);
	switch (inner_l3_proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = vxlan_get_inner_ipv6(data, data_end, *l4_off, &inner_ip6);
		if (!ret)
			return DROP_INVALID;
		if (!inner_ip6)
			return DROP_INVALID;

		*dst = lookup_ip6_remote_endpoint((union v6addr *)&inner_ip6->daddr, 0);

		*l4_proto = inner_ip6->nexthdr;
		/* calculate offset of inner ip packet */
		inner_l3_off = *l4_off + sizeof(struct udphdr) + sizeof(struct vxlanhdr) +
					   sizeof(struct ethhdr);

		/* with the offset of the inner ip packet, calculate length of inner ipv6 header */
		ipv6_off = ipv6_hdrlen_offset(ctx, inner_l3_off, l4_proto, &fraginfo);
		if (ipv6_off < 0)
			return ipv6_off;

		*l4_off = inner_l3_off + ipv6_off;
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = vxlan_get_inner_ipv4(data, data_end, *l4_off, &inner_ip4);
		if (!ret)
			return DROP_INVALID;
		if (!inner_ip4)
			return DROP_INVALID;

		*dst = lookup_ip4_remote_endpoint(inner_ip4->daddr, 0);

		*l4_proto = inner_ip4->protocol;

		*l4_off = *l4_off + sizeof(struct udphdr) + sizeof(struct vxlanhdr) +
					 sizeof(struct ethhdr) + ipv4_hdrlen(inner_ip4);
		break;
#endif /* ENABLE_IPV4 */
	default:
		return CTX_ACT_OK;
	}

	return 1;
}

static __always_inline bool
encrypt_policy_matches(const struct __ctx_buff *ctx, __u8 l4_proto, __u32 l4_off,
		       __u32 src_sec_identity, __u32 dst_sec_identity)
{
	struct ipv4_frag_l4ports __maybe_unused ports;

	switch (l4_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		/* TODO: For non-initial IP fragments the L4 header is not
		 * present at l4_off, so l4_load_ports will read arbitrary
		 * payload data, leading to incorrect policy matching.
		 */
		if (l4_load_ports(ctx, l4_off, &ports.sport) < 0)
			return false;

		return encrypt_flow_lookup(src_sec_identity,
					   ports.sport,
					   dst_sec_identity,
					   ports.dport,
					   l4_proto);
	default:
		/* For non-TCP/UDP/SCTP, look up without port info.
		 * This matches wildcard entries (prefix <= 80).
		 */
		return encrypt_flow_lookup(src_sec_identity, 0,
					   dst_sec_identity, 0, l4_proto);
	}
}

#undef host_wg_encrypt_hook
static __always_inline int
host_wg_encrypt_hook(struct __ctx_buff *ctx, __be16 proto, __u32 src_sec_identity)
{
	const struct remote_endpoint_info *dst = NULL;
	const struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	__u32 magic __maybe_unused = 0;

	__u8 l4_proto;
	__u32 l4_off = 0;
	int ret __maybe_unused = 0;

	if (!eth_is_supported_ethertype(proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
#ifdef ENABLE_NODE_ENCRYPTION
		/* Previously, ICMPv6 NA (reply to NS) was sent over cilium_wg0,
		 * which resulted in neigh entry not being created due to
		 * IFF_POINTOPOINT | IFF_NOARP set on cilium_wg0. Therefore,
		 * NA should not be sent over WG.
		 */
		if (ip6->nexthdr == IPPROTO_ICMPV6) {
			struct icmp6hdr *icmp6 = (void *)ip6 + sizeof(*ip6);

			if ((void *)icmp6 + sizeof(*icmp6) > data_end)
				return DROP_INVALID;

			if (icmp6->icmp6_type == ICMPV6_NA_MSG)
				goto out;
		}
#endif
		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		if (src_sec_identity == UNKNOWN_ID) {
			src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
			if (!src)
				return CTX_ACT_OK;

			src_sec_identity = src->sec_identity;
		}

		ret = encrypt_get_l4_info_ipv6(ctx, ip6, &l4_proto, &l4_off);
		if (ret < 0)
			return ret;
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		encrypt_get_l4_info_ipv4(ip4, &l4_proto, &l4_off);

# if defined(HAVE_ENCAP)
		/* In tunneling mode WG needs to encrypt tunnel traffic,
		 * so that src sec ID can be transferred.
		 *
		 * This also handles IPv6, as IPv6 pkts are encapsulated w/
		 * IPv4 tunneling.
		 */
		if (ctx_is_overlay(ctx)) {
			ret = encrypt_handle_vxlan_inner_packet(ctx, data, data_end, &l4_off,
								&l4_proto, &dst);

			if (ret < 0)
				return ret;
			if (ret == CTX_ACT_OK)
				goto out;

			src_sec_identity = get_identity(ctx);
			goto maybe_encrypt;
		}
# endif /* HAVE_ENCAP */
		dst = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (src_sec_identity == UNKNOWN_ID) {
			src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
			if (!src)
				return CTX_ACT_OK;

			src_sec_identity = src->sec_identity;
		}

		break;
#endif
	default:
		goto out;
	}

#ifndef ENABLE_NODE_ENCRYPTION
	/* We want to encrypt all proxy traffic. Looking at the packet mark is
	 * needed for non-transparent connections.
	 *
	 * For connections by the egress proxy (MARK_MAGIC_PROXY_EGRESS) we
	 * can rely on the provided source identity.
	 */
	magic = ctx->mark & MARK_MAGIC_HOST_MASK;
	if (magic == MARK_MAGIC_PROXY_INGRESS ||
	    magic == MARK_MAGIC_SKIP_TPROXY)
		goto maybe_encrypt;

	/* Unless node encryption is enabled, we don't want to encrypt
	 * traffic from the hostns (an exception - L7 proxy traffic).
	 *
	 * NB: if iptables has SNAT-ed the packet, its sec id is HOST_ID.
	 * This means that the packet won't be encrypted. This is fine,
	 * as with --encrypt-node=false we encrypt only pod-to-pod packets.
	 */
	if (src_sec_identity == HOST_ID)
		goto out;
#endif /* !ENABLE_NODE_ENCRYPTION */

	/* We don't want to encrypt any traffic that originates from outside
	 * the cluster. This check excludes DSR traffic from the LB node to a remote backend.
	 */
	if (!identity_is_cluster(src_sec_identity))
		goto out;

	/* If source is remote node we should treat it like outside traffic.
	 * This is possible when connection is done from pod to load balancer with DSR enabled.
	 */
	if (identity_is_remote_node(src_sec_identity))
		goto out;

maybe_encrypt: __maybe_unused
	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 */
	if (dst &&
	    !encrypt_policy_matches(ctx, l4_proto, l4_off, src_sec_identity, dst->sec_identity))
		goto out;

	if (dst && dst->key) {
		set_identity_mark(ctx, src_sec_identity, MARK_MAGIC_IDENTITY);
overlay_encrypt: __maybe_unused
		return ctx_redirect(ctx, CONFIG(wg_ifindex), 0);
	}

out:
	return CTX_ACT_OK;
}

#endif /* ENABLE_ENCRYPTION_POLICY */

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "linux/bpf.h"

#include "lib/eps.h"
#include "lib/fib.h"
#include "lib/overloadable.h"
#include "lib/enterprise_vxlan.h"

#define VRF_MAX (1U << 16)

/* VRF id used as key for VRF map */
typedef __u16 vrf_id;
/* Kernel FIB table ID used as value for VRF map */
typedef __u32 vrf_table_id;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, vrf_id);
	__type(value, vrf_table_id);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, VRF_MAX);
	__uint(map_flags, CONDITIONAL_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_vrf_map __section_maps_btf;

/*
 * lookup a table ID given a VRF id
 * @id: VRF ID to lookup
 * returns: kernel FIB table ID associated with the VRF ID, or 0 if not found
 */
static __always_inline vrf_table_id enterprise_vrf_map_get(vrf_id id)
{
	vrf_table_id *tbid;

	if (!id)
		return id;

	tbid = map_lookup_elem(&cilium_vrf_map, &id);
	return tbid ? *tbid : 0;
}

/*
 * Given a VXLAN packet which encodes a VRF ID in its GBP field, extract the
 * VRF ID and perform an eBPF redirect to the appropriate egress device and
 * CTX_ACT_REDIRECT is returned.
 *
 * If the skb is not a VXLAN packet or if no VRF ID is discovered in the GBP
 * field the function returns CTX_ACT_OK.
 *
 * -1 is returned if an error occurs.
 */
#if defined(HAVE_ENCAP) && defined(ENABLE_EGRESS_GATEWAY_HA) && __ctx_is == __ctx_skb
static __always_inline
int enterprise_vrf_redirect_to_egress(struct __ctx_buff *ctx,
				      __u16 proto)
{
	struct bpf_fib_lookup_padded fib_params = {};
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	void *data, *data_end;
	__u32 l4_off = 0;
	__s8 ext_err = 0;
	int fib_ret = 0;
	__be16 gbp = 0;
	__u32 tbid = 0;

	if (CONFIG(tunnel_protocol) != TUNNEL_PROTOCOL_VXLAN)
		return CTX_ACT_OK;

	if (!ctx_is_overlay(ctx))
		return CTX_ACT_OK;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

		gbp = vxlan_get_gbp(data, data_end, l4_off);
		if (gbp == 0)
			return CTX_ACT_OK;

		tbid = enterprise_vrf_map_get(bpf_ntohs(gbp));
		if (!tbid)
			return CTX_ACT_OK;

		fib_params.l.tbid = tbid;
		fib_ret = fib_lookup_v4(ctx, &fib_params,
					ip4->saddr, ip4->daddr,
					BPF_FIB_LOOKUP_DIRECT |
					BPF_FIB_LOOKUP_TBID);

		switch (fib_ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			break;
		default:
			return CTX_ACT_OK;
		}

		if (fib_params.l.ifindex == CONFIG(interface_ifindex))
			/* already at the correct egress interface */
			return CTX_ACT_OK;

		return fib_do_redirect(ctx, false, &fib_params, false, fib_ret,
				       fib_params.l.ifindex, &ext_err);
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		l4_off = ETH_HLEN + sizeof(struct ipv6hdr);

		gbp = vxlan_get_gbp(data, data_end, l4_off);
		if (gbp == 0)
			return CTX_ACT_OK;

		tbid = enterprise_vrf_map_get(bpf_ntohs(gbp));
		if (!tbid)
			return CTX_ACT_OK;

		fib_params.l.tbid = tbid;
		fib_ret = fib_lookup_v6(ctx, &fib_params,
					(struct in6_addr *)&ip6->saddr,
					(struct in6_addr *)&ip6->daddr,
					BPF_FIB_LOOKUP_DIRECT |
					BPF_FIB_LOOKUP_TBID);

		switch (fib_ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			break;
		default:
			return CTX_ACT_OK;
		}

		if (fib_params.l.ifindex == CONFIG(interface_ifindex))
			/* already at the correct egress interface */
			return CTX_ACT_OK;

		return fib_do_redirect(ctx, false, &fib_params, false, fib_ret,
				       fib_params.l.ifindex, &ext_err);
#endif
	default:
		return CTX_ACT_OK;
	}

	return CTX_ACT_OK;
}
#else
static __always_inline
int enterprise_vrf_redirect_to_egress(struct __ctx_buff *ctx __maybe_unused,
				      __u16 proto __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif /* HAVE_ENCAP && ENABLE_EGRESS_GATEWAY_HA && __ctx_is == __ctx_skb */

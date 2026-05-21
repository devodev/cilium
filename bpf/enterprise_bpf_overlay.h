/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_privnet.h"
#include "lib/network_device.h"

static __always_inline int
enterprise_privnet_from_overlay(struct __ctx_buff *ctx, __u16 proto,
				__s8 *ext_err __maybe_unused)
{
	const struct privnet_pip_val *dst_pip_val __maybe_unused = NULL;
	const struct privnet_pip_val *src_pip_val __maybe_unused = NULL;
	const struct privnet_fib_val *dst_fib_val __maybe_unused = NULL;
	const struct privnet_fib_val *src_fib_val __maybe_unused = NULL;
	__u32 src_sec_identity __maybe_unused = 0;
	struct bpf_tunnel_key tunnel_key = {};
	void __maybe_unused *data_end, *data;
	int ret __maybe_unused = CTX_ACT_OK;
	struct ipv6hdr *ip6 __maybe_unused;
	struct iphdr *ip4 __maybe_unused;
	__u16 subnet_id __maybe_unused;
	__u32 ifindex __maybe_unused;
	__u16 net_id __maybe_unused;
	bool unknown_flow = false;

	if (!CONFIG(privnet_enable)) {
		/* privnet isn't enabled, so we're always in PIP space */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
		return ret;
	}

	/* From overlay privnet code is only required in INB */
	if (!CONFIG(privnet_bridge_enable)) {
		/* We're not on the bridge. That means in from_overlay, the destination
		 * is always in PIP space, as it points to a local endpoint.
		 * The source, however, is unknown. It might also be in the PIP space
		 * for pod to pod flows, or it might be a netIP for the unknown flow.
		 * Set the source NetID to UNKNOWN.
		 */
		set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);
		return ret;
	}

	/* On INB, the source must be in PIP space, as it comes from a worker node.
	 * The destination unknown. It might also be in PIP space for pod to extEP flow,
	 * or it might be in a netIP space for the unknown flow.
	 * Set the destination NetID to UNKNOWN.
	 */
	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);

	if (ctx_get_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0) < 0)
		return DROP_NO_TUNNEL_KEY;

	if (tunnel_key.tunnel_id == CONFIG(privnet_unknown_sec_id))
		unknown_flow = true;
	else
		src_sec_identity = get_id_from_tunnel_id(tunnel_key.tunnel_id, proto);

	/* Not unknown flow, so we're in PIP space */
	if (!unknown_flow)
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		if (!unknown_flow) {
			/* Let's check first if the destination is a local
			 * endpoint, and the source is not a remapped address,
			 * in which case we let processing continue as usual.
			 */
			if (!privnet_pip_lookup6(*((union v6addr *)&ip6->saddr)) &&
			    lookup_ip6_endpoint(ip6))
				return CTX_ACT_OK;

			ret = privnet_ext_ep_policy_ingress6(ctx, ip6, src_sec_identity, ext_err);
			if (IS_ERR(ret))
				return ret;
		}

		ret = privnet_inb_ingress_ipv6(ctx, unknown_flow, &src_pip_val, &dst_pip_val);
		if (IS_ERR(ret))
			return ret;

		/* network and subnet IDs are based on original source IP (PIP). */
		net_id = src_pip_val->net_id;
		subnet_id = privnet_subnet_id_lookup6(net_id, src_pip_val->ip6);
		src_fib_val = privnet_fib_lookup6(net_id, subnet_id, src_pip_val->ip6);
		if (!src_fib_val)
			return DROP_UNROUTABLE;

		/* For external endpoints, the destination FIB entry doesn't
		 * have ifindex set. Thus, always use the ifindex from the
		 * source FIB entry for consistency across known and unknown
		 * flow paths.
		 */
		ifindex = src_fib_val->ifindex;
		if (ifindex == 0)
			return DROP_UNROUTABLE;

		/* Fully translated flow, found PIP map entries for source
		 * and destination addresses.
		 */
		if (src_pip_val && dst_pip_val) {
			const union macaddr *smac, *dmac;

			dst_fib_val = privnet_fib_lookup6(net_id, subnet_id, dst_pip_val->ip6);
			if (!dst_fib_val)
				return DROP_UNROUTABLE;

			smac = device_mac(ifindex);
			dmac = &dst_fib_val->mac;

			if (eth_store_saddr(ctx, smac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_daddr(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;

			return ctx_redirect(ctx, ifindex, 0);
		}

		/* Unknown flow */
		if (unknown_flow) {
			union v6addr daddr = {};

			if (!revalidate_data(ctx, &data, &data_end, &ip6))
				return DROP_INVALID;

			ipv6_addr_copy(&daddr, (union v6addr *)&ip6->daddr);

			dst_fib_val = privnet_fib_lookup6(net_id, subnet_id, daddr);
			if (!dst_fib_val)
				return DROP_UNROUTABLE;

			return privnet_redirect_neigh_fib_ipv6(dst_fib_val, &daddr,
							       ifindex);
		}

		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* Evaluate ingress policy before reverse NAT, as policies are based on
		 * PIPs.
		 * For traffic with unknown sec_id, unknown_flow is true, we should skip
		 * ingress policy evaluation as we do not have ep info for the destination.
		 */
		if (!unknown_flow) {
			/* Let's check first if the destination is a local
			 * endpoint, and the source is not a remapped address,
			 * in which case we let processing continue as usual.
			 */
			if (!privnet_pip_lookup4(ip4->saddr) && lookup_ip4_endpoint(ip4))
				return CTX_ACT_OK;

			ret = privnet_ext_ep_policy_ingress4(ctx, ip4, src_sec_identity, ext_err);
			if (IS_ERR(ret))
				return ret;
		}

		ret = privnet_inb_ingress_ipv4(ctx, unknown_flow, &src_pip_val, &dst_pip_val);
		if (IS_ERR(ret))
			return ret;

		/* network and subnet IDs are based on original source IP (PIP). */
		net_id = src_pip_val->net_id;
		subnet_id = privnet_subnet_id_lookup4(net_id, src_pip_val->ip4.be32);
		src_fib_val = privnet_fib_lookup4(net_id, subnet_id, src_pip_val->ip4.be32);
		if (!src_fib_val)
			return DROP_UNROUTABLE;

		/* For external endpoints, the destination FIB entry doesn't
		 * have ifindex set. Thus, always use the ifindex from the
		 * source FIB entry for consistency across known and unknown
		 * flow paths.
		 */
		ifindex = src_fib_val->ifindex;
		if (ifindex == 0)
			return DROP_UNROUTABLE;

		/* Fully translated flow, found PIP map entries for source
		 * and destination addresses.
		 */
		if (src_pip_val && dst_pip_val) {
			const union macaddr *smac, *dmac;

			dst_fib_val = privnet_fib_lookup4(net_id, subnet_id, dst_pip_val->ip4.be32);
			if (!dst_fib_val)
				return DROP_UNROUTABLE;

			smac = device_mac(ifindex);
			dmac = &dst_fib_val->mac;

			if (eth_store_saddr(ctx, smac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_daddr(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;

			return ctx_redirect(ctx, ifindex, 0);
		}

		/* Unknown flow */
		if (unknown_flow) {
			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				return DROP_INVALID;

			dst_fib_val = privnet_fib_lookup4(net_id, subnet_id, ip4->daddr);
			if (!dst_fib_val)
				return DROP_UNROUTABLE;

			return privnet_redirect_neigh_fib_ipv4(dst_fib_val, ip4->daddr,
							       ifindex);
		}

		break;
#endif /* ENABLE_IPV4 */
	default:
		break;
	}

	/*  Shouldn't ever end up here. The packet wasn't redirected. Drop it
	 *  just to be safe.
	 */
	return DROP_UNROUTABLE;
}

static __always_inline int enterprise_privnet_to_overlay(struct __ctx_buff *ctx __maybe_unused,
							 __be16 __maybe_unused proto)
{
	if (!CONFIG(privnet_enable)) {
		/* privnet isn't enabled, so we're always in PIP space */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
		return CTX_ACT_OK;
	}

	if (!CONFIG(privnet_bridge_enable)) {
		/* We're not on the bridge. The source must be in PIP space, as it comes from
		 * a local endpoint. The destination is unknown. It might also be in PIP space
		 * for the pod to pod flow, or it might be in a netIP space for the unknown flow.
		 * Set the destination NetID to UNKNOWN.
		 */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);
		return CTX_ACT_OK;
	}
	/* We're on the bridge. That means in to_overlay, the destination
	 * is always in PIP space, as it points to a pod on a worker node.
	 * The source, however, is unknown. It might also be in the PIP space
	 * for extEP to pod flows, or it might be a netIP for the unknown flow.
	 * Set the source NetID to UNKNOWN.
	 */
	set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	return CTX_ACT_OK;
}

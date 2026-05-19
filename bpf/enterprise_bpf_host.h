/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/drop.h"
#include "lib/drop_reasons.h"
#include "lib/encap.h"
#include "lib/icmp6.h"
#include "lib/trace.h"

#include "lib/enterprise_privnet.h"

static __always_inline int
enterprise_privnet_do_netdev(struct __ctx_buff *ctx, __u16 proto, __u32 __maybe_unused identity,
			     enum trace_point obs_point,  const bool from_host)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	void __maybe_unused *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	union v4addr dip4 __maybe_unused;
	union v6addr dip6 __maybe_unused;
	const struct privnet_fib_val *sip_val __maybe_unused = NULL;
	const struct privnet_fib_val *dip_val __maybe_unused = NULL;
	const struct remote_endpoint_info *info __maybe_unused;
	__s8 __maybe_unused ext_err = 0;
	int ret = CTX_ACT_OK;
	const __u16 *net_id;
	__u16 __maybe_unused subnet_id;

	if (!CONFIG(privnet_enable))
		return ret;

	/* we do not expect privnet traffic coming from host */
	if (from_host)
		return ret;

	net_id = privnet_get_net_id(CONFIG(interface_ifindex));
	if (!net_id)
		/* This interface is not associated to a network ID; nothing to do here.
		 * We don't treat net_id == 0 specially, the different paths will handle
		 * a miss in the FIB map as appropriate (either punt to stack or drop).
		 */
		return ret;

	switch (proto) {
	case bpf_htons(ETH_P_ARP):
		send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
				  ctx->ingress_ifindex, trace.reason, trace.monitor, proto);
		return handle_privnet_arp(ctx, *net_id, NULL);
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
						      METRIC_INGRESS);

		if (is_icmp6_ndp(ctx, ip6, ETH_HLEN)) {
			/* Reply to the neighbor solicitation messages if necessary
			 * (i.e., they target a known IP reachable through this INB),
			 * and punt all the others up to the stack unmodified, to
			 * make sure we don't break local neighbor discovery.
			 */
			return handle_privnet_ns(ctx, *net_id, NULL);
		}

		ipv6_addr_copy(&dip6, (union v6addr *)&ip6->daddr);
		subnet_id = privnet_subnet_id_lookup6(*net_id, dip6);

		ret = privnet_local_access_ingress_ipv6(ctx, *net_id, subnet_id);
		if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
			return ret;

		ret = privnet_egress_ipv6(ctx, 0, *net_id, subnet_id,
					  &sip_val, &dip_val, NULL);
		if (IS_ERR(ret))
			return ret;

		if (!sip_val || !dip_val || is_privnet_route_entry(dip_val)) {
			/* See comment for IPv4 */
			return DROP_UNROUTABLE;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

#ifdef TUNNEL_MODE
		info = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		if (!info || !info->flag_has_tunnel_ep || info->flag_skip_tunnel) {
			/* see comment for IPv4 */
			return DROP_UNROUTABLE;
		}

		if (is_privnet_route_entry(sip_val)) {
			/* see comment for IPv4 */
			ret = privnet_ct_unknown_flow_ingress_ipv6(ctx, ip6, &dip6,
								   *net_id, &trace);
			if (IS_ERR(ret))
				return ret;

			return encap_and_redirect_with_nodeid(ctx, info,
				CONFIG(privnet_unknown_sec_id),
				info->sec_identity,
				&trace, proto);
		}

		ret = privnet_ext_ep_policy_egress6(ctx, ip6, info->sec_identity,
						    &trace, &ext_err);
		if (ret != CTX_ACT_OK)
			return send_drop_notify_ext(ctx, identity,
						    info->sec_identity, 0,
						    ret, ext_err,
						    METRIC_EGRESS);

		return encap_and_redirect_with_nodeid(ctx, info,
			identity,
			info->sec_identity,
			&trace, proto);
#else
		return DROP_UNROUTABLE; /* require tunnel mode */
#endif
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
							METRIC_INGRESS);

		ret = privnet_redirect_dhcp_reply(ctx, ip4);
		if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
			return ret;

		/* Revalidate again to keep verifier happy even though we would never reach here
		 * when privnet_redirect_dhcp_reply() mangled the packet.
		 */
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
							METRIC_INGRESS);

		dip4.be32 = ip4->daddr;
		subnet_id = privnet_subnet_id_lookup4(*net_id, ip4->daddr);

		ret = privnet_local_access_ingress_ipv4(ctx, *net_id, subnet_id);
		if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
			return ret;

		ret = privnet_egress_ipv4(ctx, 0, *net_id, subnet_id,
					  &sip_val, &dip_val, NULL);
		if (IS_ERR(ret))
			return ret;

		if (!sip_val) {
			/* Source IP is not translated and there is no source route match,
			 * so there is no way to route back to the sender. It is better to
			 * drop the packet now.
			 */
			return DROP_UNROUTABLE;
		}

		if (!dip_val || is_privnet_route_entry(dip_val)) {
			/* dst_ip is not translated to an exact endpoint or dip_val exists but
			 * for a route entry (there is no endpoint associated with it).
			 * In both cases, we want to drop the packet to avoid network
			 * segmentation leakage.
			 */
			return DROP_UNROUTABLE;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

#ifdef TUNNEL_MODE
		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (!info || !info->flag_has_tunnel_ep || info->flag_skip_tunnel) {
			/* If the destination is not a Cilium-managed endpoint (i.e. there
			 * is no IPCache entry with an associated tunnel endpoint), drop
			 * the packet. Neither unknown flow nor external endpoint sources
			 * should send us packets that are not targeting a Cilium-managed
			 * endpoint.
			 */
			return DROP_UNROUTABLE;
		}

		if (is_privnet_route_entry(sip_val)) {
			/* If the packet is coming from a source which matches a route
			 * (i.e. there is no endpoint associated with it), we skip the
			 * egress policy check and redirect to the destination node using
			 * the privnet_unknown_flow identity.
			 */

			/* Perform a CT lookup using the pre-NAT destination to populate trace */
			ret = privnet_ct_unknown_flow_ingress_ipv4(ctx, ip4, &dip4,
								   *net_id, &trace);
			if (IS_ERR(ret))
				return ret;

			return encap_and_redirect_with_nodeid(ctx, info,
				CONFIG(privnet_unknown_sec_id), info->sec_identity,
				&trace, proto);
		}

		/* egress policy check is done after NAT to PIP and concluding that
		 * it is not an unknown flow.
		 */
		ret = privnet_ext_ep_policy_egress4(ctx, ip4, info->sec_identity,
						    &trace, &ext_err);
		if (ret != CTX_ACT_OK)
			return send_drop_notify_ext(ctx, identity,
						    info->sec_identity, 0,
						    ret, ext_err,
						    METRIC_EGRESS);

		return encap_and_redirect_with_nodeid(ctx, info,
						      identity, info->sec_identity,
						      &trace, proto);
#else
		return DROP_UNROUTABLE; /* require tunnel mode */
#endif
		break;
#endif /* ENABLE_IPV4 */
	default:
		break;
	}

	return ret;
}

static __always_inline int
enterprise_privnet_to_netdev(struct __ctx_buff *ctx, __u16 proto)
{
	const __u16 *local_net_id;

	if (!CONFIG(privnet_enable)) {
		/* Private networks is not enabled. We're always in P-IP space. */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
		return CTX_ACT_OK;
	}

	local_net_id = privnet_get_net_id(CONFIG(interface_ifindex));
	if (local_net_id && *local_net_id) {
		/* The netdev is directly attached to a private network. Anything entering
		 * or leaving this interface is in the configured network.
		 */
		set_privnet_net_ids(*local_net_id, *local_net_id);
		if (proto == bpf_htons(ETH_P_ARP))
			return handle_privnet_arp_egress(ctx, *local_net_id);
	} else if (!CONFIG(privnet_bridge_enable)) {
		/* We're not on the bridge, and the netdev is not attached to a private network.
		 * The source is always in PIP space. The destination is unknown, as it might be
		 * encapsulated unknown flow traffic. Let userspace figure it out.
		 */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);
	} else {
		/* We're on the bridge, and the netdev is not attached to a private network. The destination
		 * is always in PIP space. The source is unknown, as it might be encapsulated unknown flow
		 * traffic. Let userspace figure it out.
		 */
		set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);
	}

	return CTX_ACT_OK;
}

static __always_inline void enterprise_privnet_from_netdev(void)
{
	const __u16 *local_net_id;

	if (!CONFIG(privnet_enable))
		/* Private networks is not enabled. We're always in P-IP space. */
		return set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	local_net_id = privnet_get_net_id(CONFIG(interface_ifindex));
	if (local_net_id && *local_net_id)
		/* The netdev is directly attached to a private network. Anything entering
		 * or leaving this interface is in the configured network.
		 */
		return set_privnet_net_ids(*local_net_id, *local_net_id);

	if (!CONFIG(privnet_bridge_enable))
		/* We're not on the bridge, and the netdev is not attached to a private network.
		 * The destination is always in PIP space. The source is unknown, as it might be
		 * encapsulated unknown flow traffic. Let userspace figure it out.
		 */
		return set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	/* We're on the bridge, and the netdev is not attached to a private network. The source
	 * is always in PIP space. The destination is unknown, as it might be encapsulated unknown flow
	 * traffic. Let userspace figure it out.
	 */
	return set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);
}

static __always_inline void enterprise_privnet_to_host(void)
{
	/* The host is always in PIP space */
	return set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
}

static __always_inline void enterprise_privnet_from_host(void)
{
	/* The host is always in PIP space */
	return set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
}

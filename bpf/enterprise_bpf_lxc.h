/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/encap.h"
#include "lib/trace.h"
#include "lib/edt.h"

#include "lib/enterprise_inspection.h"
#include "lib/enterprise_privnet.h"
#include "lib/enterprise_evpn.h"
#include "lib/enterprise_vrf.h"

static __always_inline int enterprise_privnet_from_lxc(struct __ctx_buff *ctx __maybe_unused,
						       __u16 proto)
{
	void __maybe_unused *data, *data_end;
	struct ipv6hdr *ip6 __maybe_unused;
	struct iphdr *ip4 __maybe_unused;
	union v6addr sip6 __maybe_unused;
	const struct privnet_fib_val *dip_val __maybe_unused;
	const struct privnet_device_val *dev_val __maybe_unused;
	struct trace_ctx trace __maybe_unused = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret = CTX_ACT_OK;
	__u16 net_id;

	if (!CONFIG(privnet_enable)) {
		/* Privnet is not enabled. We're always in P-IP space */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
		return ret;
	}

	dev_val = privnet_get_device(CONFIG(interface_ifindex));
	if (unlikely(!dev_val)) {
		/* No configuration for this device */
		set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_UNKNOWN_NET_ID);
		return DROP_UNROUTABLE;
	}

	/* Private networks is enabled, but the network ID is unknown. */
	net_id = dev_val->net_id;
	if (unlikely(!net_id)) {
		set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_UNKNOWN_NET_ID);
		return DROP_UNROUTABLE;
	}

	/* We enter from the container, we're always in netIP space */
	set_privnet_net_ids(net_id, net_id);

	/* bpf_lxc will drop the packet as unsupported, return to normal control flow
	 * after setting the netID.
	 */
	if (!eth_is_supported_ethertype(proto))
		return ret;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		if (is_icmp6_ndp(ctx, ip6, ETH_HLEN))
			return handle_privnet_ns(ctx, net_id, &dev_val->ipv6);

		ipv6_addr_copy(&sip6, (union v6addr *)&ip6->saddr);

		/* Protect against source address spoofing */
		if (!ipv6_addr_equals(&sip6, &dev_val->ipv6))
			return DROP_INVALID_SIP;

		ctx_store_meta(ctx, CB_SRC_LABEL, net_id);
		return tail_call_internal(ctx, CILIUM_CALL_IPV6_PRIVNET_LXC_EGRESS, NULL);
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_ARP):
		return handle_privnet_arp(ctx, net_id, &dev_val->ipv4);
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* If this is a DHCP request redirect it to the 'cilium_dhcp' device */
		ret = privnet_redirect_dhcp_request(ctx, ip4);
		if (ret != CTX_ACT_OK)
			return ret;

		/* If no network IP assigned drop IP packets until one is assigned. */
		if (!dev_val->ipv4.be32)
			return DROP_INVALID_SIP;

		/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* Protect against source address spoofing */
		if (ip4->saddr != dev_val->ipv4.be32)
			return DROP_INVALID_SIP;

		ctx_store_meta(ctx, CB_SRC_LABEL, net_id);
		return tail_call_internal(ctx, CILIUM_CALL_IPV4_PRIVNET_LXC_EGRESS, NULL);
#endif /* ENABLE_IPV4 */
	default:
		break;
	}

	return ret;
}

__declare_tail(CILIUM_CALL_IPV4_PRIVNET_LXC_EGRESS)
static __always_inline int tail_handle_ipv4_privnet_lxc_egress(struct __ctx_buff *ctx)
{
	__u16 proto = bpf_htons(ETH_P_IP);
	const struct privnet_fib_val *dip_val;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	void *data, *data_end;
	struct iphdr *ip4;
	__s8 ext_err = 0;
	__u16 net_id;
	int ret;

	net_id = (__u16)ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	ret = privnet_egress_ipv4(ctx, SECLABEL_IPV4, net_id,
				  privnet_subnet_id_lookup4(net_id, ip4->saddr),
				  NULL, &dip_val,
				  &trace);
	if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
		goto out;

#ifdef TUNNEL_MODE
	if (dip_val && is_privnet_route_entry(dip_val)) {
		/* dip_val is route entry, we can assume that the */
		/* packet is going to INB. Encap the packet with IP */
		/* stored in privnet nat map, it will be node IP of INB and */
		/* with privnet_unknown_sec_id as VNI. */

		struct remote_endpoint_info fake_info = {0};

		fake_info.tunnel_endpoint.ip4 = dip_val->ip4;
		fake_info.sec_identity = CONFIG(privnet_unknown_sec_id);

		return encap_and_redirect_with_nodeid(ctx, &fake_info,
						      CONFIG(privnet_unknown_sec_id),
						      fake_info.sec_identity,
						      &trace, proto);
	}
#endif /* TUNNEL_MODE */

	send_trace_notify(ctx, TRACE_FROM_LXC, SECLABEL, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, TRACE_IFINDEX_UNKNOWN,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN, proto);

	edt_set_aggregate(ctx, LXC_ID);
	ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_LXC, &ext_err);
out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, SECLABEL_IPV4, UNKNOWN_ID,
					    TRACE_EP_ID_UNKNOWN, ret, ext_err,
					    METRIC_EGRESS);
	return ret;
}

__declare_tail(CILIUM_CALL_IPV6_PRIVNET_LXC_EGRESS)
static __always_inline int tail_handle_ipv6_privnet_lxc_egress(struct __ctx_buff *ctx)
{
	__u16 proto = bpf_htons(ETH_P_IPV6);
	const struct privnet_fib_val *dip_val;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__s8 ext_err = 0;
	__u16 net_id;
	int ret;

	net_id = (__u16)ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ret = privnet_egress_ipv6(ctx, SECLABEL_IPV6, net_id,
				  privnet_subnet_id_lookup6(net_id, *(union v6addr *)&ip6->saddr),
				  NULL, &dip_val,
				  &trace);
	if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
		goto out;

#ifdef TUNNEL_MODE
	if (dip_val && is_privnet_route_entry(dip_val)) {
		/* see comment for ipv4 */
		struct remote_endpoint_info fake_info = {0};

		/* only support v4 underlay for unknown flows. */
		fake_info.tunnel_endpoint.ip4 = dip_val->ip4;
		fake_info.sec_identity = CONFIG(privnet_unknown_sec_id);

		return encap_and_redirect_with_nodeid(ctx, &fake_info,
						      CONFIG(privnet_unknown_sec_id),
						      fake_info.sec_identity,
						      &trace, proto);
	}
#endif /* TUNNEL_MODE */

	send_trace_notify(ctx, TRACE_FROM_LXC, SECLABEL, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, TRACE_IFINDEX_UNKNOWN,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN, proto);

	edt_set_aggregate(ctx, LXC_ID);
	ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_LXC, &ext_err);
out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, SECLABEL_IPV6, UNKNOWN_ID,
					    TRACE_EP_ID_UNKNOWN, ret, ext_err,
					    METRIC_EGRESS);
	return ret;
}

static __always_inline int enterprise_privnet_to_lxc(struct __ctx_buff *ctx __maybe_unused)
{
	/* If we enter to_lxc we always need to be in P-IP space */
	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
	return CTX_ACT_OK;
}

#ifdef ENABLE_IPV4
static __always_inline int
enterprise_privnet_to_lxc_ipv4_after_policy(struct __ctx_buff *ctx)
{
	if (CONFIG(privnet_enable)) {
		int ret;
		const __u16 *net_id;

		net_id = privnet_get_net_id(CONFIG(interface_ifindex));
		if (unlikely(!net_id || !(*net_id)))
			return DROP_UNROUTABLE;

		ret = privnet_lxc_ingress_ipv4(ctx, SECLABEL_IPV4, *net_id, false, false, NULL);
		if (IS_ERR(ret))
			return ret;
	}
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static __always_inline int
enterprise_privnet_to_lxc_ipv6_after_policy(struct __ctx_buff *ctx)
{
	if (CONFIG(privnet_enable)) {
		int ret;
		const __u16 *net_id;

		net_id = privnet_get_net_id(CONFIG(interface_ifindex));
		if (unlikely(!net_id || !(*net_id)))
			return DROP_UNROUTABLE;

		ret = privnet_lxc_ingress_ipv6(ctx, SECLABEL_IPV6, *net_id, false, false, NULL);
		if (IS_ERR(ret))
			return ret;
	}
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPV6 */

static __always_inline bool is_privnet_unknown_inb_flow(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef HAVE_ENCAP
	if (ctx_load_meta(ctx, CB_FROM_TUNNEL)) {
		struct bpf_tunnel_key tunnel_key = {};

		if (ctx_get_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0) < 0)
			return false;

		if (tunnel_key.tunnel_id == CONFIG(privnet_unknown_sec_id))
			return true;
	}
#endif /* HAVE_ENCAP */
	return false;
}

static __always_inline bool
is_privnet_local_access_flow(struct __ctx_buff *ctx)
{
	__u16 netdev_net_id __maybe_unused;
	__u16 lxc_net_id __maybe_unused;
	const struct privnet_device_val *netdev_dev_val __maybe_unused;
	const struct privnet_device_val *lxc_dev_val __maybe_unused;

	if (CONFIG(privnet_local_access_enable)) {
		netdev_dev_val = privnet_get_device(ctx_get_ingress_ifindex(ctx));
		/* Traffic coming from another lxc device within the same private-network
		 * will also be present in privnet_get_device(lxc_idx). We need to explicitly
		 * check ingress interface is netdev device and current interface is lxc.
		 */
		if (!netdev_dev_val || netdev_dev_val->type != PRIVNET_DEVICE_TYPE_NETDEV)
			return false;

		netdev_net_id = netdev_dev_val->net_id;
		if (unlikely(!netdev_net_id))
			return false;

		lxc_dev_val = privnet_get_device(CONFIG(interface_ifindex));
		if (!lxc_dev_val || lxc_dev_val->type != PRIVNET_DEVICE_TYPE_LXC)
			return false;

		lxc_net_id = lxc_dev_val->net_id;
		if (unlikely(!lxc_net_id))
			return false;

		/* If the network ID of the ingress interface is the same as
		 * the lxc interface, it is N/S flow coming from local access
		 * interface.
		 */
		return netdev_net_id == lxc_net_id;
	}

	return false;
}

static __always_inline bool
is_privnet_evpn_flow(struct __ctx_buff *ctx)
{
	return (CONFIG(privnet_enable) && CONFIG(evpn_enable) &&
		ctx_get_ingress_ifindex(ctx) == CONFIG(evpn_device_ifindex));
}

static __always_inline bool
privnet_should_enforce_unknown_policy(struct __ctx_buff *ctx)
{
	return is_privnet_unknown_inb_flow(ctx) ||
	       is_privnet_local_access_flow(ctx) ||
	       is_privnet_evpn_flow(ctx);
}

__declare_tail(CILIUM_CALL_IPV4_PRIVNET_UNKNOWN_INGRESS)
static __always_inline int tail_handle_ipv4_privnet_unknown_ingress(struct __ctx_buff *ctx)
{
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool from_tunnel = false;
	int ret = CTX_ACT_OK;
	const __u16 *net_id;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	if (!CONFIG(privnet_enable))
		return ret;

	/* Private networks is enabled, but the network ID is unknown. */
	net_id = privnet_get_net_id(CONFIG(interface_ifindex));
	if (unlikely(!net_id || !(*net_id)))
		return DROP_UNROUTABLE;

#ifdef HAVE_ENCAP
	from_tunnel = ctx_load_meta(ctx, CB_FROM_TUNNEL);
#endif

	ret = privnet_lxc_ingress_ipv4(ctx, SECLABEL_IPV4, *net_id,
				       is_privnet_unknown_inb_flow(ctx),
				       is_privnet_evpn_flow(ctx) ||
					       is_privnet_local_access_flow(ctx),
				       &trace);
	if (IS_ERR(ret))
		return ret;

	send_trace_notify(ctx, TRACE_TO_LXC, WORLD_IPV4_ID, SECLABEL_IPV4, LXC_ID,
			  CONFIG(interface_ifindex), trace.reason, trace.monitor,
			  bpf_htons(ETH_P_IP));

	return redirect_ep(ctx, CONFIG(interface_ifindex),
			   should_redirect_peer(ctx, from_host), from_tunnel);
}

__declare_tail(CILIUM_CALL_IPV6_PRIVNET_UNKNOWN_INGRESS)
static __always_inline int tail_handle_ipv6_privnet_unknown_ingress(struct __ctx_buff *ctx)
{
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool from_tunnel = false;
	int ret = CTX_ACT_OK;
	const __u16 *net_id;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	if (!CONFIG(privnet_enable))
		return ret;

	/* Private networks is enabled, but the network ID is unknown. */
	net_id = privnet_get_net_id(CONFIG(interface_ifindex));
	if (unlikely(!net_id || !(*net_id)))
		return DROP_UNROUTABLE;

#ifdef HAVE_ENCAP
	from_tunnel = ctx_load_meta(ctx, CB_FROM_TUNNEL);
#endif

	ret = privnet_lxc_ingress_ipv6(ctx, SECLABEL_IPV6, *net_id,
				       is_privnet_unknown_inb_flow(ctx),
				       is_privnet_evpn_flow(ctx) ||
					       is_privnet_local_access_flow(ctx),
				       &trace);
	if (IS_ERR(ret))
		return ret;

	send_trace_notify(ctx, TRACE_TO_LXC, WORLD_IPV6_ID, SECLABEL_IPV6, LXC_ID,
			  CONFIG(interface_ifindex), trace.reason, trace.monitor,
			  bpf_htons(ETH_P_IPV6));

	return redirect_ep(ctx, CONFIG(interface_ifindex),
			   should_redirect_peer(ctx, from_host), from_tunnel);
}

static __always_inline int
enterprise_privnet_to_lxc_before_policy(struct __ctx_buff *ctx, __u16 proto,
					__s8 *ext_err __maybe_unused)
{
	int ret = CTX_ACT_OK;

	if (!CONFIG(privnet_enable))
		return ret;

	if (!privnet_should_enforce_unknown_policy(ctx))
		return ret;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_PRIVNET_UNKNOWN_INGRESS, ext_err);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_PRIVNET_UNKNOWN_INGRESS, ext_err);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	return ret;
}

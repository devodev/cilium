// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE
#define ENCAP_IFINDEX 1
#define EP_IFINDEX 99
#define EP_LXC_ID 0

/* default setting: known flow, set to 99 for unknown flow */
static __u32 privnet_tunnel_id = 199;

/* Enable debug output */
#define DEBUG

#define NETDEV_IFINDEX 1312

#include "enterprise_privnet_common.h"

/* packets defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_pod_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_pod_ip_icmp_req)
};

const __u8 privnet_net_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmp_req)
};

const __u8 privnet_pod_ip_icmp_req_to_endpoint[] = {
	SCAPY_BUF_BYTES(privnet_pod_ip_icmp_req_to_endpoint)
};

const __u8 privnet_pod_ipv6_icmp_req_to_endpoint[] = {
	SCAPY_BUF_BYTES(privnet_pod_ipv6_icmp_req_to_endpoint)
};

const __u8 privnet_unknown_flow_icmp_req_out[] = {
	SCAPY_BUF_BYTES(privnet_unknown_flow_icmp_req_out)
};

const __u8 privnet_unknown_flow_icmp_req_out_netip[] = {
	SCAPY_BUF_BYTES(privnet_unknown_flow_icmp_req_out_netip)
};

const __u8 privnet_unknown_flow_icmpv6_req_out[] = {
	SCAPY_BUF_BYTES(privnet_unknown_flow_icmpv6_req_out)
};

const __u8 privnet_unknown_flow_icmpv6_req_out_netip[] = {
	SCAPY_BUF_BYTES(privnet_unknown_flow_icmpv6_req_out_netip)
};

#include <bpf/config/node.h>
#include <lib/enterprise_ext_eps_maps.h>

static __always_inline int
mock_ext_eps_policy_can_access(const struct __ctx_buff *ctx __maybe_unused,
			       struct endpoint_key __maybe_unused *key,
			       __u32 __maybe_unused sec_identity, __u16 __maybe_unused ethertype,
			       __be16 __maybe_unused dport, __u8 __maybe_unused proto,
			       int __maybe_unused l4_off, __u8 __maybe_unused *match_type,
			       int __maybe_unused dir, bool __maybe_unused is_untracked_fragment,
			       __u8 __maybe_unused *audited, __s8 __maybe_unused *ext_err,
			       __u16 __maybe_unused *proxy_port, __u32 __maybe_unused *cookie)
{
	return CTX_ACT_OK;
}

#undef ext_ep_policy_verdict
#define ext_ep_policy_verdict mock_ext_eps_policy_can_access

#undef EFFECTIVE_EP_ID

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[EP_LXC_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

static struct {
	bool called;
	int ifindex;
	struct bpf_redir_neigh params;
	bool has_params;
	int plen;
	__u32 flags;
} redirect_neigh_recorder;

static struct {
	bool called;
	int ifindex;
	__u32 flags;
} ctx_redirect_recorder;

static __always_inline void reset_redirect_recorders(void)
{
	redirect_neigh_recorder.called = false;
	redirect_neigh_recorder.ifindex = 0;
	redirect_neigh_recorder.params = (struct bpf_redir_neigh){};
	redirect_neigh_recorder.has_params = false;
	redirect_neigh_recorder.plen = 0;
	redirect_neigh_recorder.flags = 0;

	ctx_redirect_recorder.called = false;
	ctx_redirect_recorder.ifindex = 0;
	ctx_redirect_recorder.flags = 0;
}

#define redirect_neigh mock_redirect_neigh
static __always_inline __maybe_unused int
mock_redirect_neigh(int ifindex, const struct bpf_redir_neigh *params,
		    int plen,
		    __u32 flags)
{
	redirect_neigh_recorder.called = true;
	redirect_neigh_recorder.ifindex = ifindex;
	redirect_neigh_recorder.plen = plen;
	redirect_neigh_recorder.flags = flags;
	if (params) {
		redirect_neigh_recorder.has_params = true;
		redirect_neigh_recorder.params = *params;
	}
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect mock_ctx_redirect
static __always_inline int
mock_ctx_redirect(const struct __sk_buff __maybe_unused *ctx, int ifindex,
		  __u32 flags)
{
	ctx_redirect_recorder.called = true;
	ctx_redirect_recorder.ifindex = ifindex;
	ctx_redirect_recorder.flags = flags;

	return CTX_ACT_REDIRECT;
}

#define ASSERT_REDIRECT_NEIGH_V4(__expected_nh, __expected_ifindex)		\
	do {									\
		if (!redirect_neigh_recorder.called)				\
			test_fatal("redirect_neigh was not called");		\
		if (ctx_redirect_recorder.called)				\
			test_fatal("ctx_redirect should not have been called");	\
		if (redirect_neigh_recorder.ifindex != (__expected_ifindex))	\
			test_fatal("unexpected redirect_neigh ifindex (got %d, want %d)", \
				   redirect_neigh_recorder.ifindex, (__expected_ifindex)); \
		if (!redirect_neigh_recorder.has_params)			\
			test_fatal("redirect_neigh should have params");	\
		if (redirect_neigh_recorder.plen != sizeof(struct bpf_redir_neigh)) \
			test_fatal("unexpected redirect_neigh params len (got %d, want %d)", \
				   redirect_neigh_recorder.plen,		\
				   (int)sizeof(struct bpf_redir_neigh));	\
		if (redirect_neigh_recorder.params.nh_family != AF_INET)	\
			test_fatal("unexpected redirect_neigh family (got %d, want %d)", \
				   redirect_neigh_recorder.params.nh_family, AF_INET); \
		if (redirect_neigh_recorder.params.ipv4_nh != (__expected_nh)) \
			test_fatal("unexpected redirect_neigh nexthop");	\
	} while (0)

#define ASSERT_REDIRECT_NEIGH_V6(__expected_nh, __expected_ifindex)		\
	do {									\
		if (!redirect_neigh_recorder.called)				\
			test_fatal("redirect_neigh was not called");		\
		if (ctx_redirect_recorder.called)				\
			test_fatal("ctx_redirect should not have been called");	\
		if (redirect_neigh_recorder.ifindex != (__expected_ifindex))	\
			test_fatal("unexpected redirect_neigh ifindex (got %d, want %d)", \
				   redirect_neigh_recorder.ifindex, (__expected_ifindex)); \
		if (!redirect_neigh_recorder.has_params)			\
			test_fatal("redirect_neigh should have params");	\
		if (redirect_neigh_recorder.plen != sizeof(struct bpf_redir_neigh)) \
			test_fatal("unexpected redirect_neigh params len (got %d, want %d)", \
				   redirect_neigh_recorder.plen,		\
				   (int)sizeof(struct bpf_redir_neigh));	\
		if (redirect_neigh_recorder.params.nh_family != AF_INET6)	\
			test_fatal("unexpected redirect_neigh family (got %d, want %d)", \
				   redirect_neigh_recorder.params.nh_family, AF_INET6); \
		if (memcmp(&redirect_neigh_recorder.params.ipv6_nh, (__expected_nh), \
			   sizeof(redirect_neigh_recorder.params.ipv6_nh)) != 0) \
			test_fatal("unexpected redirect_neigh nexthop");	\
	} while (0)

#define ASSERT_CTX_REDIRECT(__expected_ifindex)		\
	do {									\
		if (!ctx_redirect_recorder.called)				\
			test_fatal("ctx_redirect was not called");		\
		if (ctx_redirect_recorder.ifindex != (__expected_ifindex))	\
			test_fatal("unexpected ctx_redirect ifindex (got %d, want %d)", \
				   ctx_redirect_recorder.ifindex, (__expected_ifindex)); \
		if (ctx_redirect_recorder.flags != 0) \
			test_fatal("unexpected ctx_redirect flags (got %x, want 0)", \
				   ctx_redirect_recorder.flags);		\
	} while (0)

/* Include an actual datapath code */
#include "lib/bpf_overlay.h"

#include "tests/lib/endpoint.h"
#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/network_device.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, false)
ASSIGN_CONFIG(bool, privnet_bridge_enable, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */

PKTGEN("tc", "01_icmp_from_overlay_nat_src_dst_v4")
int privnet_icmp_from_overlay_nat_src_dst_v4_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_pod_ip_icmp_req);
	return 0;
}

SETUP("tc", "01_icmp_from_overlay_nat_src_dst_v4")
int privnet_icmp_from_overlay_nat_src_dst_v4_setup(struct __ctx_buff *ctx)
{
	reset_redirect_recorders();

	cilium_device_add_entry(NETDEV_IFINDEX, (__u8 *)mac_one, 0);

	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	__privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1,
					NETDEV_IFINDEX, (const union macaddr *)mac_one);
	__privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2,
					NETDEV_IFINDEX, (const union macaddr *)mac_two);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "01_icmp_from_overlay_nat_src_dst_v4")
int privnet_icmp_from_overlay_nat_src_dst_v4_check(struct __ctx_buff *ctx)
{
	test_init();

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);

	cilium_device_del_entry(NETDEV_IFINDEX);

	/* packets are redirected to netdev device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	ASSERT_CTX_REDIRECT(NETDEV_IFINDEX);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_overlay_nat_src_dst_v4", "Ether", ctx,
			   sizeof(__u32), privnet_net_ip_icmp_req,
			   sizeof(privnet_net_ip_icmp_req));

	assert_privnet_net_ids(NET_ID, NET_ID);

	reset_redirect_recorders();

	test_finish();
}

PKTGEN("tc", "02_icmp_from_overlay_to_local_endpoint")
int privnet_icmp_from_overlay_to_local_endpoint_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_pod_ip_icmp_req_to_endpoint);
	return 0;
}

SETUP("tc", "02_icmp_from_overlay_to_local_endpoint")
int privnet_icmp_from_overlay_to_local_endpoint_setup(struct __ctx_buff *ctx)
{
	/* Create an endpoint map entry to force local delivery */
	endpoint_v4_add_entry(V4_EP_IP, EP_IFINDEX, EP_LXC_ID, 0, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_four);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "02_icmp_from_overlay_to_local_endpoint")
int privnet_icmp_from_overlay_to_local_endpoint_check(struct __ctx_buff *ctx)
{
	test_init();

	endpoint_v4_del_entry(V4_EP_IP);

	assert_status_code(ctx, CTX_ACT_OK);

	test_finish();
}

PKTGEN("tc", "03_icmp_from_overlay_to_local_endpoint_v6")
int privnet_icmp_from_overlay_to_local_endpoint_v6_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_pod_ipv6_icmp_req_to_endpoint);
	return 0;
}

SETUP("tc", "03_icmp_from_overlay_to_local_endpoint_v6")
int privnet_icmp_from_overlay_to_local_endpoint_v6_setup(struct __ctx_buff *ctx)
{
	/* Create an endpoint map entry to force local delivery */
	endpoint_v6_add_entry((const union v6addr *)v6_ep_ip, EP_IFINDEX, EP_LXC_ID, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_four);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "03_icmp_from_overlay_to_local_endpoint_v6")
int privnet_icmp_from_overlay_to_local_endpoint_v6_check(struct __ctx_buff *ctx)
{
	test_init();

	endpoint_v6_del_entry((const union v6addr *)v6_ep_ip);

	assert_status_code(ctx, CTX_ACT_OK);

	test_finish();
}

PKTGEN("tc", "04_icmp_from_overlay_nat_src_unknown_dst_v4")
int privnet_icmp_from_overlay_nat_src_unknown_dst_v4_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_unknown_flow_icmp_req_out);
	return 0;
}

SETUP("tc", "04_icmp_from_overlay_nat_src_unknown_dst_v4")
int privnet_icmp_from_overlay_nat_src_unknown_dst_v4_setup(struct __ctx_buff *ctx)
{
	/* tunnel ID for unknown flow */
	privnet_tunnel_id = 99;

	reset_redirect_recorders();

	cilium_device_add_entry(NETDEV_IFINDEX, (__u8 *)mac_two, 0);

	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	__privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1,
					NETDEV_IFINDEX, (const union macaddr *)mac_one);
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN, GATEWAY_IP,
				    NETDEV_IFINDEX);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "04_icmp_from_overlay_nat_src_unknown_dst_v4")
int privnet_icmp_from_overlay_nat_src_unknown_dst_v4_check(struct __ctx_buff *ctx)
{
	test_init();

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);

	cilium_device_del_entry(NETDEV_IFINDEX);

	/* packets are redirected to netdev device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	ASSERT_REDIRECT_NEIGH_V4(V4_NET_IP_2, NETDEV_IFINDEX);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_overlay_nat_src_unknown_dst_v4", "Ether", ctx,
			   sizeof(__u32), privnet_unknown_flow_icmp_req_out_netip,
			   sizeof(privnet_unknown_flow_icmp_req_out_netip));

	assert_privnet_net_ids(NET_ID, NET_ID);

	reset_redirect_recorders();

	test_finish();
}

PKTGEN("tc", "05_icmpv6_from_overlay_nat_src_unknown_dst_v6")
int privnet_icmpv6_from_overlay_nat_src_unknown_dst_v6_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_unknown_flow_icmpv6_req_out);
	return 0;
}

SETUP("tc", "05_icmpv6_from_overlay_nat_src_unknown_dst_v6")
int privnet_icmpv6_from_overlay_nat_src_unknown_dst_v6_setup(struct __ctx_buff *ctx)
{
	/* tunnel ID for unknown flow */
	privnet_tunnel_id = 99;

	reset_redirect_recorders();

	cilium_device_add_entry(NETDEV_IFINDEX, (__u8 *)mac_two, 0);

	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	__privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
					(const union v6addr *)V6_NET_IP_1,
					(const union v6addr *)V6_POD_IP_1,
					NETDEV_IFINDEX, (const union macaddr *)mac_one);
	privnet_v6_add_subnet_route(NET_ID, SUBNET_ID,
				    (const union v6addr *)V6_NET_IP_2,
				    (const union v6addr *)V6_EXT_IP,
				    NETDEV_IFINDEX);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "05_icmpv6_from_overlay_nat_src_unknown_dst_v6")
int privnet_icmpv6_from_overlay_nat_src_unknown_dst_v6_check(struct __ctx_buff *ctx)
{
	test_init();

	privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);

	cilium_device_del_entry(NETDEV_IFINDEX);

	/* packets are redirected to netdev device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	ASSERT_REDIRECT_NEIGH_V6((const union v6addr *)V6_NET_IP_2, NETDEV_IFINDEX);

	ASSERT_CTX_BUF_OFF("privnet_icmpv6_from_overlay_nat_src_unknown_dst_v6", "Ether", ctx,
			   sizeof(__u32), privnet_unknown_flow_icmpv6_req_out_netip,
			   sizeof(privnet_unknown_flow_icmpv6_req_out_netip));

	assert_privnet_net_ids(NET_ID, NET_ID);

	reset_redirect_recorders();

	test_finish();
}

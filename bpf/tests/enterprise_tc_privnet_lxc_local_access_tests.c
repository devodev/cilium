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
#define privnet_tunnel_id 99

/* Enable debug output */
#define DEBUG

#define LXC_IFINDEX IFINDEX
#define NETDEV_IFINDEX 142

static struct {
	bool called;
	int ifindex;
	struct bpf_redir_neigh params;
	bool has_params;
	int plen;
	__u32 flags;
} redirect_neigh_recorder;

static __always_inline void reset_redirect_recorder(void)
{
	redirect_neigh_recorder.called = false;
	redirect_neigh_recorder.ifindex = 0;
	redirect_neigh_recorder.params = (struct bpf_redir_neigh){};
	redirect_neigh_recorder.has_params = false;
	redirect_neigh_recorder.plen = 0;
	redirect_neigh_recorder.flags = 0;
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

#define ASSERT_REDIRECT_NEIGH_V4(__expected_nh, __expected_ifindex)		\
	do {									\
		if (!redirect_neigh_recorder.called)				\
			test_fatal("redirect_neigh was not called");		\
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

#include "enterprise_privnet_common.h"

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmp_req)
};

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_icmpv6_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmpv6_req)
};

#include "lib/bpf_lxc.h"

#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/policy.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, LXC_IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set lxc mac */
ASSIGN_CONFIG(__u32, security_label, 100) /* set lxc security label */

static const union v4addr lxc_privnet_ipv4 = { .be32 = V4_NET_IP_1 };
static const union v6addr lxc_privnet_ipv6 = { .addr = v6_svc_one_addr };

PKTGEN("tc", "01_local_access_egress_from_lxc_v4")
int privnet_local_access_egress_from_lxc_v4_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "01_local_access_egress_from_lxc_v4")
int privnet_local_access_egress_from_lxc_v4_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(LXC_IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_add_device_entry(NETDEV_IFINDEX, NET_ID, NULL, NULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, GATEWAY_IP, NETDEV_IFINDEX);

	policy_add_egress_allow_all_entry();
	return pod_send_packet(ctx);
}

CHECK("tc", "01_local_access_egress_from_lxc_v4")
int privnet_local_access_egress_from_lxc_v4_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to netdev device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	ASSERT_REDIRECT_NEIGH_V4(V4_NET_IP_2, NETDEV_IFINDEX);

	/* check inner packet headers, src & dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_local_access_egress_from_lxc_v4", "IP", ctx,
			   sizeof(__u32), privnet_net_ip_icmp_req,
			   sizeof(privnet_net_ip_icmp_req));

	assert_privnet_net_ids(NET_ID, NET_ID);

	policy_delete_entry(false, 0, 0, 0, 0);
	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(NETDEV_IFINDEX);
	privnet_del_device_entry(LXC_IFINDEX);

	reset_redirect_recorder();

	test_finish();
}

PKTGEN("tc", "02_local_access_egress_from_lxc_v6")
int privnet_local_access_egress_from_lxc_v6_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmpv6_req);
	return 0;
}

SETUP("tc", "02_local_access_egress_from_lxc_v6")
int privnet_local_access_egress_from_lxc_v6_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(LXC_IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_add_device_entry(NETDEV_IFINDEX, NET_ID, NULL, NULL);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (union v6addr *)V6_NET_IP_1,
				      (union v6addr *)V6_POD_IP_1);
	privnet_v6_add_subnet_route(NET_ID, SUBNET_ID,
				    (union v6addr *)V6_NET_IP_2,
				    (union v6addr *)V6_EXT_IP,
				    NETDEV_IFINDEX);

	return pod_send_packet(ctx);
}

CHECK("tc", "02_local_access_egress_from_lxc_v6")
int privnet_local_access_egress_from_lxc_v6_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to netdev device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	ASSERT_REDIRECT_NEIGH_V6((union v6addr *)V6_NET_IP_2, NETDEV_IFINDEX);

	/* check inner packet headers, src & dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_local_access_egress_from_lxc_v6", "IPv6", ctx,
			   sizeof(__u32), privnet_net_ip_icmpv6_req,
			   sizeof(privnet_net_ip_icmpv6_req));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v6_del_route(NET_ID, SUBNET_ID,
			     (union v6addr *)V6_NET_IP_2);
	privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
				      (union v6addr *)V6_NET_IP_1,
				      (union v6addr *)V6_POD_IP_1);
	privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);
	privnet_del_device_entry(NETDEV_IFINDEX);
	privnet_del_device_entry(LXC_IFINDEX);

	reset_redirect_recorder();

	test_finish();
}

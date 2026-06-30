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

#define CILIUM_DHCP_IFINDEX 123

#include "enterprise_privnet_common.h"

/* packets defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmp_req)
};

const __u8 privnet_pod_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_pod_ip_icmp_req)
};

const __u8 privnet_net_ip_icmpv6_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmpv6_req)
};

const __u8 privnet_pod_ip_icmpv6_req[] = {
	SCAPY_BUF_BYTES(privnet_pod_ip_icmpv6_req)
};

const __u8 privnet_net_ip_arp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_arp_req)
};

const __u8 privnet_net_ip_arp_res[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_arp_res)
};

const __u8 privnet_net_ip_arp_req_egress[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_arp_req_egress)
};

const __u8 privnet_net_ip_garp_egress[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_garp_egress)
};

const __u8 privnet_net_ip_arp_probe[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_arp_probe)
};

const __u8 privnet_netdev_ns[] = {
	SCAPY_BUF_BYTES(privnet_netdev_ns)
};

const __u8 privnet_netdev_na[] = {
	SCAPY_BUF_BYTES(privnet_netdev_na)
};

#include <bpf/config/node.h>
#include <lib/enterprise_ext_eps_maps.h>

static int redirect_target_ifindex;
static __u32 redirect_src_ifindex;

#define ctx_redirect mock_ctx_redirect
static __always_inline int
mock_ctx_redirect(const struct __sk_buff __maybe_unused *ctx, int ifindex,
		  __u32 __maybe_unused flags)
{
	__u8 smac[ETH_ALEN];

	if (!skb_load_bytes((struct __sk_buff *)ctx, ETH_ALEN, smac, sizeof(smac)))
		redirect_src_ifindex = smac[2] << 24 | smac[3] << 16 | smac[4] << 8 | smac[5];

	redirect_target_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

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
#undef EVENT_SOURCE

/* Include an actual datapath code */
#include "lib/bpf_host.h"

#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/ipcache.h"

static __always_inline int privnet_watchdog_set(__u64 last, __u64 timeout)
{
	__u32 liveness_key = PRIVNET_WATCHDOG_LIVENESS;
	__u32 timeout_key = PRIVNET_WATCHDOG_TIMEOUT;
	int ret;

	ret = map_update_elem(&cilium_privnet_watchdog, &liveness_key, &last, BPF_ANY);
	if (ret < 0)
		return ret;

	return map_update_elem(&cilium_privnet_watchdog, &timeout_key, &timeout, BPF_ANY);
}

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, false)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, IFINDEX)
ASSIGN_CONFIG(__u32, cilium_dhcp_ifindex, CILIUM_DHCP_IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set device mac */

static __always_inline int
build_privnet_dhcp_reply(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ipv4_udp_packet(&builder, (__u8 *)mac_one,
					  (__u8 *)mac_two, V4_POD_IP_1,
					  IPV4(255, 255, 255, 255),
					  bpf_htons(DHCP_SERVER_PORT),
					  bpf_htons(DHCP_CLIENT_PORT)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "01_icmp_from_netdev_nat_src_dst")
int privnet_icmp_from_netdev_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "01_icmp_from_netdev_nat_src_dst")
int privnet_icmp_from_netdev_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	last_tunnel_id = 0;

	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	ipcache_v4_add_entry(V4_POD_IP_1, 0, 1001, INB_IP, 0);
	ipcache_v4_add_entry(V4_POD_IP_2, 0, 1002, NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "01_icmp_from_netdev_nat_src_dst")
int privnet_icmp_from_netdev_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to tunnel device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	assert_tunnel_id(1001);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_netdev_nat_src_dst", "Ether", ctx,
			   sizeof(__u32), privnet_pod_ip_icmp_req,
			   sizeof(privnet_pod_ip_icmp_req));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "01_bis_icmp_from_netdev_v6_nat_src_dst")
int privnet_icmp_from_netdev_v6_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmpv6_req);
	return 0;
}

SETUP("tc", "01_bis_icmp_from_netdev_v6_nat_src_dst")
int privnet_icmp_from_netdev_v6_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	last_tunnel_id = 0;

	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_2,
				      (const union v6addr *)V6_POD_IP_2);

	ipcache_v6_add_entry((const union v6addr *)V6_POD_IP_1, 0, 1011, INB_IP, 0);
	ipcache_v6_add_entry((const union v6addr *)V6_POD_IP_2, 0, 1012, NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "01_bis_icmp_from_netdev_v6_nat_src_dst")
int privnet_icmp_from_netdev_v6_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to tunnel device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	assert_tunnel_id(1011);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_netdev_v6_nat_src_dst", "Ether", ctx,
			   sizeof(__u32), privnet_pod_ip_icmpv6_req,
			   sizeof(privnet_pod_ip_icmpv6_req));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_2,
				      (const union v6addr *)V6_POD_IP_2);
	privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "02_icmp_from_netdev_respond_arp")
int privnet_icmp_from_netdev_respond_arp_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_arp_req);
	return 0;
}

SETUP("tc", "02_icmp_from_netdev_respond_arp")
int privnet_icmp_from_netdev_respond_arp_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns(), 3000000000ULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "02_icmp_from_netdev_respond_arp")
int privnet_icmp_from_netdev_respond_arp_check(struct __ctx_buff *ctx)
{
	test_init();

	/* The ARP response should be redirected back */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_netdev_respond_arp", "Ether", ctx,
			   sizeof(__u32), privnet_net_ip_arp_res,
			   sizeof(privnet_net_ip_arp_res));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "03_icmp_from_netdev_respond_arp_agent_down")
int privnet_icmp_from_netdev_respond_arp_pktgen_agent_down(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_arp_req);
	return 0;
}

SETUP("tc", "03_icmp_from_netdev_respond_arp_agent_down")
int privnet_icmp_from_netdev_respond_arp_setup_agent_down(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns() - 5000000000ULL, 3000000000ULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "03_icmp_from_netdev_respond_arp_agent_down")
int privnet_icmp_from_netdev_respond_arp_check_agent_down(struct __ctx_buff *ctx)
{
	test_init();

	/* No ARP response should be emitted */
	assert_status_code(ctx, TC_ACT_OK);

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "04_icmp6_from_netdev_respond_ns")
int privnet_icmp6_from_netdev_respond_ns_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_netdev_ns);
	return 0;
}

SETUP("tc", "04_icmp6_from_netdev_respond_ns")
int privnet_icmp6_from_netdev_respond_ns_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns(), 3000000000ULL);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "04_icmp6_from_netdev_respond_ns")
int privnet_icmp6_from_netdev_respond_ns_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected back to device */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("privnet_icmp6_from_netdev_respond_ns", "Ether", ctx,
			   sizeof(__u32), privnet_netdev_na,
			   sizeof(privnet_netdev_na));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "05_icmp6_from_netdev_respond_ns_agent_down")
int privnet_icmp6_from_netdev_respond_ns_pktgen_agent_down(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_netdev_ns);
	return 0;
}

SETUP("tc", "05_icmp6_from_netdev_respond_ns_agent_down")
int privnet_icmp6_from_netdev_respond_ns_setup_agent_down(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns() - 5000000000ULL, 3000000000ULL);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "05_icmp6_from_netdev_respond_ns_agent_down")
int privnet_icmp6_from_netdev_respond_ns_check_agent_down(struct __ctx_buff *ctx)
{
	test_init();

	/* No ARP response should be emitted */
	assert_status_code(ctx, TC_ACT_OK);

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "06_icmp_from_netdev_miss_src")
int privnet_icmp_from_netdev_miss_src_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "06_icmp_from_netdev_miss_src")
int privnet_icmp_from_netdev_miss_src_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	ipcache_v4_add_entry(V4_POD_IP_2, 0, 1002, NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "06_icmp_from_netdev_miss_src")
int privnet_icmp_from_netdev_miss_src_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packet should be dropped */
	assert_status_code(ctx, DROP_UNROUTABLE);

	assert_privnet_net_ids(NET_ID, PRIVNET_PIP_NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "07_icmp_from_netdev_miss_dst")
int privnet_icmp_from_netdev_miss_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "07_icmp_from_netdev_miss_dst")
int privnet_icmp_from_netdev_miss_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	ipcache_v4_add_entry(V4_POD_IP_1, 0, 1001, INB_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "07_icmp_from_netdev_miss_dst")
int privnet_icmp_from_netdev_miss_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packet should be dropped */
	assert_status_code(ctx, DROP_UNROUTABLE);

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "08_icmp_from_netdev_miss_net_id")
int privnet_icmp_from_netdev_miss_net_id_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "08_icmp_from_netdev_miss_net_id")
int privnet_icmp_from_netdev_miss_net_id_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, 0, NULL, NULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	ipcache_v4_add_entry(V4_POD_IP_1, 0, 1001, INB_IP, 0);
	ipcache_v4_add_entry(V4_POD_IP_2, 0, 1002, NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "08_icmp_from_netdev_miss_net_id")
int privnet_icmp_from_netdev_miss_net_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packet should be dropped */
	assert_status_code(ctx, DROP_UNROUTABLE);
	assert_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "09_dhcp_reply_from_netdev_redirect")
int privnet_dhcp_reply_from_netdev_redirect_pktgen(struct __ctx_buff *ctx)
{
	return build_privnet_dhcp_reply(ctx);
}

SETUP("tc", "09_dhcp_reply_from_netdev_redirect")
int privnet_dhcp_reply_from_netdev_redirect_setup(struct __ctx_buff *ctx)
{
	redirect_target_ifindex = 0;
	redirect_src_ifindex = 0;

	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "09_dhcp_reply_from_netdev_redirect")
int privnet_dhcp_reply_from_netdev_redirect_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_REDIRECT);

	if (redirect_target_ifindex != CILIUM_DHCP_IFINDEX)
		test_fatal("unexpected redirect ifindex (expected %d, got %d)",
			   CILIUM_DHCP_IFINDEX, redirect_target_ifindex);

	/* The source mac address should changed to the ifindex to which the
	 * reply originally arrived before redirecting it to cilium_dhcp.
	 */
	if (redirect_src_ifindex != IFINDEX)
		test_fatal("unexpected source mac (expected %x, got %x)",
			   IFINDEX, redirect_src_ifindex);

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "10_arp_egress_sip_rewritten")
int privnet_arp_egress_sip_rewritten_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_arp_req_egress);
	return 0;
}

SETUP("tc", "10_arp_egress_sip_rewritten")
int privnet_arp_egress_sip_rewritten_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns(), 3000000000ULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_arp_sender(NET_ID, SUBNET_ID, V4_NET_IP_1);

	return netdev_send_packet(ctx);
}

CHECK("tc", "10_arp_egress_sip_rewritten")
int privnet_arp_egress_sip_rewritten_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_arp_egress_sip_rewritten", "Ether", ctx,
			   sizeof(__u32), privnet_net_ip_arp_req,
			   sizeof(privnet_net_ip_arp_req));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_arp_sender(NET_ID, SUBNET_ID);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "11_arp_egress_garp_unchanged")
int privnet_arp_egress_garp_unchanged_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_garp_egress);
	return 0;
}

SETUP("tc", "11_arp_egress_garp_unchanged")
int privnet_arp_egress_garp_unchanged_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns(), 3000000000ULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_arp_sender(NET_ID, SUBNET_ID, V4_NET_IP_1);

	return netdev_send_packet(ctx);
}

CHECK("tc", "11_arp_egress_garp_unchanged")
int privnet_arp_egress_garp_unchanged_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_arp_egress_garp_unchanged", "Ether", ctx,
			   sizeof(__u32), privnet_net_ip_garp_egress,
			   sizeof(privnet_net_ip_garp_egress));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_arp_sender(NET_ID, SUBNET_ID);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "12_arp_egress_probe_no_sender_cache")
int privnet_arp_egress_probe_no_sender_cache_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_arp_req_egress);
	return 0;
}

SETUP("tc", "12_arp_egress_probe_no_sender_cache")
int privnet_arp_egress_probe_no_sender_cache_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns(), 3000000000ULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	/* intentionally no privnet_v4_add_arp_sender() */

	return netdev_send_packet(ctx);
}

CHECK("tc", "12_arp_egress_probe_no_sender_cache")
int privnet_arp_egress_probe_no_sender_cache_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_arp_egress_probe_no_sender_cache", "Ether", ctx,
			   sizeof(__u32), privnet_net_ip_arp_probe,
			   sizeof(privnet_net_ip_arp_probe));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "13_arp_egress_probe_watchdog_expired")
int privnet_arp_egress_probe_watchdog_expired_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_arp_req_egress);
	return 0;
}

SETUP("tc", "13_arp_egress_probe_watchdog_expired")
int privnet_arp_egress_probe_watchdog_expired_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_watchdog_set(ktime_get_ns() - 5000000000ULL, 3000000000ULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_arp_sender(NET_ID, SUBNET_ID, V4_NET_IP_1);

	return netdev_send_packet(ctx);
}

CHECK("tc", "13_arp_egress_probe_watchdog_expired")
int privnet_arp_egress_probe_watchdog_expired_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_arp_egress_probe_watchdog_expired", "Ether", ctx,
			   sizeof(__u32), privnet_net_ip_arp_probe,
			   sizeof(privnet_net_ip_arp_probe));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_arp_sender(NET_ID, SUBNET_ID);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

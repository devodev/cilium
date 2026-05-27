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
#define CIDR_IDENTITY 5678

static int redirect_target_ifindex;

#define ctx_redirect mock_ctx_redirect
static __always_inline int mock_ctx_redirect(const struct __sk_buff __maybe_unused *ctx,
					     int ifindex, __u32 __maybe_unused flags)
{
	redirect_target_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#include <bpf/config/node.h>
#include "node_config.h"
#include "lib/trace.h"
#undef EVENT_SOURCE

#undef send_trace_notify
#define send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor, proto) \
	mock_send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor, proto)

static struct {
	bool valid;
	enum trace_point obs_point;
	__u32		src_label;
	__u32		dst_label;
} last_notify;

static __always_inline void
mock_send_trace_notify(struct __ctx_buff *ctx __maybe_unused, enum trace_point obs_point,
		       __u32 src, __u32 dst, __u16 dst_id __maybe_unused,
		       __u32 ifindex __maybe_unused, enum trace_reason reason __maybe_unused,
		       __u32 monitor __maybe_unused, __be16 proto __maybe_unused)
{
	last_notify.valid = true;
	last_notify.obs_point = obs_point;
	last_notify.src_label = src;
	last_notify.dst_label = dst;
}

static __always_inline void reset_mock_notify(void)
{
	last_notify.valid = false;
	last_notify.obs_point = 0;
	last_notify.src_label = 0;
	last_notify.dst_label = 0;
}

#include "enterprise_privnet_common.h"

/* packets defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmp_req)
};

const __u8 privnet_pod_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_pod_ip_icmp_req)
};

const __u8 privnet_net_ip_tcp_syn[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_tcp_syn)
};

const __u8 privnet_pod_ip_tcp_syn[] = {
	SCAPY_BUF_BYTES(privnet_pod_ip_tcp_syn)
};

const __u8 privnet_unknown_flow_icmp_req_out[] = {
	SCAPY_BUF_BYTES(privnet_unknown_flow_icmp_req_out)
};

const __u8 privnet_unknown_flow_icmp_req_in[] = {
	SCAPY_BUF_BYTES(privnet_unknown_flow_icmp_req_in)
};

const __u8 privnet_lxc_ns_ll[] = {
	SCAPY_BUF_BYTES(privnet_lxc_ns_ll)
};

const __u8 privnet_lxc_na_ll[] = {
	SCAPY_BUF_BYTES(privnet_lxc_na_ll)
};

const __u8 privnet_lxc_ns_ep1[] = {
	SCAPY_BUF_BYTES(privnet_lxc_ns_ep1)
};

const __u8 privnet_lxc_na_ep1[] = {
	SCAPY_BUF_BYTES(privnet_lxc_na_ep1)
};

const __u8 privnet_lxc_ns_ep2[] = {
	SCAPY_BUF_BYTES(privnet_lxc_ns_ep2)
};

const __u8 privnet_lxc_ns_self[] = {
	SCAPY_BUF_BYTES(privnet_lxc_ns_self)
};

const __u8 privnet_net_ip_arp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_arp_req)
};

const __u8 privnet_net_ip_icmp_req_x_subnet[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmp_req_x_subnet)
};

const __u8 privnet_pod_ip_icmp_req_x_subnet[] = {
	SCAPY_BUF_BYTES(privnet_pod_ip_icmp_req_x_subnet)
};

const __u8 privnet_net_ipv6_tcp_syn[] = {
	SCAPY_BUF_BYTES(privnet_net_ipv6_tcp_syn)
};

const __u8 privnet_pod_ipv6_tcp_syn[] = {
	SCAPY_BUF_BYTES(privnet_pod_ipv6_tcp_syn)
};

#include "lib/bpf_lxc.h"

/* Include test helpers */
#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/ipcache.h"
#include "tests/lib/policy.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, false)
ASSIGN_CONFIG(bool, privnet_host_reachability, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, IFINDEX)
ASSIGN_CONFIG(__u32, cilium_dhcp_ifindex, CILIUM_DHCP_IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set lxc mac */
ASSIGN_CONFIG(__u32, security_label, 1234) /* set lxc security identity */

static const union v4addr lxc_privnet_ipv4 = { .be32 = V4_NET_IP_1 };
static const union v4addr lxc_privnet_ipv4_other = { .be32 = V4_NET_IP_2 };
static const union v6addr lxc_privnet_ipv6 = { .addr = v6_svc_one_addr };

PKTGEN("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), privnet_pod_ip_icmp_req,
			   sizeof(privnet_pod_ip_icmp_req));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_delete_egress_all_entry();
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* IPv4 TCP SYN packet, this test is required to validate checksum is calculated
 * correctly post NAT.
 */

PKTGEN("tc", "02_tcp_from_container_nat_src_dst")
int privnet_tcp_from_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_tcp_syn);
	return 0;
}

SETUP("tc", "02_tcp_from_container_nat_src_dst")
int privnet_tcp_from_container_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "02_tcp_from_container_nat_src_dst")
int privnet_tcp_from_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_tcp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), privnet_pod_ip_tcp_syn,
			   sizeof(privnet_pod_ip_tcp_syn));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_delete_egress_all_entry();
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* ICMP packet routed via unknown subnet route */

PKTGEN("tc", "03_icmp_from_container_nat_src_route_dst")
int privnet_icmp_from_container_nat_src_route_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "03_icmp_from_container_nat_src_route_dst")
int privnet_icmp_from_container_nat_src_route_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1); /* source entry */
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN, INB_IP, 0); /* destination entry */

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	reset_mock_notify();

	return pod_send_packet(ctx);
}

CHECK("tc", "03_icmp_from_container_nat_src_route_dst")
int privnet_icmp_from_container_nat_src_route_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* redirected via unknown flow */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	/* check inner packet headers, dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_route_dst", "IP", ctx,
			   sizeof(__u32), privnet_unknown_flow_icmp_req_out,
			   sizeof(privnet_unknown_flow_icmp_req_out));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, NET_ID);

	if (!last_notify.valid || last_notify.obs_point != TRACE_TO_OVERLAY)
		test_fatal("expected TRACE_TO_OVERLAY trace_notify to be emitted");

	if (last_notify.dst_label != WORLD_IPV4_ID)
		test_fatal("expected TRACE_TO_OVERLAY dst_label %d, got %d",
			   WORLD_IPV4_ID, last_notify.dst_label);
	if (last_notify.src_label != 99)
		test_fatal("expected TRACE_TO_OVERLAY src_label %d, got %d",
			   98, last_notify.src_label);

	policy_delete_egress_all_entry();
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* ICMP packet dropped due to egress segmentation rule */

PKTGEN("tc", "04_icmp_from_container_nat_src_miss_dst")
int privnet_icmp_from_container_nat_src_miss_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "04_icmp_from_container_nat_src_miss_dst")
int privnet_icmp_from_container_nat_src_miss_dst_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);

	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1); /* only source entry */

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "04_icmp_from_container_nat_src_miss_dst")
int privnet_icmp_from_container_nat_src_miss_dst_check(struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	test_init();

	assert_status_code(ctx, CTX_ACT_DROP); /* drop check*/

	/* check reason for drop */
	key.reason = (__u8)-DROP_UNROUTABLE;
	key.dir = METRIC_EGRESS;
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, NET_ID);

	__u64 count = 1;
	assert_metrics_count(key, count);

	policy_delete_egress_all_entry();
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* Ingress packets going to container */

PKTGEN("tc", "05_icmp_to_container_nat_src_dst")
int privnet_icmp_to_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_pod_ip_icmp_req);
	return 0;
}

SETUP("tc", "05_icmp_to_container_nat_src_dst")
int privnet_icmp_to_container_nat_src_route_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "05_icmp_to_container_nat_src_dst")
int privnet_icmp_to_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_to_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), privnet_net_ip_icmp_req,
			   sizeof(privnet_net_ip_icmp_req));

	assert_privnet_net_ids(NET_ID, NET_ID);

	policy_delete_entry(false, 0, 0, 0, 0);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* TCP packet going to container */
PKTGEN("tc", "06_tcp_to_container_nat_src_dst")
int privnet_tcp_to_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_pod_ip_tcp_syn);
	return 0;
}

SETUP("tc", "06_tcp_to_container_nat_src_dst")
int privnet_tcp_to_container_nat_src_route_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "06_tcp_to_container_nat_src_dst")
int privnet_tcp_to_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_tcp_to_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), privnet_net_ip_tcp_syn,
			   sizeof(privnet_net_ip_tcp_syn));

	assert_privnet_net_ids(NET_ID, NET_ID);

	policy_delete_entry(false, 0, 0, 0, 0);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* Ingress packet coming from unknown source */
PKTGEN("tc", "07_icmp_to_container_unknown_src_nat_dst")
int privnet_icmp_to_container_unknown_src_nat_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_pod_ip_icmp_req);
	return 0;
}

SETUP("tc", "07_icmp_to_container_unknown_src_nat_dst")
int privnet_icmp_to_container_unknown_src_nat_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	/* dst is known, no entry for src */
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);
	reset_mock_notify();
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "07_icmp_to_container_unknown_src_nat_dst")
int privnet_icmp_to_container_unknown_src_nat_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("privnet_icmp_to_container_unknown_src_nat_dst", "IP", ctx,
			   sizeof(__u32), privnet_unknown_flow_icmp_req_out,
			   sizeof(privnet_unknown_flow_icmp_req_out));

	assert_privnet_net_ids(NET_ID, NET_ID);

	if (!last_notify.valid || last_notify.obs_point != TRACE_TO_LXC)
		test_fatal("expected TRACE_TO_LXC trace_notify to be emitted");

	if (last_notify.src_label != WORLD_IPV4_ID)
		test_fatal("expected TRACE_TO_LXC src_label %d, got %d",
			   WORLD_IPV4_ID, last_notify.src_label);

	policy_delete_entry(false, 0, 0, 0, 0);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* Ingress packet coming from unknown source and destination is missing
 * in privnet maps.
 */
PKTGEN("tc", "08_icmp_to_container_unknown_src_miss_dst")
int privnet_icmp_to_container_unknown_src_miss_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_pod_ip_icmp_req);
	return 0;
}

SETUP("tc", "08_icmp_to_container_unknown_src_miss_dst")
int privnet_icmp_to_container_unknown_src_miss_dst_setup(struct __ctx_buff *ctx)
{
	/* no entry for dst */
	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);

	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "08_icmp_to_container_unknown_src_miss_dst")
int privnet_icmp_to_container_unknown_src_miss_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, DROP_UNROUTABLE); /* drop check*/

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_delete_entry(false, 0, 0, 0, 0);
	test_finish();
}

/* IPv6 test cases */

/* Placeholder for PRIVNET_ICMP6_NS_CHECK invocations where the
 * STATUS_CODE != TC_ACT_REDIRECT branch is dead but the buffer expression
 * still has to typecheck.
 */
const __u8 __UNUSED__[1] = { 0 };

static __always_inline int privnet_icmp6_ns_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_2,
				      (const union v6addr *)V6_POD_IP_2);

	return pod_send_packet(ctx);
}

#define PRIVNET_ICMP6_NS_CHECK(CTX, TEST_NAME, STATUS_CODE, NA_BUF_NAME)	\
	do {									\
		test_init();							\
										\
		assert_status_code(CTX, (STATUS_CODE));				\
		if (STATUS_CODE == TC_ACT_REDIRECT) {				\
			ASSERT_CTX_BUF_OFF(TEST_NAME, "Ether", CTX,		\
				sizeof(__u32), NA_BUF_NAME,			\
				sizeof(NA_BUF_NAME));				\
		}								\
										\
		privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,		\
			(const union v6addr *)V6_NET_IP_1,			\
			(const union v6addr *)V6_POD_IP_1);			\
		privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,		\
			(const union v6addr *)V6_NET_IP_2,			\
			(const union v6addr *)V6_POD_IP_2);			\
		privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);  \
		privnet_del_device_entry(IFINDEX);				\
										\
		test_finish();							\
	} while (0)

/* Neighbor solicitation response generated for link local address */
PKTGEN("tc", "09_icmp6_from_container_neighbor_solicitation_link_local")
int privnet_icmp6_from_container_neighbor_solicitation_link_local_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_lxc_ns_ll);
	return 0;
}

SETUP("tc", "09_icmp6_from_container_neighbor_solicitation_link_local")
int privnet_icmp6_from_container_neighbor_solicitation_link_local_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "09_icmp6_from_container_neighbor_solicitation_link_local")
int privnet_icmp6_from_container_neighbor_solicitation_link_local_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "09_icmp6_from_container_neighbor_solicitation_link_local",
			       TC_ACT_REDIRECT, privnet_lxc_na_ll
	);
}

/* Neighbor solicitation response generated for endpoint address */
PKTGEN("tc", "10_icmp6_from_container_neighbor_solicitation_ep_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_match_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_lxc_ns_ep1);
	return 0;
}

SETUP("tc", "10_icmp6_from_container_neighbor_solicitation_ep_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_match_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "10_icmp6_from_container_neighbor_solicitation_ep_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_match_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "10_icmp6_from_container_neighbor_solicitation_ep_match",
			       TC_ACT_REDIRECT, privnet_lxc_na_ep1
	);
}

/* Neighbor solicitation response should not be generated for endpoint address not in FIB map */
PKTGEN("tc", "11_icmp6_from_container_neighbor_solicitation_ep_no_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_no_match_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_lxc_ns_ep2);
	return 0;
}

SETUP("tc", "11_icmp6_from_container_neighbor_solicitation_ep_no_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_no_match_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "11_icmp6_from_container_neighbor_solicitation_ep_no_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_no_match_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "10_icmp6_from_container_neighbor_solicitation_ep_no_match",
			       TC_ACT_SHOT, __UNUSED__
	);
}

/* Neighbor solicitation response should not be generated for the self endpoint address */
PKTGEN("tc", "12_icmp6_from_container_neighbor_solicitation_self")
int privnet_icmp6_from_container_neighbor_solicitation_self_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_lxc_ns_self);
	return 0;
}

SETUP("tc", "12_icmp6_from_container_neighbor_solicitation_self")
int privnet_icmp6_from_container_neighbor_solicitation_self_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "12_icmp6_from_container_neighbor_solicitation_self")
int privnet_icmp6_from_container_neighbor_solicitation_self_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "12_icmp6_from_container_neighbor_solicitation_self",
			       TC_ACT_SHOT, __UNUSED__
	);
}

PKTGEN("tc", "13_icmp_from_container_missing_net_id")
int privnet_icmp_from_container_missing_net_id_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "13_icmp_from_container_missing_net_id")
int privnet_icmp_from_container_missing_net_id_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);

	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	return pod_send_packet(ctx);
}

CHECK("tc", "13_icmp_from_container_missing_net_id")
int privnet_icmp_from_container_missing_net_id_check(struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	__u64 count = 1;

	test_init();

	assert_status_code(ctx, CTX_ACT_DROP); /* drop check */

	/* check reason for drop */
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	assert_metrics_count(key, count);

	assert_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_UNKNOWN_NET_ID);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	test_finish();
}

/* ARP request for the privnet IPv4 should be dropped to allow DHCP renewals.
 * If we don't drop them DHCP clients will decline the IP as they detect a conflict
 * when the "arping" for the offered address.
 */

PKTGEN("tc", "14_arp_from_container_privnet_ip_match")
int privnet_arp_from_container_privnet_ip_mismatch_pktgen(struct __ctx_buff *ctx)
{

	build_privnet_packet(ctx, privnet_net_ip_arp_req);
	return 0;
}

SETUP("tc", "14_arp_from_container_privnet_ip_match")
int privnet_arp_from_container_privnet_ip_mismatch_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4_other,
				 &lxc_privnet_ipv6);
	return pod_send_packet(ctx);
}

CHECK("tc", "14_arp_from_container_privnet_ip_match")
int privnet_arp_from_container_privnet_ip_mismatch_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_DROP);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "15_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_pktgen(struct __ctx_buff *ctx)
{
	return build_privnet_dhcp_request_to(ctx, dhcp_bcast_mac,
					     IPV4(255, 255, 255, 255));
}

SETUP("tc", "15_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_setup(struct __ctx_buff *ctx)
{
	redirect_target_ifindex = 0;
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4,
				 &lxc_privnet_ipv6);
	return pod_send_packet(ctx);
}

CHECK("tc", "15_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_REDIRECT);
	if (redirect_target_ifindex != CILIUM_DHCP_IFINDEX)
		test_fatal("unexpected redirect ifindex (expected %d, got %d)",
			   CILIUM_DHCP_IFINDEX, redirect_target_ifindex);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "16_dhcp_from_container_unicast_redirect")
int privnet_dhcp_from_container_unicast_redirect_pktgen(struct __ctx_buff *ctx)
{
	return build_privnet_dhcp_request_to(ctx, (__u8 *)mac_two, V4_NET_IP_1);
}

SETUP("tc", "16_dhcp_from_container_unicast_redirect")
int privnet_dhcp_from_container_unicast_redirect_setup(struct __ctx_buff *ctx)
{
	redirect_target_ifindex = 0;
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4,
				 &lxc_privnet_ipv6);

	return pod_send_packet(ctx);
}

CHECK("tc", "16_dhcp_from_container_unicast_redirect")
int privnet_dhcp_from_container_unicast_redirect_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_REDIRECT);
	if (redirect_target_ifindex != CILIUM_DHCP_IFINDEX)
		test_fatal("unexpected redirect ifindex (expected %d, got %d)",
			   CILIUM_DHCP_IFINDEX, redirect_target_ifindex);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "17_tcp_from_container_spoofed_drop")
int privnet_tcp_from_container_spoofed_drop_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_tcp_syn);

	return 0;
}

SETUP("tc", "17_tcp_from_container_spoofed_drop")
int privnet_tcp_from_container_spoofed_drop_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);

	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4_other, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	return pod_send_packet(ctx);
}

CHECK("tc", "17_tcp_from_container_spoofed_drop")
int privnet_tcp_from_container_spoofed_drop_check(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_INVALID_SIP,
		.dir = METRIC_EGRESS,
	};
	struct metrics_value *entry = NULL;
	__u64 count = 1;

	test_init();

	/* dropped due to source address mismatch */
	assert_status_code(ctx, CTX_ACT_DROP);

	/* check reason for drop */
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	assert_privnet_net_ids(NET_ID, NET_ID);

	assert_metrics_count(key, count);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "18_icmp_from_container_to_other_subnet_nat_src_dst")
int privnet_icmp_from_container_to_other_subnet_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req_x_subnet);
	return 0;
}

SETUP("tc", "18_icmp_from_container_to_other_subnet_nat_src_dst")
int privnet_icmp_from_container_to_other_subnet_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN, OTHER_SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);

	privnet_v4_add_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4,
				     OTHER_SUBNET_V4_LEN, NET_ID, OTHER_SUBNET_ID);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "18_icmp_from_container_to_other_subnet_nat_src_dst")
int privnet_icmp_from_container_to_other_subnet_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), privnet_pod_ip_icmp_req_x_subnet,
			   sizeof(privnet_pod_ip_icmp_req_x_subnet));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	privnet_v4_del_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);

	policy_delete_egress_all_entry();
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_v4_del_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "19_icmp_from_container_peering_route_conflict")
int privnet_icmp_from_container_peering_route_conflict_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req_x_subnet);
	return 0;
}

SETUP("tc", "19_icmp_from_container_peering_route_conflict")
int privnet_icmp_from_container_peering_route_conflict_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN, OTHER_SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);

	privnet_v4_add_static_route(NET_ID, SUBNET_ID, V4_NET_IP_3, V4_PRIVNET_KEY_LEN, V4_POD_IP_1,
				    0);
	privnet_v4_add_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN,
				     NET_ID, OTHER_SUBNET_ID);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "19_icmp_from_container_peering_route_conflict")
int privnet_icmp_from_container_peering_route_conflict_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), privnet_pod_ip_icmp_req_x_subnet,
			   sizeof(privnet_pod_ip_icmp_req_x_subnet));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_delete_egress_all_entry();

	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_3, V4_PRIVNET_KEY_LEN);
	privnet_v4_del_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_v4_del_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "20_icmp_from_container_no_peering_route_match")
int privnet_icmp_from_container_no_peering_route_match_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "20_icmp_from_container_no_peering_route_match")
int privnet_icmp_from_container_no_peering_route_match_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN, OTHER_SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);

	/* Will only match static route */
	privnet_v4_add_static_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN, V4_POD_IP_1,
				    0);
	privnet_v4_add_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN,
				     NET_ID, OTHER_SUBNET_ID);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "20_icmp_from_container_no_peering_route_match")
int privnet_icmp_from_container_no_peering_route_match_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_REDIRECT);

	/* check inner packet headers, dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_route_dst", "IP", ctx,
			   sizeof(__u32), privnet_unknown_flow_icmp_req_out,
			   sizeof(privnet_unknown_flow_icmp_req_out));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, NET_ID);

	policy_delete_egress_all_entry();

	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN);
	privnet_v4_del_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_v4_del_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

PKTGEN("tc", "21_icmp_from_container_no_peering_route_match_drop")
int privnet_icmp_from_container_no_peering_route_match_drop_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "21_icmp_from_container_no_peering_route_match_drop")
int privnet_icmp_from_container_no_peering_route_match_drop_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN, OTHER_SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);

	privnet_v4_add_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN,
				     NET_ID, OTHER_SUBNET_ID);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "21_icmp_from_container_no_peering_route_match_drop")
int privnet_icmp_from_container_no_peering_route_match_drop_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_SHOT);

	policy_delete_egress_all_entry();

	privnet_v4_del_peering_route(NET_ID, SUBNET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, OTHER_SUBNET_ID, V4_NET_IP_3, V4_POD_IP_3);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_v4_del_subnet_entry(NET_ID, OTHER_SUBNET_V4, OTHER_SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* Tests unknown flow egress policy. Because the policy map is empty,
 * we expect this ICMP request to be dropped.
 */

PKTGEN("tc", "22_icmp_from_container_unknown_policy_denied")
int privnet_icmp_from_container_unknown_policy_denied_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "22_icmp_from_container_unknown_policy_denied")
int privnet_icmp_from_container_unknown_policy_denied_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_POLICY,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);

	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1); /* source entry */
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN, INB_IP, 0); /* destination entry */

	return pod_send_packet(ctx);
}

CHECK("tc", "22_icmp_from_container_unknown_policy_denied")
int privnet_icmp_from_container_unknown_policy_denied_check(struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {
		.reason = (__u8)-DROP_POLICY,
		.dir = METRIC_EGRESS,
	};
	__u64 count = 1;

	test_init();

	/* drop check */
	assert_status_code(ctx, CTX_ACT_DROP);

	/* check reason for drop */
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	assert_metrics_count(key, count);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* Tests unknown flow egress policy. The target identity is explicitly allowed
 * in the policy map and added to the CIDR identities map.
 */

PKTGEN("tc", "23_icmp_from_container_unknown_policy_allowed")
int privnet_icmp_from_container_unknown_policy_allowed_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

SETUP("tc", "23_icmp_from_container_unknown_policy_allowed")
int privnet_icmp_from_container_unknown_policy_allowed_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1); /* source entry */
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN, INB_IP, 0); /* destination entry */

	policy_add_egress_allow_l3_entry(CIDR_IDENTITY);
	privnet_v4_add_cidr_identity_entry(SUBNET_V4, SUBNET_V4_LEN, CIDR_IDENTITY);

	reset_mock_notify();

	return pod_send_packet(ctx);
}

CHECK("tc", "23_icmp_from_container_unknown_policy_allowed")
int privnet_icmp_from_container_unknown_policy_allowed_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_REDIRECT);

	if (!last_notify.valid || last_notify.obs_point != TRACE_TO_OVERLAY)
		test_fatal("expected TRACE_TO_OVERLAY trace_notify to be emitted");

	if (last_notify.dst_label != CIDR_IDENTITY)
		test_fatal("expected TRACE_TO_OVERLAY dst_label %d, got %d",
			   CIDR_IDENTITY, last_notify.dst_label);

	privnet_v4_del_cidr_identity_entry(SUBNET_V4, SUBNET_V4_LEN);
	policy_delete_egress_l3_entry(CIDR_IDENTITY);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_PRIVNET_KEY_LEN);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* Tests unknown flow ingress policy. Because the policy map is empty,
 * we expect this ICMP request to be dropped.
 */

PKTGEN("tc", "24_icmp_to_container_unknown_policy_denied")
int privnet_to_container_unknown_policy_denied_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_unknown_flow_icmp_req_in);
	return 0;
}

SETUP("tc", "24_icmp_to_container_unknown_policy_denied")
int privnet_to_container_unknown_policy_denied_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "24_icmp_to_container_unknown_policy_denied")
int privnet_icmp_to_container_unknown_policy_denied_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, DROP_POLICY);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* Tests unknown flow ingress policy. This adds an explicit policy deny
 * entry for the prefix.
 */

PKTGEN("tc", "25_icmp_to_container_unknown_policy_explicit_deny")
int privnet_to_container_unknown_policy_explicit_deny_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_unknown_flow_icmp_req_in);
	return 0;
}

SETUP("tc", "25_icmp_to_container_unknown_policy_explicit_deny")
int privnet_to_container_unknown_policy_explicit_deny_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	/* ingress allow from all */
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	/* ingress deny for CIDR identity */
	policy_add_entry(false, CIDR_IDENTITY, 0, 0, 0, true, 0);
	privnet_v4_add_cidr_identity_entry(SUBNET_V4, SUBNET_V4_LEN, CIDR_IDENTITY);

	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "25_icmp_to_container_unknown_policy_explicit_deny")
int privnet_icmp_to_container_unknown_policy_explicit_deny_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, DROP_POLICY_DENY);

	privnet_v4_del_cidr_identity_entry(SUBNET_V4, SUBNET_V4_LEN);
	policy_delete_entry(false, CIDR_IDENTITY, 0, 0, 0);
	policy_delete_entry(false, 0, 0, 0, 0);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* IPv6 TCP SYN packet, this test is required to validate checksum is calculated
 * correctly post NAT.
 */

PKTGEN("tc", "26_tcp_from_container_v6_nat_src_dst")
int privnet_tcp_from_container_v6_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ipv6_tcp_syn);
	return 0;
}

SETUP("tc", "26_tcp_from_container_v6_nat_src_dst")
int privnet_tcp_from_container_v6_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_2,
				      (const union v6addr *)V6_POD_IP_2);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "26_tcp_from_container_v6_nat_src_dst")
int privnet_tcp_from_container_v6_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_tcp_from_container_v6_nat_src_dst", "IPv6", ctx,
			   sizeof(__u32), privnet_pod_ipv6_tcp_syn,
			   sizeof(privnet_pod_ipv6_tcp_syn));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_delete_egress_all_entry();
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

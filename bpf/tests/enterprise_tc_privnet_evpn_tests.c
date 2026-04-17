// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/config/global.h> /* Needed for interface_mac config */
#include "bpf/helpers.h"
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define privnet_tunnel_id 99
#define LXC_IFINDEX 321
#define LXC_ID 123

/* Enable debug output */
#define DEBUG

/* Mock lxc policy call - will be called from privnet_evpn_ingress
 *
 */
__section_entry
	int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		   [LXC_ID] = &mock_handle_policy,
		   },
};

# define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include <bpf/config/node.h>

#include <lib/enterprise_privnet.h>
#include "tests/lib/endpoint.h"
#include "enterprise_privnet_common.h"
#include "tests/lib/enterprise_evpn.h"
#include "tests/lib/enterprise_privnet.h"

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_icmp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_icmp_req)
};

/* packet defined in ./scapy/enterprise_evpn_pkt_defs.py */
const __u8 evpn_icmpv6_req[] = {
	SCAPY_BUF_BYTES(evpn_icmpv6_req)
};

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_arp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_arp_req)
};

/* Enable configurations */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, evpn_enable, true)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_one_addr }) /* set device mac */
ASSIGN_CONFIG(__u32, evpn_device_ifindex, 123)
ASSIGN_CONFIG(union macaddr, evpn_device_mac, {.addr = mac_two_addr })

PKTGEN("tc", "01_privnet_evpn_ingress_v4")
int privnet_evpn_ingress_v4_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_icmp_req);
	return 0;
}

CHECK("tc", "01_privnet_evpn_ingress_v4")
int privnet_evpn_ingress_v4_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("baseline", {
		__u32 status_code;

		privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
		privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_1);
		endpoint_v4_add_entry(V4_POD_IP_1, LXC_IFINDEX, LXC_ID, 0, 0, 0,
				      (const __u8 *)mac_four, (const __u8 *)mac_five);

		status_code = __privnet_evpn_ingress(ctx, NET_ID);

		privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
		privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_1);
		endpoint_v4_del_entry(V4_POD_IP_1);

		if (status_code != TC_ACT_REDIRECT)
			test_fatal("unexpected status code (expected %d, got %d)",
				   TC_ACT_REDIRECT, status_code);
	});

	TEST("drop_fib_miss", {
		__u32 status_code;

		privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
		status_code = __privnet_evpn_ingress(ctx, NET_ID);
		privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);

		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	TEST("drop_route_entry", {
		__u32 status_code;

		privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
		privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, INB_IP, 0);

		status_code = __privnet_evpn_ingress(ctx, NET_ID);

		privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2);
		privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);

		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	TEST("drop_endpoint_miss", {
		__u32 status_code;

		privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
		privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_1);

		status_code = __privnet_evpn_ingress(ctx, NET_ID);

		privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_1);
		privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);

		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	test_finish();
}

PKTGEN("tc", "02_privnet_evpn_ingress_v6")
int privnet_evpn_ingress_v6_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, evpn_icmpv6_req);
	return 0;
}

CHECK("tc", "02_privnet_evpn_ingress_v6")
int privnet_evpn_ingress_v6_check(struct __ctx_buff *ctx)
{
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV6,
	};

	test_init();

	TEST("baseline", {
		__u32 status_code;

		privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
		privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
					      (const union v6addr *)V6_NET_IP_1,
					      (const union v6addr *)V6_POD_IP_1);
		endpoint_v6_add_entry((const union v6addr *)V6_POD_IP_1, LXC_IFINDEX, LXC_ID, 0, 0,
				      (const __u8 *)mac_four, (const __u8 *)mac_five);

		status_code = __privnet_evpn_ingress(ctx, NET_ID);

		privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
					      (const union v6addr *)V6_NET_IP_1,
					      (const union v6addr *)V6_POD_IP_1);
		privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);
		memcpy(&ep_key.ip6, (const union v6addr *)V6_POD_IP_1, sizeof(ep_key.ip6));
		map_delete_elem(&cilium_lxc, &ep_key);

		if (status_code != TC_ACT_REDIRECT)
			test_fatal("unexpected status code (expected %d, got %d)",
				   TC_ACT_REDIRECT, status_code);
	});

	TEST("drop_fib_miss", {
		__u32 status_code;

		privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
		status_code = __privnet_evpn_ingress(ctx, NET_ID);
		privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);

		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	TEST("drop_route_entry", {
		__u32 status_code;

		privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
		privnet_v6_add_subnet_route(NET_ID, SUBNET_ID,
					    (const union v6addr *)V6_NET_IP_1,
					    (const union v6addr *)V6_POD_IP_2, 0);

		status_code = __privnet_evpn_ingress(ctx, NET_ID);

		privnet_v6_del_route(NET_ID, SUBNET_ID, (const union v6addr *)V6_NET_IP_1);
		privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);

		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	TEST("drop_endpoint_miss", {
		__u32 status_code;

		privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
		privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
					      (const union v6addr *)V6_NET_IP_1,
					      (const union v6addr *)V6_POD_IP_1);

		status_code = __privnet_evpn_ingress(ctx, NET_ID);

		privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
					      (const union v6addr *)V6_NET_IP_1,
					      (const union v6addr *)V6_POD_IP_1);
		privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);

		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	test_finish();
}

PKTGEN("tc", "03_privnet_evpn_ingress_non_ip")
int privnet_evpn_ingress_non_ip_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_arp_req);
	return 0;
}

CHECK("tc", "03_privnet_evpn_ingress_non_ip")
int privnet_evpn_ingress_non_ip_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("drop_unknown_l3", {
		__u32 status_code;

		status_code = __privnet_evpn_ingress(ctx, NET_ID);
		if (status_code != (__u32)DROP_UNKNOWN_L3)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNKNOWN_L3, status_code);
	});

	test_finish();
}

CHECK("tc", "04_privnet_evpn_egress_v4")
int privnet_evpn_egress_v4_check(struct __ctx_buff *ctx)
{
	struct privnet_fib_val dip_val = {};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();

	TEST("evpn enabled but non vxlan route", {
		__u32 status_code;

		dip_val.type = PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE;
		status_code = privnet_evpn_egress_ipv4(ctx, NET_ID, LXC_ID,
						       &dip_val, V4_NET_IP_1,
						       &trace);
		if (status_code != CTX_ACT_OK)
			test_fatal("unexpected status code (expected %d, got %d)",
				   CTX_ACT_OK, status_code);
	});

	TEST("evpn enabled and vxlan route no fib match", {
		__u32 status_code;

		dip_val.type = PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE;
		status_code = privnet_evpn_egress_ipv4(ctx, NET_ID, LXC_ID,
						       &dip_val, V4_NET_IP_1,
						       &trace);
		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	TEST("evpn enabled and vxlan route with fib match", {
		__u32 status_code;
		union macaddr nexthop_mac = { .addr = mac_one_addr };

		dip_val.type = PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE;
		evpn_fib_v4_add_nh4(NET_ID, V4_NET_IP_1, 32, 100, nexthop_mac, v4_node_one);
		status_code = privnet_evpn_egress_ipv4(ctx, NET_ID, LXC_ID,
						       &dip_val, V4_NET_IP_1,
						       &trace);
		evpn_fib_v4_del(NET_ID, V4_NET_IP_1, 32);
		if (status_code != TC_ACT_REDIRECT)
			test_fatal("unexpected status code (expected %d, got %d)",
				   TC_ACT_REDIRECT, status_code);
	});

	test_finish();
}

CHECK("tc", "05_privnet_evpn_egress_v6")
int privnet_evpn_egress_v6_check(struct __ctx_buff *ctx)
{
	struct privnet_fib_val dip_val = {};
	union v6addr dst_ip = {};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();
	memcpy(&dst_ip, (const union v6addr *)V6_NET_IP_1, sizeof(dst_ip));

	TEST("evpn enabled but non vxlan route", {
		__u32 status_code;

		dip_val.type = PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE;
		status_code = privnet_evpn_egress_ipv6(ctx, NET_ID, LXC_ID,
						       &dip_val, dst_ip,
						       &trace);
		if (status_code != CTX_ACT_OK)
			test_fatal("unexpected status code (expected %d, got %d)",
				   CTX_ACT_OK, status_code);
	});

	TEST("evpn enabled and vxlan route no fib match", {
		__u32 status_code;

		dip_val.type = PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE;
		status_code = privnet_evpn_egress_ipv6(ctx, NET_ID, LXC_ID,
						       &dip_val, dst_ip,
						       &trace);
		if (status_code != (__u32)DROP_UNROUTABLE)
			test_fatal("unexpected status code (expected %d, got %d)",
				   DROP_UNROUTABLE, status_code);
	});

	TEST("evpn enabled and vxlan route with fib match", {
		__u32 status_code;
		union v6addr v6_nexthop = { .addr = v6_node_one_addr };
		union macaddr nexthop_mac = { .addr = mac_one_addr };

		dip_val.type = PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE;
		evpn_fib_v6_add_nh6(NET_ID, &dst_ip, 128, 100, nexthop_mac, &v6_nexthop);
		status_code = privnet_evpn_egress_ipv6(ctx, NET_ID, LXC_ID,
						       &dip_val, dst_ip,
						       &trace);
		evpn_fib_v6_del(NET_ID, &dst_ip, 128);
		if (status_code != TC_ACT_REDIRECT)
			test_fatal("unexpected status code (expected %d, got %d)",
				   TC_ACT_REDIRECT, status_code);
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");

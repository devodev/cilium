// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/config/global.h> /* Needed for interface_mac config */
#include "common.h"
#include "pktgen.h"

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define privnet_tunnel_id 99

/* Enable debug output */
#define DEBUG

#include <bpf/config/node.h>

#include <lib/enterprise_privnet.h>
#include "tests/lib/endpoint.h"
#include "enterprise_privnet_common.h"

/* Enable configurations */
ASSIGN_CONFIG(bool, evpn_enable, false)
ASSIGN_CONFIG(__u32, interface_ifindex, IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_one_addr })

CHECK("tc", "01_privnet_evpn_egress_disabled_v4")
int privnet_evpn_egress_disabled_v4_check(struct __ctx_buff *ctx)
{
	struct privnet_fib_val dip_val = {};
	int status_code;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	test_init();

	dip_val.type = PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE;
	status_code = privnet_evpn_egress_ipv4(ctx, NET_ID, 1, &dip_val,
					       V4_NET_IP_1, &trace);
	if (status_code != CTX_ACT_OK)
		test_fatal("unexpected status code (expected %d, got %d)",
			   CTX_ACT_OK, status_code);

	test_finish();
}

CHECK("tc", "02_privnet_evpn_egress_disabled_v6")
int privnet_evpn_egress_disabled_v6_check(struct __ctx_buff *ctx)
{
	struct privnet_fib_val dip_val = {};
	union v6addr dst_ip = {};
	__u32 status_code;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();
	memcpy(&dst_ip, (const union v6addr *)V6_NET_IP_1, sizeof(dst_ip));

	dip_val.type = PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE;
	status_code = privnet_evpn_egress_ipv6(ctx, NET_ID, 1, &dip_val,
					       &dst_ip, &trace);
	if (status_code != CTX_ACT_OK)
		test_fatal("unexpected status code (expected %d, got %d)",
			   CTX_ACT_OK, status_code);

	test_finish();
}

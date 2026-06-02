// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_IPV6

/* Enable debug output */
#define DEBUG

#include "enterprise_tc_evpn_egress_common.h"

/* Enable configurations */
ASSIGN_CONFIG(bool, evpn_enable, true)
ASSIGN_CONFIG(__u32, evpn_device_ifindex, 123)
ASSIGN_CONFIG(union macaddr, evpn_device_mac, {.addr = mac_two_addr })
/* Do not assign evpn_source_ipv4/6 here; this object covers the no-source path. */

CHECK("tc", "evpn_encap_and_redirect_no_source_ip")
int evpn_encap_and_redirect_no_source_ip_check(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;
	int ret;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();

	if (data + sizeof(*eth) > data_end)
		test_fatal("packet too short for ethhdr");

	eth = data;

	cleanup_test_state(eth);

	evpn_setup_fib();

	TEST("evpn_encap_and_redirect IPv4 no source", {
		ret = evpn_encap_and_redirect4(ctx, 1, 1, EVPN_V4_ADDR0, &trace);
		if (ret != TC_ACT_REDIRECT)
			test_error("Expect TC_ACT_REDIRECT, but got %d", ret);

		if (last_tunnel_key_size != TUNNEL_KEY_WITHOUT_SRC_IP)
			test_error("Expected tunnel key without source IP");

		if (last_tunnel_key.local_ipv4 != 0)
			test_error("Unexpected local_ipv4");

		cleanup_test_state(eth);
	});

	TEST("evpn_encap_and_redirect IPv6 no source", {
		ret = evpn_encap_and_redirect6(ctx, 1, 1, EVPN_V6_ADDR0, &trace);
		if (ret != TC_ACT_REDIRECT)
			test_error("Expect TC_ACT_REDIRECT, but got %d", ret);

		if (last_tunnel_key_size != TUNNEL_KEY_WITHOUT_SRC_IP)
			test_error("Expected tunnel key without source IP");

		if (last_tunnel_key.local_ipv6[0] || last_tunnel_key.local_ipv6[1] ||
		    last_tunnel_key.local_ipv6[2] || last_tunnel_key.local_ipv6[3])
			test_error("Unexpected local_ipv6");

		cleanup_test_state(eth);
	});

	evpn_cleanup_fib();

	test_finish();

	return 0;
}

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* This file contains tests for uninitialized privnet endpoints, i.e. endpoints
 * that do not yet have an assigned network IP.
 */

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

static int redirect_target_ifindex;

#define ctx_redirect mock_ctx_redirect
static __always_inline int mock_ctx_redirect(const struct __sk_buff __maybe_unused *ctx,
					     int ifindex, __u32 __maybe_unused flags)
{
	redirect_target_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#include "enterprise_privnet_common.h"

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_arp_req[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_arp_req)
};

#include "lib/bpf_lxc.h"

/* Include test helpers */
#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/policy.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, false)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, IFINDEX)
ASSIGN_CONFIG(__u32, cilium_dhcp_ifindex, CILIUM_DHCP_IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set lxc mac */

static const union v6addr lxc_privnet_ipv6 = { .addr = v6_svc_one_addr };

/* ARP request should be dropped when privnet_ipv4 is unset */

PKTGEN("tc", "01_arp_from_container_privnet_ip_unset")
int privnet_arp_from_container_privnet_ip_unset_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_arp_req);
	return 0;
}

SETUP("tc", "01_arp_from_container_privnet_ip_unset")
int privnet_arp_from_container_privnet_ip_unset_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, NULL, &lxc_privnet_ipv6);
	return pod_send_packet(ctx);
}

CHECK("tc", "01_arp_from_container_privnet_ip_unset")
int privnet_arp_from_container_privnet_ip_unset_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_DROP);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "02_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_pktgen(struct __ctx_buff *ctx)
{
	return build_privnet_dhcp_request(ctx);
}

SETUP("tc", "02_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_setup(struct __ctx_buff *ctx)
{
	redirect_target_ifindex = 0;

	privnet_add_device_entry(IFINDEX, NET_ID, NULL, &lxc_privnet_ipv6);
	return pod_send_packet(ctx);
}

CHECK("tc", "02_dhcp_from_container_redirect")
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

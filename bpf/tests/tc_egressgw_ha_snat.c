// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_NODEPORT			1
#define ENABLE_EGRESS_GATEWAY_HA	1
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_HOST_FIREWALL		1
#define ENCAP_IFINDEX		42
#define SECONDARY_IFACE_IFINDEX	44

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, const struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused);

#include "lib/bpf_host.h"

#include "lib/egressgw.h"
#include "lib/egressgw_ha.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP_IFINDEX)
		return CTX_ACT_REDIRECT;
	if (ifindex == SECONDARY_IFACE_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, const struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	/* expect no FIB lookup for packets that arrived via overlay */
	return -1;
}

// TODO: What about the snat (no number test)?

/* Test that a packet matching an egress gateway policy on the to-netdev program
 * gets correctly SNATed with the egress IP of the policy.
 */
PKTGEN("tc", "tc_egressgw_ha_snat1")
int egressgw_ha_snat1_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
		});
}

SETUP("tc", "tc_egressgw_ha_snat1")
int egressgw_ha_snat1_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, 0);
	ipcache_v4_add_entry(EGRESS_IP, 0, HOST_ID, 0, 0);

	set_identity_mark(ctx, CLIENT_IDENTITY, MARK_MAGIC_EGW_DONE);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_snat1")
int egressgw_ha_snat1_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
			.packets = 1,
			.status_code = CTX_ACT_OK
		});
}

/* Test that a packet matching an egress gateway policy on the from-netdev program
 * gets correctly revSNATed and connection tracked.
 */
PKTGEN("tc", "tc_egressgw_ha_snat1_2_reply")
int egressgw_ha_snat1_2_reply_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
			.dir = CT_INGRESS,
		});
}

SETUP("tc", "tc_egressgw_ha_snat1_2_reply")
int egressgw_ha_snat1_2_reply_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entry for the CLIENT_IP: */
	ipcache_v4_add_entry(CLIENT_IP, 0, 0, CLIENT_NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_snat1_2_reply")
int egressgw_ha_snat1_2_reply_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
			.dir = CT_INGRESS,
			.packets = 2,
			.status_code = CTX_ACT_REDIRECT,
		});
}

/* Test that replies are still handled even when the gateway is no longer active. */
PKTGEN("tc", "tc_egressgw_ha_snat1_3_reply_inactive_gw")
int egressgw_ha_snat1_3_reply_inactive_gw_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
			.dir = CT_INGRESS,
		});
}

SETUP("tc", "tc_egressgw_ha_snat1_3_reply_inactive_gw")
int egressgw_ha_snat1_3_reply_inactive_gw_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 0,
				     { 0 }, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_snat1_3_reply_inactive_gw")
int egressgw_ha_snat1_3_reply_inactive_gw_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
			.dir = CT_INGRESS,
			.packets = 3,
			.status_code = CTX_ACT_REDIRECT,
		});
}

/* Test that a second packet for the same connection is still SNATed with
 * the egress IP of the policy, even when no gateways are available.
 */
PKTGEN("tc", "tc_egressgw_ha_snat1_4_inactive_gw")
int egressgw_ha_snat1_4_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
		});
}

SETUP("tc", "tc_egressgw_ha_snat1_4_inactive_gw")
int egressgw_ha_snat1_4_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 0,
				     { 0 }, EGRESS_IP, 0);

	set_identity_mark(ctx, CLIENT_IDENTITY, MARK_MAGIC_EGW_DONE);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_snat1_4_inactive_gw")
int egressgw_ha_snat1_4_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT1,
			.packets = 4,
			.status_code = CTX_ACT_OK
		});
}

PKTGEN("tc", "tc_egressgw_ha_snat2")
int egressgw_ha_snat2_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT2,
		});
}

SETUP("tc", "tc_egressgw_ha_snat2")
int egressgw_ha_snat2_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, 0);

	set_identity_mark(ctx, CLIENT_IDENTITY, MARK_MAGIC_EGW_DONE);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_snat2")
int egressgw_ha_snat2_check(struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT2,
			.packets = 1,
			.status_code = CTX_ACT_OK
		});

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}

/* Test that a packet matching an egress gateway policy on the to-netdev program
 * gets correctly SNATed with the desired egress IP of the policy, event if the
 * packet hits a stale NAT entry.
 */
PKTGEN("tc", "tc_egressgw_ha_tuple_collision1")
int egressgw_ha_tuple_collision1_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
		});
}

SETUP("tc", "tc_egressgw_ha_tuple_collision1")
int egressgw_ha_tuple_collision1_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, 0);
	ipcache_v4_add_entry(EGRESS_IP, 0, HOST_ID, 0, 0);

	set_identity_mark(ctx, CLIENT_IDENTITY, MARK_MAGIC_EGW_DONE);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_tuple_collision1")
int egressgw_ha_tuple_collision1_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.packets = 1,
			.status_code = CTX_ACT_OK
		});

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}

PKTGEN("tc", "tc_egressgw_ha_tuple_collision2")
int egressgw_ha_tuple_collision2_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
		});
}

SETUP("tc", "tc_egressgw_ha_tuple_collision2")
int egressgw_ha_tuple_collision2_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP3, 0);
	ipcache_v4_add_entry(EGRESS_IP3, 0, HOST_ID, 0, 0);

	set_identity_mark(ctx, CLIENT_IDENTITY, MARK_MAGIC_EGW_DONE);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_tuple_collision2")
int egressgw_ha_tuple_collision2_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.tuple_collision = true,
			.packets = 2,
			.status_code = CTX_ACT_OK
		});
}

/* Test that a packet matching an egress gateway policy on the from-netdev program
 * gets correctly revSNATed and connection tracked, even if the packet hits a
 * stale NAT entry.
 */
PKTGEN("tc", "tc_egressgw_ha_tuple_collision2_reply")
int egressgw_ha_tuple_collision2_reply_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.tuple_collision = true,
			.dir = CT_INGRESS,
		});
}

SETUP("tc", "tc_egressgw_ha_tuple_collision2_reply")
int egressgw_ha_tuple_collision2_reply_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entry for the CLIENT_IP: */
	ipcache_v4_add_entry(CLIENT_IP, 0, 0, CLIENT_NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_tuple_collision2_reply")
int egressgw_ha_tuple_collision2_reply_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_SNAT_TUPLE_COLLISION,
			.dir = CT_INGRESS,
			.packets = 3,
			.status_code = CTX_ACT_REDIRECT,
		});

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0Xffffff, 24);

	return ret;
}

/* Test that a packet matching an excluded CIDR egress gateway policy on the
 * to-netdev program does not get SNATed with the egress IP of the policy.
 */
PKTGEN("tc", "tc_egressgw_ha_skip_excluded_cidr_snat")
int egressgw_ha_skip_excluded_cidr_snat_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_SNAT_EXCL_CIDR,
		});
}

SETUP("tc", "tc_egressgw_ha_skip_excluded_cidr_snat")
int egressgw_ha_skip_excluded_cidr_snat_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, 0, 0);
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, 1, {
				     EGRESS_GATEWAY_EXCLUDED_CIDR }, 0, 0);

	set_identity_mark(ctx, CLIENT_IDENTITY, MARK_MAGIC_EGW_DONE);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_skip_excluded_cidr_snat")
int egressgw_ha_skip_excluded_cidr_snat_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")

	if (memcmp(l2->h_dest, (__u8 *)ext_svc_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the external svc MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != EXTERNAL_SVC_IP)
		test_fatal("dst IP has changed");

	if (l4->source != client_port(TEST_HA_SNAT_EXCL_CIDR))
		test_fatal("src TCP port has changed");

	if (l4->dest != EXTERNAL_SVC_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

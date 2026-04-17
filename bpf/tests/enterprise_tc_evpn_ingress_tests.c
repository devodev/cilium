// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "bpf/helpers.h"
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_IPV6

/* Enable debug output */
#define DEBUG

#include <bpf/config/node.h>

/* Variable to record the net_id passed to the mock_privnet_evpn_ingress function */
__u16 mock_privnet_evpn_ingress_net_id;

/* Mock-out the privnet-specific logic in this test */
static __always_inline int
mock_privnet_evpn_ingress(struct __ctx_buff __maybe_unused *ctx, __u16 net_id)
{
	mock_privnet_evpn_ingress_net_id = net_id;
	return CTX_ACT_REDIRECT;
}

#define privnet_evpn_ingress mock_privnet_evpn_ingress

#include "tests/lib/enterprise_bpf_evpn.h"
#include "tests/lib/enterprise_vni.h"

/* packet defined in ./scapy/enterprise_evpn_pkt_defs.py */
const __u8 evpn_icmp_req[] = {
	SCAPY_BUF_BYTES(evpn_icmp_req)
};

/* packet defined in ./scapy/enterprise_evpn_pkt_defs.py */
const __u8 evpn_icmp_req_bad_dmac[] = {
	SCAPY_BUF_BYTES(evpn_icmp_req_bad_dmac)
};

/* Enable configurations */
ASSIGN_CONFIG(bool, evpn_enable, true)
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_one_addr }) /* set device mac */

/* Helper macros for tests */
#define CLEAR_METRICS_ENTRY(__dir, __reason) \
	do { \
		struct metrics_key key = { \
			.reason = (__u8)-(__reason), \
			.dir = __dir, \
		}; \
		map_delete_elem(&cilium_metrics, &key); \
	} while (0)

#define ASSERT_DROP_REASON(__code, __dir, __reason) \
	do { \
		struct metrics_key key = { \
			.reason = (__u8)-(__reason), \
			.dir = __dir, \
		}; \
		if ((__code) != CTX_ACT_DROP) \
			test_fatal("unexpected status code (expected %d, got %d)", \
				   CTX_ACT_DROP, *status_code); \
		val = map_lookup_elem(&cilium_metrics, &key); \
		if (!val) \
			test_fatal("metrics entry not found"); \
		if (val->count != 1) \
			test_fatal("unexpected metrics count (expected 1, got %d)", \
				   val->count); \
	} while (0)

/* Use this VNI for all tests. Otherwise, we can't cleanup VNI map correctly. */
const __u32 test_vni = 1;

static __always_inline void
cleanup_test_state(void) {
	vni_del(test_vni);
	mock_privnet_evpn_ingress_net_id = 0;
}

PKTGEN("tc", "01_evpn_ingress_to_privnet_endpoint")
int evpn_ingress_to_privnet_endpoint_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, evpn_icmp_req, sizeof(evpn_icmp_req));

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "01_evpn_ingress_to_privnet_endpoint")
int evpn_ingress_to_privnet_endpoint_setup(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key tunnel_key = {
		.tunnel_id = 1, /* VNI */
	};

	ctx_set_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0);
	vni_add(test_vni, 1);

	return evpn_receive_packet(ctx);
}

CHECK("tc", "01_evpn_ingress_to_privnet_endpoint")
int evpn_ingress_to_privnet_endpoint_check(const struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("unexpected status code (expected %d, got %d)",
			   CTX_ACT_REDIRECT, *status_code);

	if (mock_privnet_evpn_ingress_net_id != 1)
		test_fatal("unexpected net_id passed to privnet_evpn_ingress (expected %d, got %d)",
			   1, mock_privnet_evpn_ingress_net_id);

	cleanup_test_state();

	test_finish();
}

PKTGEN("tc", "02_evpn_ingress_tunnel_key_missing")
int evpn_ingress_tunnel_key_missing_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, evpn_icmp_req, sizeof(evpn_icmp_req));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "02_evpn_ingress_tunnel_key_missing")
int evpn_ingress_tunnel_key_missing_setup(struct __ctx_buff *ctx)
{
	CLEAR_METRICS_ENTRY(METRIC_INGRESS, DROP_NO_TUNNEL_KEY);

	vni_add(test_vni, 1);

	return evpn_receive_packet(ctx);
}

CHECK("tc", "02_evpn_ingress_tunnel_key_missing")
int evpn_ingress_tunnel_key_missing_check(const struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct metrics_value *val;
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	ASSERT_DROP_REASON(*status_code, METRIC_INGRESS, DROP_NO_TUNNEL_KEY);

	cleanup_test_state();

	test_finish();
}

PKTGEN("tc", "03_evpn_ingress_zero_vni")
int evpn_ingress_zero_vni_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, evpn_icmp_req, sizeof(evpn_icmp_req));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "03_evpn_ingress_zero_vni")
int evpn_ingress_zero_vni_setup(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key tunnel_key = {
		.tunnel_id = 0, /* VNI 0 is invalid */
	};

	ctx_set_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0);

	CLEAR_METRICS_ENTRY(METRIC_INGRESS, DROP_INVALID_VNI);

	vni_add(test_vni, 1);

	return evpn_receive_packet(ctx);
}

CHECK("tc", "03_evpn_ingress_zero_vni")
int evpn_ingress_zero_vni_check(const struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct metrics_value *val;
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	ASSERT_DROP_REASON(*status_code, METRIC_INGRESS, DROP_INVALID_VNI);

	cleanup_test_state();

	test_finish();
}

PKTGEN("tc", "04_evpn_ingress_no_vni_entry")
int evpn_ingress_no_vni_entry_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, evpn_icmp_req, sizeof(evpn_icmp_req));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "04_evpn_ingress_no_vni_entry")
int evpn_ingress_no_vni_entry_setup(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key tunnel_key = {
		.tunnel_id = 1,
	};

	ctx_set_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0);

	CLEAR_METRICS_ENTRY(METRIC_INGRESS, DROP_UNROUTABLE);

	return evpn_receive_packet(ctx);
}

CHECK("tc", "04_evpn_ingress_no_vni_entry")
int evpn_ingress_no_vni_entry_check(const struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct metrics_value *val;
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	ASSERT_DROP_REASON(*status_code, METRIC_INGRESS, DROP_UNROUTABLE);

	cleanup_test_state();

	test_finish();
}

PKTGEN("tc", "05_evpn_ingress_invalid_dst_mac")
int evpn_ingress_invalid_dst_mac_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, evpn_icmp_req_bad_dmac, sizeof(evpn_icmp_req_bad_dmac));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "05_evpn_ingress_invalid_dst_mac")
int evpn_ingress_invalid_dst_mac_setup(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key tunnel_key = {
		.tunnel_id = 1,
	};

	ctx_set_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0);

	CLEAR_METRICS_ENTRY(METRIC_INGRESS, DROP_UNROUTABLE);

	vni_add(test_vni, 1);

	return evpn_receive_packet(ctx);
}

CHECK("tc", "05_evpn_ingress_invalid_dst_mac")
int evpn_ingress_invalid_dst_mac_check(const struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct metrics_value *val;
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	ASSERT_DROP_REASON(*status_code, METRIC_INGRESS, DROP_UNROUTABLE);

	cleanup_test_state();

	test_finish();
}

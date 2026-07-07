// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1
#define ENABLE_EGRESS_GATEWAY_HA 1
#define ENABLE_EGRESS_GATEWAY_COMMON 1
#define TUNNEL_PROTOCOL TUNNEL_PROTOCOL_VXLAN
#define ENCAP_IFINDEX 99

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

#define SRC_NODE_IPV4	v4_node_one
#define DST_NODE_IPV4	v4_node_two
#define SRC_POD_IPV4	v4_pod_one
#define SRC_POD_PORT	tcp_src_one

#define SRC_NODE_IPV6	v6_node_one
#define DST_NODE_IPV6	v6_node_two

#define VRF_ID 1
#define VRF_TABLE 100

#define CURRENT_IFACE 1
#define EXPECTED_OIF 42

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	if ((flags & BPF_FIB_LOOKUP_TBID) && params->tbid == VRF_TABLE) {
		params->ifindex = EXPECTED_OIF;
		return BPF_FIB_LKUP_RET_SUCCESS;
	}

	return BPF_FIB_LKUP_RET_NOT_FWDED;
}

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex, __u32 flags __maybe_unused)
{
	if (ifindex != EXPECTED_OIF)
		return CTX_ACT_DROP;
	return CTX_ACT_REDIRECT;
}

#include "lib/bpf_host.h"
#include "lib/enterprise_vrf.h"

ASSIGN_CONFIG(__u32, interface_ifindex, CURRENT_IFACE)
ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_VXLAN)

const __u8 enterprise_vrf_egress_redirect_v4[] = {
	SCAPY_BUF_BYTES(enterprise_vrf_egress_redirect_v4)
};

PKTGEN("tc", "enterprise_vrf_egress_redirect_v4_1")
int enterprise_vrf_egress_redirect_v4_1(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, enterprise_vrf_egress_redirect_v4,
			sizeof(enterprise_vrf_egress_redirect_v4));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "enterprise_vrf_egress_redirect_v4_1")
int enterprise_vrf_egress_redirect_v4_1_setup(struct __ctx_buff *ctx)
{
	enterprise_vrf_add_entry(VRF_ID, VRF_TABLE);

	ctx->mark = MARK_MAGIC_OVERLAY;

	return netdev_send_packet(ctx);
}

CHECK("tc", "enterprise_vrf_egress_redirect_v4_1")
int enterprise_vrf_egress_redirect_v4_1_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	test_finish();
}

const __u8 enterprise_vrf_egress_redirect_v6[] = {
	SCAPY_BUF_BYTES(enterprise_vrf_egress_redirect_v6)
};

PKTGEN("tc", "enterprise_vrf_egress_redirect_v6_1")
int enterprise_vrf_egress_redirect_v6_1(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, enterprise_vrf_egress_redirect_v6,
			sizeof(enterprise_vrf_egress_redirect_v6));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "enterprise_vrf_egress_redirect_v6_1")
int enterprise_vrf_egress_redirect_v6_1_setup(struct __ctx_buff *ctx)
{
	enterprise_vrf_add_entry(VRF_ID, VRF_TABLE);

	ctx->mark = MARK_MAGIC_OVERLAY;

	return netdev_send_packet(ctx);
}

CHECK("tc", "enterprise_vrf_egress_redirect_v6_1")
int enterprise_vrf_egress_redirect_v6_1_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	test_finish();
}

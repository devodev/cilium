// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

#define MONITOR_IFINDEX 4242

static unsigned int clone_calls;
static __u32 clone_ifindex;

#define RESET_CLONE_STATE()		\
	do {				\
		clone_calls = 0;	\
		clone_ifindex = 0;	\
	} while (0)

#define ASSERT_STATUS_CODE(CTX, EXPECTED)					\
	do {									\
		void *data = (void *)(long)ctx_data(CTX);				\
		void *data_end = (void *)(long)(CTX)->data_end;			\
		__u32 *status_code;							\
		if (data + sizeof(__u32) > data_end)					\
			test_fatal("status code out of bounds");			\
		status_code = data;							\
		if (*status_code != (__u32)(EXPECTED))					\
			test_fatal("unexpected status code (expected %d, got %d)",	\
				   (__u32)(EXPECTED), *status_code);			\
	} while (0)

#define ASSERT_SINGLE_MIRROR()							\
	do {									\
		if (clone_calls != 1)						\
			test_fatal("expected exactly one inspection clone, got %u",	\
				   clone_calls);					\
		if (clone_ifindex != MONITOR_IFINDEX)				\
			test_fatal("unexpected inspection ifindex (expected %u, got %u)", \
				   MONITOR_IFINDEX, clone_ifindex);		\
	} while (0)

#define BUILD_PACKET(CTX, BUF)						\
	do {									\
		struct pktgen builder;						\
		pktgen__init(&builder, CTX);					\
		scapy_push_data(&builder, BUF, sizeof(BUF));			\
		pktgen__finish(&builder);					\
	} while (0)

long mock_clone_redirect(struct __ctx_buff *ctx __maybe_unused,
			 __u32 ifindex,
			 __u64 flags __maybe_unused)
{
	clone_calls++;
	clone_ifindex = ifindex;
	return 0;
}

#define clone_redirect mock_clone_redirect

#include "lib/bpf_lxc.h"

/* packet defined in ./scapy/enterprise_inspection_pkt_defs.py */
const __u8 inspection_egress_v4_tcp[] = {
	SCAPY_BUF_BYTES(inspection_egress_v4_tcp)
};

/* packet defined in ./scapy/enterprise_inspection_pkt_defs.py */
const __u8 inspection_ingress_v4_tcp[] = {
	SCAPY_BUF_BYTES(inspection_ingress_v4_tcp)
};

/* packet defined in ./scapy/enterprise_inspection_pkt_defs.py */
const __u8 inspection_ingress_v6_tcp[] = {
	SCAPY_BUF_BYTES(inspection_ingress_v6_tcp)
};

/* packet defined in ./scapy/enterprise_inspection_pkt_defs.py */
const __u8 inspection_ingress_arp[] = {
	SCAPY_BUF_BYTES(inspection_ingress_arp)
};

ASSIGN_CONFIG(__u16, endpoint_id, 233)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(bool, passive_inspection_enable, true)
ASSIGN_CONFIG(__u32, passive_inspection_ifindex, MONITOR_IFINDEX)

#include "lib/policy.h"

PKTGEN("tc", "tc_lxc_inspection_egress_v4")
int tc_lxc_inspection_egress_v4_pktgen(struct __ctx_buff *ctx)
{
	BUILD_PACKET(ctx, inspection_egress_v4_tcp);
	return 0;
}

SETUP("tc", "tc_lxc_inspection_egress_v4")
int tc_lxc_inspection_egress_v4_setup(struct __ctx_buff *ctx)
{
	RESET_CLONE_STATE();
	policy_add_egress_deny_all_entry();
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_lxc_inspection_egress_v4")
int tc_lxc_inspection_egress_v4_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_STATUS_CODE(ctx, CTX_ACT_DROP);
	ASSERT_SINGLE_MIRROR();

	ASSERT_CTX_BUF_OFF("inspection_egress_v4", "Ether", ctx, sizeof(__u32),
			   inspection_egress_v4_tcp, sizeof(inspection_egress_v4_tcp));

	policy_delete_egress_all_entry();
	test_finish();
}

PKTGEN("tc", "tc_lxc_inspection_ingress_arp")
int tc_lxc_inspection_ingress_arp_pktgen(struct __ctx_buff *ctx)
{
	BUILD_PACKET(ctx, inspection_ingress_arp);
	return 0;
}

SETUP("tc", "tc_lxc_inspection_ingress_arp")
int tc_lxc_inspection_ingress_arp_setup(struct __ctx_buff *ctx)
{
	RESET_CLONE_STATE();
	return pod_receive_packet(ctx);
}

CHECK("tc", "tc_lxc_inspection_ingress_arp")
int tc_lxc_inspection_ingress_arp_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_STATUS_CODE(ctx, CTX_ACT_OK);
	ASSERT_SINGLE_MIRROR();

	ASSERT_CTX_BUF_OFF("inspection_ingress_arp", "Ether", ctx, sizeof(__u32),
			   inspection_ingress_arp, sizeof(inspection_ingress_arp));

	test_finish();
}

PKTGEN("tc", "tc_lxc_inspection_ingress_v4_direct")
int tc_lxc_inspection_ingress_v4_direct_pktgen(struct __ctx_buff *ctx)
{
	BUILD_PACKET(ctx, inspection_ingress_v4_tcp);
	return 0;
}

SETUP("tc", "tc_lxc_inspection_ingress_v4_direct")
int tc_lxc_inspection_ingress_v4_direct_setup(struct __ctx_buff *ctx)
{
	RESET_CLONE_STATE();
	policy_add_ingress_deny_all_entry();
	return pod_receive_packet(ctx);
}

CHECK("tc", "tc_lxc_inspection_ingress_v4_direct")
int tc_lxc_inspection_ingress_v4_direct_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_STATUS_CODE(ctx, CTX_ACT_DROP);
	ASSERT_SINGLE_MIRROR();

	ASSERT_CTX_BUF_OFF("inspection_ingress_v4_direct", "Ether", ctx, sizeof(__u32),
			   inspection_ingress_v4_tcp, sizeof(inspection_ingress_v4_tcp));

	policy_delete_entry(false, 0, 0, 0, 0);
	test_finish();
}

PKTGEN("tc", "tc_lxc_inspection_ingress_v6_tailcall")
int tc_lxc_inspection_ingress_v6_tailcall_pktgen(struct __ctx_buff *ctx)
{
	BUILD_PACKET(ctx, inspection_ingress_v6_tcp);
	return 0;
}

SETUP("tc", "tc_lxc_inspection_ingress_v6_tailcall")
int tc_lxc_inspection_ingress_v6_tailcall_setup(struct __ctx_buff *ctx)
{
	RESET_CLONE_STATE();
	ctx_store_meta(ctx, CB_SRC_LABEL, WORLD_IPV6_ID);
	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "tc_lxc_inspection_ingress_v6_tailcall")
int tc_lxc_inspection_ingress_v6_tailcall_check(const struct __ctx_buff *ctx)
{
	test_init();
	ASSERT_STATUS_CODE(ctx, CTX_ACT_OK);
	ASSERT_SINGLE_MIRROR();

	ASSERT_CTX_BUF_OFF("inspection_ingress_v6_tailcall", "Ether", ctx, sizeof(__u32),
			   inspection_ingress_v6_tcp, sizeof(inspection_ingress_v6_tcp));

	policy_delete_entry(false, 0, 0, 0, 0);
	test_finish();
}

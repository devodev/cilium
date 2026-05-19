/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "common.h"
#include "pktgen.h"
#include "scapy.h"
#include "tests/mock_skb_metadata.h"

#define v6_net_two_addr {0xfd, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

volatile const __u8 v6_net_two[] = v6_net_two_addr;

#define NET_ID 100
#define SUBNET_ID 200

const __u8 __subnet_v6[16] = {0xfd, 0x10};
#define SUBNET_V4 IPV4(172, 16, 10, 0)
#define SUBNET_V4_LEN 24
#define SUBNET_V6 ((const union v6addr *)__subnet_v6)
#define SUBNET_V6_LEN 96

#define OTHER_SUBNET_ID 300
const __u8 __other_subnet_v6[16] = {0xfd, 0x20};
#define OTHER_SUBNET_V4 IPV4(172, 16, 20, 0)
#define OTHER_SUBNET_V4_LEN 24
#define OTHER_SUBNET_V6 ((const union v6addr *)__subnet_v6)
#define OTHER_SUBNET_V6_LEN 96

#define V4_NET_IP_1 v4_svc_one
#define V4_NET_IP_2 v4_svc_two
#define V4_NET_IP_3 IPV4(172, 16, 20, 13)
#define V4_POD_IP_1 v4_pod_one
#define V4_POD_IP_2 v4_pod_two
#define V4_POD_IP_3 v4_pod_three
#define V6_NET_IP_1 v6_svc_one
#define V6_POD_IP_1 v6_pod_one
#define V6_NET_IP_2 v6_net_two
#define V6_POD_IP_2 v6_pod_two
#define INB_IP v4_ext_one
#define GATEWAY_IP v4_ext_two
#define NODE_IP v4_node_one
#define V6_EXT_IP v6_ext_node_one
#define IFINDEX 0x42

#define V4_EP_IP IPV4(172, 255, 0, 1)
volatile const __u8 v6_ep_ip[] = { 0xfd, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 1 };

/* Scapy packet definitions */

#define build_privnet_packet(ctx, buf)				\
	do {							\
		struct pktgen builder;				\
		pktgen__init(&builder, ctx);			\
		scapy_push_data(&builder, buf, sizeof(buf));	\
		pktgen__finish(&builder);			\
	} while (0)

#define assert_status_code(ctx, expected)						\
	do {										\
		void *data = ctx_data(ctx);						\
		void *data_end = ctx_data_end(ctx);					\
		__u32 *status_code;							\
											\
		if (data + sizeof(__u32) > data_end)					\
			test_fatal("status code out of bounds");			\
											\
		status_code = data;							\
		if ((*status_code) != (__u32)(expected))				\
			test_fatal("unexpected status code (expected %d, got %d)",	\
					(__u32)(expected), *status_code);		\
	} while (0)

#define assert_tunnel_id(expected)							\
	do {										\
		if (last_tunnel_id != (__u32)(expected))				\
			test_fatal("unexpected tunnel ID (expected %d, got %d)",	\
					(__u32)(expected), last_tunnel_id);		\
	} while (0)

#define assert_privnet_net_ids(expected_src, expected_dst)				\
	do {										\
		__u16 actual_src = 0;							\
		__u16 actual_dst = 0;							\
		get_privnet_net_ids(&actual_src, &actual_dst);				\
		if (actual_src != (expected_src))					\
			test_fatal("unexpected src netID (expected %d, got %d)",	\
					(expected_src), actual_src);			\
		if (actual_dst != (expected_dst))					\
			test_fatal("unexpected dst netID (expected %d, got %d)",	\
					(expected_dst), actual_dst);			\
	} while (0)									\

#define skb_get_tunnel_key mock_tunnel_key
int mock_tunnel_key(struct __ctx_buff *ctx __maybe_unused,
		    struct bpf_tunnel_key *to,
		    __u32 size __maybe_unused,
		    __u32 flags __maybe_unused)
{
	to->tunnel_id = privnet_tunnel_id;
	return 0;
}

__u32 last_tunnel_id;

#define skb_set_tunnel_key mock_set_tunnel_key
int mock_set_tunnel_key(struct __sk_buff __maybe_unused *ctx,
			const struct bpf_tunnel_key *to,
			__u32 __maybe_unused size,
			__u32 __maybe_unused flags)
{
	last_tunnel_id = to->tunnel_id;
	return 0;
}

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

#define LXC_IFINDEX 142
#define LXC_ID 142

#include "enterprise_privnet_common.h"

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_tcp_syn[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_tcp_syn)
};

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_net_ip_tcp_syn_ttl_dec[] = {
	SCAPY_BUF_BYTES(privnet_net_ip_tcp_syn_ttl_dec)
};

/* packet defined in ./scapy/enterprise_privnet_pkt_defs.py */
const __u8 privnet_netdev_ns[] = {
	SCAPY_BUF_BYTES(privnet_netdev_ns)
};

#include <bpf/config/node.h>
#include <lib/enterprise_ext_eps_maps.h>

/* Mock lxc policy call - will be called from privnet_local_access_ingress. */
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

static struct {
	bool called;
	__u32 lxc_id;
} policy_tail_call_recorder;

static __always_inline void reset_policy_tail_call_recorder(void)
{
	policy_tail_call_recorder.called = false;
	policy_tail_call_recorder.lxc_id = 0;
}

#define ASSERT_POLICY_TAIL_CALL(__expected_lxc_id)						\
	do {											\
		if (!policy_tail_call_recorder.called)						\
			test_fatal("tail_call_dynamic was not called");				\
		if (policy_tail_call_recorder.lxc_id != (__expected_lxc_id))			\
			test_fatal("unexpected tail_call_dynamic endpoint ID (got %d, want %d",	\
				   (__expected_lxc_id), policy_tail_call_recorder.lxc_id);	\
	} while (0)

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx, const void *map __maybe_unused,
		       __u32 slot)
{
	policy_tail_call_recorder.called = true;
	policy_tail_call_recorder.lxc_id = slot;

	tail_call(ctx, &mock_policy_call_map, slot);
}

static __always_inline int
mock_ext_eps_policy_can_access(struct __ctx_buff __maybe_unused *ctx,
			       struct endpoint_key __maybe_unused *key,
			       __u32 __maybe_unused sec_identity, __u16 __maybe_unused ethertype,
			       __be16 __maybe_unused dport, __u8 __maybe_unused proto,
			       int __maybe_unused l4_off, __u8 __maybe_unused *match_type,
			       int __maybe_unused dir, bool __maybe_unused is_untracked_fragment,
			       __u8 __maybe_unused *audited, __s8 __maybe_unused *ext_err,
			       __u16 __maybe_unused *proxy_port, __u32 __maybe_unused *cookie)
{
	return CTX_ACT_OK;
}

#undef ext_ep_policy_verdict
#define ext_ep_policy_verdict mock_ext_eps_policy_can_access

#undef EFFECTIVE_EP_ID
#undef EVENT_SOURCE

/* Include an actual datapath code */
#include "lib/bpf_host.h"

/* Include test helpers */
#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/endpoint.h"

/* Enable privnet and local access mode */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set device mac */

PKTGEN("tc", "01_local_access_ingress_from_netdev")
int privnet_local_access_ingress_from_netdev_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_net_ip_tcp_syn);
	return 0;
}

SETUP("tc", "01_local_access_ingress_from_netdev")
int privnet_local_access_ingress_from_netdev_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(V4_POD_IP_2, LXC_IFINDEX, LXC_ID, 0, 0, 0,
			      (const __u8 *)mac_two, (const __u8 *)mac_one);

	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_add_device_entry(LXC_IFINDEX, NET_ID, NULL, NULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_1, GATEWAY_IP, IFINDEX);
	__privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2, IFINDEX, NULL);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "01_local_access_ingress_from_netdev")
int privnet_local_access_ingress_from_netdev_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to lxc device */
	assert_status_code(ctx, TC_ACT_REDIRECT);
	ASSERT_POLICY_TAIL_CALL(LXC_ID);

	/* check inner packet headers, src & dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_local_access_from_netdev_no_nat", "Ether", ctx,
			   sizeof(__u32), privnet_net_ip_tcp_syn_ttl_dec,
			   sizeof(privnet_net_ip_tcp_syn_ttl_dec));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(LXC_IFINDEX);
	privnet_del_device_entry(IFINDEX);

	endpoint_v4_del_entry(V4_POD_IP_2);

	reset_policy_tail_call_recorder();

	test_finish();
}

PKTGEN("tc", "02_local_access_icmpv6_ns_ingress_from_netdev")
int privnet_local_access_icmpv6_ns_ingress_from_netdev_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, privnet_netdev_ns);
	return 0;
}

SETUP("tc", "02_local_access_icmpv6_ns_ingress_from_netdev")
int privnet_local_access_icmpv6_ns_ingress_from_netdev_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((const union v6addr *)V6_POD_IP_2, LXC_IFINDEX, LXC_ID,
			      0, 0, (const __u8 *)mac_two, (const __u8 *)mac_one);

	privnet_add_device_entry(IFINDEX, NET_ID, NULL, NULL);
	privnet_add_device_entry(LXC_IFINDEX, NET_ID, NULL, NULL);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_subnet_route(NET_ID, SUBNET_ID,
				    (const union v6addr *)V6_NET_IP_1,
				    (const union v6addr *)V6_EXT_IP,
				    IFINDEX);
	__privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
					(const union v6addr *)V6_NET_IP_2,
					(const union v6addr *)V6_POD_IP_2,
					IFINDEX, NULL);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "02_local_access_icmpv6_ns_ingress_from_netdev")
int privnet_local_access_icmpv6_ns_ingress_from_netdev_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are not redirected to lxc device but handled in
	 * privnet_handle_ns
	 */
	assert_status_code(ctx, TC_ACT_OK);
	if (policy_tail_call_recorder.called)
		test_fatal("ICMPv6 NS packet unexpectedly redirected to endpoint");

	ASSERT_CTX_BUF_OFF("privnet_local_access_icmpv6_ns_ingress_from_netdev_no_nat",
			   "Ether", ctx,
			   sizeof(__u32), privnet_netdev_ns,
			   sizeof(privnet_netdev_ns));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_2,
				      (const union v6addr *)V6_POD_IP_2);
	privnet_v6_del_route(NET_ID, SUBNET_ID,
			     (const union v6addr *)V6_NET_IP_1);
	privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);
	privnet_del_device_entry(LXC_IFINDEX);
	privnet_del_device_entry(IFINDEX);

	endpoint_v6_del_entry((const union v6addr *)V6_POD_IP_2);

	reset_policy_tail_call_recorder();

	test_finish();
}

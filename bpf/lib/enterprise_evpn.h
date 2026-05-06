/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "enterprise_config.h"

#ifndef EVPN_FIB_MAP_SIZE
#define EVPN_FIB_MAP_SIZE 65536
#endif

#include "socket.h"
#include "eth.h"
#include "drop_reasons.h"
#include "trace.h"

DECLARE_ENTERPRISE_CONFIG(bool, evpn_enable,
			  "True if evpn feature is enabled")
DECLARE_ENTERPRISE_CONFIG(__u32, evpn_device_ifindex,
			  "The interface index of the evpn vxlan device")
DECLARE_ENTERPRISE_CONFIG(union macaddr, evpn_device_mac,
			  "The mac address of the evpn vxlan device")

#define V4_EVPN_FIB_KEY_LEN (sizeof(__u32) * 8)
#define V6_EVPN_FIB_KEY_LEN (sizeof(union v6addr) * 8)

#define EVPN_FIB_STATIC_PREFIX					\
(8 * (sizeof(struct evpn_fib_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define EVPN_FIB_PREFIX_LEN(PREFIX) (EVPN_FIB_STATIC_PREFIX + (PREFIX))

struct evpn_fib_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 family;
	__u8 pad0;
	__u16 net_id;
	union {
		union v4addr	ip4;
		union v6addr	ip6;
	};
};

struct evpn_fib_val {
	__u32 vni;
	__u8 family;
	__u8 pad0[3];

	/* Remote VTEP MAC address (inner destination MAC) */
	union macaddr mac;

	/* Remote VTEP address (outer destination IP) */
	union {
		union v4addr	ip4;
		union v6addr	ip6;
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct evpn_fib_key);
	__type(value, struct evpn_fib_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EVPN_FIB_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_evpn_fib __section_maps_btf;

static __always_inline const struct evpn_fib_val *
evpn_fib_lookup4(__u16 net_id, __be32 addr)
{
	struct evpn_fib_key key = {};

	key.lpm_key.prefixlen = EVPN_FIB_PREFIX_LEN(V4_EVPN_FIB_KEY_LEN);
	key.family = AF_INET;
	key.net_id = net_id;
	key.ip4.be32 = addr;

	return map_lookup_elem(&cilium_evpn_fib, &key);
}

static __always_inline const struct evpn_fib_val *
evpn_fib_lookup6(__u16 net_id, const union v6addr *addr)
{
	struct evpn_fib_key key = {};

	key.lpm_key.prefixlen = EVPN_FIB_PREFIX_LEN(V6_EVPN_FIB_KEY_LEN);
	key.family = AF_INET6;
	key.net_id = net_id;
	key.ip6 = *addr;

	return map_lookup_elem(&cilium_evpn_fib, &key);
}

static __always_inline __maybe_unused int
evpn_set_tunnel_key(struct __ctx_buff *ctx, const struct evpn_fib_val *fib_val)
{
	int ret;
	struct bpf_tunnel_key tunnel_key = {};

	tunnel_key.tunnel_id = fib_val->vni;
	tunnel_key.tunnel_ttl = IPDEFTTL;

	if (fib_val->family == AF_INET) {
		tunnel_key.remote_ipv4 = bpf_ntohl(fib_val->ip4.be32);
		ret = ctx_set_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP,
					 BPF_F_ZERO_CSUM_TX);
		if (ret < 0)
			return DROP_WRITE_ERROR;
	} else if (fib_val->family == AF_INET6) {
		tunnel_key.remote_ipv6[0] = fib_val->ip6.p1;
		tunnel_key.remote_ipv6[1] = fib_val->ip6.p2;
		tunnel_key.remote_ipv6[2] = fib_val->ip6.p3;
		tunnel_key.remote_ipv6[3] = fib_val->ip6.p4;
		ret = ctx_set_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP,
					 BPF_F_ZERO_CSUM_TX | BPF_F_TUNINFO_IPV6);
		if (ret < 0)
			return DROP_WRITE_ERROR;
	} else {
		/* Unsupported address family */
		return DROP_INVALID;
	}

	return 0;
}

static __always_inline __maybe_unused int
evpn_encap_and_redirect4(struct __ctx_buff *ctx, __u16 net_id, __u32 sec_label,
			 __be32 dst_ip, struct trace_ctx *trace)
{
	union macaddr evpn_mac = CONFIG(evpn_device_mac);
	const struct evpn_fib_val *fib_val;
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;
	int ret;

	fib_val = evpn_fib_lookup4(net_id, dst_ip);
	if (!fib_val)
		return DROP_UNROUTABLE;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return DROP_INVALID;

	memcpy(eth->h_dest, fib_val->mac.addr, ETH_ALEN);
	memcpy(eth->h_source, evpn_mac.addr, ETH_ALEN);

	ret = evpn_set_tunnel_key(ctx, fib_val);
	if (ret < 0)
		return ret;

	send_trace_notify(ctx, TRACE_TO_NETWORK, sec_label, WORLD_IPV4_ID, TRACE_EP_ID_UNKNOWN,
			  CONFIG(evpn_device_ifindex), trace->reason, trace->monitor,
			  bpf_htons(ETH_P_IP));

	return ctx_redirect(ctx, CONFIG(evpn_device_ifindex), 0);
}

static __always_inline __maybe_unused int
evpn_encap_and_redirect6(struct __ctx_buff *ctx, __u16 net_id, __u32 sec_label,
			 union v6addr dst_ip, struct trace_ctx *trace)
{
	union macaddr evpn_mac = CONFIG(evpn_device_mac);
	const struct evpn_fib_val *fib_val;
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;
	int ret;

	fib_val = evpn_fib_lookup6(net_id, &dst_ip);
	if (!fib_val)
		return DROP_UNROUTABLE;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return DROP_INVALID;

	memcpy(eth->h_dest, fib_val->mac.addr, ETH_ALEN);
	memcpy(eth->h_source, evpn_mac.addr, ETH_ALEN);

	ret = evpn_set_tunnel_key(ctx, fib_val);
	if (ret < 0)
		return ret;

	send_trace_notify(ctx, TRACE_TO_NETWORK, sec_label, WORLD_IPV6_ID, TRACE_EP_ID_UNKNOWN,
			  CONFIG(evpn_device_ifindex), trace->reason, trace->monitor,
			  bpf_htons(ETH_P_IPV6));

	return ctx_redirect(ctx, CONFIG(evpn_device_ifindex), 0);
}

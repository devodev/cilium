/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) Isovalent, Inc. - All Rights Reserved. */

#pragma once

#ifndef CILIUM_LB_FLOW_LOG_MAP_SIZE
#define CILIUM_LB_FLOW_LOG_MAP_SIZE 200000
#endif

#include <lib/enterprise_time.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, long);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, 1);
} CILIUM_LB_FLOW_LOG_TABLE_MAP __section_maps_btf;

#define FL_DISABLED	0
#define FL_TABLE_1	1
#define FL_TABLE_2	2

static long fl_table_in_use(void)
{
	int key = 0;
	long *value;

	value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_TABLE_MAP, &key);
	if (always_succeeds(value) && *value >= FL_DISABLED && *value <= FL_TABLE_2)
		return *value;

	return 0;
}

struct fl_value {
	__u64 flow_start_ns;
	__u64 flow_end_ns;
	__u64 bytes;
	__u64 packets;
};

#define FLOW_IPV4	0
#define FLOW_IPV6	1
#define FLOW_L2		2
#define __FLOW_MAX	FLOW_L2

struct fl_error_value {
	__u64 err_e2big;
	__u64 err_other;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct fl_error_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, __FLOW_MAX);
} CILIUM_LB_FLOW_LOG_ERRORS_MAP __section_maps_btf;

#define	E2BIG 7

static void lb_flow_log_err(int flow, int err)
{
	struct fl_error_value *value;

	if (flow > __FLOW_MAX)
		return;

	value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_ERRORS_MAP, &flow);
	if (always_succeeds(value)) {
		if (likely(err == E2BIG))
			value->err_e2big += 1;
		else
			value->err_other += 1;
	}
}

struct fl_key_v4 {
	__u32 ifindex;
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8 nexthdr;
	__u8 pad1;
	__u8 pad2;
	__u8 pad3;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct fl_key_v4);
	__type(value, struct fl_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, CILIUM_LB_FLOW_LOG_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} CILIUM_LB_FLOW_LOG_V4_1_MAP __section_maps_btf,
  CILIUM_LB_FLOW_LOG_V4_2_MAP __section_maps_btf;

static __always_inline int
lb_flow_log_v4(const struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct iphdr *ipv4_hdr;
	struct fl_key_v4 key;
	struct fl_value *value = NULL;
	long table_in_use = fl_table_in_use();
	__u64 time_now;

	if (table_in_use == FL_DISABLED)
		return CTX_ACT_OK;

	ipv4_hdr = data + sizeof(struct ethhdr);
	if (ctx_no_room(ipv4_hdr + 1, data_end))
		return CTX_ACT_DROP;

	memset(&key, 0, sizeof(key));
	key.ifindex = ctx->ingress_ifindex;
	key.saddr = ipv4_hdr->saddr;
	key.daddr = ipv4_hdr->daddr;
	key.nexthdr = ipv4_hdr->protocol;
	if (key.nexthdr == IPPROTO_TCP || key.nexthdr == IPPROTO_UDP)
		if (l4_load_ports(ctx, ETH_HLEN + ipv4_hdrlen(ipv4_hdr), &key.sport) < 0)
			return CTX_ACT_DROP;

	time_now = bpf_ktime_get_nsec();

	if (table_in_use == FL_TABLE_1)
		value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_V4_1_MAP, &key);
	else
		value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_V4_2_MAP, &key);
	if (value) {
		value->bytes += (data_end - data);
		value->packets += 1;
		value->flow_end_ns = time_now;
	} else {
		struct fl_value _value = {
			.flow_start_ns = time_now,
			.flow_end_ns = time_now,
			.bytes = (data_end - data),
			.packets = 1,
		};
		int ret;

		if (table_in_use == FL_TABLE_1)
			ret = map_update_elem(&CILIUM_LB_FLOW_LOG_V4_1_MAP, &key, &_value, 0);
		else
			ret = map_update_elem(&CILIUM_LB_FLOW_LOG_V4_2_MAP, &key, &_value, 0);
		if (ret)
			lb_flow_log_err(FLOW_IPV4, -ret);
	}

	return CTX_ACT_OK;
}

struct fl_key_v6 {
	union v6addr saddr;
	union v6addr daddr;
	__u32 ifindex;
	__be16 sport;
	__be16 dport;
	__u8 nexthdr;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct fl_key_v6);
	__type(value, struct fl_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, CILIUM_LB_FLOW_LOG_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} CILIUM_LB_FLOW_LOG_V6_1_MAP __section_maps_btf,
  CILIUM_LB_FLOW_LOG_V6_2_MAP __section_maps_btf;

static __always_inline int
lb_flow_log_v6(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ipv6hdr *ipv6_hdr;
	struct fl_key_v6 key;
	struct fl_value *value = NULL;
	long table_in_use = fl_table_in_use();
	__u64 time_now;
	int hdrlen;

	if (table_in_use == FL_DISABLED)
		return CTX_ACT_OK;

	ipv6_hdr = data + ETH_HLEN;
	if ((void *)(ipv6_hdr + 1) > data_end)
		return CTX_ACT_DROP;

	memset(&key, 0, sizeof(key));
	key.ifindex = ctx->ingress_ifindex;
	ipv6_addr_copy(&key.saddr, (void *)&ipv6_hdr->saddr);
	ipv6_addr_copy(&key.daddr, (void *)&ipv6_hdr->daddr);
	key.nexthdr = ipv6_hdr->nexthdr;

	hdrlen = ipv6_hdrlen(ctx, &key.nexthdr);
	if (hdrlen < 0)
		return CTX_ACT_DROP;

	if (key.nexthdr == IPPROTO_TCP || key.nexthdr == IPPROTO_UDP)
		if (l4_load_ports(ctx, ETH_HLEN + hdrlen, &key.sport) < 0)
			return CTX_ACT_DROP;

	time_now = bpf_ktime_get_nsec();

	if (table_in_use == FL_TABLE_1)
		value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_V6_1_MAP, &key);
	else
		value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_V6_2_MAP, &key);
	if (value) {
		value->bytes += (data_end - data);
		value->packets += 1;
		value->flow_end_ns = time_now;
	} else {
		struct fl_value _value = {
			.flow_start_ns = time_now,
			.flow_end_ns = time_now,
			.bytes = (data_end - data),
			.packets = 1,
		};
		int ret;

		if (table_in_use == FL_TABLE_1)
			ret = map_update_elem(&CILIUM_LB_FLOW_LOG_V6_1_MAP, &key, &_value, 0);
		else
			ret = map_update_elem(&CILIUM_LB_FLOW_LOG_V6_2_MAP, &key, &_value, 0);
		if (ret)
			lb_flow_log_err(FLOW_IPV6, -ret);
	}

	return CTX_ACT_OK;
}

struct fl_key_l2 {
	__u8 dst_mac[ETH_ALEN];
	__u8 src_mac[ETH_ALEN];
	__u32 ifindex;
	__be16 type;
	__u16 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct fl_key_l2);
	__type(value, struct fl_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, CILIUM_LB_FLOW_LOG_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} CILIUM_LB_FLOW_LOG_L2_1_MAP __section_maps_btf,
  CILIUM_LB_FLOW_LOG_L2_2_MAP __section_maps_btf;

static __always_inline int
lb_flow_log_l2(const struct __ctx_buff *ctx __maybe_unused)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth = data;
	struct fl_key_l2 key;
	struct fl_value *value = NULL;
	long table_in_use = fl_table_in_use();
	const int copy_len = 12;
	__u64 time_now;

	if (table_in_use == FL_DISABLED)
		return CTX_ACT_OK;

	if ((void *)(eth + 1) > data_end)
		return CTX_ACT_DROP;

	time_now = bpf_ktime_get_nsec();

	memcpy(&key, eth, copy_len);
	key.ifindex = ctx->ingress_ifindex;
	key.type = eth->h_proto;
	key._pad = 0;

	if (table_in_use == FL_TABLE_1)
		value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_L2_1_MAP, &key);
	else
		value = map_lookup_elem(&CILIUM_LB_FLOW_LOG_L2_2_MAP, &key);
	if (value) {
		value->bytes += (data_end - data);
		value->packets += 1;
		value->flow_end_ns = time_now;
	} else {
		struct fl_value _value = {
			.flow_start_ns = time_now,
			.flow_end_ns = time_now,
			.bytes = (data_end - data),
			.packets = 1,
		};
		int ret;

		if (table_in_use == FL_TABLE_1)
			ret = map_update_elem(&CILIUM_LB_FLOW_LOG_L2_1_MAP, &key, &_value, 0);
		else
			ret = map_update_elem(&CILIUM_LB_FLOW_LOG_L2_2_MAP, &key, &_value, 0);
		if (ret)
			lb_flow_log_err(FLOW_L2, -ret);
	}

	return CTX_ACT_OK;
}

static __always_inline int
lb_flow_log(const struct __ctx_buff *ctx, __u16 proto)
{
	switch (proto) {
	case bpf_htons(ETH_P_IP):
		return lb_flow_log_v4(ctx);
	case bpf_htons(ETH_P_IPV6):
		return lb_flow_log_v6(ctx);
	default:
		return lb_flow_log_l2(ctx);
	}

	return CTX_ACT_OK;
}

static __always_inline int
lb_early_hook(const struct __ctx_buff *ctx __maybe_unused, __u16 proto __maybe_unused)
{
	int ret = CTX_ACT_OK;

#ifdef LB_FLOW_LOGS_ENABLED
	ret = lb_flow_log(ctx, proto);
#endif
	return ret;
}

#define xdp_early_hook	lb_early_hook
#define tcx_early_hook	lb_early_hook

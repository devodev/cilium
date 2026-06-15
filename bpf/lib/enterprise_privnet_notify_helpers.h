/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Based on enterprise/pkg/privnet/tables.NetworkIDReserved */
#define PRIVNET_PIP_NET_ID     0
/* Based on enterprise/pkg/privnet/tables.NetworkIDUnknown */
#define PRIVNET_UNKNOWN_NET_ID 65535

struct privnet_net_id {
	__u16 src_id;
	__u16 dst_id;
	__u32 pad;
};

/* Scratch map containing current src and dst net ID */
struct {
#ifndef BPF_TEST
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
#else
	__uint(type, BPF_MAP_TYPE_ARRAY);
#endif
	__uint(max_entries, 1);
	__type(key, __u32);		      /* only one key */
	__type(value, struct privnet_net_id);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_percpu_privnet_net_id __section_maps_btf;

static __always_inline void get_privnet_net_ids(__u16 *src_id, __u16 *dst_id)
{
	__u32 zero = 0;
	struct privnet_net_id *value =
		map_lookup_elem(&cilium_percpu_privnet_net_id, &zero);

	if (unlikely(!value))
		return;

	*src_id = value->src_id;
	*dst_id = value->dst_id;
}

static __always_inline void set_privnet_net_ids(__u16 src_id, __u16 dst_id)
{
	__u32 zero = 0;
	struct privnet_net_id *value =
		map_lookup_elem(&cilium_percpu_privnet_net_id, &zero);

	if (unlikely(!value))
		return;

	value->src_id = src_id;
	value->dst_id = dst_id;
}

static __always_inline void set_privnet_net_src_id(__u16 src_id)
{
	__u32 zero = 0;
	struct privnet_net_id *value =
		map_lookup_elem(&cilium_percpu_privnet_net_id, &zero);

	if (unlikely(!value))
		return;

	value->src_id = src_id;
}

static __always_inline void set_privnet_net_dst_id(__u16 dst_id)
{
	__u32 zero = 0;
	struct privnet_net_id *value =
		map_lookup_elem(&cilium_percpu_privnet_net_id, &zero);

	if (unlikely(!value))
		return;

	value->dst_id = dst_id;
}

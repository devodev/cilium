/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "linux/bpf.h"

#define VRF_MAX (1U << 16)

/* VRF id used as key for VRF map */
typedef __u16 vrf_id;
/* Kernel FIB table ID used as value for VRF map */
typedef __u32 vrf_table_id;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, vrf_id);
	__type(value, vrf_table_id);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, VRF_MAX);
	__uint(map_flags, CONDITIONAL_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_vrf_map __section_maps_btf;

/*
 * lookup a table ID given a VRF id
 * @id: VRF ID to lookup
 * returns: kernel FIB table ID associated with the VRF ID, or 0 if not found
 */
static __always_inline vrf_table_id enterprise_vrf_map_get(vrf_id id)
{
	vrf_table_id *tbid;

	if (!id)
		return id;

	tbid = map_lookup_elem(&cilium_vrf_map, &id);
	return tbid ? *tbid : 0;
}

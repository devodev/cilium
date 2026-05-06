/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

struct vni_key {
	__u32 vni;
};

struct vni_val {
	__u16 net_id;
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct vni_key);
	__type(value, struct vni_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, VNI_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_vni __section_maps_btf;

static __always_inline const struct vni_val *
vni_lookup(__u32 vni)
{
	struct vni_key key = {
		.vni = vni,
	};
	return map_lookup_elem(&cilium_vni, &key);
}

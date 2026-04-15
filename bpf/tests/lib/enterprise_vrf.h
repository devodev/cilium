/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline void
enterprise_vrf_add_entry(vrf_id vrf, vrf_table_id tbid)
{
	map_update_elem(&cilium_vrf_map, &vrf, &tbid, BPF_ANY);
}

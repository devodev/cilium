/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>

struct vxlanhdr_gbp {
	__u8	vx_flags;
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8	reserved_flags1:3,
		policy_applied:1,
		reserved_flags2:2,
		dont_learn:1,
		reserved_flags3:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	reserved_flags1:1,
		dont_learn:1,
		reserved_flags2:2,
		policy_applied:1,
		reserved_flags3:3;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__be16	policy_id;
	__be32	vx_vni;
};


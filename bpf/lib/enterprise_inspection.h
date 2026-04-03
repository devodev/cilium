/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "enterprise_inspection_config.h"

#define enterprise_inspection_to_container(ctx) enterprise_mirror_to_inspection_iface(ctx)

#define enterprise_inspection_from_container(ctx) enterprise_mirror_to_inspection_iface(ctx)

/* Mirror a clone of the packet to the passive inspection interface.
 * Called before policy evaluation so that IDS/monitoring tools observe
 * all traffic including policy-denied packets.  The return value of
 * clone_redirect is intentionally ignored: a failed clone must never
 * affect the original packet's forwarding path.
 */
static __always_inline int
enterprise_mirror_to_inspection_iface(struct __ctx_buff *ctx)
{
	__u32 ifindex;

	if (!CONFIG(passive_inspection_enable))
		return CTX_ACT_OK;

	ifindex = CONFIG(passive_inspection_ifindex);

	if (!ifindex || ifindex == CONFIG(interface_ifindex))
		return CTX_ACT_OK;

	clone_redirect(ctx, ifindex, 0);

	return CTX_ACT_OK;
}

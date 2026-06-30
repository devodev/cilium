/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_config.h"
/* Re-define DECLARE_CONFIG so the policy-specific global runtime config
 * variables end up as enterprise variables in bpf_overlay.c because current OSS
 * bpf_overlay.c doesn't otherwise include lib/policy.h.
 */
#undef DECLARE_CONFIG
#define DECLARE_CONFIG DECLARE_ENTERPRISE_CONFIG
#include "lib/policy.h"
#undef DECLARE_CONFIG
#define DECLARE_CONFIG(type, name, description) DECLARE_CONFIG_KIND("object", type, name, description)
#include "lib/policy_log.h"

struct non_pinned_policy_map {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, struct policy_entry);
	__uint(max_entries, POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} __dummy_inner_ext_eps_policy__ __section_maps_btf;

/* Per-endpoint policy enforcement map */
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, struct endpoint_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EXT_EPS_POLICY_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct non_pinned_policy_map);
} cilium_ext_eps_policy __section_maps_btf;

static __always_inline int
__ext_eps_policy_can_access(const struct __ctx_buff *ctx, const struct endpoint_key *key,
			    __u32 sec_identity, __u16 ethertype, __be16 dport,
			    __u8 proto, int l4_off, __u8 *match_type, int dir,
			    bool is_untracked_fragment, __u8 *audited,
			    __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	int ret;
	void *map;

	/* __policy_can_access uses local_id to output a debug message only,
	 * hence it is fine to pass a dummy value there.
	 */
	__u32 local_id = 0;

	map = map_lookup_elem(&cilium_ext_eps_policy, key);
	if (!map)
		return DROP_EP_NOT_READY;

	/* shouldn't this be set here instead? XXX: check with the normal path */
	*audited = 0;

	ret = __policy_can_access(map, ctx, local_id, sec_identity, ethertype, dport, proto,
				  l4_off, dir, is_untracked_fragment, match_type,
				  ext_err, proxy_port, cookie);
	if (ret >= 0)
		return ret;

	cilium_dbg(ctx, DBG_POLICY_DENIED, local_id, sec_identity);

#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif
	return ret;
}

#define ext_ep_policy_verdict(ctx, key, sec_identity, ethertype, dport, proto,			  \
			      l4_off, match_type, dir, is_untracked_fragment,			  \
			      audited, ext_err, proxy_port, cookie)				  \
			__ext_eps_policy_can_access(ctx, key, sec_identity, ethertype,		  \
				    dport, proto, l4_off, match_type, dir, is_untracked_fragment, \
				    audited, ext_err, proxy_port, cookie)

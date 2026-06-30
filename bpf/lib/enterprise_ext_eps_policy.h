/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/eps.h"
#include "enterprise_ext_eps_maps.h"

#define EGRESS_POLICY	!!(CT_EGRESS)
#define INGRESS_POLICY	!(CT_EGRESS)

static __always_inline int
ext_eps_policy_can_egress4(const struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
			   __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
			   __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	struct endpoint_key key = {
		.ip4.be32 = ip,
		.family = ENDPOINT_KEY_IPV4,
	};

	return ext_ep_policy_verdict(ctx, &key, dst_id, ETH_P_IP, dport, proto, l4_off,
				     match_type, EGRESS_POLICY, false, audited, ext_err,
				     proxy_port, cookie);
}

static __always_inline int
ext_eps_policy_can_ingress4(const struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
			    __be16 dport, __u8 proto, int l4_off, bool is_untracked_fragment,
			    __u8 *match_type, __u8 *audited, __s8 *ext_err, __u16 *proxy_port,
			    __u32 *cookie)
{
	struct endpoint_key key = {
		.ip4.be32 = ip,
		.family = ENDPOINT_KEY_IPV4,
	};

	return ext_ep_policy_verdict(ctx, &key, dst_id, ETH_P_IP, dport, proto,
				     l4_off, match_type, INGRESS_POLICY, is_untracked_fragment,
				     audited, ext_err, proxy_port, cookie);
}

static __always_inline int
ext_eps_policy_can_egress6(const struct __ctx_buff *ctx, union v6addr ip6, __u32 dst_id,
			   __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
			   __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	struct endpoint_key key = {
		.ip6 = ip6,
		.family = ENDPOINT_KEY_IPV6,
	};

	return ext_ep_policy_verdict(ctx, &key, dst_id, ETH_P_IPV6, dport, proto,
				     l4_off, match_type, EGRESS_POLICY, false,
				     audited, ext_err, proxy_port, cookie);
}

static __always_inline int
ext_eps_policy_can_ingress6(const struct __ctx_buff *ctx, union v6addr ip6, __u32 dst_id,
			    __be16 dport, __u8 proto, int l4_off, bool is_untracked_fragment,
			    __u8 *match_type, __u8 *audited, __s8 *ext_err, __u16 *proxy_port,
			    __u32 *cookie)
{
	struct endpoint_key key = {
		.ip6 = ip6,
		.family = ENDPOINT_KEY_IPV6,
	};

	return ext_ep_policy_verdict(ctx, &key, dst_id, ETH_P_IPV6, dport, proto,
				     l4_off, match_type, INGRESS_POLICY, is_untracked_fragment,
				     audited, ext_err, proxy_port, cookie);
}

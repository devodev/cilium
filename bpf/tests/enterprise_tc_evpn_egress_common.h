/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/config/node.h>

#include "common.h"
#include "pktgen.h"
#include <lib/common.h>

static int last_redirect_ifindex;
static struct bpf_tunnel_key last_tunnel_key;
static __u32 last_tunnel_key_size;

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect
static __always_inline int
mock_ctx_redirect(const struct __sk_buff __maybe_unused *ctx, int ifindex,
		  __u32 __maybe_unused flags)
{
	last_redirect_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#undef ctx_set_tunnel_key
#define ctx_set_tunnel_key mock_ctx_set_tunnel_key
static __always_inline int
mock_ctx_set_tunnel_key(const struct __sk_buff __maybe_unused *ctx,
			struct bpf_tunnel_key *tunnel_key, __u32 size,
			__u32 __maybe_unused flags)
{
	memcpy(&last_tunnel_key, tunnel_key, sizeof(last_tunnel_key));
	last_tunnel_key_size = size;

	return 0;
}

#include <lib/enterprise_evpn.h>
#include "tests/lib/enterprise_evpn.h"
#include "enterprise_evpn_common.h"

static __always_inline void
cleanup_test_state(struct ethhdr *eth)
{
	last_redirect_ifindex = 0;
	memset(&last_tunnel_key, 0, sizeof(last_tunnel_key));
	last_tunnel_key_size = 0;
	memset(eth->h_dest, 0, ETH_ALEN);
	memset(eth->h_source, 0, ETH_ALEN);
}

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#if defined(ENABLE_EGRESS_GATEWAY_HA) && !defined(ENABLE_EGRESS_GATEWAY_COMMON)
#define ENABLE_EGRESS_GATEWAY_COMMON
#endif

/* Tunnel key structure size with local_ipv{4,6} fields included */
#ifndef TUNNEL_KEY_WITH_SRC_IP
#define TUNNEL_KEY_WITH_SRC_IP					\
	(offsetof(struct bpf_tunnel_key, local_ipv6) +		\
	 field_sizeof(struct bpf_tunnel_key, local_ipv6))
#endif

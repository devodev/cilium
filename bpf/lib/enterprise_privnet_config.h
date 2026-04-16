/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "enterprise_config.h"

DECLARE_ENTERPRISE_CONFIG(bool, privnet_enable,
			  "True if the endpoint is in a non-default network")
DECLARE_ENTERPRISE_CONFIG(__u32, privnet_unknown_sec_id,
			  "The security identifier for unknown network traffic")
DECLARE_ENTERPRISE_CONFIG(bool, privnet_bridge_enable,
			  "True if running on network bridge")
DECLARE_ENTERPRISE_CONFIG(bool, privnet_local_access_enable,
			  "True if running in local access mode")
DECLARE_ENTERPRISE_CONFIG(bool, privnet_host_reachability,
			  "True if host / remote node traffic is allowed into privnet")
DECLARE_ENTERPRISE_CONFIG(union v4addr, privnet_host_snat_ipv4,
			  "Link-local IPv4 address used to SNAT host traffic to PrivNet")
DECLARE_ENTERPRISE_CONFIG(union v6addr, privnet_host_snat_ipv6,
			  "Link-local IPv6 address used to SNAT host traffic to PrivNet")
DECLARE_ENTERPRISE_CONFIG(__u32, cilium_dhcp_ifindex,
			  "Interface index for cilium_dhcp device")

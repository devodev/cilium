/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "lib/egress_gateway_ha.h"
#include "lib/enterprise_encrypt.h"
#include "lib/enterprise_privnet.h"
#include "lib/enterprise_vni.h"

add_type(struct egress_gw_ha_ct_entry);
add_type(struct egress_gw_ha_policy_key);
add_type(struct egress_gw_ha_policy_entry_v2);
add_type(struct egress_gw_standalone_key);
add_type(struct egress_gw_standalone_entry);
add_type(struct encryption_policy_key);
add_type(struct encryption_policy_entry);
add_type(struct privnet_arp_sender_key);
add_type(struct privnet_arp_sender_val);
add_type(struct privnet_fib_key);
add_type(struct privnet_fib_val);
add_type(struct privnet_pip_key);
add_type(struct privnet_pip_val);
add_type(struct vni_key);
add_type(struct vni_val);
add_type(struct evpn_fib_key);
add_type(struct evpn_fib_val);

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <bpf/config/global.h>
#include <bpf/config/node.h>

#define SECLABEL WORLD_ID
#define SECLABEL_IPV4 WORLD_IPV4_ID
#define SECLABEL_IPV6 WORLD_IPV6_ID

#include "lib/common.h"
#include "lib/drop_reasons.h"
#include "lib/nodeport.h"
#include "lib/enterprise_privnet.h"
#include "lib/enterprise_evpn.h"
#include "lib/enterprise_vni.h"

/* Make this function mockable for better testing */
#ifndef privnet_evpn_ingress
#define privnet_evpn_ingress(ctx, net_id) \
	__privnet_evpn_ingress(ctx, net_id)
#endif

static __always_inline
int valid_dmac(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
	union macaddr dmac = {};
	union macaddr interface_mac = CONFIG(interface_mac);

	ret = eth_load_daddr(ctx, dmac.addr, 0);
	if (IS_ERR(ret))
		return ret;

	if (eth_addrcmp(&dmac, &interface_mac) != 0) {
		ret = DROP_UNROUTABLE;
		return ret;
	}

	return ret;
}

/* Attached to the ingress of cilium_evpn device to execute on packets
 * entering the node via the evpn-vxlan tunnel.
 */
__section_entry
int cil_from_evpn(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key tunnel_key;
	const struct vni_val *vni_val;
	int ret = CTX_ACT_DROP;

	if (!CONFIG(evpn_enable))
		return ret;

	/* Before resolving VNI => NetID mapping, we don't know which
	 * address space we are in.
	 */
	set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_UNKNOWN_NET_ID);

	ret = ctx_get_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0);
	if (IS_ERR(ret)) {
		ret = DROP_NO_TUNNEL_KEY;
		goto out;
	}

	if (tunnel_key.tunnel_id == 0) {
		ret = DROP_INVALID_VNI;
		goto out;
	}

	vni_val = vni_lookup(tunnel_key.tunnel_id);
	if (!vni_val || vni_val->net_id == 0) {
		ret = DROP_UNROUTABLE;
		goto out;
	}

	/* Now we know the NetID, we can set it for the rest of the processing. */
	set_privnet_net_ids(vni_val->net_id, vni_val->net_id);

	ret = valid_dmac(ctx);
	if (IS_ERR(ret))
		goto out;

	ret = privnet_evpn_ingress(ctx, vni_val->net_id);

out:
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, WORLD_ID, ret, METRIC_INGRESS);

	return ret;
}

/* Attached to the egress of cilium_evpn device to execute on packets
 * leaving the node via the evpn-vxlan tunnel.
 */
__section_entry
int cil_to_evpn(struct __ctx_buff __maybe_unused *ctx)
{
	return CTX_ACT_OK;
}

BPF_LICENSE("Dual BSD/GPL");

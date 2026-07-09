/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "arp.h"
#include "auxvars.h"
#include "conntrack.h"
#include "conntrack_map.h"
#include "drop_reasons.h"
#include "eps.h"
#include "icmp6.h"
#include "ipfrag.h"
#include "local_delivery.h"
#include "trace.h"

#include "enterprise_privnet_config.h"
#include "enterprise_privnet_conntrack.h"
#include "enterprise_ext_eps_policy.h"
#include "enterprise_evpn.h"

DEFINE_AUX(struct ipv6_ct_tuple, privnet_unknown_egress6_tuple);

/*
 * Privnet datapath for communication between kubernetes cluster and Isovalent Network Bridge.
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐             ┌───────────────────────────────────────────────┐
 *  │                                                                     │             │                                               │
 *  │                       K8s cluster                                   │             │                 Bridge                        │
 *  │                                                                     │             │                                               │
 *  │ ┌─────────────────────┐       ┌────────────────────────────────────┐│             │ ┌──────────────────┐  ┌────────────────┐      │┌──────────────────┐
 *  │ │ Pod1                │       │ BPF LXC                            ││             │ │ BPF overlay      │  │ BPF netdev     │      ││ External VM      │
 *  │ │                     │       │                                    ││             │ │                  │  │                │      ││                  │
 *  │ │ mac:  pm1           │       │                                    ││             │ │                  │ ││                │net a ││ mac: ext_m3      │
 *  │ │ ip:   ip4_1 ip6_1   │   │   │                   │                ││             │ │                  │ ││                │eth_a ││ ip:  ip4_3 ip6_3 │
 *  │ │ routes:             │   │   │                   │                ││             │ │                  │ ││                │mac_a ││                  │
 *  │ │ default via LL addr │   │   │ cil_from_con      │ cil_lxc_policy ││             │ │cil_from_overlay  │ ││ do_netdev      │      ││                  │
 *  │ └─────────────────────┘   │   └───────────────────┼────────────────┘│             │ └──────────────────┘ │└────────────────┘      │└──────────────────┘
 *  │                           │                       │                 │             │                      │                        │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *  │ 1. ARP Handling           │                       │                 │             │                      │                        │
 *  │ arp:                      │                       │                 │             │                      │                        │
 *  │     who is 169.254.0.1    │                       │                 │             │                      │                        │
 *  │ ns:                       │                       │                 │             │                      │                        │
 *  │     who is ff80::100      │      ┌─────────┐      │                 │             │                      │                        │
 *  │                           │      │ Blind   │      │                 │             │                      │                        │
 *  │                    ───────┼─────►│ Response│      │                 │             │                      │                        │      arp
 *  │                           │      │         │      │                 │             │                      │                        │       who is ip4_1
 *  │                           │      └────┬────┘      │                 │             │                      │                        │      ns
 *  │                           │           │           │                 │             │                      │  ┌──────────┐          │       who is ip6_1
 *  │                           │           │           │                 │             │                      │  │privnet   │◄─────────┼─────
 *  │     arp reply             │           │           │                 │             │                      │  │fib       │          │
 *  │     na             ◄──────┼───────────┘           │                 │             │                      │  │lookup    │          │
 *  │        lxc mac            │                       │                 │             │                      │  └────┬─────┘          │
 *  │                           │                       │                 │             │                      │       │                │
 *  │                           │                       │                 │             │                      │       │                │
 *  │                           │                       │                 │             │                      │       │   Proxy response
 *  │                           │                       │                 │             │                      │       └────────────────┬─────►
 *  │                           │                       │                 │             │                      │               mac_a    │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *  │ 2. From Pod to External EP│        cil_from_con   │ cil_lxc_policy  │             │   cil_from_overlay   │   do_netdev            │
 *  │                           │                       │                 │             │                      │                        │
 *  │                           │     ┌───────────────┐ │                 │             │                      │                        │
 *  │                           │     │privnet egress │ │                 │             │                      │                        │
 *  │                           │     │               │ │                 │             │                      │                        │
 *  │      sm: pm1              │     │privnet-fib    │ │                 │             │                      │                        │
 *  │      dm: lxcm     ────────┼────►│snat/dnat      │ │                 │             │                      │                        │
 *  │      sip: ip4_1           │     │enforce-seg    │ │                 │             │                      │                        │
 *  │      dip: ip4_3           │     └─────┬─────────┘ │                 │             │                      │                        │
 *  │                           │           │           │                 │             │                      │                        │
 *  │                           │           ▼           │                 │             │                      │                        │
 *  │                           │      sm: pm1          │                 │             │   ┌───────────────┐  │                        │
 *  │                           │      dm: lxcm         │                 │             │   │External EP    │  │                        │
 *  │                           │      sip: ip4_pip1 ───┼─────────[─Encapsulated─]──────┼──►│Ingress Policy │  │                        │
 *  │                           │      dip: ip4_pip3    │                 │             │   │               │  │                        │
 *  │                           │                       │                 │             │   └───────┬───────┘  │                        │
 *  │                           │                       │                 │             │           │          │                        │
 *  │                           │                       │                 │             │           ▼          │                        │
 *  │                           │                       │                 │             │   ┌───────────────┐  │                        │
 *  │                           │                       │                 │             │   │privnet ingress│  │                        │
 *  │                           │                       │                 │             │   │               │  │                        │
 *  │                           │                       │                 │             │   │privnet-pip    │  │                        │
 *  │                           │                       │                 │             │   │rev snat/dnat  │  │                        │
 *  │                           │                       │                 │             │   │enforce seg    │  │                        │
 *  │                           │                       │                 │             │   └───────┬───────┘  │                        │
 *  │                           │                       │                 │             │           │          │                        │
 *  │                           │                       │                 │             │           ▼          │                        │
 *  │                           │                       │                 │             │        sm: mac_a     │                        │
 *  │                           │                       │                 │             │        dm: ext_m3    │                        │
 *  │                           │                       │                 │             │        sip: ip4_1  ──┼────────────────────────┼─────►
 *  │                           │                       │                 │             │        dip: ip4_3    │                        │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *  │ 3. From External EP to Pod│       cil_from_con    │  cil_lxc_policy │             │  cil_from_overlay    │   do_netdev            │
 *  │                           │                       │                 │             │                      │                        │
 *  │                           │                       │                 │             │                      │  ┌───────────────┐     │
 *  │                           │                       │                 │             │                      │  │privnet egress │     │      sm: ext_m3
 *  │                           │                       │                 │             │                      │  │               │     │      dm: mac_a
 *  │                           │                       │                 │             │                      │  │privnet-fib    │◄────┼────  sip: ip4_3
 *  │                           │                       │                 │             │                      │  │snat/dnat      │     │      dip: ip4_1
 *  │                           │                       │                 │             │                      │  │enforce seg    │     │
 *  │                           │                       │                 │             │                      │  └───────┬───────┘     │
 *  │                           │                       │                 │             │                      │          │             │
 *  │                           │                       │                 │             │                      │          ▼             │
 *  │                           │                       │                 │             │                      │    sm: ext_m3          │
 *  │                           │                       │                 │             │                      │    dm: mac_a           │
 *  │                           │                       │                 │             │                      │    sip: ip4_pip3       │
 *  │                           │                       │                 │             │                      │    dip: ip4_pip1       │
 *  │                           │                       │                 │             │                      │          │             │
 *  │                           │                       │                 │             │                      │          ▼             │
 *  │                           │                       │┌──────────────┐ │             │                      │  ┌───────────────┐     │
 *  │                           │                       ││privnet ingres│ │             │                      │  │External EP    │     │
 *  │                           │                       ││              │◄┼───────────[─Encapsulated─]─────────┼──┤Egress Policy  │     │
 *  │                           │                       ││privnet pip   │ │             │                      │  │               │     │
 *  │                           │                       ││rev snat/dnat │ │             │                      │  └───────────────┘     │
 *  │                           │                       ││enforce seg   │ │             │                      │                        │
 *  │                           │                       │└──────┬───────┘ │             │                      │                        │
 *  │                           │                       │       │         │             │                      │                        │
 *  │                           │                       │       ▼         │             │                      │                        │
 *  │                           │                       │   sm: lxc_m     │             │                      │                        │
 *  │                           │                       │   dm: mac_a     │             │                      │                        │
 *  │                     ◄─────┼───────────────────────┼── sip: ip4_3    │             │                      │                        │
 *  │                           │                       │   dip: ip4_1    │             │                      │                        │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *
 *	1. ARP/NS Handling
 *		a. In kubernetes cluster, ARP requests from pods are blindly responded by lxc device with its own MAC address.
 *		b. In INB, ARP request coming from external endpoints should only get response for the pods which are in connected
 *			kubernetes cluster. Care must be taken to not attract unroutable traffic to INB.
 *.     c. If ARP request is for pod's own network IP do not reply to not mess up DHCP
 *	2. Pod to External EP
 *		a. Traffic from pod comes with dip of external ep ip and source of its own private ip.
 *			- cil_from_container -> enterprise_privnet hook
 *		b. Privnet egress
 *			- lookup for net-id:sip/dip in privnet-fib map
 *			- sip/dip go through stateless NAT to their equivalent pod IPs.
 *			- segmentation enforcement
 *		c. Packet follows regular Cilium datapath ( via overlay reaches INB )
 *		d. In cil_from_overlay, ingress processing of packet is done. Starting with external EP L3/L4 ingress policy
 *		   checks.
 *		e. Privnet ingress
 *			- lookup in privnet-pip map for pod IP to get private IPs
 *			- sip/dip go through stateless revNAT back to original IPs.
 *			- ingress segmentation enforced.
 *		f. Packet is redirected out to the attached privnet link.
 *	3. External EP to Pod
 *		a. Packet comes from netdev device ( do_netdev )
 *		b. Privnet egress
 *			Similar to 2.b
 *		c. Similar to 2.c
 *		d. In cil_lxc_policy, regular policy evaluation is done.
 *		e. Privnet ingress ( similar to 2.e )
 *		f. Packet is redirected to lxc device.
 *  4. DHCP
 *      a. Pod has no network IP yet and uses DHCP
 *      b. Privnet egress
 *         - if packet is DHCP then set endpoint ID in src MAC and
 *           redirect packet to 'cilium_dhcp_ifindex'.
 *         - drop other packets as long as network IP is all zeros
 *      c. Agent reads DHCP request from cilium_dhcp device and relays
 *      d. Relay response sent to pod's host-side veth device
 */

/* Based on enterprise/pkg/maps/privnet.FIBKeyTypeDefault */
#define PRIVNET_FIB_KEY_TYPE_DEFAULT 0
/* Based on enterprise/pkg/maps/privnet.FIBKeyTypePeering */
#define PRIVNET_FIB_KEY_TYPE_PEERING 1

struct privnet_fib_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 net_id;
	__u16 subnet_id;
	__u8 family;
	__u8 type;
	__u8 pad[2];
	union {
		union v4addr	ip4;
		union v6addr	ip6;
	};
};

/* Corresponds to enterprise/pkg/privnet/tables.MapEntryType */
enum privnet_fib_type {
	/* MapEntryTypeEndpoint */
	PRIVNET_FIB_VAL_TYPE_ENDPOINT		= 0,
	/* MapEntryTypeExternalEndpoint */
	PRIVNET_FIB_VAL_TYPE_EXTERNAL_ENDPOINT	= 1,
	/* MapEntryTypeDCNRoute */
	PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE	= 2,
	/* MapEntryTypeStaticRoute */
	PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE	= 3,
	/* MapEntryTypeEVNPRoute */
	PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE	= 4,
	/* MapEntryTypePeeringRoute */
	PRIVNET_FIB_VAL_TYPE_PEERING_ROUTE	= 5,
};

struct privnet_fib_val {
	union {
		union v4addr	ip4;
		union v6addr	ip6;
	};
	union macaddr mac;
	__u8 pad4;
	__u8 type;
	__u8 flag_l2_announce:1,
		pad:7;
	__u8 family;
	__u32 ifindex;
	__u32 vni;
	__u16 peer_net_id;
	__u16 peer_subnet_id;
};

struct privnet_pip_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 family;
	__u8 pad[3];
	union {
		union v4addr	ip4;
		union v6addr	ip6;
	};
};

struct privnet_pip_val {
	union {
		union v4addr	ip4;
		union v6addr	ip6;
	};
	__u8 pad;
	__u8 family;
	__u16 net_id;
};

enum privnet_device_type {
	PRIVNET_DEVICE_TYPE_LXC = 0,
	PRIVNET_DEVICE_TYPE_NETDEV = 1,
};

struct privnet_device_key {
	__u32 ifindex;
};

struct privnet_device_val {
	__u16 net_id;
	__u8 type;
	__u8 pad1;
	union v4addr ipv4;
	union v6addr ipv6;
};

struct privnet_subnet_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 net_id;
	__u8 family;
	__u8 pad[1];
	union {
		union v4addr	ip4;
		union v6addr	ip6;
	};
};

struct privnet_subnet_val {
	__u16 subnet_id;
};

struct privnet_arp_sender_key {
	__u16 net_id;
	__u16 subnet_id;
};

struct privnet_arp_sender_val {
	__be32 ipv4;
};

static __always_inline int
privnet_nat_v4_addr(struct __ctx_buff *ctx, __be32 old_addr, __be32 new_addr, int addr_off)
{
	void *data, *data_end;
	bool has_l4_header;
	struct iphdr *ip4;
	__u8 nexthdr;
	__u64 l4_off;
	__wsum sum;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	nexthdr = ip4->protocol;
	has_l4_header = ipfrag_has_l4_header(ipfrag_encode_ipv4(ip4));
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	sum = csum_diff(&old_addr, 4, &new_addr, 4, 0);
	if (ctx_store_bytes(ctx, ETH_HLEN + addr_off, &new_addr, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	if (ipv4_csum_update_by_diff(ctx, ETH_HLEN, sum) < 0)
		return DROP_CSUM_L3;

	if (has_l4_header) {
		struct csum_offset csum = {};

		csum_l4_offset_and_flags(nexthdr, &csum);

		/* Amend the L4 checksum due to changing the addresses. */
		if (csum.offset &&
		    csum_l4_replace(ctx, l4_off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

	return CTX_ACT_OK;
}

static __always_inline int
privnet_nat_v6_addr(struct __ctx_buff *ctx, const union v6addr *old_addr,
		    const union v6addr *new_addr, int addr_off)
{
	fraginfo_t fraginfo = 0;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u8 nexthdr;
	__wsum sum;
	int hdrlen;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	sum = csum_diff(old_addr, 16, new_addr, 16, 0);
	if (ctx_store_bytes(ctx, ETH_HLEN + addr_off, new_addr, 16, 0) < 0)
		return DROP_WRITE_ERROR;

	if (ipfrag_has_l4_header(fraginfo)) {
		struct csum_offset csum = {};

		csum_l4_offset_and_flags(nexthdr, &csum);

		/* Amend the L4 checksum due to changing the addresses. */
		if (csum.offset &&
		    csum_l4_replace(ctx, ETH_HLEN + hdrlen, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

	return CTX_ACT_OK;
}

static __always_inline bool
is_privnet_route_entry(const struct privnet_fib_val *val)
{
	if (!val)
		return false;

	switch (val->type) {
	case PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE:
		fallthrough;
	case PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE:
		fallthrough;
	case PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE:
		fallthrough;
	case PRIVNET_FIB_VAL_TYPE_PEERING_ROUTE:
		return true;
	}

	return false;
}

#define V4_PRIVNET_KEY_LEN (sizeof(__u32) * 8)
#define V6_PRIVNET_KEY_LEN (sizeof(union v6addr) * 8)

#define PRIVNET_FIB_STATIC_PREFIX					\
(8 * (sizeof(struct privnet_fib_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define PRIVNET_FIB_PREFIX_LEN(PREFIX) (PRIVNET_FIB_STATIC_PREFIX + (PREFIX))

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct privnet_fib_key);
	__type(value, struct privnet_fib_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_PIP_FIB_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_privnet_fib __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct privnet_pip_key);
	__type(value, struct privnet_pip_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_PIP_FIB_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_privnet_pip __section_maps_btf;

static __always_inline const struct privnet_fib_val *
privnet_fib_lookup(const struct privnet_fib_key *key) {
	const struct privnet_fib_val *peering_ret;
	const struct privnet_fib_val *ret = map_lookup_elem(&cilium_privnet_fib, key);
	struct privnet_fib_key peer_key;

	/* If the initial lookup found an (external) endpoint in the requested
	 * subnet, directly return it. Endpoints in the current subnet will always
	 * have precedence over endpoints in peered subnets
	 */
	if (ret && !is_privnet_route_entry(ret))
		return ret;

	/* If the initial lookup did not find an (external) endpoint in the requested
	 * subnet, make a secondary lookup to find if there is a peered subnet that
	 * covers the requested IP.
	 * If not we'll return the result of the initial lookup, which might be a route
	 * or empty.
	 */
	peer_key = *key;
	peer_key.type = PRIVNET_FIB_KEY_TYPE_PEERING;
	peering_ret = map_lookup_elem(&cilium_privnet_fib, &peer_key);
	if (!peering_ret)
		return ret;

	/* Make a lookup in the peered subnet. If we find an endpoint (and only an endpoint not
	 * an external endpoint), we return it. Otherwise we return the result of the initial
	 * lookup.
	 */
	peer_key.type = PRIVNET_FIB_KEY_TYPE_DEFAULT;
	peer_key.net_id = peering_ret->peer_net_id;
	peer_key.subnet_id = peering_ret->peer_subnet_id;
	peering_ret = map_lookup_elem(&cilium_privnet_fib, &peer_key);
	if (peering_ret &&
	    !is_privnet_route_entry(peering_ret) &&
	    peering_ret->type != PRIVNET_FIB_VAL_TYPE_EXTERNAL_ENDPOINT)
		return peering_ret;

	return ret;
}

static __always_inline const struct privnet_fib_val *
privnet_fib_lookup4(__u16 net_id, __u16 subnet_id, __be32 addr) {
	struct privnet_fib_key key = {};

	key.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V4_PRIVNET_KEY_LEN);
	key.net_id = net_id;
	key.subnet_id = subnet_id;
	key.family = ENDPOINT_KEY_IPV4;
	key.type = PRIVNET_FIB_KEY_TYPE_DEFAULT;
	key.ip4.be32 = addr;

	return privnet_fib_lookup(&key);
}

static __always_inline const struct privnet_fib_val *
privnet_fib_lookup6(__u16 net_id, __u16 subnet_id, union v6addr addr) {
	struct privnet_fib_key key = {};

	key.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V6_PRIVNET_KEY_LEN);
	key.net_id = net_id;
	key.subnet_id = subnet_id;
	key.family = ENDPOINT_KEY_IPV6;
	key.type = PRIVNET_FIB_KEY_TYPE_DEFAULT;
	key.ip6 = addr;

	return privnet_fib_lookup(&key);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct privnet_device_key);
	__type(value, struct privnet_device_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_DEVICES_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_privnet_devices __section_maps_btf;

static __always_inline const __u16 *privnet_get_net_id(__u32 ifindex)
{
	const struct privnet_device_key key = { .ifindex = ifindex };
	const struct privnet_device_val *val;

	val = map_lookup_elem(&cilium_privnet_devices, &key);
	return val ? &val->net_id : NULL;
}

static __always_inline const struct privnet_device_val *privnet_get_device(__u32 ifindex)
{
	const struct privnet_device_key key = { .ifindex = ifindex };

	return map_lookup_elem(&cilium_privnet_devices, &key);
}

#define PRIVNET_SUBNET_STATIC_PREFIX						\
(8 * (sizeof(struct privnet_subnet_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define PRIVNET_SUBNET_PREFIX_LEN(PREFIX) (PRIVNET_SUBNET_STATIC_PREFIX + (PREFIX))

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct privnet_subnet_key);
	__type(value, struct privnet_subnet_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_SUBNETS_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_privnet_subnets __section_maps_btf;

static __always_inline __u16 privnet_subnet_id_lookup4(__u16 net_id, __be32 addr)
{
	struct privnet_subnet_key key = {};
	const struct privnet_subnet_val *val;

	key.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(V4_PRIVNET_KEY_LEN);
	key.net_id = net_id;
	key.family = ENDPOINT_KEY_IPV4;
	key.ip4.be32 = addr;

	val = map_lookup_elem(&cilium_privnet_subnets, &key);
	return val ? val->subnet_id : 0;
}

static __always_inline __u16 privnet_subnet_id_lookup6(__u16 net_id, union v6addr addr)
{
	struct privnet_subnet_key key = {};
	const struct privnet_subnet_val *val;

	key.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(V6_PRIVNET_KEY_LEN);
	key.net_id = net_id;
	key.family = ENDPOINT_KEY_IPV6;
	key.ip6 = addr;

	val = map_lookup_elem(&cilium_privnet_subnets, &key);
	return val ? val->subnet_id : 0;
}

/*
 * cilium_privnet_watchdog is used to detect when the Cilium agent is down for
 * a prolonged period of time.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_WATCHDOG_MAP_SIZE);
} cilium_privnet_watchdog __section_maps_btf;

enum privnet_watchdog_index {
	PRIVNET_WATCHDOG_LIVENESS = 0,
	PRIVNET_WATCHDOG_TIMEOUT = 1,
};

static __always_inline bool privnet_agent_alive(void)
{
	__u32 liveness_key = PRIVNET_WATCHDOG_LIVENESS;
	__u32 timeout_key = PRIVNET_WATCHDOG_TIMEOUT;
	__u64 *last = map_lookup_elem(&cilium_privnet_watchdog, &liveness_key);
	__u64 *timeout = map_lookup_elem(&cilium_privnet_watchdog, &timeout_key);

	if (unlikely(!last || !timeout))
		return false;

	if (ktime_get_ns() - (*last) > (*timeout))
		return false;

	return true;
}

/* cilium_privnet_cidr_identity contains a global prefix to identity mapping
 * used by privnet "unknown flow" policy. It works similar to cilium_ipcache,
 * but only contains prefixes that are guaranteed to not be managed by Cilium.
 */
struct privnet_cidr_identity_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 family;
	__u8 pad[3];
	union {
		union v4addr ip4;
		union v6addr ip6;
	};
};

struct privnet_cidr_identity {
	__u32 sec_identity;
};

#define PRIVNET_CIDR_IDENTITY_STATIC_PREFIX					\
(8 * (sizeof(struct privnet_cidr_identity_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define PRIVNET_CIDR_IDENTITY_PREFIX_LEN(PREFIX) (PRIVNET_CIDR_IDENTITY_STATIC_PREFIX + (PREFIX))

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct privnet_cidr_identity_key);
	__type(value, struct privnet_cidr_identity);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CIDR_IDENTITY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_privnet_cidr_identity __section_maps_btf;

static __always_inline const struct privnet_cidr_identity *
privnet_cidr_identity_lookup4(const void *map, __be32 addr) {
	struct privnet_cidr_identity_key key = {};

	key.lpm_key.prefixlen = PRIVNET_CIDR_IDENTITY_PREFIX_LEN(V4_PRIVNET_KEY_LEN);
	key.family = ENDPOINT_KEY_IPV4;
	key.ip4.be32 = addr;

	return map_lookup_elem(map, &key);
}

static __always_inline const struct privnet_cidr_identity *
privnet_cidr_identity_lookup6(const void *map, union v6addr addr) {
	struct privnet_cidr_identity_key key = {};

	key.lpm_key.prefixlen = PRIVNET_CIDR_IDENTITY_PREFIX_LEN(V6_PRIVNET_KEY_LEN);
	key.family = ENDPOINT_KEY_IPV6;
	key.ip6 = addr;

	return map_lookup_elem(map, &key);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct privnet_arp_sender_key);
	__type(value, struct privnet_arp_sender_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_ARP_SENDER_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_privnet_arp_sender_cache __section_maps_btf;

static __always_inline __be32
privnet_get_arp_sender(__u16 net_id, __u16 subnet_id)
{
	struct privnet_arp_sender_key key = {
		.net_id = net_id,
		.subnet_id = subnet_id,
	};
	struct privnet_arp_sender_val *val;
	__be32 ipv4 = 0;

	val = map_lookup_elem(&cilium_privnet_arp_sender_cache, &key);
	if (val)
		ipv4 = val->ipv4;

	return ipv4;
}

static __always_inline bool
privnet_is_identity_any_host(__u32 identity)
{
	return identity_is_host(identity) ||
		identity_is_remote_node(identity) ||
		identity_is_ingress(identity);
}

/* The function does SNAT for a (remote) host packets destined to a PrivNet workload.
 *
 * The dst IP of the packet is in the P-IP space. Thus, we can use the global CT and NAT
 * BPF maps (no risk for the IP overlaps).
 */
static __always_inline int
privnet_host_snat_ingress4(struct __ctx_buff *ctx __maybe_unused)
{
#if defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT)
	struct ipv4_nat_target target = {
		.addr = CONFIG(privnet_host_snat_ipv4).be32,
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		/* No need to set .needs_ct, as the relevant CT entry should exist before this function is
		 * invoked (created by bpf_lxc). For posterity, missing CT entry can result in
		 * the PurgeOrphanNATEntries (GC) removing the NAT entries of non-closed connections.
		 */
	};
	struct ipv4_ct_tuple tuple = {};
	struct trace_ctx trace = {};
	void *data, *data_end;
	fraginfo_t fraginfo;
	struct iphdr *ip4;
	__s8 ext_err = 0;
	int l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	fraginfo = ipfrag_encode_ipv4(ip4);

	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	return snat_v4_nat(ctx, &tuple, ip4, fraginfo, l4_off,
			   &target, &trace, &ext_err);
#else
	return 0;
#endif /* ENABLE_IPV4 && ENABLE_NODEPORT */
}

/* The function does rev-SNAT to packets destined to a (remote) host (from
 * the link-local IP addr).
 */
static __always_inline int
privnet_host_rev_snat_egress4(struct __ctx_buff *ctx __maybe_unused)
{
#if defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT)
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	struct trace_ctx trace = {};
	__s8 ext_err = 0;

	return snat_v4_rev_nat(ctx, &target, &trace, &ext_err);
#else
	return 0;
#endif /* ENABLE_IPV4 && ENABLE_NODEPORT */
}

/* See comment for privnet_host_snat_ingress4(). */
static __always_inline int
privnet_host_snat_ingress6(struct __ctx_buff *ctx __maybe_unused)
{
#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
	struct snat_v6_args *args = AUX(snat_v6_args);
	fraginfo_t fraginfo = 0;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int hdrlen, l4_off;
	__s8 ext_err = 0;

	memset(args, 0, sizeof(*args));
	args->target.addr = CONFIG(privnet_host_snat_ipv6);
	args->target.min_port = NODEPORT_PORT_MIN_NAT;
	args->target.max_port = NODEPORT_PORT_MAX_NAT;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	args->tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &args->tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	snat_v6_init_tuple(ip6, NAT_DIR_EGRESS, &args->tuple);

	l4_off = (__u32)(((void *)ip6 - data) + hdrlen);


	return snat_v6_nat(ctx, fraginfo, l4_off, &ext_err);
#else
	return 0;
#endif /* ENABLE_IPV6 && ENABLE_NODEPORT */
}

/* See comment for privnet_host_rev_snat_egress4(). */
static __always_inline int
privnet_host_rev_snat_egress6(struct __ctx_buff *ctx __maybe_unused)
{
#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	struct trace_ctx trace = {};
	__s8 ext_err = 0;

	return snat_v6_rev_nat(ctx, &target, &trace, &ext_err);
#else
	return 0;
#endif /* ENABLE_IPV6 && ENABLE_NODEPORT */
}

static __always_inline int
enforce_privnet_egress_segmentation(const struct privnet_fib_val *sip_val,
				    const struct privnet_fib_val *dip_val,
				    bool host_traffic)
{
	if (sip_val && !dip_val) {
		/* The destination mapping not present, where as source has an entry.
		 *
		 * In LXC, this would mean that privnet enabled pod sent out packet to
		 * destination for which there is no endpoint or route associated. To prevent
		 * this packet to leak into underlay it is better to drop it.
		 *
		 * In netdev, this would mean packet came in from connected L2 segment. Src
		 * for some reason believe that destination is in kubernetes cluster. However,
		 * absence of dip_val suggests there is no ep present with that dst ip (within
		 * private network). It is better to drop the packet as we have no way to route
		 * to the destination and do not want this packet to leave via INB underlay.
		 *
		 * In lxc, we still need to allow packet to (remote) host, if the host reachability
		 * is enabled.
		 */
		if (is_defined(IS_BPF_LXC) && CONFIG(privnet_host_reachability) && host_traffic)
			return CTX_ACT_OK;

		return DROP_UNROUTABLE;
	}

	return CTX_ACT_OK;
}

/* privnet_redirect_neigh_fib_ipv4() - redirect packet to the specified
 * interface based on the given FIB map entry.
 * @dip_val: FIB map entry
 * @daddr: destination address extracted from the packet
 * @ifindex: ifindex of the interface to redirect the packet to
 *
 * The packet is redirected using redirect_neigh(). The neigh lookup is for the
 * given destination IP address if the FIB map entry is a subnet route or for
 * the nexthop IP in case of a static route.
 *
 * Return: CTX_ACT_REDIRECT if the packet was redirected, DROP_UNROUTABLE if no
 *         route was found for the destination IP and the packet should be
 *         dropped.
 */
static __always_inline int
privnet_redirect_neigh_fib_ipv4(const struct privnet_fib_val *dip_val, __be32 daddr,
				__u32 ifindex)
{
	struct bpf_redir_neigh nh_params = {
		.nh_family = AF_INET,
	};

	if (!dip_val)
		return DROP_UNROUTABLE;

	if (dip_val->type == PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE)
		/* Subnet route: neigh lookup for destination IP */
		nh_params.ipv4_nh = daddr;
	else if (dip_val->type == PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE)
		/* Subnet route: neigh lookup for nexthop IP */
		nh_params.ipv4_nh = dip_val->ip4.be32;
	else
		/* No route found for destination IP */
		return DROP_UNROUTABLE;

	return redirect_neigh(ifindex, &nh_params, sizeof(nh_params), 0);
}

/* privnet_local_access_egress_ipv4() - redirect packet to the connected local
 * access interface, if specified in the given FIB map entry.
 * @ctx: packet context
 * @sec_label: source security identity
 * @dst_sec_identity: destination security identity for trace notification
 * @dip_val: FIB map entry
 * @daddr: destination address extracted from the packet
 * @trace: trace metadata for trace notification
 *
 * The packet is redirected using privnet_redirect_neigh_fib_ipv4().
 *
 * Return: CTX_ACT_REDIRECT if the packet was redirected, CTX_ACT_OK if no action
 *         was taken, DROP_UNROUTABLE if no route was found for the destination
 *         IP and the packet should be dropped.
 */
static __always_inline int
privnet_local_access_egress_ipv4(struct __ctx_buff *ctx, __u32 sec_label,
				 __u32 dst_sec_identity,
				 const struct privnet_fib_val *dip_val, __be32 daddr,
				 struct trace_ctx *trace)
{
	__u32 ifindex = dip_val->ifindex;
	int ret;

	if (!CONFIG(privnet_local_access_enable) || ifindex == 0 ||
	    (dip_val->type != PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE &&
	     dip_val->type != PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE))
		return CTX_ACT_OK;

	ret = privnet_redirect_neigh_fib_ipv4(dip_val, daddr, ifindex);
	if (ret == CTX_ACT_REDIRECT && trace)
		send_trace_notify(ctx, TRACE_TO_NETWORK, sec_label, dst_sec_identity,
				  TRACE_EP_ID_UNKNOWN, ifindex, trace->reason,
				  trace->monitor, bpf_htons(ETH_P_IP));

	return ret;
}

static __always_inline int
privnet_evpn_egress_ipv4(struct __ctx_buff *ctx, __u16 net_id, __u32 sec_label,
			 const struct privnet_fib_val *dip_val, __be32 daddr,
			 struct trace_ctx *trace)
{
	if (CONFIG(evpn_enable) && dip_val->type == PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE)
		return evpn_encap_and_redirect4(ctx, net_id, sec_label, daddr, trace);

	return CTX_ACT_OK;
}

static __always_inline int
privnet_unknown_policy_can_access(const struct __ctx_buff *ctx, __u32 local_id, __u32 remote_id,
				  __u16 ethertype, __be16 dport, __u8 proto, int off, int dir,
				  bool is_untracked_fragment, __u8 *match_type, __s8 *ext_err,
				  __u16 *proxy_port, __u32 *cookie, __u8 *audited)
{
	int verdict = CTX_ACT_OK;

	verdict = policy_can_access(ctx, local_id, remote_id,
				    ethertype, dport, proto, off, dir,
				    is_untracked_fragment, match_type, ext_err,
				    proxy_port, cookie);

	if (audited) {
		*audited = 0;
#ifdef POLICY_AUDIT_MODE
		if (IS_ERR(verdict)) {
			verdict = CTX_ACT_OK;
			*audited = 1;
		}
#endif
	}

	if (verdict < 0)
		cilium_dbg(ctx, DBG_POLICY_DENIED, local_id, remote_id);

	/* unknown flow doesn't support redirect to proxy, so return a policy drop */
	if (proxy_port && *proxy_port)
		verdict = DROP_POLICY;

	return verdict;
}

__noinline __weak int
privnet_unknown_policy_egress4(const struct __ctx_buff *ctx,
			       __u16 net_id,
			       __u32 sec_label,
			       __u32 *dst_sec_identity,
			       struct trace_ctx *trace)
{
	const struct privnet_cidr_identity *info = NULL;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	fraginfo_t fraginfo __maybe_unused;
	bool is_untracked_fragment = false;
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	__u32 local_dst_sec_identity;
	void *ct_map, *ct_map_any;
	int verdict = CTX_ACT_OK;
	void *data, *data_end;
	__u16 proxy_port = 0;
	__s8 *ext_err = NULL;
	struct iphdr *ip4;
	__u32 monitor = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	int l4_off;
	int ct_ret;
	int ret;

	if (!dst_sec_identity)
		dst_sec_identity = &local_dst_sec_identity;

	*dst_sec_identity = WORLD_IPV4_ID;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	fraginfo = ipfrag_encode_ipv4(ip4);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipfrag_is_fragment(fraginfo);
#endif

	tuple.nexthdr = ip4->protocol;
	tuple.saddr = ip4->saddr;
	tuple.daddr = ip4->daddr;

	ct_map = privnet_get_ct_map4(&tuple, net_id);
	ct_map_any = privnet_get_ct_any_map4(net_id);
	if (unlikely(!ct_map || !ct_map_any))
		return DROP_EP_NOT_READY;

	ct_ret = ct_lookup4(ct_map, &tuple, ctx, ip4, l4_off,
			    CT_EGRESS, SCOPE_BIDIR, &ct_state, &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	info = privnet_cidr_identity_lookup4(&cilium_privnet_cidr_identity, ip4->daddr);
	if (info)
		*dst_sec_identity = info->sec_identity;

	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	verdict = privnet_unknown_policy_can_access(ctx, sec_label, *dst_sec_identity, ETH_P_IP,
						    tuple.dport, tuple.nexthdr, l4_off, CT_EGRESS,
						    is_untracked_fragment, &policy_match_type,
						    ext_err, &proxy_port, &cookie, &audited);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		/* Unknown flow doesn't support proxy port, so no need to set any of the ct_state fields */
		struct ct_state ct_state_new = {};

		ret = ct_create4(ct_map, ct_map_any, &tuple,
				 ctx, CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, *dst_sec_identity, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

/* privnet_egress_ipv4 can be called as traffic comes from pod to lxc, it should be
 * the first thing to happen before processing the packet further in bpf_lxc.
 *
 * It can also be called from connected L2 segment on INB(network bridge), traffic coming
 * from external endpoints or unknown sources which are destined to kubernetes
 * cluster endpoints.
 *
 * Following operations are done at egress
 * - FIB lookup for source and destination in privnet_fib map.
 * - If lookup contains endpoint entries, it will do stateless NAT based on the entry.
 * - In local access mode, the packet may be redirected directly to the network
 *   device given in the FIB map entry ifindex.
 * - Basic segmentation check.
 * - Egress policy enforcement for unknown flow (when invoked from lxc)
 * - Returns lookup result for source and destination.
 */
static __always_inline int privnet_egress_ipv4(struct __ctx_buff *ctx,
					       __u32 sec_label, __u16 net_id, __u16 subnet_id,
					       const struct privnet_fib_val **src_privnet_entry,
					       const struct privnet_fib_val **dst_privnet_entry,
					       __u32 *dst_sec_identity, struct trace_ctx *trace)
{
	void *data, *data_end;
	struct iphdr *ip4;
	const struct privnet_fib_val *sip_val = NULL;
	const struct privnet_fib_val *dip_val = NULL;
	int ret = CTX_ACT_OK;
	bool host_traffic = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	host_traffic = is_defined(IS_BPF_LXC) && CONFIG(privnet_host_reachability) &&
		ip4->daddr == CONFIG(privnet_host_snat_ipv4).be32;

	/* Don't lookup destination FIB entry for traffic to the host SNAT IP.
	 * The configured routes should not never apply to this traffic and the
	 * packet will be dropped if there is no SNAT entry.
	 */
	if (!host_traffic)
		dip_val = privnet_fib_lookup4(net_id, subnet_id, ip4->daddr);

	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		/* Apply egress unknown policy before local-access or evpn
		 * redirect. Unknown policy is applied under these conditions:
		 * (a) Destination is route entry, corollary, destination is not
		 * Cilium managed endpoint - dst will remain in private-network space.
		 * (b) Apply policy at lxc egress, this is indirectly enforced by
		 * sec_label, which will be set when called from bpf_lxc.
		 */
		if (is_privnet_route_entry(dip_val) && sec_label) {
			/* enforce egress policy for unknown flow */
			ret = privnet_unknown_policy_egress4(ctx, net_id, sec_label,
							     dst_sec_identity, trace);
			if (ret != CTX_ACT_OK)
				return ret;

			ret = privnet_local_access_egress_ipv4(ctx, sec_label,
							       *dst_sec_identity, dip_val,
							       ip4->daddr, trace);
			if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
				return ret;

			/* We can return on redirect here as Privnet <=> EVPN communication doesn't require NAT */
			ret = privnet_evpn_egress_ipv4(ctx, net_id, sec_label,
						       dip_val, ip4->daddr, trace);
			if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
				return ret;
		}

		if (!is_privnet_route_entry(dip_val)) {
			/* Only NAT if entry is for the endpoint, for route
			 * entries, skip NATing.
			 */
			ret = privnet_nat_v4_addr(ctx, ip4->daddr, dip_val->ip4.be32,
						  IPV4_DADDR_OFF);
			if (IS_ERR(ret)) {
				if (ret == DROP_CSUM_L3 || ret == DROP_CSUM_L4)
					/* Checksum failure still means we (somewhat)
					 * successfully NATed the packet.
					 */
					set_privnet_net_dst_id(PRIVNET_PIP_NET_ID);
				return ret;
			}
			/* Set net id to default network.*/
			set_privnet_net_dst_id(PRIVNET_PIP_NET_ID);
		}
	}

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	sip_val = privnet_fib_lookup4(net_id, subnet_id, ip4->saddr);
	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		if (!is_privnet_route_entry(sip_val)) {
			/* Only NAT if entry is for the endpoint, for route
			 * entries, skip NATing.
			 */
			ret = privnet_nat_v4_addr(ctx, ip4->saddr, sip_val->ip4.be32,
						  IPV4_SADDR_OFF);
			if (IS_ERR(ret)) {
				if (ret == DROP_CSUM_L3 || ret == DROP_CSUM_L4)
					/* Checksum failure still means we (somewhat)
					 * successfully NATed the packet.
					 */
					set_privnet_net_src_id(PRIVNET_PIP_NET_ID);
				return ret;
			}
			/* Set net id to default network.*/
			set_privnet_net_src_id(PRIVNET_PIP_NET_ID);
		}
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (host_traffic && sip_val) {
		const struct remote_endpoint_info *info;
		__u32 host_dst_sec_identity;

		ret = privnet_host_rev_snat_egress4(ctx);
		if (IS_ERR(ret))
			return ret;
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		host_dst_sec_identity = info ? info->sec_identity : UNKNOWN_ID;
		if (!privnet_is_identity_any_host(host_dst_sec_identity))
			return DROP_UNROUTABLE;

		/* Set net id to default network.*/
		set_privnet_net_dst_id(PRIVNET_PIP_NET_ID);
	}

	return enforce_privnet_egress_segmentation(sip_val, dip_val, host_traffic);
}

__noinline __weak int
privnet_unknown_policy_egress6(const struct __ctx_buff *ctx,
			       __u16 net_id,
			       __u32 sec_label,
			       __u32 *dst_sec_identity,
			       struct trace_ctx *trace)
{
	struct ipv6_ct_tuple *tuple = AUX(privnet_unknown_egress6_tuple);
	const struct privnet_cidr_identity *info = NULL;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	bool is_untracked_fragment = false;
	struct ct_state ct_state = {};
	__u32 local_dst_sec_identity;
	void *ct_map, *ct_map_any;
	int verdict = CTX_ACT_OK;
	fraginfo_t fraginfo = 0;
	void *data, *data_end;
	__u16 proxy_port = 0;
	__s8 *ext_err = NULL;
	struct ipv6hdr *ip6;
	__u32 monitor = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	int hdrlen;
	int l4_off;
	int ct_ret;
	int ret;

	if (!dst_sec_identity)
		dst_sec_identity = &local_dst_sec_identity;

	*dst_sec_identity = WORLD_IPV6_ID;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	memset(tuple, 0, sizeof(*tuple));
	tuple->nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple->nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);

	ct_map = privnet_get_ct_map6(tuple, net_id);
	ct_map_any = privnet_get_ct_any_map6(net_id);
	if (unlikely(!ct_map || !ct_map_any))
		return DROP_EP_NOT_READY;

	ct_ret = ct_lookup6(ct_map, tuple, ctx, ip6, fraginfo, l4_off,
			    CT_EGRESS, SCOPE_BIDIR, &ct_state, &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	info = privnet_cidr_identity_lookup6(&cilium_privnet_cidr_identity,
					     *((union v6addr *)&ip6->daddr));
	if (info)
		*dst_sec_identity = info->sec_identity;

	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	verdict = privnet_unknown_policy_can_access(ctx, sec_label, *dst_sec_identity, ETH_P_IPV6,
						    tuple->dport, tuple->nexthdr, l4_off, CT_EGRESS,
						    is_untracked_fragment, &policy_match_type,
						    ext_err, &proxy_port, &cookie, &audited);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		/* Unknown flow doesn't support proxy port, so no need to set any of the ct_state fields */
		struct ct_state ct_state_new = {};

		ret = ct_create6(ct_map, ct_map_any, tuple,
				 ctx, CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, *dst_sec_identity, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

/* See comment for privnet_redirect_neigh_fib_ipv4() */
static __always_inline int
privnet_redirect_neigh_fib_ipv6(const struct privnet_fib_val *dip_val, const union v6addr *daddr,
				__u32 ifindex)
{
	struct bpf_redir_neigh nh_params = {
		.nh_family = AF_INET6,
	};

	if (!dip_val)
		return DROP_UNROUTABLE;

	if (dip_val->type == PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE)
		/* Subnet route: neigh lookup for destination IP */
		__bpf_memcpy_builtin(&nh_params.ipv6_nh, daddr,
				     sizeof(nh_params.ipv6_nh));
	else if (dip_val->type == PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE)
		/* Subnet route: neigh lookup for nexthop IP */
		__bpf_memcpy_builtin(&nh_params.ipv6_nh, &dip_val->ip6,
				     sizeof(nh_params.ipv6_nh));
	else
		/* No route found for destination IP */
		return DROP_UNROUTABLE;

	return redirect_neigh(ifindex, &nh_params, sizeof(nh_params), 0);
}

/* See comment for privnet_local_access_egress_ipv4() */
static __always_inline int
privnet_local_access_egress_ipv6(struct __ctx_buff *ctx, __u32 sec_label,
				 __u32 dst_sec_identity,
				 const struct privnet_fib_val *dip_val,
				 const union v6addr *daddr, struct trace_ctx *trace)
{
	__u32 ifindex = dip_val->ifindex;
	int ret;

	if (!CONFIG(privnet_local_access_enable) || ifindex == 0 ||
	    (dip_val->type != PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE &&
	     dip_val->type != PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE))
		return CTX_ACT_OK;

	ret = privnet_redirect_neigh_fib_ipv6(dip_val, daddr, ifindex);
	if (ret == CTX_ACT_REDIRECT && trace)
		send_trace_notify(ctx, TRACE_TO_NETWORK, sec_label, dst_sec_identity,
				  TRACE_EP_ID_UNKNOWN, ifindex, trace->reason,
				  trace->monitor, bpf_htons(ETH_P_IPV6));

	return ret;
}

static __always_inline int
privnet_evpn_egress_ipv6(struct __ctx_buff *ctx, __u16 net_id, __u32 sec_label,
			 const struct privnet_fib_val *dip_val,
			 const union v6addr *daddr, struct trace_ctx *trace)
{
	if (CONFIG(evpn_enable) && dip_val->type == PRIVNET_FIB_VAL_TYPE_VXLAN_ROUTE)
		return evpn_encap_and_redirect6(ctx, net_id, sec_label, daddr, trace);

	return CTX_ACT_OK;
}

/* See comment for privnet_egress_ipv4() */
static __always_inline int privnet_egress_ipv6(struct __ctx_buff *ctx,
					       __u32 sec_label, __u16 net_id, __u16 subnet_id,
					       const struct privnet_fib_val **src_privnet_entry,
					       const struct privnet_fib_val **dst_privnet_entry,
					       __u32 *dst_sec_identity, struct trace_ctx *trace)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	const struct privnet_fib_val *sip_val = NULL;
	const struct privnet_fib_val *dip_val = NULL;
	union v6addr orig_sip, orig_dip;
	int ret = CTX_ACT_OK;
	bool host_traffic = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);

	/* Host reachability is disabled for v6 due to BPF complexity limits */
	if (is_defined(WIP) && is_defined(IS_BPF_LXC) && CONFIG(privnet_host_reachability)) {
		union v6addr snat_ipv6 = CONFIG(privnet_host_snat_ipv6);

		if (ipv6_addr_equals((union v6addr *)&ip6->daddr, &snat_ipv6))
			host_traffic = true;
	}

	/* Don't lookup destination FIB entry for traffic to the host SNAT IP.
	 * The configured routes should not never apply to this traffic and the
	 * packet will be dropped if there is no SNAT entry.
	 */
	if (!host_traffic)
		dip_val = privnet_fib_lookup6(net_id, subnet_id, orig_dip);

	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		if (is_privnet_route_entry(dip_val) && sec_label) {
			/* enforce egress policy for unknown flow */
			ret = privnet_unknown_policy_egress6(ctx, net_id, sec_label,
							     dst_sec_identity, trace);
			if (ret != CTX_ACT_OK)
				return ret;

			ret = privnet_local_access_egress_ipv6(ctx, sec_label,
							       *dst_sec_identity, dip_val,
							       &orig_dip, trace);
			if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
				return ret;

			/* We can return on redirect here as Privnet <=> EVPN communication doesn't require NAT */
			ret = privnet_evpn_egress_ipv6(ctx, net_id, sec_label, dip_val,
						       &orig_dip, trace);
			if (IS_ERR(ret) || ret == CTX_ACT_REDIRECT)
				return ret;
		}

		if (!is_privnet_route_entry(dip_val)) {
			ret = privnet_nat_v6_addr(ctx, &orig_dip, &dip_val->ip6,
						  IPV6_DADDR_OFF);
			if (IS_ERR(ret))
				return ret;
			/* Set net id to default network.*/
			set_privnet_net_dst_id(PRIVNET_PIP_NET_ID);
		}
	}

	sip_val = privnet_fib_lookup6(net_id, subnet_id, orig_sip);
	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		if (!is_privnet_route_entry(sip_val)) {
			ret = privnet_nat_v6_addr(ctx, &orig_sip, &sip_val->ip6,
						  IPV6_SADDR_OFF);
			if (IS_ERR(ret))
				return ret;
			/* Set net id to default network.*/
			set_privnet_net_src_id(PRIVNET_PIP_NET_ID);
		}
	}

	/* Host reachability is disabled for v6 due to BPF complexity limits */
	if (is_defined(WIP) && host_traffic && sip_val) {
		const struct remote_endpoint_info *info;
		__u32 host_dst_sec_identity;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		ret = privnet_host_rev_snat_egress6(ctx);
		if (IS_ERR(ret))
			return ret;
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);

		info = lookup_ip6_remote_endpoint(&orig_dip, 0);
		host_dst_sec_identity = info ? info->sec_identity : UNKNOWN_ID;
		if (!privnet_is_identity_any_host(host_dst_sec_identity))
			return DROP_UNROUTABLE;

		/* Set net id to default network.*/
		set_privnet_net_dst_id(PRIVNET_PIP_NET_ID);
	}

	return enforce_privnet_egress_segmentation(sip_val, dip_val, host_traffic);
}

#define PRIVNET_PIP_STATIC_PREFIX						\
(8 * (sizeof(struct privnet_pip_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define PRIVNET_PIP_PREFIX_LEN(PREFIX) (PRIVNET_PIP_STATIC_PREFIX + (PREFIX))

static __always_inline __maybe_unused const struct privnet_pip_val *
privnet_pip_lookup4(__be32 addr) {
	struct privnet_pip_key key = {};

	key.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V4_PRIVNET_KEY_LEN);
	key.family = ENDPOINT_KEY_IPV4;
	key.ip4.be32 = addr;

	return map_lookup_elem(&cilium_privnet_pip, &key);
}

static __always_inline __maybe_unused const struct privnet_pip_val *
privnet_pip_lookup6(union v6addr addr) {
	struct privnet_pip_key key = {};

	key.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V6_PRIVNET_KEY_LEN);
	key.family = ENDPOINT_KEY_IPV6;
	key.ip6 = addr;

	return map_lookup_elem(&cilium_privnet_pip, &key);
}

/*
 * Semantics of enforce_privnet_ingress_segmentation are slightly different from
 * enforce_privnet_egress_segmentation. PIP map does not contain route entries,
 * therefore for unknown flow, we do not get route hit.
 */
static __always_inline int
enforce_privnet_ingress_segmentation_at_inb(bool unknown_flow,
					    const struct privnet_pip_val *sip_val,
					    const struct privnet_pip_val *dip_val)
{
	if (unknown_flow) {
		if (sip_val)
			return CTX_ACT_OK;
	} else {
		if (sip_val && dip_val && sip_val->net_id == dip_val->net_id)
			return CTX_ACT_OK;
	}

	return DROP_UNROUTABLE;
}

static __always_inline int
enforce_privnet_ingress_segmentation_at_lxc(bool unknown_flow, bool host_traffic,
					    __u16 net_id,
					    const struct privnet_pip_val *sip_val,
					    const struct privnet_pip_val *dip_val)
{
	/* For ingress traffic, valid dip entry must exist, since traffic in going to pod.
	 * Similarly, dip net_id must match lxc net_id.
	 */
	if (!dip_val || net_id != dip_val->net_id)
		return DROP_UNROUTABLE;

	/* Allow traffic from unknown flows. */
	if (unknown_flow)
		return CTX_ACT_OK;

	/* For known flows, sip net_id must match lxc net_id. */
	if (sip_val && net_id == sip_val->net_id)
		return CTX_ACT_OK;

	/* Allow packet if it is from (remote) host (e.g. ILB request from T2 node) */
	if (CONFIG(privnet_host_reachability) && host_traffic)
		return CTX_ACT_OK;

	return DROP_UNROUTABLE;
}

__noinline __weak int
privnet_unknown_policy_ingress4(const struct __ctx_buff *ctx,
				__u16 net_id,
				__u32 sec_label,
				__u32 *src_sec_identity,
				struct trace_ctx *trace)
{
	const struct privnet_cidr_identity *info = NULL;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	bool is_untracked_fragment = false;
	__u32 local_src_sec_identity;
	int verdict = CTX_ACT_OK;
	void *data, *data_end;
	__u16 proxy_port = 0;
	__s8 *ext_err = NULL;
	struct iphdr *ip4;
	__u32 monitor = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	int l4_off;
	int ct_ret;
	int ret;

	void *ct_map, *ct_map_any;
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};

	if (!src_sec_identity)
		src_sec_identity = &local_src_sec_identity;

	*src_sec_identity = WORLD_IPV4_ID;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipfrag_is_fragment(ipfrag_encode_ipv4(ip4));
#endif

	tuple.nexthdr = ip4->protocol;
	tuple.saddr = ip4->saddr;
	tuple.daddr = ip4->daddr;

	ct_map = privnet_get_ct_map4(&tuple, net_id);
	ct_map_any = privnet_get_ct_any_map4(net_id);
	if (unlikely(!ct_map || !ct_map_any))
		return DROP_EP_NOT_READY;

	ct_ret = ct_lookup4(ct_map, &tuple, ctx, ip4, l4_off,
			    CT_INGRESS, SCOPE_BIDIR, &ct_state, &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	info = privnet_cidr_identity_lookup4(&cilium_privnet_cidr_identity, ip4->saddr);
	if (info)
		*src_sec_identity = info->sec_identity;

	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	verdict = privnet_unknown_policy_can_access(ctx, sec_label, *src_sec_identity, ETH_P_IP,
						    tuple.dport, tuple.nexthdr, l4_off, CT_INGRESS,
						    is_untracked_fragment, &policy_match_type,
						    ext_err, &proxy_port, &cookie, &audited);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		/* Unknown flow doesn't support proxy port, so no need to set any of the ct_state fields */
		struct ct_state ct_state_new = {};

		ret = ct_create4(ct_map, ct_map_any, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, *src_sec_identity, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

/* privnet_lxc_ingress_ipv4 should be called for privnet enabled endpoints when traffic is going to
 * those endpoints, but only if the packet is in PIP space, i.e. not for unknown flow or local
 * access.
 *
 * Following changes are done in this call
 * - Lookup of private IP from PIPs.
 * - Translating PIP to private IPs, for both source and destination.
 * - SNAT request if source is host.
 * - Enforce segmentation to prevent invalid traffic from going to the destination.
 */
static __always_inline int
privnet_lxc_ingress_ipv4(struct __ctx_buff *ctx, __u16 net_id)
{
	const struct privnet_pip_val *sip_val = NULL;
	const struct privnet_pip_val *dip_val = NULL;
	bool host_traffic = false; /* pkt originating from a (remote) host identity */
	void *data, *data_end;
	int ret = CTX_ACT_OK;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	sip_val = privnet_pip_lookup4(ip4->saddr);

	/* SNAT (remote) host request. This must happen be before the stateless P-IP SNAT, as
	 * the host SNAT uses global CT/NAT maps (P-IP and PrivNet netIP can collide).
	 */
	if (CONFIG(privnet_host_reachability) && !sip_val) {
		const struct remote_endpoint_info *info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		__u32 src_sec_identity = info ? info->sec_identity : UNKNOWN_ID;

		if (privnet_is_identity_any_host(src_sec_identity)) {
			host_traffic = true;
			ret = privnet_host_snat_ingress4(ctx);
			if (IS_ERR(ret))
				return ret;
			set_privnet_net_src_id(net_id);
		}
	}

	/* Perform source NAT only if :
	 * (a) corresponding netIP exist, and
	 * (b) the network ID matches the expected one.
	 */
	if (sip_val && net_id == sip_val->net_id) {
		ret = privnet_nat_v4_addr(ctx, ip4->saddr, sip_val->ip4.be32, IPV4_SADDR_OFF);
		if (IS_ERR(ret)) {
			if (ret == DROP_CSUM_L3 || ret == DROP_CSUM_L4)
				/* Checksum failure still means we (somewhat)
				 * successfully NATed the packet
				 */
				set_privnet_net_src_id(sip_val->net_id);
			return ret;
		}
		/* Set net id to target network.*/
		set_privnet_net_src_id(sip_val->net_id);
	}

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	dip_val = privnet_pip_lookup4(ip4->daddr);
	if (dip_val && net_id == dip_val->net_id) {
		/* Perform destination NAT only if:
		 * (a) the network ID matches the expected one
		 */
		ret = privnet_nat_v4_addr(ctx, ip4->daddr, dip_val->ip4.be32, IPV4_DADDR_OFF);
		if (IS_ERR(ret)) {
			if (ret == DROP_CSUM_L3 || ret == DROP_CSUM_L4)
				/* Checksum failure still means we (somewhat)
				 * successfully NATed the packet
				 */
				set_privnet_net_dst_id(dip_val->net_id);
			return ret;
		}
		/* Set net id to target network.*/
		set_privnet_net_dst_id(dip_val->net_id);
	}

	return enforce_privnet_ingress_segmentation_at_lxc(false, host_traffic,
							   net_id, sip_val, dip_val);
}

/* privnet_lxc_unknown_ingress_ipv4 should be called for privnet enabled endpoints when unknown
 * flow traffic is going to those endpoints, i.e. when the destination is translated, but the
 * source is in netIP space.
 *
 * Following changes are done in this call
 * - Lookup of destination IP from PIPs.
 * - Translating PIP to private IPs, fordestination.
 * - Do unknown flow policy enforcement.
 * - Enforce segmentation to prevent invalid traffic from going to the destination.
 */
static __always_inline int
privnet_lxc_unknown_ingress_ipv4(struct __ctx_buff *ctx,
				 __u32 sec_label, __u16 net_id,
				 __u32 *src_sec_identity,
				 struct trace_ctx *trace)
{
	const struct privnet_pip_val *dip_val = NULL;
	void *data, *data_end;
	int ret = CTX_ACT_OK;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	dip_val = privnet_pip_lookup4(ip4->daddr);
	if (dip_val && net_id == dip_val->net_id) {
		/* Perform destination NAT only if:
		 * (a) the network ID matches the expected one
		 */
		ret = privnet_nat_v4_addr(ctx, ip4->daddr, dip_val->ip4.be32, IPV4_DADDR_OFF);
		if (IS_ERR(ret)) {
			if (ret == DROP_CSUM_L3 || ret == DROP_CSUM_L4)
				/* Checksum failure still means we (somewhat)
				 * successfully NATed the packet
				 */
				set_privnet_net_ids(dip_val->net_id, dip_val->net_id);
			return ret;
		}
		/* Set net id to target network.
		 * For unknown flow - the source is also in the target
		 * network, even though we did not NAT it.
		 */
		set_privnet_net_ids(dip_val->net_id, dip_val->net_id);
	}

	/* enforce ingress policy for unknown flow */
	ret = privnet_unknown_policy_ingress4(ctx, net_id, sec_label, src_sec_identity, trace);
	if (ret != CTX_ACT_OK)
		return ret;

	return enforce_privnet_ingress_segmentation_at_lxc(true, false,
							   net_id, NULL, dip_val);
}

/* privnet_lxc_unxlated_ingress_ipv4 should be called for privnet enabled endpoints when unxlated
 * traffic is going to those endpoints, i.e. traffic from local access or EVPN.
 *
 * The call does unknown flow policy
 */
static __always_inline int
privnet_lxc_unxlated_ingress_ipv4(const struct __ctx_buff *ctx,
				  __u32 sec_label, __u16 net_id,
				  __u32 *src_sec_identity,
				  struct trace_ctx *trace)
{
	/* unxlated_flow means both src and dst are in private-network space. As such
	 * there will be no entry for such src/dst in pip map.
	 * Set net_ids based on passed net_id and check ingress unknown policy.
	 * And return early after ingress policy check.
	 */
	set_privnet_net_ids(net_id, net_id);
	return privnet_unknown_policy_ingress4(ctx, net_id, sec_label, src_sec_identity, trace);
}

/* privnet_inb_ingress_ipv4 should be called from overlay device in INB for traffic
 * coming from k8s cluster and going towards connected INB network.
 *
 * Following changes are done in this call
 * - Lookup of private IP from PIPs.
 *   - src is always expected to be PIP, dst depends on unknown flow.
 * - Translating pip to private IPs, for both source and destination.
 * - Enforce policy/segmentation to prevent invalid traffic from going to the destination.
 */
static __always_inline int
privnet_inb_ingress_ipv4(struct __ctx_buff *ctx, bool unknown_flow,
			 const struct privnet_pip_val **src_privnet_entry,
			 const struct privnet_pip_val **dst_privnet_entry)
{
	void *data, *data_end;
	struct iphdr *ip4;
	const struct privnet_pip_val *sip_val = NULL;
	const struct privnet_pip_val *dip_val = NULL;
	int ret = CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	sip_val = privnet_pip_lookup4(ip4->saddr);
	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		ret = privnet_nat_v4_addr(ctx, ip4->saddr, sip_val->ip4.be32, IPV4_SADDR_OFF);
		if (IS_ERR(ret)) {
			if (ret == DROP_CSUM_L3 || ret == DROP_CSUM_L4)
				/* Checksum failure still means we (somewhat)
				 * successfully NATed the packet
				 */
				set_privnet_net_src_id(sip_val->net_id);
			return ret;
		}
		/* Set net id to target network.*/
		set_privnet_net_src_id(sip_val->net_id);
	}

	if (unknown_flow) {
		/* if it is unknown flow, then we skip dip as destination IP is not
		 * PIP. This is for traffic coming from k8s cluster into INB
		 * and going out to connected L2 network.
		 * The destination netID is the assumed to be the same as the source netID.
		 */
		if (sip_val)
			set_privnet_net_dst_id(sip_val->net_id);
		goto out;
	}

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	dip_val = privnet_pip_lookup4(ip4->daddr);
	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		/* Perform destination NAT only if:
		 * (a) it matches the one of the sip entry.
		 */
		if (sip_val && sip_val->net_id == dip_val->net_id) {
			ret = privnet_nat_v4_addr(ctx, ip4->daddr, dip_val->ip4.be32,
						  IPV4_DADDR_OFF);
			if (IS_ERR(ret)) {
				if (ret == DROP_CSUM_L3 || ret == DROP_CSUM_L4)
					/* Checksum failure still means we (somewhat)
					 * successfully NATed the packet
					 */
					set_privnet_net_dst_id(dip_val->net_id);
				return ret;
			}
			/* Set net id to target network.*/
			set_privnet_net_dst_id(dip_val->net_id);
		}
	}

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

out:
	return enforce_privnet_ingress_segmentation_at_inb(unknown_flow, sip_val, dip_val);
}

__noinline __weak int
privnet_unknown_policy_ingress6(const struct __ctx_buff *ctx,
				__u16 net_id,
				__u32 sec_label,
				__u32 *src_sec_identity,
				struct trace_ctx *trace)
{
	const struct privnet_cidr_identity *info = NULL;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	bool is_untracked_fragment = false;
	struct ipv6_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	__u32 local_src_sec_identity;
	void *ct_map, *ct_map_any;
	int verdict = CTX_ACT_OK;
	fraginfo_t fraginfo = 0;
	void *data, *data_end;
	__u16 proxy_port = 0;
	__s8 *ext_err = NULL;
	struct ipv6hdr *ip6;
	__u32 monitor = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	int hdrlen;
	int l4_off;
	int ct_ret;
	int ret;

	if (!src_sec_identity)
		src_sec_identity = &local_src_sec_identity;

	*src_sec_identity = WORLD_IPV6_ID;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);

	ct_map = privnet_get_ct_map6(&tuple, net_id);
	ct_map_any = privnet_get_ct_any_map6(net_id);
	if (unlikely(!ct_map || !ct_map_any))
		return DROP_EP_NOT_READY;

	ct_ret = ct_lookup6(ct_map, &tuple, ctx, ip6, fraginfo, l4_off,
			    CT_INGRESS, SCOPE_BIDIR, &ct_state, &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	info = privnet_cidr_identity_lookup6(&cilium_privnet_cidr_identity,
					     *(union v6addr *)&ip6->saddr);
	if (info)
		*src_sec_identity = info->sec_identity;

	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	verdict = privnet_unknown_policy_can_access(ctx, sec_label, *src_sec_identity, ETH_P_IPV6,
						    tuple.dport, tuple.nexthdr, l4_off, CT_INGRESS,
						    is_untracked_fragment, &policy_match_type,
						    ext_err, &proxy_port, &cookie, &audited);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		/* Unknown flow doesn't support proxy port, so no need to set any of the ct_state fields */
		struct ct_state ct_state_new = {};

		ret = ct_create6(ct_map, ct_map_any, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, *src_sec_identity, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

static __always_inline int
privnet_lxc_ingress_ipv6(struct __ctx_buff *ctx, __u16 net_id)
{
	const struct privnet_pip_val *sip_val = NULL;
	const struct privnet_pip_val *dip_val = NULL;
	union v6addr orig_sip, orig_dip;
	bool host_traffic = false;
	void *data, *data_end;
	int ret = CTX_ACT_OK;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);

	sip_val = privnet_pip_lookup6(orig_sip);

	/* Host reachability is disabled for v6 due to BPF complexity limits */
	if (is_defined(WIP) && CONFIG(privnet_host_reachability) && !sip_val) {
		const struct remote_endpoint_info *info = lookup_ip6_remote_endpoint(&orig_sip, 0);
		__u32 src_sec_identity = info ? info->sec_identity : UNKNOWN_ID;

		if (privnet_is_identity_any_host(src_sec_identity)) {
			host_traffic = true;
			ret = privnet_host_snat_ingress6(ctx);
			if (IS_ERR(ret))
				return ret;
			set_privnet_net_src_id(net_id);
		}
	}

	/* Perform source NAT only if corresponding netIP exists and the network ID matches. */
	if (sip_val && net_id == sip_val->net_id) {
		ret = privnet_nat_v6_addr(ctx, &orig_sip, &sip_val->ip6,
					  IPV6_SADDR_OFF);
		if (IS_ERR(ret))
			return ret;
		/* Set net id to target network.*/
		set_privnet_net_src_id(sip_val->net_id);
	}

	dip_val = privnet_pip_lookup6(orig_dip);
	if (dip_val && net_id == dip_val->net_id) {
		ret = privnet_nat_v6_addr(ctx, &orig_dip, &dip_val->ip6,
					  IPV6_DADDR_OFF);
		if (IS_ERR(ret))
			return ret;
		/* Set net id to target network.*/
		set_privnet_net_dst_id(dip_val->net_id);
	}

	return enforce_privnet_ingress_segmentation_at_lxc(false, host_traffic,
							   net_id, sip_val, dip_val);
}

static __always_inline int
privnet_lxc_unknown_ingress_ipv6(struct __ctx_buff *ctx, __u32 sec_label, __u16 net_id,
				 __u32 *src_sec_identity, struct trace_ctx *trace)
{
	const struct privnet_pip_val *dip_val = NULL;
	union v6addr orig_dip __align_stack_8;
	void *data, *data_end;
	int ret = CTX_ACT_OK;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);

	dip_val = privnet_pip_lookup6(orig_dip);
	if (dip_val && net_id == dip_val->net_id) {
		ret = privnet_nat_v6_addr(ctx, &orig_dip, &dip_val->ip6,
					  IPV6_DADDR_OFF);
		if (IS_ERR(ret))
			return ret;

		/* Set net ids to target network.
		 * For in unknown flow - the source is also in the target
		 * network, even though we did not NAT it.
		 */
		set_privnet_net_ids(dip_val->net_id, dip_val->net_id);
	}

	/* enforce ingress policy for unknown flow */
	ret = privnet_unknown_policy_ingress6(ctx, net_id, sec_label, src_sec_identity, trace);
	if (ret != CTX_ACT_OK)
		return ret;

	return enforce_privnet_ingress_segmentation_at_lxc(true, false,
							   net_id, NULL, dip_val);
}

static __always_inline int
privnet_lxc_unxlated_ingress_ipv6(const struct __ctx_buff *ctx, __u32 sec_label, __u16 net_id,
				  __u32 *src_sec_identity, struct trace_ctx *trace)
{
	set_privnet_net_ids(net_id, net_id);
	return privnet_unknown_policy_ingress6(ctx, net_id, sec_label, src_sec_identity, trace);
}

/* See comments in privnet_inb_ingress_ipv4 */
static __always_inline int
privnet_inb_ingress_ipv6(struct __ctx_buff *ctx, bool unknown_flow,
			 const struct privnet_pip_val **src_privnet_entry,
			 const struct privnet_pip_val **dst_privnet_entry)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	const struct privnet_pip_val *sip_val = NULL;
	const struct privnet_pip_val *dip_val = NULL;
	union v6addr orig_sip, orig_dip;
	int ret = CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);

	sip_val = privnet_pip_lookup6(orig_sip);

	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		ret = privnet_nat_v6_addr(ctx, &orig_sip, &sip_val->ip6,
					  IPV6_SADDR_OFF);
		if (IS_ERR(ret))
			return ret;
		/* Set net id to target network.*/
		set_privnet_net_src_id(sip_val->net_id);
	}

	if (unknown_flow) {
		if (sip_val)
			set_privnet_net_dst_id(sip_val->net_id);
		goto out;
	}

	dip_val = privnet_pip_lookup6(orig_dip);
	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		if (sip_val && sip_val->net_id == dip_val->net_id) {
			ret = privnet_nat_v6_addr(ctx, &orig_dip, &dip_val->ip6,
						  IPV6_DADDR_OFF);
			if (IS_ERR(ret))
				return ret;
			/* Set net id to target network.*/
			set_privnet_net_dst_id(dip_val->net_id);
		}
	}

	/* revalidate data before accessing ip6, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

out:
	return enforce_privnet_ingress_segmentation_at_inb(unknown_flow, sip_val, dip_val);
}

static __always_inline int
privnet_evpn_ingress_ipv4(struct __ctx_buff *ctx, __u16 net_id)
{
	const struct privnet_fib_val *dip_val;
	const struct endpoint_info *ep;
	void *data, *data_end;
	struct iphdr *ip4;
	__u16 subnet_id;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	subnet_id = privnet_subnet_id_lookup4(net_id, ip4->daddr);

	dip_val = privnet_fib_lookup4(net_id, subnet_id, ip4->daddr);
	if (!dip_val)
		return DROP_UNROUTABLE;

	/* We only want to handle EVPN => Endpoint ingress at this
	 * point. Drop in any other case for now.
	 */
	if (dip_val->type != PRIVNET_FIB_VAL_TYPE_ENDPOINT)
		return DROP_UNROUTABLE;

	/* When we don't have an endpoint, don't route further. */
	ep = __lookup_ip4_endpoint(dip_val->ip4.be32);
	if (!ep)
		return DROP_UNROUTABLE;

	return ipv4_local_delivery(ctx, ETH_HLEN, WORLD_IPV4_ID, MARK_MAGIC_IDENTITY,
				   ip4, ep, METRIC_INGRESS, false, false, 0);
}

static __always_inline int
privnet_evpn_ingress_ipv6(struct __ctx_buff *ctx, __u16 net_id)
{
	const struct privnet_fib_val *dip_val;
	const struct endpoint_info *ep;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr daddr;
	__u16 subnet_id;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&daddr, (union v6addr *)&ip6->daddr);

	subnet_id = privnet_subnet_id_lookup6(net_id, daddr);

	dip_val = privnet_fib_lookup6(net_id, subnet_id, daddr);
	if (!dip_val)
		return DROP_UNROUTABLE;

	/* We only want to handle EVPN => Endpoint ingress at this
	 * point. Drop in any other case for now.
	 */
	if (dip_val->type != PRIVNET_FIB_VAL_TYPE_ENDPOINT)
		return DROP_UNROUTABLE;

	/* When we don't have an endpoint, don't route further. */
	ep = __lookup_ip6_endpoint((const union v6addr *)&dip_val->ip6);
	if (!ep)
		return DROP_UNROUTABLE;

	return ipv6_local_delivery(ctx, ETH_HLEN, WORLD_IPV6_ID, MARK_MAGIC_IDENTITY,
				   ep, METRIC_INGRESS, false, false);
}

static __always_inline int
__privnet_evpn_ingress(struct __ctx_buff *ctx, const __u16 net_id)
{
	__u16 proto;

	if (!CONFIG(privnet_enable))
		return CTX_ACT_DROP;

	if (!validate_ethertype(ctx, &proto))
		return DROP_INVALID;

	switch (proto) {
	case bpf_htons(ETH_P_IP):
		return privnet_evpn_ingress_ipv4(ctx, net_id);
	case bpf_htons(ETH_P_IPV6):
		return privnet_evpn_ingress_ipv6(ctx, net_id);
	default:
		return DROP_UNKNOWN_L3;
	}
}

static __always_inline int
privnet_ext_ep_policy_egress4(struct __ctx_buff *ctx,
			      struct iphdr *ip4,
			      __u32 dst_sec_identity,
			      struct trace_ctx *trace,
			      __s8 *ext_err)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};
	int verdict = CTX_ACT_OK;
	__u16 proxy_port = 0;
	__u32 monitor = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	int l4_off;
	int ct_ret;
	int ret;

	/* calculate tuple */
	tuple.nexthdr = ip4->protocol;
	tuple.saddr = ip4->saddr;
	tuple.daddr = ip4->daddr;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ct_ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, ip4, l4_off,
			    CT_EGRESS, SCOPE_BIDIR, &ct_state, &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	verdict = ext_eps_policy_can_egress4(ctx, ip4->saddr, dst_sec_identity, tuple.dport,
					     ip4->protocol, l4_off, &policy_match_type, &audited,
					     ext_err, &proxy_port, &cookie);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		/* TODO: To make userspace proxy work, we need to set src_sec_id here */
		struct ct_state ct_state_new = {};

		ret = ct_create4(get_ct_map4(&tuple), &cilium_ct_any4_global, &tuple,
				 ctx, CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, dst_sec_identity, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

static __always_inline int
privnet_ext_ep_policy_ingress4(struct __ctx_buff *ctx,
			       struct iphdr *ip4,
			       __u32 src_sec_identity,
			       __s8 *ext_err)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	int verdict = CTX_ACT_OK;
	__u16 proxy_port = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	__u32 monitor = 0;
	int l4_off;
	int ct_ret;
	int ret;
	bool is_untracked_fragment = false;
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipfrag_is_fragment(ipfrag_encode_ipv4(ip4));
#endif

	tuple.nexthdr = ip4->protocol;
	tuple.saddr = ip4->saddr;
	tuple.daddr = ip4->daddr;
	ct_ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, ip4, l4_off,
			    CT_INGRESS, SCOPE_BIDIR, &ct_state, &monitor);

	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	verdict = ext_eps_policy_can_ingress4(ctx, ip4->daddr, src_sec_identity, tuple.dport,
					      ip4->protocol, l4_off, is_untracked_fragment,
					      &policy_match_type, &audited, ext_err, &proxy_port,
					      &cookie);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		struct ct_state ct_state_new = {};

		ct_state_new.src_sec_id = src_sec_identity;
		ret = ct_create4(get_ct_map4(&tuple), &cilium_ct_any4_global, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, src_sec_identity, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

static __always_inline int
privnet_ext_ep_policy_egress6(struct __ctx_buff *ctx,
			      struct ipv6hdr *ip6,
			      __u32 dst_sec_identity,
			      struct trace_ctx *trace,
			      __s8 *ext_err __maybe_unused)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	struct ipv6_ct_tuple tuple = {};
	int hdrlen, l4_off, ct_ret, ret;
	int verdict = CTX_ACT_OK;
	fraginfo_t fraginfo = 0;
	__u16 proxy_port = 0;
	__u32 monitor = 0;
	__u8 audited = 0;
	__u32 cookie = 0;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);

	ct_ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, ip6,
			    fraginfo, l4_off,
			    CT_EGRESS, SCOPE_BIDIR, NULL,
			    &monitor);
	if (trace) {
		trace->monitor = monitor;
		trace->reason = (enum trace_reason)ct_ret;
	}

	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	/* using tuple.daddr as the local endpoint IP here because ct_lookup swaps the order */
	verdict = ext_eps_policy_can_egress6(ctx, tuple.daddr, dst_sec_identity, tuple.dport,
					     ip6->nexthdr, l4_off, &policy_match_type,
					     &audited, ext_err, &proxy_port, &cookie);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		/* TODO: To make userspace proxy work, we need to set src_sec_id here */
		struct ct_state ct_state_new = {};

		ret = ct_create6(get_ct_map6(&tuple), &cilium_ct_any6_global, &tuple,
				 ctx, CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, dst_sec_identity, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

static __always_inline int
privnet_ext_ep_policy_ingress6(struct __ctx_buff *ctx,
			       struct ipv6hdr *ip6,
			       __u32 src_sec_identity,
			       __s8 *ext_err __maybe_unused)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	bool is_untracked_fragment = false;
	struct ipv6_ct_tuple tuple = {};
	int hdrlen, l4_off, ct_ret, ret;
	int verdict = CTX_ACT_OK;
	fraginfo_t fraginfo = 0;
	__u16 proxy_port = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	__u32 monitor = 0;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);

#ifndef ENABLE_IPV6_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipfrag_is_fragment(fraginfo);
#endif

	ct_ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, ip6,
			    fraginfo, l4_off,
			    CT_INGRESS, SCOPE_BIDIR, NULL,
			    &monitor);
	/* Skip policy enforcement for return traffic. */
	if (ct_ret == CT_REPLY || ct_ret == CT_RELATED)
		return CTX_ACT_OK;

	/* using tuple.saddr as the local endpoint IP here because ct_lookup swaps the order */
	verdict = ext_eps_policy_can_ingress6(ctx, tuple.saddr, src_sec_identity, tuple.dport,
					      ip6->nexthdr, l4_off, is_untracked_fragment,
					      &policy_match_type, &audited, ext_err, &proxy_port,
					      &cookie);

	/* Only create CT entry for accepted connections */
	if (ct_ret == CT_NEW && verdict == CTX_ACT_OK) {
		struct ct_state ct_state_new = {};

		ct_state_new.src_sec_id = src_sec_identity;
		ret = ct_create6(get_ct_map6(&tuple), &cilium_ct_any6_global, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_ret != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, src_sec_identity, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, false,
					   verdict, proxy_port, policy_match_type, audited,
					   0, cookie);
	}

	return verdict;
}

#ifdef ENABLE_IPV6
static __always_inline bool ipv6_addr_is_link_local(const union v6addr *ip6addr)
{
	/* fe80::/10: first 10 bits must be 1111111010 */
	return (ip6addr->addr[0] == 0xfe) && ((ip6addr->addr[1] & 0xc0) == 0x80);
}

static __always_inline int
handle_privnet_ns(struct __ctx_buff *ctx, const __u16 net_id,
		  const union v6addr *ep_addr)
{
	union macaddr mac = CONFIG(interface_mac);
	const struct privnet_fib_val *val;
	union v6addr tip;
	__u8 type;

	if (icmp6_load_type(ctx, ETH_HLEN + sizeof(struct ipv6hdr), &type) < 0 ||
	    type != ICMP6_NS_MSG_TYPE)
		return CTX_ACT_OK;

	if (ctx_load_bytes(ctx, ETH_HLEN + ICMP6_ND_TARGET_OFFSET, tip.addr,
			   sizeof(((struct ipv6hdr *)NULL)->saddr)) < 0)
		return CTX_ACT_OK;

	if (is_defined(IS_BPF_LXC) && ipv6_addr_is_link_local(&tip)) {
		/*
		 * Only applicable for LXC.
		 * We are expecting default route from inside the VM as 'default via <some-link-local-address>.
		 * Which means connected VM will send NS for a link local address.
		 * Check target address is 0xfe80 address, if yes then respond with NS.
		 *
		 * TODO: Have a better way to configure link local route inside the VM and only respond to
		 * NS for that address.
		 */
		return icmp6_send_ndisc_adv(ctx, ETH_HLEN, &mac, false);
	}

	val = privnet_fib_lookup6(net_id, privnet_subnet_id_lookup6(net_id, tip), tip);

	/* Don't reply to NDs if the agent is not alive, as the map state may
	 * be out of sync, and we may conflict with the newly activated INB.
	 */
	if (!val || is_privnet_route_entry(val) ||
	    !(is_defined(IS_BPF_LXC) || (val->flag_l2_announce && privnet_agent_alive())) ||
	    (!is_defined(IS_BPF_LXC) && CONFIG(privnet_local_access_enable) &&
	     val->ifindex != CONFIG(interface_ifindex)))
		return CTX_ACT_OK;

	if (is_defined(IS_BPF_LXC) && ep_addr) {
		/*
		 * Don't reply to neighbor solicitations for the IPv6 address
		 * associated with the local endpoint, to avoid issues caused
		 * by duplicate address detection checks.
		 */
		if (ipv6_addr_equals(&tip, ep_addr))
			return DROP_UNROUTABLE;
	}

	return icmp6_send_ndisc_adv(ctx, ETH_HLEN, &mac, false);
}
#endif /* ENABLE_IPv6 */

static __always_inline bool ipv4_addr_is_link_local(const __be32 ip4)
{
	return (bpf_ntohl(ip4) >> 16) == 0xA9FE /* 169 254 */;
}

/* handle_privnet_arp_egress - rewrite the SIP of an egress ARP request
 * to the privnet per-subnet "sender IP". Falls back to 0.0.0.0
 * (ARP probe) when the agent is not alive. No-op for non-requests,
 * gratuitous announcements.
 */
static __always_inline int
handle_privnet_arp_egress(struct __ctx_buff *ctx, __u16 net_id)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct arphdr *arp = data + ETH_HLEN;
	struct arp_eth *arp_eth;
	__u16 subnet_id = 0;
	__be32 sender_ip = 0;
	__u32 sip_off = 0;

	if (data + ETH_HLEN + sizeof(*arp) + sizeof(*arp_eth) > data_end)
		return DROP_INVALID;

	if (arp->ar_op != bpf_htons(ARPOP_REQUEST))
		return CTX_ACT_OK;

	arp_eth = data + ETH_HLEN + sizeof(*arp);

	/* Preserve gratuitous announcements (sip == tip) */
	if (arp_eth->ar_sip == arp_eth->ar_tip)
		return CTX_ACT_OK;

	subnet_id = privnet_subnet_id_lookup4(net_id, arp_eth->ar_tip);
	if (!subnet_id)
		return CTX_ACT_OK;

	if (privnet_agent_alive())
		sender_ip = privnet_get_arp_sender(net_id, subnet_id);

	/* ARP sip_off = 28 ( Eth 14 + ARP HDR 8 + SIP OFFSET 6 ) */
	sip_off = ETH_HLEN + sizeof(struct arphdr) +
		  offsetof(struct arp_eth, ar_sip);

	if (ctx_store_bytes(ctx, sip_off, &sender_ip, sizeof(sender_ip), 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}

static __always_inline int
handle_privnet_arp(struct __ctx_buff *ctx, const __u16 net_id,
		   const union v4addr *ep_addr __maybe_unused)
{
	union macaddr mac = CONFIG(interface_mac);
	union macaddr smac;
	__be32 sip, tip;
	const struct privnet_fib_val *val;

	/* Prevent the compiler from making (incorrect) assumptions on the content
	 * of the mac variable, and in turn optimizing out the eth_addrcmp(dmac, mac)
	 * check of arp_validate. Otherwise, no response would be generated for
	 * unicast ARP requests.
	 */
	barrier_data(&mac);

	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;

	if (ep_addr) {
		/* No network IP assigned so drop all ARP requests until one is assigned.
		 * This ensures the DHCP client won't reject an offer when it tries to
		 * arping the offered address.
		 */
		if (!ep_addr->be32)
			return DROP_UNROUTABLE;

		/* Don't reply to ARP requests for the endpoint's own network IP in order
		 * to allow DHCP renewal (DHCP clients ARPing to check if IP is in use).
		 */
		if (tip == ep_addr->be32)
			return DROP_UNROUTABLE;

		return CTX_ACT_OK;
	}

	if (ipv4_addr_is_link_local(tip)) {
		/*
		 * Only applicable for LXC.
		 * We are expecting default route from inside the VM as 'default via <some-link-local-address>.
		 * Which means connected VM will send ARP for a link local address.
		 * Check target address is the link local address, if yes then respond with ARP
		 * and skip the fib lookup and agent liveness check.
		 */
		return arp_respond(ctx, &mac, tip, &smac, sip, 0);
	}

	val = privnet_fib_lookup4(net_id, privnet_subnet_id_lookup4(net_id, tip), tip);

	/* Don't reply to ARPs if the agent is not alive, as the map state may
	 * be out of sync, and we may conflict with the newly activated INB.
	 */
	if (!val || !val->flag_l2_announce || !privnet_agent_alive() ||
	    (CONFIG(privnet_local_access_enable) && val->ifindex != CONFIG(interface_ifindex)))
		return CTX_ACT_OK;

	return arp_respond(ctx, &mac, tip, &smac, sip, 0);
}

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

/*
 * Redirect DHCP reply packet to cilium_dhcp so the agent can process it
 * without using a raw socket bound to an external facing interface.
 *
 * Returns the result of ctx_redirect() for matching DHCP replies and
 * CTX_ACT_OK otherwise.
 */
static __always_inline int
privnet_redirect_dhcp_reply(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	__u32 dhcp_ifindex = CONFIG(cilium_dhcp_ifindex);
	__be16 sport, dport;
	int l4_off;

	if (!dhcp_ifindex || THIS_IS_L3_DEV || ip4->protocol != IPPROTO_UDP)
		return CTX_ACT_OK;

	/* Destination is 255.255.255.255? */
	if (ip4->daddr != bpf_htonl(0xffffffff))
		return CTX_ACT_OK;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	if (l4_load_port(ctx, l4_off + UDP_SPORT_OFF, &sport) < 0 ||
	    l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
		return DROP_INVALID;

	if (sport != bpf_htons(DHCP_SERVER_PORT) || dport != bpf_htons(DHCP_CLIENT_PORT))
		return CTX_ACT_OK;

	/* Set the source mac address to "0 0 <ifindex>" so agent knows which
	 * interface the packet arrived to and can attribute the reply to the right
	 * request even if there are mac address and xid overlaps between different
	 * private networks (as long as the same interface is not used).
	 */
	{
		__u32 src_ifindex = CONFIG(interface_ifindex);
		__u8 src[ETH_ALEN] = { 0, 0, src_ifindex >> 24 & 0xff, src_ifindex >> 16 & 0xff,
				       src_ifindex >> 8 & 0xff, src_ifindex & 0xff};

		if (ctx_store_bytes(ctx, ETH_ALEN, src, sizeof(src), 0) < 0)
			return DROP_WRITE_ERROR;
	}

	return ctx_redirect(ctx, dhcp_ifindex, 0);
}

#ifdef IS_BPF_LXC

/* redirect DHCP packets coming from the pod to the 'cilium_dhcp' device,
 * which the agent will then relay and forward the reply back to the endpoint's
 * host-side veth device
 */
static __always_inline int
privnet_redirect_dhcp_request(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	__be16 dport;
	int l4_off;
	__u32 dhcp_ifindex = CONFIG(cilium_dhcp_ifindex);

	if (!dhcp_ifindex)
		return CTX_ACT_OK;

	/* DHCP redirection requires an L2 frame since we rewrite source/destination MACs. */
	if (THIS_IS_L3_DEV)
		return CTX_ACT_OK;

	/* UDP and going to DHCP server port? */
	if (ip4->protocol != IPPROTO_UDP)
		return CTX_ACT_OK;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
		return CTX_ACT_OK;
	if (dport != bpf_htons(DHCP_SERVER_PORT))
		return CTX_ACT_OK;

	/* Encode the endpoint id into the source MAC so agent can reliably associate the request
	 * with a specific endpoint. Set the destination MAC as broadcast to ensure the agent
	 * raw packet socket can read the packet.
	 *
	 * Source MAC      -> 00:00:00:00:ep:ep
	 * Destination MAC -> FF:FF:FF:FF:FF:FF
	 */
	{
		__u64 dst = 0xffffffffffffffff;
		__u16 src_lo = bpf_htons(LXC_ID);
		__u32 src_hi = 0;

		ctx_store_bytes(ctx, ETH_ALEN, &src_hi, 4, 0);
		ctx_store_bytes(ctx, ETH_ALEN + 4, &src_lo, sizeof(src_lo), 0);
		ctx_store_bytes(ctx, 0, &dst, ETH_ALEN, 0);
	}

	/* Redirect to 'cilium_dhcp' device */
	return ctx_redirect(ctx, dhcp_ifindex, 0);
}

#endif /* IS_BPF_LXC */

static __always_inline bool
is_privnet_local_access_ingress(const struct privnet_fib_val *val)
{
	/* local access ingress for this device and for a local endpoint */
	return val &&
		val->ifindex == CONFIG(interface_ifindex) &&
		val->type == PRIVNET_FIB_VAL_TYPE_ENDPOINT;
}

/* privnet_local_access_ingress_ipv4() - redirect packet to the endpoint's lxc
 * interface if a local access the FIB map entry exists.
 * @ctx: packet buffer
 * @net_id: network ID
 * @subnet_id: sub-network ID
 *
 * Return: CTX_ACT_REDIRECT if the packet was redirected, CTX_ACT_OK if no action
 *         was taken, DROP_UNROUTABLE if no route was found for the destination
 *         IP and the packet should be dropped.
 */
static __always_inline int
privnet_local_access_ingress_ipv4(struct __ctx_buff *ctx, const __u16 net_id,
				  const __u16 subnet_id)
{
	void *data, *data_end;
	struct iphdr *ip4;
	const struct privnet_fib_val *dip_val = NULL;
	const struct endpoint_info *ep = NULL;

	if (!CONFIG(privnet_local_access_enable))
		return CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	dip_val = privnet_fib_lookup4(net_id, subnet_id, ip4->daddr);
	if (is_privnet_local_access_ingress(dip_val)) {
		/* Found endpoint FIB map entry with local access ifindex for
		 * destination address. This implies local access N/S traffic.
		 * Look up local endpoint for destination NetIP address.
		 */
		ep = __lookup_ip4_endpoint(dip_val->ip4.be32);
		if (ep) {
			/* Redirect to the corresponding endpoint's lxc policy program. */
			return ipv4_local_delivery(ctx, ETH_HLEN, WORLD_IPV4_ID,
						   MARK_MAGIC_IDENTITY, ip4, ep,
						   METRIC_INGRESS, false, false, 0);
		}

		/* No local endpoint found to redirect to. */
		return DROP_UNROUTABLE;
	}

	/* No local access FIB map entry found. Continue the regular bpf_host
	 * packet flow and let it decide on this packet's fate.
	 */
	return CTX_ACT_OK;
}

/* See comment for privnet_local_access_ingress_ipv4() */
static __always_inline int
privnet_local_access_ingress_ipv6(struct __ctx_buff *ctx, const __u16 net_id,
				  const __u16 subnet_id)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr daddr;
	const struct privnet_fib_val *dip_val = NULL;
	const struct endpoint_info *ep = NULL;

	if (!CONFIG(privnet_local_access_enable))
		return CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&daddr, (union v6addr *)&ip6->daddr);

	dip_val = privnet_fib_lookup6(net_id, subnet_id, daddr);
	if (is_privnet_local_access_ingress(dip_val)) {
		/* Found endpoint FIB map entry with local access ifindex for
		 * destination address. This implies local access N/S traffic.
		 * Look up local endpoint for destination NetIP address.
		 */
		ep = __lookup_ip6_endpoint(&dip_val->ip6);
		if (ep) {
			/* Redirect to the corresponding endpoint's lxc interface policy program. */
			return ipv6_local_delivery(ctx, ETH_HLEN, WORLD_IPV6_ID,
						   MARK_MAGIC_IDENTITY, ep,
						   METRIC_INGRESS, false, false);
		}

		/* No local endpoint found to redirect to. */
		return DROP_UNROUTABLE;
	}

	/* No local access FIB map entry found. Continue the regular bpf_host
	 * packet flow and let it decide on this packet's fate.
	 */
	return CTX_ACT_OK;
}

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline void
__privnet_fib_v4_add_entry(__u16 net_id, __u16 subnet_id, __be32 prefix, __u8 prefix_len,
			   __be32 nexthop, enum privnet_fib_type type, bool l2_announce,
			   __u32 ifindex, const union macaddr *mac)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.subnet_id = subnet_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};
	struct privnet_fib_val value = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = nexthop,
		.type = (__u8)type,
		.flag_l2_announce = l2_announce,
		.ifindex = ifindex,
	};

	if (mac)
		value.mac = *mac;

	map_update_elem(&cilium_privnet_fib, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_fib_v4_del_entry(__u16 net_id, __u16 subnet_id, __be32 prefix, __u8 prefix_len)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.subnet_id = subnet_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};

	map_delete_elem(&cilium_privnet_fib, &key);
}

static __always_inline void
__privnet_fib_v6_add_entry(__u16 net_id, __u16 subnet_id, const union v6addr *prefix,
			   const union v6addr *nexthop, enum privnet_fib_type type,
			   bool l2_announce, __u32 ifindex, const union macaddr *mac)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.net_id = net_id,
		.subnet_id = subnet_id,
		.family = ENDPOINT_KEY_IPV6,
	};
	struct privnet_fib_val value = {
		.family = ENDPOINT_KEY_IPV6,
		.type = (__u8)type,
		.flag_l2_announce = l2_announce,
		.ifindex = ifindex,
	};

	ipv6_addr_copy_unaligned(&key.ip6, prefix);
	ipv6_addr_copy_unaligned(&value.ip6, nexthop);

	if (mac)
		value.mac = *mac;

	map_update_elem(&cilium_privnet_fib, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_fib_v6_del_entry(__u16 net_id, __u16 subnet_id, const union v6addr *prefix)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.net_id = net_id,
		.subnet_id = subnet_id,
		.family = ENDPOINT_KEY_IPV6,
	};

	ipv6_addr_copy_unaligned(&key.ip6, prefix);

	map_delete_elem(&cilium_privnet_fib, &key);
}

static __always_inline void
__privnet_pip_v4_add_entry(__be32 pod_ip, __u16 net_id, __be32 net_ip)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V4_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = pod_ip,
	};

	struct privnet_pip_val value = {
		.family = ENDPOINT_KEY_IPV4,
		.net_id = net_id,
		.ip4.be32 = net_ip,
	};

	map_update_elem(&cilium_privnet_pip, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_pip_v4_del_entry(__be32 pod_ip)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V4_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = pod_ip,
	};

	map_delete_elem(&cilium_privnet_pip, &key);
}

static __always_inline void
__privnet_pip_v6_add_entry(const union v6addr *pod_ip, const union v6addr *net_ip, __be16 net_id)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV6,
	};
	struct privnet_pip_val value = {
		.family = ENDPOINT_KEY_IPV6,
		.net_id = net_id,
	};

	ipv6_addr_copy_unaligned(&key.ip6, pod_ip);
	ipv6_addr_copy_unaligned(&value.ip6, net_ip);

	map_update_elem(&cilium_privnet_pip, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_pip_v6_del_entry(const union v6addr *pod_ip)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV6,
	};
	ipv6_addr_copy_unaligned(&key.ip6, pod_ip);

	map_delete_elem(&cilium_privnet_pip, &key);
}

static __always_inline void
__privnet_v4_add_endpoint_entry(__u16 net_id, __u16 subnet_id, __be32 net_ip, __be32 pod_ip,
				__u32 ifindex, const union macaddr *mac)
{
	__privnet_fib_v4_add_entry(net_id, subnet_id, net_ip, V4_PRIVNET_KEY_LEN, pod_ip,
				   PRIVNET_FIB_VAL_TYPE_ENDPOINT, true, ifindex, mac);
	__privnet_pip_v4_add_entry(pod_ip, net_id, net_ip);
}

static __always_inline void
privnet_v4_add_endpoint_entry(__u16 net_id, __u16 subnet_id, __be32 net_ip, __be32 pod_ip)
{
	__privnet_v4_add_endpoint_entry(net_id, subnet_id, net_ip, pod_ip, 0, NULL);
}

static __always_inline void
privnet_v4_del_endpoint_entry(__u16 net_id, __u16 subnet_id, __be32 net_ip, __be32 pod_ip)
{
	__privnet_fib_v4_del_entry(net_id, subnet_id, net_ip, V4_PRIVNET_KEY_LEN);
	__privnet_pip_v4_del_entry(pod_ip);
}

static __always_inline void
privnet_v4_add_subnet_route(__u16 net_id, __u16 subnet_id, __be32 prefix, __u8 prefix_len,
			    __be32 nexthop, __u32 ifindex)
{
	__privnet_fib_v4_add_entry(net_id, subnet_id, prefix, prefix_len, nexthop,
				   PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE, false, ifindex, NULL);
}

static __always_inline void
privnet_v4_add_static_route(__u16 net_id, __u16 subnet_id, __be32 prefix, __u8 prefix_len,
			    __be32 nexthop, __u32 ifindex)
{
	__privnet_fib_v4_add_entry(net_id, subnet_id, prefix, prefix_len, nexthop,
				   PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE, false, ifindex, NULL);
}

static __always_inline void
privnet_v4_del_route(__u16 net_id, __u16 subnet_id, __be32 prefix, __u8 prefix_len)
{
	__privnet_fib_v4_del_entry(net_id, subnet_id, prefix, prefix_len);
}

static __always_inline void
privnet_v4_add_peering_route(__u16 net_id, __u16 subnet_id, __be32 prefix, __u8 prefix_len,
			     __u16 peer_net, __u16 peer_subnet)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.subnet_id = subnet_id,
		.type = PRIVNET_FIB_KEY_TYPE_PEERING,
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};
	struct privnet_fib_val value = {
		.family = ENDPOINT_KEY_IPV4,
		.peer_net_id = peer_net,
		.peer_subnet_id = peer_subnet,
	};

	map_update_elem(&cilium_privnet_fib, &key, &value, BPF_ANY);
}

static __always_inline void
privnet_v4_del_peering_route(__u16 net_id, __u16 subnet_id, __be32 prefix, __u8 prefix_len)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.subnet_id = subnet_id,
		.type = PRIVNET_FIB_KEY_TYPE_PEERING,
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};

	map_delete_elem(&cilium_privnet_fib, &key);
}

static __always_inline void
__privnet_v6_add_endpoint_entry(__u16 net_id, __u16 subnet_id, const union v6addr *net_ip,
				const union v6addr *pod_ip, __u32 ifindex,
				const union macaddr *mac)
{
	__privnet_fib_v6_add_entry(net_id, subnet_id, net_ip, pod_ip,
				   PRIVNET_FIB_VAL_TYPE_ENDPOINT, true, ifindex, mac);
	__privnet_pip_v6_add_entry(pod_ip, net_ip, net_id);
}

static __always_inline void
privnet_v6_add_endpoint_entry(__u16 net_id, __u16 subnet_id, const union v6addr *net_ip,
			      const union v6addr *pod_ip)
{
	__privnet_v6_add_endpoint_entry(net_id, subnet_id, net_ip, pod_ip, 0, NULL);
}

static __always_inline void
privnet_v6_del_endpoint_entry(__u16 net_id, __u16 subnet_id, const union v6addr *net_ip,
			      const union v6addr *pod_ip)
{
	__privnet_fib_v6_del_entry(net_id, subnet_id, net_ip);
	__privnet_pip_v6_del_entry(pod_ip);
}

static __always_inline void
privnet_v6_add_subnet_route(__u16 net_id, __u16 subnet_id, const union v6addr *prefix,
			    const union v6addr *nexthop, __u32 ifindex)
{
	__privnet_fib_v6_add_entry(net_id, subnet_id, prefix, nexthop,
				   PRIVNET_FIB_VAL_TYPE_SUBNET_ROUTE, false, ifindex, NULL);
}

static __always_inline void
privnet_v6_add_static_route(__u16 net_id, __u16 subnet_id, const union v6addr *prefix,
			    const union v6addr *nexthop, __u32 ifindex)
{
	__privnet_fib_v6_add_entry(net_id, subnet_id, prefix, nexthop,
				   PRIVNET_FIB_VAL_TYPE_STATIC_ROUTE, false, ifindex, NULL);
}

static __always_inline void
privnet_v6_del_route(__u16 net_id, __u16 subnet_id, const union v6addr *prefix)
{
	__privnet_fib_v6_del_entry(net_id, subnet_id, prefix);
}

static __always_inline void
privnet_add_device_entry(__u32 ifindex, __u16 net_id,
			 const union v4addr *ipv4,
			 const union v6addr *ipv6)
{
	struct privnet_device_key key = { .ifindex = ifindex };
	struct privnet_device_val val __aligned(8) = {};

	val.net_id = net_id;

	if (ipv4)
		val.ipv4 = *ipv4;
	if (ipv6)
		memcpy(&val.ipv6, ipv6, sizeof(val.ipv6));

	map_update_elem(&cilium_privnet_devices, &key, &val, BPF_ANY);
}

static __always_inline void
privnet_del_device_entry(__u32 ifindex)
{
	struct privnet_device_key key = { .ifindex = ifindex };

	map_delete_elem(&cilium_privnet_devices, &key);
}

static __always_inline void
privnet_v4_add_subnet_entry(__u16 net_id, __be32 prefix, __u8 prefix_len, __u16 subnet_id)
{
	struct privnet_subnet_key key = {
		.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};
	struct privnet_subnet_val val = { .subnet_id = subnet_id };

	map_update_elem(&cilium_privnet_subnets, &key, &val, BPF_ANY);
}

static __always_inline void
privnet_v6_add_subnet_entry(__u16 net_id, const union v6addr *prefix,
			    __u8 prefix_len, __u16 subnet_id)
{
	struct privnet_subnet_key key = {
		.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV6,
	};
	struct privnet_subnet_val val = { .subnet_id = subnet_id };

	ipv6_addr_copy_unaligned(&key.ip6, prefix);
	map_update_elem(&cilium_privnet_subnets, &key, &val, BPF_ANY);
}

static __always_inline void
privnet_v4_del_subnet_entry(__u16 net_id, __be32 prefix, __u8 prefix_len)
{
	struct privnet_subnet_key key = {
		.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};

	map_delete_elem(&cilium_privnet_subnets, &key);
}

static __always_inline void
privnet_v6_del_subnet_entry(__u16 net_id, const union v6addr *prefix, __u8 prefix_len)
{
	struct privnet_subnet_key key = {
		.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(prefix_len),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV6,
	};

	ipv6_addr_copy_unaligned(&key.ip6, prefix);
	map_delete_elem(&cilium_privnet_subnets, &key);
}

static const __u8 dhcp_bcast_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
#define DHCP_SERVER_PORT 67

static __always_inline int
build_privnet_dhcp_request_to(struct __ctx_buff *ctx, const __u8 *dmac, __be32 daddr)
{
	struct pktgen builder;
	__be32 saddr = v4_all;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ipv4_udp_packet(&builder, (__u8 *)mac_one,
					  (__u8 *)dmac, saddr, daddr,
					  bpf_htons(68), bpf_htons(DHCP_SERVER_PORT)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
build_privnet_dhcp_request(struct __ctx_buff *ctx)
{
	return build_privnet_dhcp_request_to(ctx, dhcp_bcast_mac,
					     IPV4(255, 255, 255, 255));
}

static __always_inline void
privnet_v4_add_cidr_identity_entry(__be32 prefix, __u8 prefix_len, __u32 sec_identity)
{
	struct privnet_cidr_identity_key key = {
		.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(prefix_len),
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};
	struct privnet_cidr_identity val = { .sec_identity = sec_identity };

	map_update_elem(&cilium_privnet_cidr_identity, &key, &val, BPF_ANY);
}

static __always_inline void
privnet_v4_del_cidr_identity_entry(__be32 prefix, __u8 prefix_len)
{
	struct privnet_cidr_identity_key key = {
		.lpm_key.prefixlen = PRIVNET_SUBNET_PREFIX_LEN(prefix_len),
		.family = ENDPOINT_KEY_IPV4,
		.ip4.be32 = prefix,
	};
	map_delete_elem(&cilium_privnet_cidr_identity, &key);
}

static __always_inline void
privnet_v4_add_arp_sender(__u16 net_id, __u16 subnet_id, __be32 ipv4)
{
	struct privnet_arp_sender_key key = {
		.net_id = net_id,
		.subnet_id = subnet_id,
	};
	struct privnet_arp_sender_val val = { .ipv4 = ipv4 };

	map_update_elem(&cilium_privnet_arp_sender_cache, &key, &val, BPF_ANY);
}

static __always_inline void
privnet_v4_del_arp_sender(__u16 net_id, __u16 subnet_id)
{
	struct privnet_arp_sender_key key = {
		.net_id = net_id,
		.subnet_id = subnet_id,
	};

	map_delete_elem(&cilium_privnet_arp_sender_cache, &key);
}

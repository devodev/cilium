# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import pkt_defs as pd
from scapy.all import *
def with_ttl_decremented(pkt):
    """Return a new packet with TTL decremented by 1 and recalculated checksum."""
    new_pkt = pkt.copy()
    new_pkt[IP].ttl -= 1
    del new_pkt[IP].chksum
    return Ether(bytes(new_pkt))

# IPv4 privnet addresses for pods in the cluster, reusing svc addresses.
v4_pod_one_netip    = pd.v4_svc_one
v4_pod_two_netip    = pd.v4_svc_two

v6_pod_one_netip    = pd.v6_svc_one
ns_pod_one_maddr    = pd.l2_announce6_ns_ma # reusing same ns as pkt_defs.py which is for v6_svc_one
ns_pod_one_mmac     = pd.l2_announce6_ns_mmac

v6_pod_two_netip    = "fd10::2"
ns_pod_two_maddr    = pd.v6_get_ns_addr(v6_pod_two_netip)
ns_pod_two_mmac     = pd.v6_get_ns_mac(v6_pod_two_netip)

v6_pod_three_netip  = "fd10::3"
ns_pod_three_maddr  = pd.v6_get_ns_addr(v6_pod_three_netip)
ns_pod_three_mmac   = pd.v6_get_ns_mac(v6_pod_three_netip)

# Pods in different subnet
v4_pod_three_netip  = "172.16.20.13"

v4_local_ep = "172.255.0.1"
v6_local_ep = "fd10::ffff:1"

# LXC NS and NA addressing
ns_target_ip = "fe80::100"
ns_mac = "33:33:00:00:01:00" # Multicast MAC for target IP fe80::100
ns_dst_ip = "ff02::1:ff00:100" # Multicast destination for NS

# Test packet/buffer definitions
## Privnet packet definitions
privnet_net_ip_arp_req = (
    Ether(dst=pd.mac_bcast, src=pd.mac_one) /
    ARP(op="who-has", psrc=v4_pod_one_netip, pdst=v4_pod_two_netip,
        hwsrc=pd.mac_one, hwdst=pd.mac_bcast)
)

## arp_req_egress is arp packet with sip = node_ip
privnet_net_ip_arp_req_egress = (
        Ether(dst=pd.mac_bcast, src=pd.mac_one) /
        ARP(op="who-has", psrc=pd.v4_node_one, pdst=v4_pod_two_netip,
            hwsrc=pd.mac_one, hwdst=pd.mac_bcast)
)

## garp_egress is arp req packet with sip == dip
privnet_net_ip_garp_egress = (
    Ether(dst=pd.mac_bcast, src=pd.mac_one) /
    ARP(op="who-has", psrc=v4_pod_two_netip, pdst=v4_pod_two_netip,
        hwsrc=pd.mac_one, hwdst=pd.mac_bcast)
)

## arp_probe is the arp req with sender IP 0.0.0.0.
privnet_net_ip_arp_probe = (
        Ether(dst=pd.mac_bcast, src=pd.mac_one) /
        ARP(op="who-has", psrc="0.0.0.0", pdst=v4_pod_two_netip,
            hwsrc=pd.mac_one, hwdst=pd.mac_bcast)
)

privnet_net_ip_arp_res = (
    Ether(dst=pd.mac_one, src=pd.mac_two) /
    ARP(op="is-at", psrc=v4_pod_two_netip, pdst=v4_pod_one_netip,
        hwsrc=pd.mac_two, hwdst=pd.mac_one)
)

privnet_net_ip_icmp_req = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=v4_pod_one_netip, dst=v4_pod_two_netip) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

privnet_net_ip_icmpv6_req = (
    Ether(dst=pd.mac_one, src=pd.mac_two) /
    IPv6(src=v6_pod_one_netip, dst=v6_pod_two_netip) /
    ICMPv6EchoRequest(id=1, seq=1) /
    Raw(load=b"ping")
)

privnet_pod_ip_icmp_req = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=pd.v4_pod_one, dst=pd.v4_pod_two) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

privnet_net_ip_icmp_req_x_subnet = (
    Ether(src=pd.mac_one, dst=pd.mac_three) /
    IP(src=v4_pod_one_netip, dst=v4_pod_three_netip) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")

)
privnet_pod_ip_icmp_req_x_subnet = (
    Ether(src=pd.mac_one, dst=pd.mac_three) /
    IP(src=pd.v4_pod_one, dst=pd.v4_pod_three) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

privnet_net_ip_tcp_syn = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=v4_pod_one_netip, dst=v4_pod_two_netip) /
    TCP(sport=1234, dport=80, flags="S") /
    Raw(load=b"syn")
)
privnet_net_ip_tcp_syn_ttl_dec = with_ttl_decremented(privnet_net_ip_tcp_syn)

privnet_pod_ip_tcp_syn = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=pd.v4_pod_one, dst=pd.v4_pod_two) /
    TCP(sport=1234, dport=80, flags="S") /
    Raw(load=b"syn")
)

privnet_net_ipv6_tcp_syn = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IPv6(src=v6_pod_one_netip, dst=v6_pod_two_netip, hlim=255) /
    TCP(sport=1234, dport=80, flags="S") /
    Raw(load=b"syn")
)
privnet_pod_ipv6_tcp_syn = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IPv6(src=pd.v6_pod_one, dst=pd.v6_pod_two, hlim=255) /
    TCP(sport=1234, dport=80, flags="S") /
    Raw(load=b"syn")
)

## Unknown flow packets, source is translated whereas destination is not.
privnet_unknown_flow_icmp_req_out = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=pd.v4_pod_one, dst=v4_pod_two_netip) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)
privnet_unknown_flow_icmp_req_out_netip = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=v4_pod_one_netip, dst=v4_pod_two_netip) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

privnet_unknown_flow_icmpv6_req_out = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IPv6(src=pd.v6_pod_one, dst=v6_pod_two_netip) /
    ICMPv6EchoRequest(id=1, seq=1) /
    Raw(load=b"ping")
)
privnet_unknown_flow_icmpv6_req_out_netip = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IPv6(src=v6_pod_one_netip, dst=v6_pod_two_netip) /
    ICMPv6EchoRequest(id=1, seq=1) /
    Raw(load=b"ping")
)

## Unknown flow packet, destination is translated whereas source is not.
privnet_unknown_flow_icmp_req_in = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=v4_pod_one_netip, dst=pd.v4_pod_two) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

## Pod to local endpoint packets
privnet_pod_ip_icmp_req_to_endpoint = (
    Ether(src=pd.mac_one, dst=pd.mac_three) /
    IP(src=pd.v4_pod_one, dst=v4_local_ep) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

privnet_pod_ipv6_icmp_req_to_endpoint = (
    Ether(src=pd.mac_one, dst=pd.mac_three) /
    IPv6(src=pd.v6_pod_one, dst=v6_local_ep) /
    ICMPv6EchoRequest(id=1, seq=1) /
    Raw(load=b"ping")
)

## IPv6 NS and NA packets

### Packets coming from LXC
privnet_lxc_ns_ll = (
    Ether(src=pd.mac_one, dst=ns_mac) /
    IPv6(src=v6_pod_one_netip, dst=ns_dst_ip, hlim=255) /
    ICMPv6ND_NS(tgt=ns_target_ip) /
    ICMPv6NDOptSrcLLAddr(lladdr=pd.mac_one)
)
privnet_lxc_na_ll = (
    Ether(src=pd.mac_two, dst=pd.mac_one) /
    IPv6(src=ns_target_ip, dst=v6_pod_one_netip, hlim=255) /
    ICMPv6ND_NA(R=0, S=1, O=1, tgt=ns_target_ip) /
    ICMPv6NDOptDstLLAddr(lladdr=pd.mac_two)
)
privnet_lxc_ns_ep1 = (
    Ether(src=pd.mac_one, dst=ns_pod_two_mmac) /
    IPv6(src=v6_pod_one_netip, dst=ns_pod_two_maddr, hlim=255) /
    ICMPv6ND_NS(tgt=v6_pod_two_netip) /
    ICMPv6NDOptSrcLLAddr(lladdr=pd.mac_one)
)
privnet_lxc_na_ep1 = (
    Ether(src=pd.mac_two, dst=pd.mac_one) /
    IPv6(src=v6_pod_two_netip, dst=v6_pod_one_netip, hlim=255) /
    ICMPv6ND_NA(R=0, S=1, O=1, tgt=v6_pod_two_netip) /
    ICMPv6NDOptDstLLAddr(lladdr=pd.mac_two)
)
privnet_lxc_ns_ep2 = (
    Ether(src=pd.mac_one, dst=ns_pod_two_mmac) /
    IPv6(src=v6_pod_one_netip, dst=ns_pod_three_maddr, hlim=255) /
    ICMPv6ND_NS(tgt=v6_pod_three_netip) /
    ICMPv6NDOptSrcLLAddr(lladdr=pd.mac_one)
)
privnet_lxc_ns_self = (
    Ether(src=pd.mac_one, dst=ns_pod_one_mmac) /
      IPv6(src=pd.v6_all, dst=ns_pod_one_maddr, hlim=255) /
      ICMPv6ND_NS(tgt=v6_pod_one_netip) /
      ICMPv6NDOptSrcLLAddr(lladdr=pd.mac_one)
)
privnet_host_to_pod_tcp_syn = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=pd.v4_node_one, dst=pd.v4_pod_one) /
    TCP(sport=54321, dport=80, flags="S") /
    Raw(load=b"syn")
)
privnet_pod_to_host_tcp_synack = (
    Ether(src=pd.mac_one, dst=pd.mac_two) /
    IP(src=v4_pod_one_netip, dst="169.254.7.1") /
    TCP(sport=80, dport=54321, flags="SA") /
    Raw(load=b"syn")
)

### Packets coming to netdev
privnet_netdev_ns = (
    Ether(src=pd.mac_one, dst=ns_pod_one_mmac) /
    IPv6(src=pd.v6_ext_node_one, dst=ns_pod_one_maddr, hlim=255) /
    ICMPv6ND_NS(tgt=v6_pod_one_netip) /
    ICMPv6NDOptSrcLLAddr(lladdr=pd.mac_one)
)
privnet_netdev_na = (
    Ether(src=pd.mac_two, dst=pd.mac_one) /
    IPv6(src=v6_pod_one_netip, dst=pd.v6_ext_node_one, hlim=255) /
    ICMPv6ND_NA(R=0, S=1, O=1, tgt=v6_pod_one_netip) /
    ICMPv6NDOptDstLLAddr(lladdr=pd.mac_two)
)

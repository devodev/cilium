# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

vxlan_port = 8472

vrf_id = 1

vxlan_vni = 12345

src_pod_port = 22330

vxlan_gbp_flags = 0x88

enterprise_vrf_egress_redirect_v4 = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two) /
    UDP(sport=src_pod_port, dport=vxlan_port, chksum=0) /
    VXLAN(flags=vxlan_gbp_flags, gpid=vrf_id, vni=vxlan_vni) /
        Ether(src=mac_one, dst=mac_two) /
        IP(src=v4_pod_one, dst=v4_ext_one) /
        TCP(sport=src_pod_port, dport=80, flags="S") /
        Raw(default_data)
)

enterprise_vrf_egress_redirect_v6 = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_node_one, dst=v6_node_two) /
    UDP(sport=src_pod_port, dport=vxlan_port, chksum=0) /
    VXLAN(flags=vxlan_gbp_flags, gpid=vrf_id, vni=vxlan_vni) /
        Ether(src=mac_one, dst=mac_two) /
        IPv6(src=v6_pod_one, dst=v6_node_three) /
        TCP(sport=src_pod_port, dport=80, flags="S") /
        Raw(default_data)
)

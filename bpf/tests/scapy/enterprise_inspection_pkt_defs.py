# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

import pkt_defs as pd
from pkt_defs_common import *

## Inspection (enterprise_tc_lxc_inspection.c)
inspection_egress_v4_tcp = (
    Ether(dst=pd.mac_two, src=pd.mac_one) /
    IP(src=pd.v4_pod_one, dst=pd.v4_ext_one) /
    TCP(sport=111, dport=222) /
    Raw(load=pd.default_data)
)

inspection_ingress_v4_tcp = (
    Ether(dst=pd.mac_one, src=pd.mac_two) /
    IP(src=pd.v4_ext_one, dst=pd.v4_pod_one) /
    TCP(sport=222, dport=111) /
    Raw(load=pd.default_data)
)

inspection_ingress_v6_tcp = (
    Ether(dst=pd.mac_one, src=pd.mac_two) /
    IPv6(src=pd.v6_ext_node_one, dst=pd.v6_pod_one) /
    TCP(sport=222, dport=111) /
    Raw(load=pd.default_data)
)

inspection_ingress_arp = (
    Ether(dst=pd.mac_one, src=pd.mac_two, type=0x0806) /
    ARP(hwsrc=pd.mac_two, psrc=pd.v4_ext_one, hwdst=pd.mac_one, pdst=pd.v4_pod_one, op=1)
)

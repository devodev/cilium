#!/bin/sh
set -e

# enable IPv6 forwarding
sysctl -w net.ipv6.conf.all.forwarding=1

###################
## vxlan vtep-ip ##
###################
ip addr add 100.64.0.1/32 dev lo

#############################
# ip-vrf vrf1 / l3vni 100 ##
#############################
ip link add vrf1 type vrf table 1100
ip link set vrf1 up
ip link add br100 type bridge
ip link set br100 master vrf1 addrgenmode none
ip link set br100 addr aa:bb:cc:00:00:64
ip link add vni100 type vxlan local 100.64.0.1 dstport 4789 id 100 nolearning
ip link set vni100 master br100 addrgenmode none
ip link set vni100 type bridge_slave neigh_suppress on learning off
ip link set vni100 up
ip link set br100 up

ip link set dev net3 up
ip link set dev net3 master vrf1
ip addr add 192.168.1.1/24 dev net3
ip addr add fd10:0:1::1/64 dev net3

#############################
## ip-vrf vrf2 / l3vni 200 ##
#############################
ip link add vrf2 type vrf table 1200
ip link set vrf2 up
ip link add br200 type bridge
ip link set br200 master vrf2 addrgenmode none
ip link set br200 addr aa:bb:cc:00:00:c8
ip link add vni200 type vxlan local 100.64.0.1 dstport 4789 id 200 nolearning
ip link set vni200 master br200 addrgenmode none
ip link set vni200 type bridge_slave neigh_suppress on learning off
ip link set vni200 up
ip link set br200 up

ip link set dev net4 up
ip link set dev net4 master vrf2
ip addr add 192.168.2.1/24 dev net4
ip addr add fd10:0:2::1/64 dev net4

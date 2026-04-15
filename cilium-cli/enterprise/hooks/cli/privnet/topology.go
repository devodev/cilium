// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type INBInfo struct {
	NodeAttachments []NodeAttachment
	ClusterName     string
}

type VMAffinity string

var (
	SameNode  VMAffinity = "same-node"
	OtherNode VMAffinity = "other-node"
)

type VMKind string

var (
	VMKindClient  VMKind = "client"
	VMKindEcho    VMKind = "echo"
	VMKindExtern  VMKind = "extern"
	VMKindUnknown VMKind = "unknown"
)

type VMName string

func (n VMName) String() string {
	return string(n)
}

func ClientVM(network NetworkName) VMName {
	return VMName(fmt.Sprintf("client-%s", network))
}

func EchoVM(network NetworkName) VMName {
	return VMName(fmt.Sprintf("echo-same-node-%s", network))
}

func EchoOtherVM(network NetworkName) VMName {
	return VMName(fmt.Sprintf("echo-other-node-%s", network))
}

type NetworkName string

func (n NetworkName) String() string {
	return string(n)
}

type SubnetName string

const (
	SubnetName0 = SubnetName("subnet-0")
	SubnetName1 = SubnetName("subnet-1")
)

func (n SubnetName) String() string {
	return string(n)
}

func NADFor(network NetworkName, subnet SubnetName) string {
	return fmt.Sprintf("%s-%s", network, subnet)
}

type VM struct {
	ID          string
	Name        VMName
	Description string

	NAD string

	NetName   NetworkName
	NetSubnet SubnetName

	NetIPv4 netip.Addr
	NetIPv6 netip.Addr

	NetIPv4Gateway netip.Addr
	NetIPv6Gateway netip.Addr // workaround for lack of RA in KubeVirt

	NetDNSServer netip.Addr

	NetMAC   string
	Affinity VMAffinity
	Kind     VMKind
}

func (vm *VM) IP(family features.IPFamily) netip.Addr {
	switch family {
	case features.IPFamilyV6:
		return vm.NetIPv6
	default:
		return vm.NetIPv4
	}
}

func (vm *VM) DescName() string {
	if vm.Description == "" {
		return vm.Name.String()
	}
	return fmt.Sprintf("%s [%s]", vm.Name, vm.Description)
}

type Route struct {
	Destination netip.Prefix
	Gateway     netip.Addr
}

type Subnet struct {
	Name   SubnetName
	CIDRv4 string
	CIDRv6 string
	Routes []Route
}

type NodeAttachment struct {
	Interface string
	VlanID    int
}

type NetworkData struct {
	Prefixes        []Subnet
	INBs            []INBInfo
	VMs             []VM
	Unknown         []VM
	NodeAttachments []NodeAttachment
}

var networkTopology = map[NetworkName]NetworkData{
	NetworkA: {
		Prefixes: []Subnet{
			{
				Name:   SubnetName0,
				CIDRv4: "192.168.250.0/24",
				CIDRv6: "fd10:0:250::0/64",
				Routes: []Route{
					{
						Destination: netip.MustParsePrefix("192.168.252.0/24"),
						Gateway:     netip.MustParseAddr("192.168.250.254"),
					},
					{
						Destination: netip.MustParsePrefix("fd10:0:252::/64"),
						Gateway:     netip.MustParseAddr("fd10:0:250::fffe"),
					},
					{
						Destination: netip.MustParsePrefix("192.168.255.0/24"),
						Gateway:     netip.MustParseAddr("192.168.250.200"),
					},
					{
						Destination: netip.MustParsePrefix("fd10:0:255::/64"),
						Gateway:     netip.MustParseAddr("fd10:0:250::200"),
					},
				},
			},
		},
		INBs: []INBInfo{
			{
				NodeAttachments: []NodeAttachment{{Interface: "ethA"}},
				ClusterName:     "privnet-inb0",
			},
			{
				NodeAttachments: []NodeAttachment{{Interface: "ethA"}},
				ClusterName:     "privnet-inb1",
			},
		},
		VMs: []VM{
			{
				ID:             "vm-A1",
				Name:           ClientVM(NetworkA),
				NetName:        NetworkA,
				NAD:            NADFor(NetworkA, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.250.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:250::10"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.250.254"),
				NetMAC:         "f2:54:1c:1f:84:94",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
			{
				ID:             "vm-A2",
				Name:           EchoVM(NetworkA),
				NetName:        NetworkA,
				NAD:            NADFor(NetworkA, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.250.20"),
				NetIPv6:        netip.MustParseAddr("fd10:0:250::20"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.250.254"),
				NetMAC:         "de:a9:fd:7d:af:bf",
				Affinity:       SameNode,
				Kind:           VMKindEcho,
			},
			{
				ID:             "vm-A3",
				Name:           EchoOtherVM(NetworkA),
				NetName:        NetworkA,
				NAD:            NADFor(NetworkA, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.250.21"),
				NetIPv6:        netip.MustParseAddr("fd10:0:250::21"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.250.254"),
				NetMAC:         "be:68:f6:fc:6a:4a",
				Affinity:       OtherNode,
				Kind:           VMKindEcho,
			},
			{
				ID:             "",
				Name:           VMName("client-dhcp-network-a"),
				NetName:        NetworkA,
				NetSubnet:      SubnetName0,
				NAD:            NADFor(NetworkA, SubnetName0),
				NetIPv4:        netip.MustParseAddr("0.0.0.0"), /* zero or missing IPv4 signals use of DHCP */
				NetIPv6:        netip.MustParseAddr("fd10:0:250::15"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.250.254"),
				NetMAC:         "02:00:00:e6:bb:ff",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
		},
		Unknown: []VM{
			{
				Name:    "privnet-vm-net-c1",
				NetName: NetworkC,
				NetIPv4: netip.MustParseAddr("192.168.252.200"),
				NetIPv6: netip.MustParseAddr("fd10:0:252::200"),
				Kind:    VMKindUnknown,
			},
			{
				Name:        "privnet-vm-net-a1",
				NetName:     NetworkA,
				Description: "alt-if",
				NetIPv4:     netip.MustParseAddr("192.168.255.200"),
				NetIPv6:     netip.MustParseAddr("fd10:0:255::200"),
				Kind:        VMKindUnknown,
			},
		},
	},
	NetworkB: {
		Prefixes: []Subnet{
			{
				Name:   SubnetName0,
				CIDRv4: "192.168.251.0/24",
				CIDRv6: "fd10:0:251::/64",
			},
			{
				Name:   SubnetName1,
				CIDRv4: "192.168.253.0/24",
				CIDRv6: "fd10:0:253::/64",
				Routes: []Route{
					{
						Destination: netip.MustParsePrefix("0.0.0.0/0"),
						Gateway:     netip.MustParseAddr("192.168.253.254"),
					},
					{
						Destination: netip.MustParsePrefix("::/0"),
						Gateway:     netip.MustParseAddr("fd10:0:253::fffe"),
					},
				},
			},
		},
		INBs: []INBInfo{
			{
				NodeAttachments: []NodeAttachment{{Interface: "ethB"}},
				ClusterName:     "privnet-inb0",
			},
			{
				NodeAttachments: []NodeAttachment{{Interface: "ethB"}},
				ClusterName:     "privnet-inb1",
			},
		},
		VMs: []VM{
			{
				ID:             "vm-B1",
				Name:           ClientVM(NetworkB),
				NetName:        NetworkB,
				NAD:            NADFor(NetworkB, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.251.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:251::10"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.251.254"),
				NetMAC:         "42:f9:eb:33:4d:54",
				Affinity:       OtherNode,
				Kind:           VMKindClient,
			},
			{
				Name:           EchoOtherVM(NetworkB),
				NetName:        NetworkB,
				NAD:            NADFor(NetworkB, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.251.22"),
				NetIPv6:        netip.MustParseAddr("fd10:0:251::22"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.251.254"),
				NetMAC:         "0e:13:85:69:e9:f7",
				Affinity:       OtherNode,
				Kind:           VMKindEcho,
			},
			{
				Name:           ClientVM(NetworkB) + "-2",
				NetName:        NetworkB,
				NAD:            NADFor(NetworkB, SubnetName1),
				NetIPv4:        netip.MustParseAddr("192.168.253.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:253::10"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.253.254"),
				NetMAC:         "42:f9:eb:33:1a:83",
				Affinity:       OtherNode,
				Kind:           VMKindClient,
			},
		},
	},
	NetworkC: {
		Prefixes: []Subnet{
			{
				Name:   SubnetName0,
				CIDRv4: "192.168.252.0/24",
				CIDRv6: "fd10:0:252::/64",
				Routes: []Route{
					{
						Destination: netip.MustParsePrefix("0.0.0.0/0"),
						Gateway:     netip.MustParseAddr("192.168.252.254"),
					},
					{
						Destination: netip.MustParsePrefix("::/0"),
						Gateway:     netip.MustParseAddr("fd10:0:252::fffe"),
					},
				},
			},
		},
		INBs: []INBInfo{
			{
				NodeAttachments: []NodeAttachment{{Interface: "ethC"}},
				ClusterName:     "privnet-inb1",
			},
		},
		VMs: []VM{
			{
				ID:             "vm-C1",
				Name:           ClientVM(NetworkC),
				NetName:        NetworkC,
				NAD:            NADFor(NetworkC, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.252.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:252::10"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
				NetMAC:         "52:1f:62:0a:ff:07",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
			{
				Name:           EchoOtherVM(NetworkC),
				NetName:        NetworkC,
				NetIPv4:        netip.MustParseAddr("192.168.252.22"),
				NetIPv6:        netip.MustParseAddr("fd10:0:252::22"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
				NetMAC:         "5e:ae:22:a7:37:87",
				Affinity:       OtherNode,
				Kind:           VMKindEcho,
			},
		},
		Unknown: []VM{
			{
				Name:    "privnet-vm-net-a1",
				NetName: NetworkA,
				NetIPv4: netip.MustParseAddr("192.168.250.200"),
				NetIPv6: netip.MustParseAddr("fd10:0:250::200"),
				Kind:    VMKindUnknown,
			},
			{
				Name:        "privnet-vm-net-c1",
				NetName:     NetworkC,
				Description: "alt-if",
				NetIPv4:     netip.MustParseAddr("192.168.252.210"),
				NetIPv6:     netip.MustParseAddr("fd10:0:252::210"),
				Kind:        VMKindUnknown,
			},
		},
	},
	NetworkD: {
		Prefixes: []Subnet{
			{
				Name:   SubnetName0,
				CIDRv4: "192.168.252.0/24",
				CIDRv6: "fd10:0:252::/64",
				Routes: []Route{
					{
						Destination: netip.MustParsePrefix("0.0.0.0/0"),
						Gateway:     netip.MustParseAddr("192.168.252.254"),
					},
					{
						Destination: netip.MustParsePrefix("::/0"),
						Gateway:     netip.MustParseAddr("fd10:0:252::fffe"),
					},
				},
			},
		},
		INBs: []INBInfo{
			{
				NodeAttachments: []NodeAttachment{{Interface: "ethD"}},
				ClusterName:     "privnet-inb1",
			},
		},
		VMs: []VM{
			{
				Name:           ClientVM(NetworkD),
				NetName:        NetworkD,
				NetIPv4:        netip.MustParseAddr("192.168.252.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:252::10"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
				NetMAC:         "d2:32:c6:44:58:86",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
		},
		Unknown: []VM{
			{
				Name:        "privnet-vm-net-d1",
				NetName:     NetworkD,
				Description: "alt-if",
				NetIPv4:     netip.MustParseAddr("192.168.252.210"),
				NetIPv6:     netip.MustParseAddr("fd10:0:252::210"),
				Kind:        VMKindUnknown,
			},
		},
	},
	NetworkE: {
		Prefixes: []Subnet{
			{
				Name:   SubnetName0,
				CIDRv4: "192.168.10.0/24",
				CIDRv6: "fd10:0:10::/64",
				Routes: []Route{
					{
						Destination: netip.MustParsePrefix("0.0.0.0/0"),
						Gateway:     netip.MustParseAddr("192.168.10.254"),
					},
					{
						Destination: netip.MustParsePrefix("::/0"),
						Gateway:     netip.MustParseAddr("fd10:0:10::fffe"),
					},
				},
			},
		},
		INBs: []INBInfo{},
		VMs: []VM{
			{
				ID:             "",
				Name:           VMName("client-dhcp-network-e"),
				NetName:        NetworkE,
				NetSubnet:      SubnetName0,
				NAD:            NADFor(NetworkE, SubnetName0),
				NetIPv4:        netip.MustParseAddr("0.0.0.0"), /* zero or missing IPv4 signals use of DHCP */
				NetIPv6:        netip.MustParseAddr("fd10:0:10::15"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.10.254"),
				NetMAC:         "02:42:ac:11:00:02",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
			{
				ID:             "",
				Name:           EchoVM(NetworkE),
				NetName:        NetworkE,
				NAD:            NADFor(NetworkE, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.10.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:10::10"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.10.254"),
				NetMAC:         "4e:7c:b2:91:d3:08",
				Affinity:       SameNode,
				Kind:           VMKindEcho,
			},
			{
				ID:             "",
				Name:           EchoOtherVM(NetworkE),
				NetName:        NetworkE,
				NAD:            NADFor(NetworkE, SubnetName0),
				NetIPv4:        netip.MustParseAddr("192.168.10.21"),
				NetIPv6:        netip.MustParseAddr("fd10:0:10::21"),
				NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.10.254"),
				NetMAC:         "a6:f1:3e:c4:58:2b",
				Affinity:       OtherNode,
				Kind:           VMKindEcho,
			},
		},
		Unknown: []VM{
			{
				Name:        "privnet-vm-net-e1",
				NetName:     NetworkE,
				Description: "alt-if",
				NetIPv4:     netip.MustParseAddr("192.168.10.200"),
				NetIPv6:     netip.MustParseAddr("fd10:0:10::200"),
				Kind:        VMKindUnknown,
			},
		},
		NodeAttachments: []NodeAttachment{{Interface: "eth1", VlanID: 10}},
	},
}

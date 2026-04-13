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
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/mac"
)

type INBInfo struct {
	NodeAttachments []NodeAttachment
	ClusterName     string
}

type VMAffinityType string

var (
	SameNode  VMAffinityType = "same-node"
	OtherNode VMAffinityType = "other-node"
)

type VMAffinity struct {
	Type   VMAffinityType
	Target VMName
}

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

// DesiredVM represents the specification of a (possibly mocked) VM to be
// automatically created in the testbed.
type DesiredVM struct {
	ID   string
	Name VMName

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
	Mock     bool
}

func (vm DesiredVM) ToVMs() []VM {
	return []VM{{
		Name:      vm.Name,
		Interface: "eth0",
		NetName:   vm.NetName,
		NetSubnet: vm.NetSubnet,
		NetIPv4:   vm.NetIPv4,
		NetIPv6:   vm.NetIPv6,
		NetMAC:    vm.NetMAC,
		Kind:      vm.Kind,
		Mock:      vm.Mock,
	}}
}

// VM models the source and/or destination endpoint of a test scenario.
type VM struct {
	Name      VMName
	Interface string

	NetName   NetworkName
	NetSubnet SubnetName

	NetIPv4 netip.Addr
	NetIPv6 netip.Addr
	NetMAC  string

	Kind VMKind
	Mock bool
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
	if vm.Interface == "" {
		return vm.Name.String()
	}
	return fmt.Sprintf("%s [%s]", vm.Name, vm.Interface)
}

func (vm *VM) ToNetworkAttachment() types.NetworkAttachment {
	return types.NetworkAttachment{
		Network: string(vm.NetName),
		Subnet:  string(vm.NetSubnet),
		IPv4:    vm.NetIPv4,
		IPv6:    vm.NetIPv6,
		MAC:     mac.MustParseMAC(vm.NetMAC),
	}
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
	Unknown         []VM
	NodeAttachments []NodeAttachment
}

var networkTopology = struct {
	Networks map[NetworkName]NetworkData
	VMs      []DesiredVM
}{
	Networks: map[NetworkName]NetworkData{
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
			Unknown: []VM{
				{
					Name:    "privnet-vm-net-c1",
					NetName: NetworkC,
					NetIPv4: netip.MustParseAddr("192.168.252.200"),
					NetIPv6: netip.MustParseAddr("fd10:0:252::200"),
					Kind:    VMKindUnknown,
				},
				{
					Name:      "privnet-vm-net-a1",
					NetName:   NetworkA,
					Interface: "alt-if",
					NetIPv4:   netip.MustParseAddr("192.168.255.200"),
					NetIPv6:   netip.MustParseAddr("fd10:0:255::200"),
					Kind:      VMKindUnknown,
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

			Unknown: []VM{
				{
					Name:    "privnet-vm-net-a1",
					NetName: NetworkA,
					NetIPv4: netip.MustParseAddr("192.168.250.200"),
					NetIPv6: netip.MustParseAddr("fd10:0:250::200"),
					Kind:    VMKindUnknown,
				},
				{
					Name:      "privnet-vm-net-c1",
					NetName:   NetworkC,
					Interface: "alt-if",
					NetIPv4:   netip.MustParseAddr("192.168.252.210"),
					NetIPv6:   netip.MustParseAddr("fd10:0:252::210"),
					Kind:      VMKindUnknown,
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
			Unknown: []VM{
				{
					Name:      "privnet-vm-net-d1",
					NetName:   NetworkD,
					Interface: "alt-if",
					NetIPv4:   netip.MustParseAddr("192.168.252.210"),
					NetIPv6:   netip.MustParseAddr("fd10:0:252::210"),
					Kind:      VMKindUnknown,
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
			Unknown: []VM{
				{
					Name:      "privnet-vm-net-e1",
					NetName:   NetworkE,
					Interface: "alt-if",
					NetIPv4:   netip.MustParseAddr("192.168.10.200"),
					NetIPv6:   netip.MustParseAddr("fd10:0:10::200"),
					Kind:      VMKindUnknown,
				},
			},
			NodeAttachments: []NodeAttachment{{Interface: "eth1", VlanID: 10}},
		},
	},

	VMs: []DesiredVM{
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
			Affinity:       VMAffinity{SameNode, ClientVM(NetworkA)},
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
			Affinity:       VMAffinity{OtherNode, ClientVM(NetworkA)},
			Kind:           VMKindEcho,
		},
		{
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
			Kind:           VMKindClient,
		},
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
			Affinity:       VMAffinity{OtherNode, ClientVM(NetworkB)},
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
			Kind:           VMKindClient,
			Mock:           true,
		},
		{
			Name:           ClientVM(NetworkC),
			NetName:        NetworkC,
			NAD:            NADFor(NetworkC, SubnetName0),
			NetIPv4:        netip.MustParseAddr("192.168.252.10"),
			NetIPv6:        netip.MustParseAddr("fd10:0:252::10"),
			NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
			NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
			NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
			NetMAC:         "52:1f:62:0a:ff:07",
			Kind:           VMKindClient,
			Mock:           true,
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
			Affinity:       VMAffinity{OtherNode, ClientVM(NetworkC)},
			Kind:           VMKindEcho,
			Mock:           true,
		},
		{
			Name:           ClientVM(NetworkD),
			NetName:        NetworkD,
			NetIPv4:        netip.MustParseAddr("192.168.252.10"),
			NetIPv6:        netip.MustParseAddr("fd10:0:252::10"),
			NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
			NetIPv4Gateway: netip.MustParseAddr("169.254.0.100"),
			NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
			NetMAC:         "d2:32:c6:44:58:86",
			Kind:           VMKindClient,
			Mock:           true,
		},
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
			Affinity:       VMAffinity{SameNode, VMName("client-dhcp-network-e")},
			Kind:           VMKindEcho,
			Mock:           true,
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
			Affinity:       VMAffinity{OtherNode, VMName("client-dhcp-network-e")},
			Kind:           VMKindEcho,
			Mock:           true,
		},
	},
}

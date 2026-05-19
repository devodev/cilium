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
	"slices"

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
	VMKindClient    VMKind = "client"
	VMKindEcho      VMKind = "echo"
	VMKindSecondary VMKind = "secondary"
	VMKindExtern    VMKind = "extern"
	VMKindUnknown   VMKind = "unknown"
)

type VMName string

func (n VMName) String() string {
	return string(n)
}

func (n VMName) ForInterface(ifname string) VMName {
	if ifname == "" || ifname == "eth0" {
		return n
	}

	return VMName(fmt.Sprintf("%s-%s", n, ifname))
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
	SubnetName2 = SubnetName("subnet-2")
)

func (n SubnetName) String() string {
	return string(n)
}

func NADFor(network NetworkName, subnet SubnetName) string {
	return fmt.Sprintf("%s-%s", network, subnet)
}

// DesiredVM represents the specification of a (possibly mocked) VM to be
// automatically created in the testbed. A DesiredVM can be composed of
// one or multiple network interfaces.
type DesiredVM struct {
	ID   string
	Name VMName

	Interfaces []Interface

	Affinity VMAffinity
	Kind     VMKind
	Mock     bool
}

func (vm DesiredVM) ToVMs() []VM {
	var vms = make([]VM, 0, len(vm.Interfaces))

	for idx, iface := range vm.Interfaces {
		var kind = vm.Kind
		if idx > 0 {
			kind = VMKindSecondary
		}

		vms = append(vms, VM{
			Name:      vm.Name,
			Interface: iface.Name(uint(idx)),
			Kind:      kind,
			Mock:      vm.Mock,

			NetName:   iface.Network,
			NetSubnet: iface.Subnet,
			NetIPv4:   iface.IPv4,
			NetIPv6:   iface.IPv6,
			NetMAC:    iface.MAC,
		})
	}

	return vms
}

// VM models the source and/or destination endpoint of a test scenario. Each
// VM instance univocally maps to a single VM network interface; in other words,
// a single DesiredVM encompassing N network interfaces gets mapped to N VM
// VM instances, one for each network interface.
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

func (vm *VM) IsDHCPEnabled(family features.IPFamily) bool {
	return family == features.IPFamilyV4 && vm.NetIPv4.IsUnspecified()
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

func (vm *VM) UniqueName() VMName {
	return vm.Name.ForInterface(vm.Interface)
}

type Interface struct {
	Network NetworkName
	Subnet  SubnetName

	NAD string
	MAC string

	IPv4 netip.Addr
	IPv6 netip.Addr

	Routes []Route

	DNSServer netip.Addr
}

func (i Interface) Name(idx uint) string {
	return fmt.Sprintf("eth%d", idx)
}

func (i Interface) ToNetworkAttachment(idx uint) types.NetworkAttachment {
	return types.NetworkAttachment{
		Network:   string(i.Network),
		Subnet:    string(i.Subnet),
		Interface: i.Name(idx),
		IPv4:      i.IPv4,
		IPv6:      i.IPv6,
		MAC:       mac.MustParseMAC(i.MAC),
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

func newVMRoutes(d string, ifidx uint) []Route {
	var dest = netip.MustParsePrefix(d)

	var tmpl = "169.254.0.1%02d"
	if dest.Addr().Is6() {
		tmpl = "fe80::1%02d"
	}

	var gw = netip.MustParseAddr(fmt.Sprintf(tmpl, ifidx))
	return []Route{
		{Destination: netip.PrefixFrom(gw, gw.BitLen())},
		{Destination: dest, Gateway: gw},
	}
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
					Name:    "privnet-vm-net-e1",
					NetName: NetworkE,
					NetIPv4: netip.MustParseAddr("192.168.10.200"),
					NetIPv6: netip.MustParseAddr("fd10:0:10::200"),
					Kind:    VMKindUnknown,
				},
				{
					Name:    "privnet-vm-net-e2",
					NetName: NetworkE,
					NetIPv4: netip.MustParseAddr("192.168.10.201"),
					NetIPv6: netip.MustParseAddr("fd10:0:10::201"),
					Kind:    VMKindUnknown,
				},
			},
			NodeAttachments: []NodeAttachment{{Interface: "eth1", VlanID: 10}},
		},
		NetworkF: {
			Prefixes: []Subnet{
				{
					Name:   SubnetName0,
					CIDRv4: "192.168.254.0/27",
					CIDRv6: "fd10:0:254:1::/64",
				},
				{
					Name:   SubnetName1,
					CIDRv4: "192.168.254.32/27",
					CIDRv6: "fd10:0:254:2::/64",
				},
				{
					Name:   SubnetName2,
					CIDRv4: "192.168.254.64/27",
					CIDRv6: "fd10:0:254:3::/64",
				},
			},
		},
	},

	VMs: []DesiredVM{
		{
			ID:   "vm-A1",
			Name: ClientVM(NetworkA),
			Interfaces: []Interface{
				{
					Network:   NetworkA,
					NAD:       NADFor(NetworkA, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.250.10"),
					IPv6:      netip.MustParseAddr("fd10:0:250::10"),
					Routes:    slices.Concat(newVMRoutes("0.0.0.0/0", 0), newVMRoutes("::/0", 0)),
					DNSServer: netip.MustParseAddr("192.168.250.254"),
					MAC:       "f2:54:1c:1f:84:94",
				},
				{
					Network: NetworkF,
					NAD:     NADFor(NetworkF, SubnetName0),
					IPv4:    netip.MustParseAddr("192.168.254.1"),
					IPv6:    netip.MustParseAddr("fd10:0:254:1::1"),
					Routes:  slices.Concat(newVMRoutes("192.168.254.0/27", 1), newVMRoutes("fd10:0:254:1::0/64", 1)),
					MAC:     "f2:54:1c:1f:84:95",
				},
				{
					Network: NetworkF,
					NAD:     NADFor(NetworkF, SubnetName1),
					IPv4:    netip.MustParseAddr("192.168.254.33"),
					IPv6:    netip.MustParseAddr("fd10:0:254:2::33"),
					Routes:  slices.Concat(newVMRoutes("192.168.254.32/27", 2), newVMRoutes("fd10:0:254:2::0/64", 2)),
					MAC:     "f2:54:1c:1f:84:96",
				},
				{
					Network: NetworkF,
					NAD:     NADFor(NetworkF, SubnetName2),
					IPv4:    netip.MustParseAddr("192.168.254.65"),
					IPv6:    netip.MustParseAddr("fd10:0:254:3::65"),
					Routes:  slices.Concat(newVMRoutes("192.168.254.64/27", 3), newVMRoutes("fd10:0:254:3::0/64", 3)),
					MAC:     "f2:54:1c:1f:84:97",
				},
			},
			Kind: VMKindClient,
		},
		{
			ID:   "vm-A2",
			Name: EchoVM(NetworkA),
			Interfaces: []Interface{
				{
					Network:   NetworkA,
					NAD:       NADFor(NetworkA, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.250.20"),
					IPv6:      netip.MustParseAddr("fd10:0:250::20"),
					Routes:    slices.Concat(newVMRoutes("0.0.0.0/0", 0), newVMRoutes("::/0", 0)),
					DNSServer: netip.MustParseAddr("192.168.250.254"),
					MAC:       "de:a9:fd:7d:af:bf",
				},
				{
					Network: NetworkF,
					NAD:     NADFor(NetworkF, SubnetName0),
					IPv4:    netip.MustParseAddr("192.168.254.2"),
					IPv6:    netip.MustParseAddr("fd10:0:254:1::2"),
					Routes:  slices.Concat(newVMRoutes("192.168.254.0/27", 1), newVMRoutes("fd10:0:254:1::0/64", 1)),
					MAC:     "de:a9:fd:7d:af:be",
				},
			},
			Affinity: VMAffinity{SameNode, ClientVM(NetworkA)},
			Kind:     VMKindEcho,
		},
		{
			ID:   "vm-A3",
			Name: EchoOtherVM(NetworkA),
			Interfaces: []Interface{
				{
					Network:   NetworkA,
					NAD:       NADFor(NetworkA, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.250.21"),
					IPv6:      netip.MustParseAddr("fd10:0:250::21"),
					Routes:    slices.Concat(newVMRoutes("0.0.0.0/0", 0), newVMRoutes("::/0", 0)),
					DNSServer: netip.MustParseAddr("192.168.250.254"),
					MAC:       "be:68:f6:fc:6a:4a",
				},
			},
			Affinity: VMAffinity{OtherNode, ClientVM(NetworkA)},
			Kind:     VMKindEcho,
		},
		{
			Name: VMName("client-dhcp-network-b-a"),
			Interfaces: []Interface{
				{
					Network:   NetworkB,
					Subnet:    SubnetName1,
					NAD:       NADFor(NetworkB, SubnetName1),
					IPv4:      netip.MustParseAddr("0.0.0.0"), /* zero or missing IPv4 signals use of DHCP */
					IPv6:      netip.MustParseAddr("fd10:0:253::15"),
					Routes:    newVMRoutes("::/0", 0),
					DNSServer: netip.MustParseAddr("192.168.253.254"),
					MAC:       "02:00:00:e6:bb:fe",
				},
				{
					Network:   NetworkA,
					Subnet:    SubnetName0,
					NAD:       NADFor(NetworkA, SubnetName0),
					IPv4:      netip.MustParseAddr("0.0.0.0"), /* zero or missing IPv4 signals use of DHCP */
					IPv6:      netip.MustParseAddr("fd10:0:250::15"),
					Routes:    newVMRoutes("fd10:0:250::/64", 1),
					DNSServer: netip.MustParseAddr("192.168.250.254"),
					MAC:       "02:00:00:e6:bb:ff",
				},
			},
			Kind: VMKindClient,
		},
		{
			ID:   "vm-B1",
			Name: ClientVM(NetworkB),
			Interfaces: []Interface{
				{
					Network:   NetworkB,
					NAD:       NADFor(NetworkB, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.251.10"),
					IPv6:      netip.MustParseAddr("fd10:0:251::10"),
					Routes:    slices.Concat(newVMRoutes("0.0.0.0/0", 0), newVMRoutes("::/0", 0)),
					DNSServer: netip.MustParseAddr("192.168.251.254"),
					MAC:       "42:f9:eb:33:4d:54",
				},
			},
			Kind: VMKindClient,
		},
		{
			Name: EchoOtherVM(NetworkB),
			Interfaces: []Interface{
				{
					Network:   NetworkB,
					NAD:       NADFor(NetworkB, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.251.22"),
					IPv6:      netip.MustParseAddr("fd10:0:251::22"),
					Routes:    slices.Concat(newVMRoutes("0.0.0.0/0", 0), newVMRoutes("::/0", 0)),
					DNSServer: netip.MustParseAddr("192.168.251.254"),
					MAC:       "0e:13:85:69:e9:f7",
				},
				{
					Network: NetworkF,
					NAD:     NADFor(NetworkF, SubnetName1),
					IPv4:    netip.MustParseAddr("192.168.254.34"),
					IPv6:    netip.MustParseAddr("fd10:0:254:2::34"),
					Routes:  slices.Concat(newVMRoutes("192.168.254.32/27", 1), newVMRoutes("fd10:0:254:2::0/64", 1)),
					MAC:     "0e:13:85:69:e9:f8",
				},
			},
			Affinity: VMAffinity{OtherNode, ClientVM(NetworkB)},
			Kind:     VMKindEcho,
		},
		{
			Name: ClientVM(NetworkB) + "-2",
			Interfaces: []Interface{
				{
					Network:   NetworkB,
					NAD:       NADFor(NetworkB, SubnetName1),
					IPv4:      netip.MustParseAddr("192.168.253.10"),
					IPv6:      netip.MustParseAddr("fd10:0:253::10"),
					DNSServer: netip.MustParseAddr("192.168.253.254"),
					MAC:       "42:f9:eb:33:1a:83",
				},
			},
			Kind: VMKindClient,
			Mock: true,
		},
		{
			Name: ClientVM(NetworkC),
			Interfaces: []Interface{
				{
					Network:   NetworkC,
					NAD:       NADFor(NetworkC, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.252.10"),
					IPv6:      netip.MustParseAddr("fd10:0:252::10"),
					DNSServer: netip.MustParseAddr("192.168.252.254"),
					MAC:       "52:1f:62:0a:ff:07",
				},
			},
			Kind: VMKindClient,
			Mock: true,
		},
		{
			Name: EchoOtherVM(NetworkC),
			Interfaces: []Interface{
				{
					Network:   NetworkC,
					IPv4:      netip.MustParseAddr("192.168.252.22"),
					IPv6:      netip.MustParseAddr("fd10:0:252::22"),
					DNSServer: netip.MustParseAddr("192.168.252.254"),
					MAC:       "5e:ae:22:a7:37:87",
				},
				{
					Network: NetworkF,
					NAD:     NADFor(NetworkF, SubnetName2),
					IPv4:    netip.MustParseAddr("192.168.254.66"),
					IPv6:    netip.MustParseAddr("fd10:0:254:3::66"),
					Routes:  newVMRoutes("fd10:0:254:3::0/64", 1),
					MAC:     "5e:ae:22:a7:37:88",
				},
			},
			Affinity: VMAffinity{OtherNode, ClientVM(NetworkC)},
			Kind:     VMKindEcho,
			Mock:     true,
		},
		{
			Name: ClientVM(NetworkD),
			Interfaces: []Interface{
				{
					Network:   NetworkD,
					IPv4:      netip.MustParseAddr("192.168.252.10"),
					IPv6:      netip.MustParseAddr("fd10:0:252::10"),
					DNSServer: netip.MustParseAddr("192.168.252.254"),
					MAC:       "d2:32:c6:44:58:86",
				},
			},
			Kind: VMKindClient,
			Mock: true,
		},
		{
			ID:   "",
			Name: VMName("client-dhcp-network-e"),
			Interfaces: []Interface{
				{
					Network:   NetworkE,
					Subnet:    SubnetName0,
					NAD:       NADFor(NetworkE, SubnetName0),
					IPv4:      netip.MustParseAddr("0.0.0.0"), /* zero or missing IPv4 signals use of DHCP */
					IPv6:      netip.MustParseAddr("fd10:0:10::15"),
					Routes:    newVMRoutes("::/0", 0),
					DNSServer: netip.MustParseAddr("192.168.10.254"),
					MAC:       "02:42:ac:11:00:02",
				},
			},

			Kind: VMKindClient,
		},
		{
			ID:   "",
			Name: EchoVM(NetworkE),
			Interfaces: []Interface{
				{
					Network:   NetworkE,
					NAD:       NADFor(NetworkE, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.10.10"),
					IPv6:      netip.MustParseAddr("fd10:0:10::10"),
					DNSServer: netip.MustParseAddr("192.168.10.254"),
					MAC:       "4e:7c:b2:91:d3:08",
				},
			},
			Affinity: VMAffinity{SameNode, VMName("client-dhcp-network-e")},
			Kind:     VMKindEcho,
			Mock:     true,
		},
		{
			ID:   "",
			Name: EchoOtherVM(NetworkE),
			Interfaces: []Interface{
				{
					Network:   NetworkE,
					NAD:       NADFor(NetworkE, SubnetName0),
					IPv4:      netip.MustParseAddr("192.168.10.21"),
					IPv6:      netip.MustParseAddr("fd10:0:10::21"),
					DNSServer: netip.MustParseAddr("192.168.10.254"),
					MAC:       "a6:f1:3e:c4:58:2b",
				},
			},
			Affinity: VMAffinity{OtherNode, VMName("client-dhcp-network-e")},
			Kind:     VMKindEcho,
			Mock:     true,
		},
	},
}

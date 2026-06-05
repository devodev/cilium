package multinetwork

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/node/addressing"
)

func mustRoute(dst, gw string) *netlink.Route {
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		panic(err)
	}
	ip := net.ParseIP(gw)
	if ip == nil {
		panic("invalid gateway")
	}

	return &netlink.Route{
		Dst:      ipnet,
		Gw:       ip,
		Protocol: linux_defaults.RTProto,
	}
}

func Test_extractNodeIPsforNetworks(t *testing.T) {
	type args struct {
		networks []*iso_v1alpha1.IsovalentPodNetwork
		nodeIPv4 deviceToIPMap
		nodeIPv6 deviceToIPMap
	}
	tests := []struct {
		name string
		args args
		want map[string]nodeIPPair
	}{
		{
			name: "no networks",
			args: args{
				networks: nil,
				nodeIPv4: nil,
				nodeIPv6: nil,
			},
			want: map[string]nodeIPPair{},
		},
		{
			name: "no node IPs",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "network-1",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							Routes: []iso_v1alpha1.RouteSpec{
								{
									Destination: "10.0.0.0/16",
									Gateway:     "10.0.0.1",
								},
								{
									Destination: "fd00::/64",
									Gateway:     "fd00::1",
								},
							},
						},
					},
				},
				nodeIPv4: nil,
				nodeIPv6: nil,
			},
			want: map[string]nodeIPPair{},
		},
		{
			name: "no routes",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "network-1",
						},
					},
				},
				nodeIPv4: deviceToIPMap{
					"eno1": net.ParseIP("10.20.30.40"),
				},
				nodeIPv6: deviceToIPMap{
					"eno1": net.ParseIP("fd00::10"),
				},
			},
			want: map[string]nodeIPPair{},
		},
		{
			name: "no matching routes",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "network-1",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							Routes: []iso_v1alpha1.RouteSpec{
								{
									Destination: "10.0.0.0/16",
									Gateway:     "10.0.0.1",
								},
								{
									Destination: "fd00::/64",
									Gateway:     "fd00::1",
								},
							},
						},
					},
				},
				nodeIPv4: deviceToIPMap{
					"eno1": net.ParseIP("192.168.10.20"),
				},
				nodeIPv6: deviceToIPMap{
					"eno1": net.ParseIP("fc00::30"),
				},
			},
			want: map[string]nodeIPPair{},
		},
		{
			name: "matching routes",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "network-1",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							Routes: []iso_v1alpha1.RouteSpec{
								{
									Destination: "10.0.0.0/16",
									Gateway:     "10.0.0.1",
								},
								{
									Destination: "fd00::/64",
									Gateway:     "fd00::1",
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "network-2",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							Routes: []iso_v1alpha1.RouteSpec{
								{
									Destination: "172.16.0.0/16",
									Gateway:     "172.16.0.1",
								},
								{
									Destination: "fc00::/96",
									Gateway:     "fc00::1",
								},
							},
						},
					},
				},
				nodeIPv4: deviceToIPMap{
					"eno1": net.ParseIP("10.0.0.10"),
					"eno2": net.ParseIP("172.16.0.10"),
					"eno3": net.ParseIP("192.168.0.10"),
				},
				nodeIPv6: deviceToIPMap{
					"eno1": net.ParseIP("fd00::10"),
					"eno2": net.ParseIP("fc00::10"),
					"eno3": net.ParseIP("fe00::10"),
				},
			},
			want: map[string]nodeIPPair{
				"network-1": {
					ipv4:       net.ParseIP("10.0.0.10"),
					ipv4Device: "eno1",
					ipv6:       net.ParseIP("fd00::10"),
					ipv6Device: "eno1",
				},
				"network-2": {
					ipv4:       net.ParseIP("172.16.0.10"),
					ipv4Device: "eno2",
					ipv6:       net.ParseIP("fc00::10"),
					ipv6Device: "eno2",
				},
			},
		},
		{
			name: "multiple matching interfaces for same network",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "network-1",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							Routes: []iso_v1alpha1.RouteSpec{
								{
									Destination: "10.0.0.0/8",
									Gateway:     "10.0.0.1",
								},
							},
						},
					},
				},
				nodeIPv4: deviceToIPMap{
					"eno1": net.ParseIP("10.0.0.10"),
					"eno2": net.ParseIP("10.0.0.20"),
				},
				nodeIPv6: nil,
			},
			want: map[string]nodeIPPair{
				"network-1": {
					ipv4:       net.ParseIP("10.0.0.10"),
					ipv4Device: "eno1",
				},
			},
		},
		{
			name: "default network is skipped",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							Routes: []iso_v1alpha1.RouteSpec{
								{
									Destination: "0.0.0.0/0",
									Gateway:     "10.0.0.1",
								},
							},
						},
					},
				},
				nodeIPv4: deviceToIPMap{
					"eno1": net.ParseIP("10.0.0.10"),
					"eno2": net.ParseIP("192.168.0.10"),
				},
				nodeIPv6: nil,
			},
			want: map[string]nodeIPPair{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNodeIPsforNetworks(hivetest.Logger(t), tt.args.networks, tt.args.nodeIPv4, tt.args.nodeIPv6)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("extractNodeIPsforNetworks (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_extractDirectNodeRoutes(t *testing.T) {
	type args struct {
		networks []*iso_v1alpha1.IsovalentPodNetwork
		node     *v2.CiliumNode
	}
	tests := []struct {
		name       string
		args       args
		wantRoutes []*netlink.Route
	}{
		{
			name: "no network",
			args: args{
				networks: nil,
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v2.NodeSpec{
						Addresses: []v2.NodeAddress{
							{
								Type: addressing.NodeInternalIP,
								IP:   "192.168.10.20",
							},
						},
						IPAM: ipamTypes.IPAMSpec{
							Pools: ipamTypes.IPAMPoolSpec{
								Allocated: []ipamTypes.IPAMPoolAllocation{
									{
										Pool: "default",
										CIDRs: []iputil.Prefix{
											iputil.PrefixFrom(netip.MustParsePrefix("10.20.30.0/24")),
										},
									},
								},
							},
						},
					},
				},
			},
			wantRoutes: nil,
		},
		{
			name: "no node IP",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							IPAM: iso_v1alpha1.IPAMSpec{
								Mode: "multi-pool",
								Pool: iso_v1alpha1.IPAMPoolSpec{
									Name: "default",
								},
							},
						},
					},
				},
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pools: ipamTypes.IPAMPoolSpec{
								Allocated: []ipamTypes.IPAMPoolAllocation{
									{
										Pool: "default",
										CIDRs: []iputil.Prefix{
											iputil.PrefixFrom(netip.MustParsePrefix("10.20.30.0/24")),
										},
									},
								},
							},
						},
					},
				},
			},
			wantRoutes: nil,
		},
		{
			name: "default network",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							IPAM: iso_v1alpha1.IPAMSpec{
								Mode: "multi-pool",
								Pool: iso_v1alpha1.IPAMPoolSpec{
									Name: "default",
								},
							},
						},
					},
				},
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v2.NodeSpec{
						Addresses: []v2.NodeAddress{
							{
								Type: addressing.NodeInternalIP,
								IP:   "192.168.10.20",
							},
						},
						IPAM: ipamTypes.IPAMSpec{
							Pools: ipamTypes.IPAMPoolSpec{
								Allocated: []ipamTypes.IPAMPoolAllocation{
									{
										Pool: "default",
										CIDRs: []iputil.Prefix{
											iputil.PrefixFrom(netip.MustParsePrefix("10.20.30.0/24")),
										},
									},
								},
							},
						},
					},
				},
			},
			wantRoutes: []*netlink.Route{
				mustRoute("10.20.30.0/24", "192.168.10.20"),
			},
		},
		{
			name: "dual-stack routes",
			args: args{
				networks: []*iso_v1alpha1.IsovalentPodNetwork{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							IPAM: iso_v1alpha1.IPAMSpec{
								Mode: "multi-pool",
								Pool: iso_v1alpha1.IPAMPoolSpec{
									Name: "default",
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "network-1",
						},
						Spec: iso_v1alpha1.PodNetworkSpec{
							IPAM: iso_v1alpha1.IPAMSpec{
								Mode: "multi-pool",
								Pool: iso_v1alpha1.IPAMPoolSpec{
									Name: "pool-1",
								},
							},
						},
					},
				},
				node: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v2.NodeSpec{
						Addresses: []v2.NodeAddress{
							{
								Type: addressing.NodeInternalIP,
								IP:   "192.168.10.20",
							},
							{
								Type: addressing.NodeInternalIP,
								IP:   "fc00::30",
							},
							{
								Type: newNetworkAddressingType("network-1"),
								IP:   "172.16.0.40",
							},
							{
								Type: newNetworkAddressingType("network-1"),
								IP:   "fd00::50",
							},
						},
						IPAM: ipamTypes.IPAMSpec{
							Pools: ipamTypes.IPAMPoolSpec{
								Allocated: []ipamTypes.IPAMPoolAllocation{
									{
										Pool: "default",
										CIDRs: []iputil.Prefix{
											iputil.PrefixFrom(netip.MustParsePrefix("10.20.30.0/24")),
											iputil.PrefixFrom(netip.MustParsePrefix("fd00:20::/64")),
										},
									},
									{
										Pool: "pool-1",
										CIDRs: []iputil.Prefix{
											iputil.PrefixFrom(netip.MustParsePrefix("172.20.40.0/26")),
											iputil.PrefixFrom(netip.MustParsePrefix("172.20.50.0/26")),
											iputil.PrefixFrom(netip.MustParsePrefix("fd00:80::/96")),
											iputil.PrefixFrom(netip.MustParsePrefix("fd00:90::/96")),
										},
									},
								},
							},
						},
					},
				},
			},
			wantRoutes: []*netlink.Route{
				mustRoute("10.20.30.0/24", "192.168.10.20"),
				mustRoute("fd00:20::/64", "fc00::30"),
				mustRoute("172.20.40.0/26", "172.16.0.40"),
				mustRoute("172.20.50.0/26", "172.16.0.40"),
				mustRoute("fd00:80::/96", "fd00::50"),
				mustRoute("fd00:90::/96", "fd00::50"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRoutes := extractDirectNodeRoutes(hivetest.Logger(t), tt.args.networks, tt.args.node)
			if diff := cmp.Diff(gotRoutes, tt.wantRoutes); diff != "" {
				t.Errorf("extractDirectNodeRoutes (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_extractRemovedRoutes(t *testing.T) {
	type args struct {
		oldRoutes []*netlink.Route
		newRoutes []*netlink.Route
	}
	tests := []struct {
		name        string
		args        args
		wantRemoved []*netlink.Route
	}{
		{
			name: "no routes",
			args: args{
				oldRoutes: nil,
				newRoutes: nil,
			},
			wantRemoved: nil,
		},
		{
			name: "no old routes",
			args: args{
				oldRoutes: nil,
				newRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
				},
			},
			wantRemoved: nil,
		},
		{
			name: "no new routes",
			args: args{
				oldRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
				},
				newRoutes: nil,
			},
			wantRemoved: []*netlink.Route{
				mustRoute("10.20.30.0/24", "192.168.10.20"),
			},
		},
		{
			name: "no removed routes",
			args: args{
				oldRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
				},
				newRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.40.50.0/24", "192.168.10.20"),
				},
			},
			wantRemoved: nil,
		},
		{
			name: "removed routes",
			args: args{
				oldRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.40.50.0/24", "192.168.10.20"),
				},
				newRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
				},
			},
			wantRemoved: []*netlink.Route{
				mustRoute("10.40.50.0/24", "192.168.10.20"),
			},
		},
		{
			name: "removed routes with different gateway",
			args: args{
				oldRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.40.50.0/24", "192.168.10.20"),
				},
				newRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.40.50.0/24", "172.16.30.40"),
				},
			},
			wantRemoved: []*netlink.Route{
				mustRoute("10.40.50.0/24", "192.168.10.20"),
			},
		},
		{
			name: "removed routes with different destination",
			args: args{
				oldRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.80.90.0/24", "192.168.10.20"),
				},
				newRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.40.50.0/24", "192.168.10.20"),
				},
			},
			wantRemoved: []*netlink.Route{
				mustRoute("10.80.90.0/24", "192.168.10.20"),
			},
		},
		{
			name: "different order, but no removed routes",
			args: args{
				oldRoutes: []*netlink.Route{
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.40.50.0/24", "192.168.10.20"),
					mustRoute("10.60.70.0/24", "192.168.10.20"),
					mustRoute("10.80.90.0/24", "192.168.10.20"),
				},
				newRoutes: []*netlink.Route{
					mustRoute("10.80.90.0/24", "192.168.10.20"),
					mustRoute("10.20.30.0/24", "192.168.10.20"),
					mustRoute("10.60.70.0/24", "192.168.10.20"),
					mustRoute("10.40.50.0/24", "192.168.10.20"),
				},
			},
			wantRemoved: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRemoved := extractRemovedRoutes(tt.args.oldRoutes, tt.args.newRoutes)
			if diff := cmp.Diff(gotRemoved, tt.wantRemoved); diff != "" {
				t.Errorf("extractRemovedRoutes (-want +got):\n%s", diff)
			}
		})
	}
}

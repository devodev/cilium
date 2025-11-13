// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	bgptypes "github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

type testService struct {
	frontend *loadbalancer.Frontend
	backends []*loadbalancer.Backend
}

var (
	dummyLabel = bgp.MPLSLabelStack{
		Labels: []uint32{1234},
	}

	vrf1LBIngressIP = netip.MustParseAddr("192.168.100.1")
	vrf2LBIngressIP = netip.MustParseAddr("192.168.200.1")

	vrf1LBSvcName = loadbalancer.NewServiceName("", "vrf1-service")
	vrf1SvcLabel  = map[string]string{"svc": "vrf1"}
	vrf1LBSvc     = &loadbalancer.Service{
		Name:             vrf1LBSvcName,
		Labels:           labels.Map2Labels(vrf1SvcLabel, string(source.Kubernetes)),
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}

	vrf2LBSvcName = loadbalancer.NewServiceName("", "vrf2-service")
	vrf2SvcLabel  = map[string]string{"svc": "vrf2"}
	vrf2LBSvc     = &loadbalancer.Service{
		Name:             vrf2LBSvcName,
		Labels:           labels.Map2Labels(vrf2SvcLabel, string(source.Kubernetes)),
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}

	vrfSvcETPCluster = func(orig *loadbalancer.Service) *loadbalancer.Service {
		return &loadbalancer.Service{
			Name:             orig.Name,
			Labels:           orig.Labels,
			ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
			IntTrafficPolicy: orig.IntTrafficPolicy,
		}
	}

	vrf1SvcBackend1 = newTestBackend(vrf1LBSvcName, backendAddr("10.0.0.1", 80), "test-node", loadbalancer.BackendStateActive)
	vrf2SvcBackend1 = newTestBackend(vrf2LBSvcName, backendAddr("10.0.0.2", 80), "test-node", loadbalancer.BackendStateActive)

	vrf1AdvertLabel = map[string]string{"vrf": "vrf1"}
	vrf2AdvertLabel = map[string]string{"vrf": "vrf2"}

	vrf1Config = &v1alpha1.IsovalentBGPVRFConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vrf1-config",
		},
		Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: vrf1AdvertLabel,
					},
				},
			},
		},
	}

	vrf2Config = &v1alpha1.IsovalentBGPVRFConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vrf2-config",
		},
		Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: vrf2AdvertLabel,
					},
				},
			},
		},
	}

	vrf1BGPAdvert = v1.BGPAdvertisement{
		AdvertisementType: "Service",
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{
				v2.BGPLoadBalancerIPAddr,
			},
		},
		Selector: &slimv1.LabelSelector{
			MatchLabels: vrf1SvcLabel,
		},
	}
	vrf1Advert = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "vrf1-advert",
			Labels: vrf1AdvertLabel,
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{vrf1BGPAdvert},
		},
	}

	vrf2BGPAdvert = v1.BGPAdvertisement{
		AdvertisementType: "Service",
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{
				v2.BGPLoadBalancerIPAddr,
			},
		},
		Selector: &slimv1.LabelSelector{
			MatchLabels: vrf2SvcLabel,
		},
	}
	vrf2Advert = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "vrf2-advert",
			Labels: vrf2AdvertLabel,
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{vrf2BGPAdvert},
		},
	}

	testCiliumNodeConfig = &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
	}

	vrf1RDConfig = v1.IsovalentBGPNodeVRF{
		VRFRef:    ptr.To("vrf1"),
		ConfigRef: ptr.To("vrf1-config"),
		RD:        ptr.To("65001:1"),
		ImportRTs: []string{"65001:1"},
		ExportRTs: []string{"65001:1"},
	}
	vrf1RDConfigUpdated = v1.IsovalentBGPNodeVRF{
		VRFRef:    ptr.To("vrf1"),
		ConfigRef: ptr.To("vrf1-config"),
		RD:        ptr.To("65101:1"),
		ImportRTs: []string{"65101:1"},
		ExportRTs: []string{"65101:1"},
	}

	vrf2RDConfig = v1.IsovalentBGPNodeVRF{
		VRFRef:    ptr.To("vrf2"),
		ConfigRef: ptr.To("vrf2-config"),
		RD:        ptr.To("65001:2"),
		ImportRTs: []string{"65001:2"},
		ExportRTs: []string{"65001:2"},
	}
	vrf2ConfigUpdated = v1.IsovalentBGPNodeVRF{
		VRFRef:    ptr.To("vrf2"),
		ConfigRef: ptr.To("vrf2-config"),
		RD:        ptr.To("65101:2"),
		ImportRTs: []string{"65101:2"},
		ExportRTs: []string{"65101:2"},
	}

	testBGPNodeInstance = &v1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		VRFs:     []v1.IsovalentBGPNodeVRF{vrf1RDConfig, vrf2RDConfig},
	}

	testBGPNodeInstanceUpdatedRD = &v1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		VRFs:     []v1.IsovalentBGPNodeVRF{vrf1RDConfigUpdated, vrf2ConfigUpdated},
	}

	testBGPNodeInstanceUpdatedNoVRF = &v1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		VRFs:     []v1.IsovalentBGPNodeVRF{},
	}

	locator = types.MustNewLocator(
		netip.MustParsePrefix("fd00::/64"),
	)
	structure = types.MustNewSIDStructure(48, 16, 16, 0)
)

func TestServiceVRFFullReconciler(t *testing.T) {
	vrf1RD, err := bgp.ParseRouteDistinguisher("65001:1")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf1RDUpdated, err := bgp.ParseRouteDistinguisher("65101:1")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf2RD, err := bgp.ParseRouteDistinguisher("65001:2")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf2RDUpdated, err := bgp.ParseRouteDistinguisher("65101:2")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf1LBIngressIPNLRI := mustLabeledVPNIPAddrPrefix(netip.PrefixFrom(vrf1LBIngressIP, vrf1LBIngressIP.BitLen()), dummyLabel, vrf1RD)
	vrf1LBIngressIPNLRIUpdated := mustLabeledVPNIPAddrPrefix(netip.PrefixFrom(vrf1LBIngressIP, vrf1LBIngressIP.BitLen()), dummyLabel, vrf1RDUpdated)
	vrf2LBIngressIPNLRI := mustLabeledVPNIPAddrPrefix(netip.PrefixFrom(vrf2LBIngressIP, vrf2LBIngressIP.BitLen()), dummyLabel, vrf2RD)
	vrf2LBIngressIPNLRIUpdated := mustLabeledVPNIPAddrPrefix(netip.PrefixFrom(vrf2LBIngressIP, vrf2LBIngressIP.BitLen()), dummyLabel, vrf2RDUpdated)

	testAllocator, err := sidmanager.NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
	if err != nil {
		t.Fatalf("failed to create structured SID allocator: %v", err)
	}
	vrf1SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "vrf1", "vrf1", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 1: %v", err)
	}
	vrf2SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::"), "vrf2", "vrf2", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 2: %v", err)
	}

	testSRv6VRF1 := &srv6.VRF{
		VRFID:   1,
		SIDInfo: vrf1SIDInfo,
	}
	testSRv6VRF2 := &srv6.VRF{
		VRFID:   2,
		SIDInfo: vrf2SIDInfo,
	}

	tests := []struct {
		name            string
		prevMetadata    ServiceVRFReconcilerMetadata
		vrfConfigs      []*v1alpha1.IsovalentBGPVRFConfig
		adverts         []*v1.IsovalentBGPAdvertisement
		services        []testService
		bgpNodeInstance *v1.IsovalentBGPNodeInstance
		expectedAdverts VRFAdvertisements
		expectedPaths   vrfSimplePathsMap // to keep tests simple, compare nlri which is RD:LBVIP
	}{
		{
			name: "pre config: none, new config: 2 VRFs, expect: 2 paths",
			prevMetadata: ServiceVRFReconcilerMetadata{ // empty metadata
				vrfPaths:   make(VRFPaths),
				vrfAdverts: make(VRFAdvertisements),
			},
			vrfConfigs: []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:    []*v1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
		},
		{
			name: "pre config: 2 path, new config: 1 VRF, expect: 1 path removed, 1 path unchanged",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path
							},
						},
					},
					"vrf2": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs: []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config},
			adverts:    []*v1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
			},
		},
		{
			name: "pre config: 2 path, new config: no advertisement, expect: 2 paths removed",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path
							},
						},
					},
					"vrf2": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs: []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:    []*v1.IsovalentBGPAdvertisement{},
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: nil,
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: nil,
				},
			},
			expectedPaths: vrfSimplePathsMap{},
		},
		{
			name: "pre config: 2 path, new config: no vrf config, expect: 2 paths removed",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path
							},
						},
					},
					"vrf2": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs: []*v1alpha1.IsovalentBGPVRFConfig{},
			adverts:    []*v1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{},
			expectedPaths:   vrfSimplePathsMap{},
		},
		{
			name: "pre config: 2 path, new config: updated RDs, expect: 2 updated paths",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path with old RD
							},
						},
					},
					"vrf2": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path with old RD
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs: []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:    []*v1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			bgpNodeInstance: testBGPNodeInstanceUpdatedRD, // updated RD
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRIUpdated.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRIUpdated.String()},
					},
				},
			},
		},
		{
			name: "pre config: 2 path, new config: delete VRFs, expect: empty paths",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI},
							},
						},
					},
					"vrf2": reconciler.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvcName.Name()}: reconciler.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconciler.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI},
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs: []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:    []*v1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			bgpNodeInstance: testBGPNodeInstanceUpdatedNoVRF, // No VRFs
			expectedAdverts: VRFAdvertisements{},
			expectedPaths:   vrfSimplePathsMap{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			// IsovalentAdvertisement mock
			vrfConfigMockStore := store.NewMockBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]()
			for _, vrfConfig := range tt.vrfConfigs {
				vrfConfigMockStore.Upsert(vrfConfig)
			}
			advertMockStore := store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
			for _, advert := range tt.adverts {
				advertMockStore.Upsert(advert)
			}
			isoAdverts := &IsovalentAdvertisement{
				logger:  logger,
				adverts: advertMockStore,
				vrfs:    vrfConfigMockStore,
			}

			// init test statedb
			db := statedb.New()
			frontendsTable, err := loadbalancer.NewFrontendsTable(loadbalancer.Config{}, db)
			req.NoError(err)

			// insert frontends & backends into statedb
			tx := db.WriteTxn(frontendsTable)
			nextBackendRevision := statedb.Revision(1)
			for _, svc := range tt.services {
				for _, backend := range svc.backends {
					svc.frontend.Backends = concatBackend(svc.frontend.Backends, *backend, nextBackendRevision)
					nextBackendRevision++
				}
				_, _, err = frontendsTable.Insert(tx, svc.frontend)
				req.NoError(err)
			}
			tx.Commit()

			// srv6 manager mock
			srv6Manager := newMockSRv6Manager(map[k8stypes.NamespacedName]*srv6.VRF{
				{Name: "vrf1"}: testSRv6VRF1,
				{Name: "vrf2"}: testSRv6VRF2,
			})

			svcVRFReconciler := &ServiceVRFReconciler{
				logger:    logger,
				db:        db,
				frontends: frontendsTable,
				adverts:   isoAdverts,
				upgrader:  newUpgraderMock(tt.bgpNodeInstance),
				srv6Paths: &srv6Paths{
					Logger:      logger,
					SRv6Manager: srv6Manager,
				},
				srv6Manager: srv6Manager,
				metadata:    make(map[string]ServiceVRFReconcilerMetadata),
			}

			// setup preconfig
			testOSSBGPInstance := &instance.BGPInstance{
				Name:   "fake-instance",
				Router: fake.NewEnterpriseFakeRouter(),
			}
			testBGPInstance := &EnterpriseBGPInstance{
				Name:   testOSSBGPInstance.Name,
				Router: upgradeRouter(testOSSBGPInstance.Router),
			}
			svcVRFReconciler.Init(testOSSBGPInstance)
			svcVRFReconciler.setMetadata(testBGPInstance, tt.prevMetadata)

			// reconcile twice to test idempotency
			for range 2 {
				err := svcVRFReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
					BGPInstance: testOSSBGPInstance,
					CiliumNode:  testCiliumNodeConfig,
				})
				req.NoError(err)
			}

			// check if the expected metadata is the same as the actual metadata
			runningMetadata := svcVRFReconciler.getMetadata(testBGPInstance)
			req.Equal(tt.expectedAdverts, runningMetadata.vrfAdverts)

			// check expected Paths
			compareSimplePath(req, tt.expectedPaths, runningMetadata.vrfPaths)
		})
	}
}

func TestServiceVRFPartialReconcile(t *testing.T) {
	vrf1RD, err := bgp.ParseRouteDistinguisher("65001:1")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}
	vrf2RD, err := bgp.ParseRouteDistinguisher("65001:2")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf1LBIngressIPNLRI := mustLabeledVPNIPAddrPrefix(netip.PrefixFrom(vrf1LBIngressIP, vrf1LBIngressIP.BitLen()), dummyLabel, vrf1RD)
	vrf2LBIngressIPNLRI := mustLabeledVPNIPAddrPrefix(netip.PrefixFrom(vrf2LBIngressIP, vrf2LBIngressIP.BitLen()), dummyLabel, vrf2RD)

	testAllocator, err := sidmanager.NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
	if err != nil {
		t.Fatalf("failed to create structured SID allocator: %v", err)
	}
	testAllocator2, err := sidmanager.NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeUSID)
	if err != nil {
		t.Fatalf("failed to create structured SID allocator: %v", err)
	}
	vrf1SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "vrf1", "vrf1", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 1: %v", err)
	}
	vrf1SIDInfoUpdated, err := testAllocator2.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "vrf1", "vrf1", types.BehaviorUDT4)
	if err != nil {
		t.Fatalf("failed to allocate updated SID for VRF 1: %v", err)
	}
	vrf2SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::"), "vrf2", "vrf2", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 2: %v", err)
	}

	testSRv6VRF1 := &srv6.VRF{
		VRFID:   1,
		SIDInfo: vrf1SIDInfo,
	}
	testSRv6VRF1Updated := &srv6.VRF{
		VRFID:   1,
		SIDInfo: vrf1SIDInfoUpdated,
	}
	testSRv6VRF2 := &srv6.VRF{
		VRFID:   2,
		SIDInfo: vrf2SIDInfo,
	}

	tests := []struct {
		name                       string
		services                   []testService
		expectedAdverts            VRFAdvertisements
		expectedPaths              vrfSimplePathsMap
		expectedVRFSIDs            VRFSIDInfo
		updatedServices            []testService
		updatedSRv6VRFs            map[k8stypes.NamespacedName]*srv6.VRF
		expectedAdvertsAfterUpdate VRFAdvertisements
		expectedPathsAfterUpdate   vrfSimplePathsMap
		expectedVRFSIDsAfterUpdate VRFSIDInfo
	}{
		{
			name: "pre config: none, new config: 2 VRFs, expect: 2 paths",
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			// No update, after update should be the same as before
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
		},
		{
			name: "pre config: 2 paths, update service to eTP=Cluster, expect 1 path removed, 1 path unchanged",
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			updatedServices: []testService{
				{
					frontend: svcLBFrontend(vrfSvcETPCluster(vrf2LBSvc), vrf2LBIngressIP.String()), // update 1 service to have eTP=Cluster
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
		},
		{
			name: "pre config: 1 paths, update service to eTP=Local, expect 1 path added, 1 path unchanged",
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrfSvcETPCluster(vrf2LBSvc), vrf2LBIngressIP.String()), // start with eTP=Cluster
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			updatedServices: []testService{
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()), // set eTP=Local
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
		},
		{
			name: "pre config: 0 paths, add endpoints, expect 2 path added",
			services: []testService{ // start with 2 services with no backends
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
				},
			},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			updatedServices: []testService{ // add backends to services
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
		},
		{
			name: "pre config: 2 paths, update SIDInfo, expect 2 path and SIDInfo updated",
			services: []testService{
				{
					frontend: svcLBFrontend(vrf1LBSvc, vrf1LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf1SvcBackend1},
				},
				{
					frontend: svcLBFrontend(vrf2LBSvc, vrf2LBIngressIP.String()),
					backends: []*loadbalancer.Backend{vrf2SvcBackend1},
				},
			},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			// Update SIDInfo
			updatedSRv6VRFs: map[k8stypes.NamespacedName]*srv6.VRF{
				{Name: "vrf1"}: testSRv6VRF1Updated,
				{Name: "vrf2"}: testSRv6VRF2,
			},
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvcName.Name()}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfoUpdated, // validate with new SID info
				"vrf2": vrf2SIDInfo,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			isoAdverts := &IsovalentAdvertisement{
				logger:  logger,
				adverts: store.InitMockStore[*v1.IsovalentBGPAdvertisement]([]*v1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert}),
				vrfs:    store.InitMockStore[*v1alpha1.IsovalentBGPVRFConfig]([]*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config}),
			}

			// init test statedb
			db := statedb.New()
			frontendsTable, err := loadbalancer.NewFrontendsTable(loadbalancer.Config{}, db)
			req.NoError(err)

			// insert frontends & backends into statedb
			tx := db.WriteTxn(frontendsTable)
			nextBackendRevision := statedb.Revision(1)
			for _, svc := range tt.services {
				for _, backend := range svc.backends {
					svc.frontend.Backends = concatBackend(svc.frontend.Backends, *backend, nextBackendRevision)
					nextBackendRevision++
				}
				_, _, err = frontendsTable.Insert(tx, svc.frontend)
				req.NoError(err)
			}
			tx.Commit()

			// srv6 manager mock
			srv6Manager := newMockSRv6Manager(map[k8stypes.NamespacedName]*srv6.VRF{
				{Name: "vrf1"}: testSRv6VRF1,
				{Name: "vrf2"}: testSRv6VRF2,
			})

			svcVRFReconciler := &ServiceVRFReconciler{
				logger:    logger,
				db:        db,
				frontends: frontendsTable,
				adverts:   isoAdverts,
				upgrader:  newUpgraderMock(testBGPNodeInstance),
				srv6Paths: &srv6Paths{
					Logger:      logger,
					SRv6Manager: srv6Manager,
				},
				srv6Manager: srv6Manager,
				metadata:    make(map[string]ServiceVRFReconcilerMetadata),
			}

			// setup preconfig
			testOSSBGPInstance := &instance.BGPInstance{
				Name:   "fake-instance",
				Router: fake.NewEnterpriseFakeRouter(),
			}
			testBGPInstance := &EnterpriseBGPInstance{
				Name:   testOSSBGPInstance.Name,
				Router: upgradeRouter(testOSSBGPInstance.Router),
			}
			svcVRFReconciler.Init(testOSSBGPInstance)
			defer svcVRFReconciler.Cleanup(testOSSBGPInstance)

			// reconcile to test initial state
			err = svcVRFReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
				BGPInstance: testOSSBGPInstance,
				CiliumNode:  testCiliumNodeConfig,
			})
			req.NoError(err)

			// check if the expected metadata is the same as the actual metadata
			runningMetadata := svcVRFReconciler.getMetadata(testBGPInstance)
			req.Equal(tt.expectedAdverts, runningMetadata.vrfAdverts)
			req.Equal(tt.expectedVRFSIDs, runningMetadata.vrfSIDs)
			compareSimplePath(req, tt.expectedPaths, runningMetadata.vrfPaths)

			// update frontends and backends in statedb
			tx = db.WriteTxn(frontendsTable)
			for _, svc := range tt.updatedServices {
				for _, backend := range svc.backends {
					svc.frontend.Backends = concatBackend(svc.frontend.Backends, *backend, nextBackendRevision)
					nextBackendRevision++
				}
				_, _, err = frontendsTable.Insert(tx, svc.frontend)
				req.NoError(err)
			}
			tx.Commit()

			// update SRv6 VRFs
			for key, vrf := range tt.updatedSRv6VRFs {
				srv6Manager.upsertVRF(key, vrf)
			}

			// reconcile again to test parital reconciliation
			err = svcVRFReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
				BGPInstance: testOSSBGPInstance,
				CiliumNode:  testCiliumNodeConfig,
			})
			req.NoError(err)

			// check if the expected metadata is the same as the actual metadata
			runningMetadata = svcVRFReconciler.getMetadata(testBGPInstance)
			req.Equal(tt.expectedAdvertsAfterUpdate, runningMetadata.vrfAdverts)
			// also check if SID is updated
			if len(tt.updatedSRv6VRFs) > 0 {
				req.Equal(tt.expectedVRFSIDsAfterUpdate, runningMetadata.vrfSIDs)
			}
			compareSimplePath(req, tt.expectedPathsAfterUpdate, runningMetadata.vrfPaths)
		})
	}
}

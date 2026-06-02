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
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	ossInstance "github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
)

// svcTestStep represents one step in the service reconciler test execution.
// Each step builds on the state of the previous step: if some of the step resources is provided,
// the resource is upserted (in case of the "delete" prefix, it is deleted).
type svcTestStep struct {
	name                string
	peers               []v1.IsovalentBGPNodePeer
	peerConfigs         []*v1.IsovalentBGPPeerConfig
	advertisements      []*v1.IsovalentBGPAdvertisement
	frontends           []*loadbalancer.Frontend
	deleteFrontends     []*loadbalancer.Frontend
	backends            []*loadbalancer.Backend
	expectedMetadata    ServiceReconcilerMetadata
	nodeStatus          NodeStatus
	maintenanceOverride *v1.IsovalentBGPMaintenance
}

type svcTestFixture struct {
	hive               *ciliumhive.Hive
	svcReconciler      *ServiceReconciler
	db                 *statedb.DB
	frontends          statedb.RWTable[*loadbalancer.Frontend]
	peerConfigStore    *store.MockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]
	advertStore        *store.MockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]
	nodeStatusProvider *mockNodeStatusProvider
}

func Test_ServiceHealthChecker(t *testing.T) {
	var (
		redSvcHCEnabled = &loadbalancer.Service{
			Name:   redSvcName,
			Labels: redSvcLabels,
			Annotations: map[string]string{
				annotation.ServiceHealthProbeInterval: "5s",
			},
			ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
			IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		}
		redSvcHCEnabledThreshold2 = &loadbalancer.Service{
			Name:   redSvcName,
			Labels: redSvcLabels,
			Annotations: map[string]string{
				annotation.ServiceHealthProbeInterval:         "5s",
				annotation.ServiceHealthBGPAdvertiseThreshold: "2",
			},
			ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
			IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		}
		redSvcHCNoAdvertisement = &loadbalancer.Service{
			Name:   redSvcName,
			Labels: redSvcLabels,
			Annotations: map[string]string{
				annotation.ServiceNoAdvertisement: "true",
			},
			ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
			IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		}
	)

	runServiceTests(t, []svcTestStep{
		{
			name:        "do not advertise new service with no health updates",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name:      "advertise the service after healthy backend update",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name:      "advertise the service after multiple backend updates",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.1.1", 80), "node1", loadbalancer.BackendStateQuarantined),
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node2", loadbalancer.BackendStateActive),
				newTestBackend(redSvcName, backendAddr("10.1.1.2", 80), "node3", loadbalancer.BackendStateQuarantined),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name:      "do not advertise the service after unhealthy backend update (all unhealthy)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.1.1", 80), "node1", loadbalancer.BackendStateQuarantined),
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node2", loadbalancer.BackendStateQuarantined),
				newTestBackend(redSvcName, backendAddr("10.1.1.2", 80), "node3", loadbalancer.BackendStateQuarantined),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name:      "advertise the service even after unhealthy backend update if health-checking is disabled",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4)}, // health-checking not enabled in this svc
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateQuarantined),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name:      "do not advertise the service after unhealthy backend update (2 unhealthy)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateQuarantined),
				newTestBackend(redSvcName, backendAddr("10.1.0.2", 80), "node1", loadbalancer.BackendStateQuarantined),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name: "advertise existing service with multiple frontend ports - all healthy",
			frontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcHCEnabled, ingressV4, 80, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvcHCEnabled, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
			},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 443), "node1", loadbalancer.BackendStateActive),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name: "withdraw the service with multiple frontend ports - 1 unhealthy port",
			frontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcHCEnabled, ingressV4, 80, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvcHCEnabled, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
			},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 443), "node1", loadbalancer.BackendStateQuarantined),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name: "advertise dual-stack service with multiple frontend IPs - all healthy",
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			deleteFrontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcHCEnabled, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
			},
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4), svcLBFrontend(redSvcHCEnabled, ingressV6)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
				newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateActive),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
		{
			name:      "partially advertise dual-stack service with multiple frontend IPs - 1 unhealthy IP",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4), svcLBFrontend(redSvcHCEnabled, ingressV6)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateQuarantined),
				newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateActive),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
		{
			name:      "do not advertise dual-stack service with multiple frontend IPs - all unhealthy",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabled, ingressV4), svcLBFrontend(redSvcHCEnabled, ingressV6)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateQuarantined),
				newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateQuarantined),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
		{
			name: "advertise existing service after a backend update - non-default threshold, healthy",
			deleteFrontends: []*loadbalancer.Frontend{
				svcLBFrontend(redSvcHCEnabled, ingressV6),
			},
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabledThreshold2, ingressV4)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
				newTestBackend(redSvcName, backendAddr("10.1.0.2", 80), "node1", loadbalancer.BackendStateActive),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name:      "withdraw existing service after a backend update - non-default threshold, 1 unhealthy",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCEnabledThreshold2, ingressV4)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
				newTestBackend(redSvcName, backendAddr("10.1.0.2", 80), "node1", loadbalancer.BackendStateQuarantined),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
		{
			name:      "do not advertise service with no-advertisement annotation",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcHCNoAdvertisement, ingressV4)},
			backends: []*loadbalancer.Backend{
				newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
				newTestBackend(redSvcName, backendAddr("10.1.0.2", 80), "node1", loadbalancer.BackendStateActive),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{lbSvcAdvertWithSelector(redSvcSelector)},
					},
				},
				ServicePaths: reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
					},
				},
			},
		},
	})
}

var (
	redSvcKey            = resource.Key{Name: "red-svc", Namespace: "non-default"}
	redSvc2Key           = resource.Key{Name: "red-svc2", Namespace: "non-default"}
	redSvcSelector       = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}}
	mismatchSvcSelector  = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	aggregateV4Prefix24  = "192.168.0.0/24"
	ingressV4            = "192.168.0.1"
	ingressV4Prefix      = "192.168.0.1/32"
	externalV4           = "192.168.0.2"
	externalV4Prefix     = "192.168.0.2/32"
	clusterV4            = "192.168.0.3"
	clusterV4Prefix      = "192.168.0.3/32"
	aggregateV6Prefix120 = "2001:db8::/120"
	ingressV6            = "2001:db8::1"
	ingressV6Prefix      = "2001:db8::1/128"
	externalV6           = "2001:db8::2"
	externalV6Prefix     = "2001:db8::2/128"
	clusterV6            = "2001:db8::3"
	clusterV6Prefix      = "2001:db8::3/128"

	redSvcName      = loadbalancer.NewServiceName(redSvcKey.Namespace, redSvcKey.Name)
	redSvc2Name     = loadbalancer.NewServiceName(redSvc2Key.Namespace, redSvc2Key.Name)
	redSvcLabels    = labels.Map2Labels(redSvcSelector.MatchLabels, string(source.Kubernetes))
	redSvcTPCluster = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	redSvcTPLocal = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
	}
	redSvcExtTPLocal = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	redSvcIntTPLocal = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
	}
	redSvc2TPCluster = &loadbalancer.Service{
		Name:             redSvc2Name,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	// redSvcExtTPLocalWithProxy is a service with eTP=Local and ProxyRedirect set,
	// simulating a Gateway API / Ingress service where local Envoy handles traffic.
	redSvcExtTPLocalWithProxy = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		ProxyRedirect: &loadbalancer.ProxyRedirect{
			ProxyPort: 10000,
			Ports:     []uint16{80, 443},
		},
	}
	svcFrontend = func(svc *loadbalancer.Service, addr string, port uint16, svcType loadbalancer.SVCType) *loadbalancer.Frontend {
		return &loadbalancer.Frontend{
			FrontendParams: loadbalancer.FrontendParams{
				ServiceName: svc.Name,
				Address:     loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster(addr), port, 0),
				Type:        svcType,
			},
			Service:  svc,
			Backends: func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {},
		}
	}
	svcLBFrontend = func(svc *loadbalancer.Service, addr string) *loadbalancer.Frontend {
		return svcFrontend(svc, addr, 80, loadbalancer.SVCTypeLoadBalancer)
	}
	svcExtIPFrontend = func(svc *loadbalancer.Service, addr string) *loadbalancer.Frontend {
		return svcFrontend(svc, addr, 80, loadbalancer.SVCTypeExternalIPs)
	}
	svcClusterIPFrontend = func(svc *loadbalancer.Service, addr string) *loadbalancer.Frontend {
		return svcFrontend(svc, addr, 80, loadbalancer.SVCTypeClusterIP)
	}
	backendAddr = func(addr string, port uint16) loadbalancer.L3n4Addr {
		return loadbalancer.NewL3n4Addr(
			loadbalancer.TCP,
			cmtypes.MustParseAddrCluster(addr),
			port,
			loadbalancer.ScopeExternal,
		)
	}
	redSvcBackendsLocal = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateActive),
	}
	redSvcBackendsMixed = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("10.2.0.1", 80), "node2", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:2000::1", 80), "node2", loadbalancer.BackendStateActive),
	}
	redSvcBackendsRemote = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.2.0.1", 80), "node2", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:2000::1", 80), "node2", loadbalancer.BackendStateActive),
	}
	redSvcBackendsLocalTerminating = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateTerminating),
		newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateTerminating),
	}

	redPeer65001v4LBRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v4LBRP     = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}

	redPeer65001Svc2v4LBRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v4LBRP     = func() *entTypes.ExtendedRoutePolicy {
		return &entTypes.ExtendedRoutePolicy{
			Name:       redPeer65001Svc2v4LBRPName,
			Type:       types.RoutePolicyTypeExport,
			Statements: redPeer65001v4LBRP.Statements,
		}
	}

	redPeer65001v4LBRPWith24PrefixLen = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
								PrefixLenMin: 24, // It's hardcoded to 24 for tests
								PrefixLenMax: 24,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v4LBRPMultiPaths = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
								PrefixLenMin: 24, // It's hardcoded to 24 for tests
								PrefixLenMax: 24,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}

	redPeer65001v6LBRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v6LBRP     = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v6LBRPWith120PrefixLen = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v6LBRPMultiPaths = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001Svc2v6LBRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v6LBRP     = func() *entTypes.ExtendedRoutePolicy {
		return &entTypes.ExtendedRoutePolicy{
			Name:       redPeer65001Svc2v6LBRPName,
			Type:       types.RoutePolicyTypeExport,
			Statements: redPeer65001v6LBRP.Statements,
		}
	}

	redPeer65001v4ExtRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v4ExtRP     = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v4ExtRPWithPrefixAgg = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
								PrefixLenMin: 24,
								PrefixLenMax: 24,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v4ExtRPMultiPaths = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
								PrefixLenMin: 24, // It's hardcoded to 24 for tests
								PrefixLenMax: 24,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}

	redPeer65001v6ExtRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v6ExtRP     = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v6ExtRPWithPrefixAgg = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v6ExtRPMultiPaths = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}

	redPeer65001v4ClusterRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v4ClusterRP     = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v4ClusterRPWithPrefixAgg = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
								PrefixLenMin: 24,
								PrefixLenMax: 24,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v4ClusterRPMultiPaths = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
								PrefixLenMin: 24, // It's hardcoded to 24 for tests
								PrefixLenMax: 24,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}

	redPeer65001v6ClusterRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v6ClusterRP     = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v6ClusterRPWithPrefixAgg = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}
	redPeer65001v6ClusterRPMultiPaths = &entTypes.ExtendedRoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
						},
					},
				}},
				Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"}},
				},
			},
		},
	}

	redSvcAdvert = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp",
			},
		},
	}

	redSvcAdvertWithAdvertisements = func(adverts ...v1.BGPAdvertisement) *v1.IsovalentBGPAdvertisement {
		cp := redSvcAdvert.DeepCopy()
		cp.Spec.Advertisements = adverts
		return cp
	}

	redV6SvcAdvert = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-v6-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp_v6",
			},
		},
	}

	redV6SvcAdvertWithAdvertisements = func(adverts ...v1.BGPAdvertisement) *v1.IsovalentBGPAdvertisement {
		cp := redV6SvcAdvert.DeepCopy()
		cp.Spec.Advertisements = adverts
		return cp
	}

	lbSvcAdvert = v1.BGPAdvertisement{
		AdvertisementType: v1.BGPServiceAdvert,
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
		},
		Attributes: &v1.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}
	lbSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v1.BGPAdvertisement {
		cp := lbSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}
	lbSvcAdvertWithSelectorAndPrefixLen = func(selector *slim_metav1.LabelSelector, prefixLen int32) v1.BGPAdvertisement {
		cp := lbSvcAdvert.DeepCopy()
		cp.Selector = selector
		if prefixLen < 32 {
			cp.Service.AggregationLengthIPv4 = ptr.To[int32](prefixLen)
		} else {
			cp.Service.AggregationLengthIPv6 = ptr.To[int32](prefixLen)
		}
		return *cp
	}

	externalSvcAdvert = v1.BGPAdvertisement{
		AdvertisementType: v1.BGPServiceAdvert,
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPExternalIPAddr},
		},
		Attributes: &v1.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	externalSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v1.BGPAdvertisement {
		cp := externalSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}
	exSvcAdvertWithSelectorAndPrefixLen = func(selector *slim_metav1.LabelSelector, prefixLen int32) v1.BGPAdvertisement {
		cp := externalSvcAdvert.DeepCopy()
		cp.Selector = selector
		if prefixLen < 32 {
			cp.Service.AggregationLengthIPv4 = ptr.To[int32](prefixLen)
		} else {
			cp.Service.AggregationLengthIPv6 = ptr.To[int32](prefixLen)
		}
		return *cp
	}

	clusterIPSvcAdvert = v1.BGPAdvertisement{
		AdvertisementType: v1.BGPServiceAdvert,
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
		},
		Attributes: &v1.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	clusterIPSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v1.BGPAdvertisement {
		cp := clusterIPSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}
	clusterIPSvcAdvertWithSelectorAndPrefixLen = func(selector *slim_metav1.LabelSelector, prefixLen int32) v1.BGPAdvertisement {
		cp := clusterIPSvcAdvert.DeepCopy()
		cp.Selector = selector
		if prefixLen < 32 {
			cp.Service.AggregationLengthIPv4 = ptr.To[int32](prefixLen)
		} else {
			cp.Service.AggregationLengthIPv6 = ptr.To[int32](prefixLen)
		}
		return *cp
	}

	// red peer config
	redPeerConfig = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					Advertisements: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "red_bgp",
						},
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					Advertisements: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "red_bgp_v6",
						},
					},
				},
			},
		},
	}

	testBGPInstanceConfig = &v1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				Name:        "red-peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config-red",
				},
			},
		},
	}

	testPeerID = PeerID{
		Name:    "red-peer-65001",
		Address: "10.10.10.1",
	}
)

// Test_ServiceLBReconciler tests reconciliation of service of type load-balancer
func Test_ServiceLBReconciler(t *testing.T) {
	runServiceTests(t, []svcTestStep{
		{
			name:           "Service (LB) with advertisement( empty )",
			peerConfigs:    []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:      []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - mismatch labels",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=cluster)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on node)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:    redSvcBackendsLocal,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, mixed ep)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:    redSvcBackendsMixed,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on remote)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:    redSvcBackendsRemote,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, backends are terminating)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:    redSvcBackendsLocalTerminating,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - prefix aggregation (eTP=Cluster, iTP=Local)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcIntTPLocal, ingressV4), svcLBFrontend(redSvcIntTPLocal, ingressV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRPWith24PrefixLen,
						redPeer65001v6LBRPName: redPeer65001v6LBRPWith120PrefixLen,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - eTP=Local, iTP=Cluster - no prefix aggregation",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:    redSvcBackendsLocal,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)), // /32 advertisement
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)), // /128 advertisement
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP, // policy is also created for /32 advertisement
						redPeer65001v6LBRPName: redPeer65001v6LBRP, // policy is also created for /128 advertisement
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - prefix aggregation (eTP=Cluster), aggregate and full match advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24), lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120), lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
							ingressV4Prefix:     types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
							ingressV6Prefix:      types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRPMultiPaths,
						redPeer65001v6LBRPName: redPeer65001v6LBRPMultiPaths,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		// Test that Gateway API / Ingress services with ProxyRedirect are advertised
		// even with eTP=Local and no local backends, because traffic is handled by
		// the local Envoy proxy.
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, no backends, ProxyRedirect set)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocalWithProxy, ingressV4), svcLBFrontend(redSvcExtTPLocalWithProxy, ingressV6)},
			backends:    nil, // no backends
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	})
}

// Test_ServiceExternalIPReconciler tests reconciliation of cluster service with external IP
func Test_ServiceExternalIPReconciler(t *testing.T) {
	runServiceTests(t, []svcTestStep{
		{
			name:           "Service (External) with advertisement( empty )",
			peerConfigs:    []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:      []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - mismatch labels",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=cluster)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=local, ep on node)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:    redSvcBackendsLocal,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=local, mixed ep)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:    redSvcBackendsMixed,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=local, ep on remote)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:    redSvcBackendsRemote,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with prefix aggregation - eTP=Cluster, iTP=Local",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcIntTPLocal, externalV4), svcExtIPFrontend(redSvcIntTPLocal, externalV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRPWithPrefixAgg,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRPWithPrefixAgg,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - eTP=Local, iTP=Cluster - no prefix aggregation",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:    redSvcBackendsLocal,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)), // /32 advertisement
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)), // /128 advertisement
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP, // /32 policy
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP, // /128 policy
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - prefix aggregation (eTP=Cluster), aggregate and full match advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24), externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120), externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
							externalV4Prefix:    types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
							externalV6Prefix:     types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRPMultiPaths,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRPMultiPaths,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	})
}

// Test_ServiceClusterIPReconciler tests reconciliation of cluster service
func Test_ServiceClusterIPReconciler(t *testing.T) {
	runServiceTests(t, []svcTestStep{
		{
			name:           "Service (Cluster) with advertisement( empty )",
			peerConfigs:    []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:      []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - mismatch labels",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=cluster)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on node)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:    redSvcBackendsLocal,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, mixed ep)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:    redSvcBackendsMixed,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on remote)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:    redSvcBackendsRemote,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with prefix aggregation - eTP=Cluster",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRPWithPrefixAgg,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRPWithPrefixAgg,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - iTP=Local - no prefix aggregation",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:    redSvcBackendsLocal,
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)), // /32 advertisement
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)), // /128 advertisement
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP, // /32 policy
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP, // /128 policy
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - prefix aggregation (iTP=Cluster), aggregate and full match advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24), clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120), clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
							clusterV4Prefix:     types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.MustNewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
							clusterV6Prefix:      types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRPMultiPaths,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRPMultiPaths,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	})
}

// Test_ServiceAndAdvertisementModifications is a step test, in which each step modifies the advertisement or service parameters.
func Test_ServiceAndAdvertisementModifications(t *testing.T) {
	runServiceTests(t, []svcTestStep{
		{
			name:           "Initial setup - Service (nil) with advertisement( empty )",
			peerConfigs:    []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			advertisements: nil,
			frontends:      nil,
			backends:       nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name: "Add service (Cluster, External) with advertisement(Cluster) - matching labels",
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6),
				svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Only cluster IPs are advertised
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update advertisement(Cluster, External) - matching labels",
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{
							v2.BGPClusterIPAddr,
							v2.BGPExternalIPAddr,
						},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{
							v2.BGPClusterIPAddr,
							v2.BGPExternalIPAddr,
						},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are advertised
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v4ExtRPName:     redPeer65001v4ExtRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
						redPeer65001v6ExtRPName:     redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update service (Cluster, External) traffic policy local",
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPLocal, clusterV4), svcClusterIPFrontend(redSvcTPLocal, clusterV6),
				svcExtIPFrontend(redSvcTPLocal, externalV4), svcExtIPFrontend(redSvcTPLocal, externalV6),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are withdrawn, since traffic policy is local and there are no endpoints.
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update local endpoints (Cluster, External)",
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPLocal, clusterV4), svcClusterIPFrontend(redSvcTPLocal, clusterV6),
				svcExtIPFrontend(redSvcTPLocal, externalV4), svcExtIPFrontend(redSvcTPLocal, externalV6),
			},
			backends: redSvcBackendsLocal,
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are advertised since there is local endpoint.
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v4ExtRPName:     redPeer65001v4ExtRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
						redPeer65001v6ExtRPName:     redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Delete local endpoints (Cluster, External)",
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPLocal, clusterV4), svcClusterIPFrontend(redSvcTPLocal, clusterV6),
				svcExtIPFrontend(redSvcTPLocal, externalV4), svcExtIPFrontend(redSvcTPLocal, externalV6),
			},
			backends: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are withdrawn since local endpoints were deleted.
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
	})
}

func Test_ServiceVIPSharing(t *testing.T) {
	runServiceTests(t, []svcTestStep{
		{
			name:        "Add service 1 (LoadBalancer, port 80) with advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			frontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcTPCluster, ingressV4, 80, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvcTPCluster, ingressV6, 80, loadbalancer.SVCTypeLoadBalancer),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Add service 2 (LoadBalancer, port 443) with the same VIP",
			frontends: []*loadbalancer.Frontend{
				svcFrontend(redSvc2TPCluster, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvc2TPCluster, ingressV6, 443, loadbalancer.SVCTypeLoadBalancer),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
					redSvc2Key: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
					redSvc2Key: RoutePolicyMap{
						redPeer65001Svc2v4LBRPName: redPeer65001Svc2v4LBRP(),
						redPeer65001Svc2v6LBRPName: redPeer65001Svc2v6LBRP(),
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Delete service 1 (LoadBalancer, port 80)",
			deleteFrontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcTPCluster, ingressV4, 80, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvcTPCluster, ingressV6, 80, loadbalancer.SVCTypeLoadBalancer),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvc2Key: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvc2Key: RoutePolicyMap{
						redPeer65001Svc2v4LBRPName: redPeer65001Svc2v4LBRP(),
						redPeer65001Svc2v6LBRPName: redPeer65001Svc2v6LBRP(),
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Delete service 2 (LoadBalancer, port 443)",
			deleteFrontends: []*loadbalancer.Frontend{
				svcFrontend(redSvc2TPCluster, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvc2TPCluster, ingressV6, 443, loadbalancer.SVCTypeLoadBalancer),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconciler.ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
	})
}

func Test_ServiceAdvertisementWithPeerIPChange(t *testing.T) {
	runServiceTests(t, []svcTestStep{
		{
			name:        "Add service and advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.1"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v1.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: &entTypes.ExtendedRoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*entTypes.ExtendedRoutePolicyStatement{
								{
									Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Type:      types.RoutePolicyMatchAny,
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV4Prefix),
													PrefixLenMin: 32,
													PrefixLenMax: 32,
												},
											},
										},
									}},
									Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"}},
									},
								},
							},
						},
						redPeer65001v6LBRPName: &entTypes.ExtendedRoutePolicy{
							Name: redPeer65001v6LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*entTypes.ExtendedRoutePolicyStatement{
								{
									Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Type:      types.RoutePolicyMatchAny,
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV6Prefix),
													PrefixLenMin: 128,
													PrefixLenMax: 128,
												},
											},
										},
									}},
									Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"}},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					PeerID{Name: "red-peer-65001", Address: "10.10.10.1"}: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Change peer IP address",
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.99"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconciler.ResourceAFPathsMap{
					redSvcKey: reconciler.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: &entTypes.ExtendedRoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*entTypes.ExtendedRoutePolicyStatement{
								{
									Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Type:      types.RoutePolicyMatchAny,
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.99")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV4Prefix),
													PrefixLenMin: 32,
													PrefixLenMax: 32,
												},
											},
										},
									}},
									Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"}},
									},
								},
							},
						},
						redPeer65001v6LBRPName: &entTypes.ExtendedRoutePolicy{
							Name: redPeer65001v6LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*entTypes.ExtendedRoutePolicyStatement{
								{
									Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Type:      types.RoutePolicyMatchAny,
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.99")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV6Prefix),
													PrefixLenMin: 128,
													PrefixLenMax: 128,
												},
											},
										},
									}},
									Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"}},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					PeerID{Name: "red-peer-65001", Address: "10.10.10.99"}: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v1.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
	})
}

func Test_ServiceNodeMaintenance(t *testing.T) {
	var (
		peerAdvertisements = PeerAdvertisements{
			testPeerID: FamilyAdvertisements{
				{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
					lbSvcAdvertWithSelector(redSvcSelector),
				},
				{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
			},
		}
		expectedServicePaths = reconciler.ResourceAFPathsMap{
			redSvcKey: reconciler.AFPathsMap{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
				},
			},
		}
		expectedPolicies = ResourceRoutePolicyMap{
			redSvcKey: RoutePolicyMap{
				redPeer65001v4LBRPName: &entTypes.ExtendedRoutePolicy{
					Name: redPeer65001v4LBRPName,
					Type: types.RoutePolicyTypeExport,
					Statements: []*entTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
								MatchNeighbors: &types.RoutePolicyNeighborMatch{
									Type:      types.RoutePolicyMatchAny,
									Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
								},
								MatchPrefixes: &types.RoutePolicyPrefixMatch{
									Type: types.RoutePolicyMatchAny,
									Prefixes: []types.RoutePolicyPrefix{
										{
											CIDR:         netip.MustParsePrefix(ingressV4Prefix),
											PrefixLenMin: 32,
											PrefixLenMax: 32,
										},
									},
								},
							}},
							Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
								RouteAction:    types.RoutePolicyActionAccept,
								AddCommunities: []string{"65535:65281"}},
							},
						},
					},
				},
			},
		}
		expectedPoliciesWithGSCommunity = ResourceRoutePolicyMap{
			redSvcKey: RoutePolicyMap{
				redPeer65001v4LBRPName: &entTypes.ExtendedRoutePolicy{
					Name: redPeer65001v4LBRPName,
					Type: types.RoutePolicyTypeExport,
					Statements: []*entTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: entTypes.ExtendedRoutePolicyConditions{RoutePolicyConditions: types.RoutePolicyConditions{
								MatchNeighbors: &types.RoutePolicyNeighborMatch{
									Type:      types.RoutePolicyMatchAny,
									Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
								},
								MatchPrefixes: &types.RoutePolicyPrefixMatch{
									Type: types.RoutePolicyMatchAny,
									Prefixes: []types.RoutePolicyPrefix{
										{
											CIDR:         netip.MustParsePrefix(ingressV4Prefix),
											PrefixLenMin: 32,
											PrefixLenMax: 32,
										},
									},
								},
							}},
							Actions: entTypes.ExtendedRoutePolicyActions{RoutePolicyActions: types.RoutePolicyActions{
								RouteAction:    types.RoutePolicyActionAccept,
								AddCommunities: []string{"65535:65281", gracefulShutdownCommunityValue}},
							},
						},
					},
				},
			},
		}
	)

	runServiceTests(t, []svcTestStep{
		{
			name:        "Add service and advertisement - advertise normally",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			frontends:  []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			nodeStatus: NodeReady,
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPolicies,
				ServicePaths:          expectedServicePaths,
			},
		},
		{
			name:       "Update node status - node maintenance, advertise GS community",
			nodeStatus: NodeMaintenance,
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPoliciesWithGSCommunity,
				ServicePaths:          expectedServicePaths,
			},
		},
		{
			name:       "Update node status - node maintenance timeout expired, withdraw",
			nodeStatus: NodeMaintenanceTimeExpired,
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPoliciesWithGSCommunity,
				ServicePaths:          reconciler.ResourceAFPathsMap{},
			},
		},
		{
			name:                "Add maintenance override - force disable maintenance mode, advertise again",
			nodeStatus:          NodeMaintenance,
			maintenanceOverride: &v1.IsovalentBGPMaintenance{Mode: v1.BGPMaintenanceModeDisabled},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPolicies,
				ServicePaths:          expectedServicePaths,
			},
		},
		{
			name:                "Delete maintenance override - withdraw again",
			nodeStatus:          NodeMaintenanceTimeExpired,
			maintenanceOverride: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPoliciesWithGSCommunity,
				ServicePaths:          reconciler.ResourceAFPathsMap{},
			},
		},
		{
			name:       "Update node status - node ready, advertise again",
			nodeStatus: NodeReady,
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPolicies,
				ServicePaths:          expectedServicePaths,
			},
		},
		{
			name:                "Add maintenance override - force maintenance, advertise GS community",
			nodeStatus:          NodeReady,
			maintenanceOverride: &v1.IsovalentBGPMaintenance{Mode: v1.BGPMaintenanceModeCommunity},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPoliciesWithGSCommunity,
				ServicePaths:          expectedServicePaths,
			},
		},
		{
			name:                "Update maintenance override - force maintenance withdrawal",
			nodeStatus:          NodeReady,
			maintenanceOverride: &v1.IsovalentBGPMaintenance{Mode: v1.BGPMaintenanceModeWithdrawal},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPolicies,
				ServicePaths:          reconciler.ResourceAFPathsMap{},
			},
		},
		{
			name:                "Delete maintenance override - advertise again",
			nodeStatus:          NodeReady,
			maintenanceOverride: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerAdvertisements,
				ServiceRoutePolicies:  expectedPolicies,
				ServicePaths:          expectedServicePaths,
			},
		},
	})
}

func runServiceTests(t *testing.T, steps []svcTestStep) {
	// start the test hive
	f := newServiceTestFixture(t)
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})

	// init BGP instance
	testBGPInstance := &ossInstance.BGPInstance{
		Name:   "fake-instance",
		Router: fake.NewEnterpriseFakeRouter(),
	}
	ceeBGPInstance := &EnterpriseBGPInstance{
		Name:   testBGPInstance.Name,
		Router: upgradeRouter(testBGPInstance.Router),
	}
	f.svcReconciler.Init(ceeBGPInstance)
	t.Cleanup(func() {
		f.svcReconciler.Cleanup(ceeBGPInstance)
	})

	for _, tt := range steps {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			// set node status
			f.nodeStatusProvider.SetNodeStatus(tt.nodeStatus)

			// upsert peeConfigs & advertisements
			for _, peerConfig := range tt.peerConfigs {
				f.peerConfigStore.Upsert(peerConfig)
			}
			for _, advert := range tt.advertisements {
				f.advertStore.Upsert(advert)
			}

			// upsert / delete service frontends & backends
			tx := f.db.WriteTxn(f.frontends)
			// delete frontends
			for _, fe := range tt.deleteFrontends {
				_, _, err = f.frontends.Delete(tx, fe)
				req.NoError(err)
			}
			nextBackendRevision := statedb.Revision(1)
			// upsert frontends with backends
			for _, fe := range tt.frontends {
				// set frontend's backends
				for _, be := range tt.backends {
					if fe.Address.IsIPv6() == be.Address.IsIPv6() && fe.Address.Port() == be.Address.Port() {
						fe.Backends = concatBackend(fe.Backends, *be, nextBackendRevision)
						nextBackendRevision++
					}
				}
				_, _, err = f.frontends.Insert(tx, fe)
				req.NoError(err)
			}
			tx.Commit()

			// update node instance config
			desiredConfig := testBGPInstanceConfig.DeepCopy()
			if len(tt.peers) > 0 {
				desiredConfig.Peers = tt.peers
			}
			desiredConfig.Maintenance = tt.maintenanceOverride

			// reconcile twice to validate idempotency
			for range 2 {
				err = f.svcReconciler.Reconcile(context.Background(), EnterpriseReconcileParams{
					BGPInstance:   ceeBGPInstance,
					DesiredConfig: desiredConfig,
					CiliumNode: &v2.CiliumNode{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node1",
						},
					},
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, f.svcReconciler.getMetadata(ceeBGPInstance))

			// validate that advertised paths match expected metadata
			advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
		})
	}
}

func newServiceTestFixture(t *testing.T) *svcTestFixture {
	f := &svcTestFixture{
		peerConfigStore:    store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig](),
		advertStore:        store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement](),
		nodeStatusProvider: newMockNodeStatusProvider(),
	}
	f.hive = ciliumhive.New(
		cell.Module("service-reconciler-test", "Service reconciler test",
			svcrouteconfig.Cell,

			cell.Provide(
				signaler.NewBGPCPSignaler,

				loadbalancer.NewFrontendsTable,
				statedb.RWTable[*loadbalancer.Frontend].ToTable,

				func() *IsovalentAdvertisement {
					return newIsovalentAdvertisement(
						AdvertisementIn{
							Logger:          hivetest.Logger(t),
							PeerConfigStore: f.peerConfigStore,
							AdvertStore:     f.advertStore,
						})
				},
				func() NodeStatusProvider {
					return f.nodeStatusProvider
				},
				func() paramUpgrader {
					return newUpgraderMock(testBGPInstanceConfig)
				},
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableBGPControlPlane: true,
					}
				},
				func() Config {
					return Config{
						SvcHealthCheckingEnabled:           true,
						MaintenanceGracefulShutdownEnabled: true,
						MaintenanceWithdrawTime:            1 * time.Second,
					}
				},
				func() config.Config {
					return config.Config{Enabled: true, StatusReportEnabled: false}
				},
				func() loadbalancer.Config {
					return loadbalancer.Config{}
				},
			),
			cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*loadbalancer.Frontend]) {
				f.db = db
				f.frontends = table
			}),
			cell.Invoke(func(p ServiceReconcilerIn) {
				out := NewServiceReconciler(p)
				f.svcReconciler = out.EnterpriseReconciler.(*ServiceReconciler)
			}),
		),
	)
	return f
}

func newTestBackend(svcName loadbalancer.ServiceName, addr loadbalancer.L3n4Addr, node string, state loadbalancer.BackendState) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		ServiceName: svcName,
		Address:     addr,
		NodeName:    node,
		PortNames:   nil,
		Weight:      0,
		State:       state,
		Source:      source.Kubernetes,
	}
}

func concatBackend(bes loadbalancer.BackendsSeq2, be loadbalancer.Backend, rev statedb.Revision) loadbalancer.BackendsSeq2 {
	return func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
		if !yield(&be, rev) {
			return
		}
		bes(yield)
	}
}

func serviceMetadataEqual(req *require.Assertions, expectedMetadata, runningMetadata ServiceReconcilerMetadata) {
	req.Truef(PeerAdvertisementsEqual(expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements),
		"ServiceAdvertisements mismatch, expected: %v, got: %v", expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements)

	req.Lenf(runningMetadata.ServicePaths, len(expectedMetadata.ServicePaths),
		"ServicePaths length mismatch, expected: %v, got: %v", expectedMetadata.ServicePaths, runningMetadata.ServicePaths)

	for svc, expectedSvcPaths := range expectedMetadata.ServicePaths {
		runningSvcPaths, exists := runningMetadata.ServicePaths[svc]
		req.Truef(exists, "Service not found in running: %v", svc)

		runningFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range runningSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			runningFamilyPaths[family] = pathSet
		}

		expectedFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range expectedSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			expectedFamilyPaths[family] = pathSet
		}

		req.Equal(expectedFamilyPaths, runningFamilyPaths)
	}

	req.Equalf(expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies,
		"ServiceRoutePolicies mismatch, expected: %v, got: %v", expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies)
}

func advertisedPrefixesMatch(req *require.Assertions, bgpInstance *ossInstance.BGPInstance, expectedPaths reconciler.ResourceAFPathsMap) {
	expected := make(map[string]*types.Path)
	for _, svcPaths := range expectedPaths {
		for _, afPaths := range svcPaths {
			for _, path := range afPaths {
				expected[path.NLRI.String()] = path
			}
		}
	}

	advertised := make(map[string]*types.Path)
	routes, err := bgpInstance.Router.GetRoutes(context.Background(), &types.GetRoutesRequest{TableType: types.TableTypeLocRIB})
	req.NoError(err)
	for _, route := range routes.Routes {
		for _, path := range route.Paths {
			advertised[path.NLRI.String()] = path
		}
	}

	expPrefixes := slices.Collect(maps.Keys(expected))
	advPrefixes := slices.Collect(maps.Keys(advertised))
	req.ElementsMatchf(expPrefixes, advPrefixes, "advertised prefixes do not match expected metadata, expected: %v, got: %v", expPrefixes, advPrefixes)
}

type failingFakeRouter struct {
	*fake.EnterpriseFakeRouter
	failPolicyName string
	failPrefix     string
}

func (r *failingFakeRouter) AddRoutePolicyExtended(ctx context.Context, p entTypes.RoutePolicyExtendedRequest) error {
	if p.Policy != nil && p.Policy.Name == r.failPolicyName {
		return errors.New("injected add route policy failure")
	}
	return r.EnterpriseFakeRouter.AddRoutePolicyExtended(ctx, p)
}

func (r *failingFakeRouter) AdvertisePath(ctx context.Context, p types.PathRequest) (types.PathResponse, error) {
	if p.Path != nil && p.Path.NLRI.String() == r.failPrefix {
		return types.PathResponse{}, errors.New("injected advertise path failure")
	}
	return r.FakeRouter.AdvertisePath(ctx, p)
}

func TestServiceReconcilerMetadataPartialFailure(t *testing.T) {
	// runFailedReconcile runs a reconciliation attempt that should fail thanks to passed failingFakeRouter.
	// One aggregated service advertisement is being reconciled here.
	runFailedReconcile := func(t *testing.T, router *failingFakeRouter, initialMetadata ServiceReconcilerMetadata) ServiceReconcilerMetadata {
		t.Helper()
		req := require.New(t)

		f := newServiceTestFixture(t)
		log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
		err := f.hive.Start(log, context.Background())
		req.NoError(err)
		t.Cleanup(func() {
			f.hive.Stop(log, context.Background())
		})

		testBGPInstance := &instance.EnterpriseBGPInstance{
			Name:   "fake-instance",
			Router: router,
		}
		testEnterpriseBGPInstance := &EnterpriseBGPInstance{
			Name:   testBGPInstance.Name,
			Router: router,
		}
		f.svcReconciler.Init(testBGPInstance)
		t.Cleanup(func() {
			f.svcReconciler.Cleanup(testBGPInstance)
		})

		// Upsert peer config and aggregation advertisement
		f.peerConfigStore.Upsert(redPeerConfig)
		f.advertStore.Upsert(redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)))
		f.svcReconciler.setMetadata(testEnterpriseBGPInstance, initialMetadata)

		// Upser service frontend + backend
		frontend := svcLBFrontend(redSvcTPCluster, ingressV4)
		frontend.Backends = concatBackend(frontend.Backends, *newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive), 1)
		tx := f.db.WriteTxn(f.frontends)
		_, _, err = f.frontends.Insert(tx, frontend)
		req.NoError(err)
		tx.Commit()

		// Run reconcile
		err = f.svcReconciler.Reconcile(t.Context(), EnterpriseReconcileParams{
			BGPInstance:   testBGPInstance,
			DesiredConfig: testBGPInstanceConfig,
			CiliumNode:    testCiliumNodeConfig,
		})
		req.Error(err)

		return f.svcReconciler.getMetadata(testEnterpriseBGPInstance)
	}

	// This covers failed route policy replacement:
	// The old policy is removed, new policy addition fails during reconcile,
	// so metadata must not keep the old policy that was removed during partial reconcile.
	t.Run("route policy reconcile failure", func(t *testing.T) {
		req := require.New(t)

		router := &failingFakeRouter{
			EnterpriseFakeRouter: fake.NewEnterpriseFakeRouter(),
			failPolicyName:       redPeer65001v4LBRPName,
		}

		// add pre-existing route policy that will be updated in the reconcile
		err := router.EnterpriseFakeRouter.AddRoutePolicyExtended(t.Context(), entTypes.RoutePolicyExtendedRequest{
			Policy: redPeer65001v4LBRP, // non-aggregation policy, should be replaced with aggregation
		})
		req.NoError(err)

		initialMetadata := ServiceReconcilerMetadata{
			ServicePaths:          make(reconciler.ResourceAFPathsMap),
			ServiceAdvertisements: make(PeerAdvertisements),
			ServiceRoutePolicies: ResourceRoutePolicyMap{
				redSvcKey: {
					redPeer65001v4LBRPName: redPeer65001v4LBRP,
				},
			},
		}
		newMetadata := runFailedReconcile(t, router, initialMetadata)

		// route policy should be removed from metadata as well as router now
		req.Empty(newMetadata.ServiceRoutePolicies[redSvcKey])
		policies, err := router.GetRoutePoliciesExtended(t.Context())
		req.NoError(err)
		req.Empty(policies.Policies)

		// ServiceAdvertisements should not update after failure, FrontendChangesInitialized should be false
		req.Empty(newMetadata.ServiceAdvertisements)
		req.False(newMetadata.FrontendChangesInitialized)
	})

	// This covers failed path replacement:
	// The old path is withdrawn, the replacement advertise fails during reconcile,
	// so metadata must not keep the withdrawn old path after reconcile.
	t.Run("advertise path failure", func(t *testing.T) {
		req := require.New(t)

		router := &failingFakeRouter{
			EnterpriseFakeRouter: fake.NewEnterpriseFakeRouter(),
			failPrefix:           aggregateV4Prefix24, // aggregation prefix will fail during reconcile
		}
		oldPath := types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)) // non-aggregated prefix

		req.NoError(router.EnterpriseFakeRouter.AddRoutePolicyExtended(t.Context(), entTypes.RoutePolicyExtendedRequest{
			Policy: redPeer65001v4LBRP,
		}))
		_, err := router.EnterpriseFakeRouter.AdvertisePath(t.Context(), types.PathRequest{
			Path: oldPath,
		})
		req.NoError(err)

		initialMetadata := ServiceReconcilerMetadata{
			ServicePaths: reconciler.ResourceAFPathsMap{
				redSvcKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						ingressV4Prefix: oldPath,
					},
				},
			},
			ServiceAdvertisements: make(PeerAdvertisements),
			ServiceRoutePolicies: ResourceRoutePolicyMap{
				redSvcKey: {
					redPeer65001v4LBRPName: redPeer65001v4LBRP,
				},
			},
		}
		newMetadata := runFailedReconcile(t, router, initialMetadata)

		// service prefix should be withdrawn from metadata as well as router now
		paths := newMetadata.ServicePaths[redSvcKey][types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast}]
		req.NotContains(paths, ingressV4Prefix)
		req.NotContains(paths, aggregateV4Prefix24)

		routes, err := router.GetRoutes(t.Context(), &types.GetRoutesRequest{TableType: types.TableTypeLocRIB})
		req.NoError(err)
		req.Empty(routes.Routes)

		// ServiceAdvertisements should not update after failure, FrontendChangesInitialized should be false
		req.Empty(newMetadata.ServiceAdvertisements)
		req.False(newMetadata.FrontendChangesInitialized)
	})
}

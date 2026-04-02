// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

var (
	isoClusterConfig = &v1.IsovalentBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "test-bgp-cluster-config",
			Labels: map[string]string{
				"bgp": "dummy_label",
			},
		},
		Spec: v1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"bgp": "rack1",
				},
			},
			BGPInstances: []v1.IsovalentBGPInstance{
				{
					Name:      "instance-1",
					LocalASN:  ptr.To[int64](65001),
					LocalPort: ptr.To[int32](179),
					Peers: []v1.IsovalentBGPPeer{
						{
							Name:        "peer-1",
							PeerAddress: ptr.To[string]("192.168.10.10"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v1.PeerConfigReference{
								Name: "peer-config-1",
							},
						},
						{
							Name:        "peer-2",
							PeerAddress: ptr.To[string]("192.168.10.20"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v1.PeerConfigReference{
								Name: "peer-config-2",
							},
						},
						{
							Name:        "peer-3",
							PeerAddress: ptr.To[string]("192.168.10.30"),
							PeerASN:     ptr.To[int64](65002),
						},
					},
				},
			},
		},
	}
	isoNodeConfigSpec = v1.IsovalentBGPNodeInstance{
		Name:      "instance-1",
		LocalASN:  ptr.To[int64](65001),
		LocalPort: ptr.To[int32](179),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				Name:        "peer-1",
				PeerAddress: ptr.To[string]("192.168.10.10"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config-1",
				},
			},
			{
				Name:        "peer-2",
				PeerAddress: ptr.To[string]("192.168.10.20"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config-2",
				},
			},
			{
				Name:        "peer-3",
				PeerAddress: ptr.To[string]("192.168.10.30"),
				PeerASN:     ptr.To[int64](65002),
			},
		},
	}

	ossClusterConfig = &v2.CiliumBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "test-bgp-cluster-config",
			Labels: map[string]string{
				"bgp": "dummy_label",
			},
		},
		Spec: v2.CiliumBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"bgp": "rack1",
				},
			},
			BGPInstances: []v2.CiliumBGPInstance{
				{
					Name:      "instance-1",
					LocalASN:  ptr.To[int64](65001),
					LocalPort: ptr.To[int32](179),
					Peers: []v2.CiliumBGPPeer{
						{
							Name:        "peer-1",
							PeerAddress: ptr.To[string]("192.168.10.10"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v2.PeerConfigReference{
								Name: "peer-config-1",
							},
						},
						{
							Name:        "peer-2",
							PeerAddress: ptr.To[string]("192.168.10.20"),
							PeerASN:     ptr.To[int64](65002),
							PeerConfigRef: &v2.PeerConfigReference{
								Name: "peer-config-2",
							},
						},
						{
							Name:        "peer-3",
							PeerAddress: ptr.To[string]("192.168.10.30"),
							PeerASN:     ptr.To[int64](65002),
						},
					},
				},
			},
		},
	}
	ossPeerConfigSpec = v2.CiliumBGPPeerConfigSpec{
		Transport: &v2.CiliumBGPTransport{
			PeerPort: ptr.To[int32](179),
		},
		Timers: &v2.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](12),
			HoldTimeSeconds:         ptr.To[int32](9),
			KeepAliveTimeSeconds:    ptr.To[int32](3),
		},
		AuthSecretRef: ptr.To[string]("bgp-secret"),
		GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](12),
		},
		Families: []v2.CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: v2.CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Advertisements: &slimv1.LabelSelector{
					MatchLabels: map[string]slimv1.MatchLabelsValue{
						"bgp": "advert-1",
					},
				},
			},
		},
	}
	isoFamilyWithAdverts = []v1.IsovalentBGPFamilyWithAdverts{
		{
			CiliumBGPFamily: ossPeerConfigSpec.Families[0].CiliumBGPFamily,
			Advertisements:  ossPeerConfigSpec.Families[0].Advertisements,
		},
	}
	isoPeerConfig = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "peer-config-1",
			Labels: map[string]string{
				"bgp": "dummy_label_1",
			},
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ossPeerConfigSpec.Transport.PeerPort,
			},
			Timers:          ossPeerConfigSpec.Timers,
			AuthSecretRef:   ossPeerConfigSpec.AuthSecretRef,
			GracefulRestart: ossPeerConfigSpec.GracefulRestart,
			Families:        isoFamilyWithAdverts,
		},
	}
	ossPeerConfig = &v2.CiliumBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "peer-config-1",
			Labels: map[string]string{
				"bgp": "dummy_label_1",
			},
		},
		Spec: ossPeerConfigSpec,
	}
	isoAdvertPodCIDR = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-pod-cidr",
			Labels: map[string]string{
				"bgp": "advert-1",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				{
					AdvertisementType: "PodCIDR",
					Attributes: &v2.BGPAttributes{
						LocalPreference: ptr.To[int64](99),
					},
				},
				{
					AdvertisementType: "EgressGateway", // should be ignored by mapper
					Attributes: &v2.BGPAttributes{
						LocalPreference: ptr.To[int64](100),
					},
				},
			},
		},
	}
	ossAdvertPodCIDR = &v2.CiliumBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-pod-cidr",
			Labels: map[string]string{
				"bgp": "advert-1",
			},
		},
		Spec: v2.CiliumBGPAdvertisementSpec{
			Advertisements: []v2.BGPAdvertisement{
				{
					AdvertisementType: "PodCIDR",
					Attributes: &v2.BGPAttributes{
						LocalPreference: ptr.To[int64](99),
					},
				},
			},
		},
	}
	isoAdvertIPPool = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-ip-pool",
			Labels: map[string]string{
				"bgp": "advert-2",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				{
					AdvertisementType: "CiliumPodIPPool",
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"pool": "blue",
						},
					},
					Attributes: &v2.BGPAttributes{
						LocalPreference: ptr.To[int64](101),
					},
				},
			},
		},
	}
	ossAdvertIPPool = &v2.CiliumBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-ip-pool",
			Labels: map[string]string{
				"bgp": "advert-2",
			},
		},
		Spec: v2.CiliumBGPAdvertisementSpec{
			Advertisements: []v2.BGPAdvertisement{
				{
					AdvertisementType: "CiliumPodIPPool",
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"pool": "blue",
						},
					},
					Attributes: &v2.BGPAttributes{
						LocalPreference: ptr.To[int64](101),
					},
				},
			},
		},
	}
	isoAdvertService = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-service",
			Labels: map[string]string{
				"bgp": "advert-3",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				{
					AdvertisementType: "Service",
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{
							v2.BGPLoadBalancerIPAddr,
							v2.BGPClusterIPAddr,
							v2.BGPExternalIPAddr,
						},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"service": "nginx",
						},
					},
					Attributes: &v2.BGPAttributes{
						LocalPreference: ptr.To[int64](102),
					},
				},
			},
		},
	}
	ossAdvertService = &v2.CiliumBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "advert-service",
			Labels: map[string]string{
				"bgp": "advert-3",
			},
		},
		Spec: v2.CiliumBGPAdvertisementSpec{
			Advertisements: []v2.BGPAdvertisement{
				{
					AdvertisementType: "Service",
					Service: &v2.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{
							v2.BGPLoadBalancerIPAddr,
							v2.BGPClusterIPAddr,
							v2.BGPExternalIPAddr,
						},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]slimv1.MatchLabelsValue{
							"service": "nginx",
						},
					},
					Attributes: &v2.BGPAttributes{
						LocalPreference: ptr.To[int64](102),
					},
				},
			},
		},
	}
)

func Test_Mapping(t *testing.T) {
	tests := []struct {
		description              string
		isoClusterConfig         *v1.IsovalentBGPClusterConfig
		isoPeerConfig            *v1.IsovalentBGPPeerConfig
		isoAdvert                *v1.IsovalentBGPAdvertisement
		isoNodeConfigOR          *v1.IsovalentBGPNodeConfigOverride
		expectedOSSClusterConfig *v2.CiliumBGPClusterConfig
		expectedOSSPeerConfig    *v2.CiliumBGPPeerConfig
		expectedOSSAdvert        *v2.CiliumBGPAdvertisement
		expectedOSSNodeConfigOR  *v2.CiliumBGPNodeConfigOverride
	}{
		{
			description:              "test cluster config mapping",
			isoClusterConfig:         isoClusterConfig,
			expectedOSSClusterConfig: ossClusterConfig,
		},
		{
			description:           "test peer config mapping",
			isoPeerConfig:         isoPeerConfig,
			expectedOSSPeerConfig: ossPeerConfig,
		},
		{
			description:       "test bgp advertisement - pod cidr",
			isoAdvert:         isoAdvertPodCIDR,
			expectedOSSAdvert: ossAdvertPodCIDR,
		},
		{
			description:       "test bgp advertisement - pod IP pool",
			isoAdvert:         isoAdvertIPPool,
			expectedOSSAdvert: ossAdvertIPPool,
		},
		{
			description:       "test bgp advertisement - service",
			isoAdvert:         isoAdvertService,
			expectedOSSAdvert: ossAdvertService,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := require.New(t)
			f := newFixture(t, ctx, req, fixtureConfig{enableStatusReport: true})

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			// insert enterprise objects
			upsertIsoBGPCC(req, ctx, f, tt.isoClusterConfig)
			upsertIsoBGPPC(req, ctx, f, tt.isoPeerConfig)
			upsertIsoBGPAdvert(req, ctx, f, tt.isoAdvert)
			upsertIsoBGPNodeConfigOR(req, ctx, f, tt.isoNodeConfigOR)

			// check OSS objects are created as expected
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoClusterConfig == nil {
					clusterConfigs, err := f.ossClusterClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Empty(c, clusterConfigs.Items)
					return
				}

				ossClusterConfig, err := f.ossClusterClient.Get(ctx, tt.isoClusterConfig.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				isoClusterConfig, err := f.isoClusterClient.Get(ctx, tt.isoClusterConfig.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, tt.expectedOSSClusterConfig.Name, ossClusterConfig.Name)
				assert.Equal(c, tt.expectedOSSClusterConfig.Labels, ossClusterConfig.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: isoClusterConfig.ResourceVersion}, ossClusterConfig.Annotations)
				assertOwnerReferences(c, ossClusterConfig.OwnerReferences, v1.IsovalentBGPClusterConfigKindDefinition, isoClusterConfig)
				assert.True(c, tt.expectedOSSClusterConfig.Spec.DeepEqual(&ossClusterConfig.Spec))
			}, TestTimeout, 50*time.Millisecond)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoPeerConfig == nil {
					peerConfigs, err := f.ossPeerConfClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Empty(c, peerConfigs.Items)
					return
				}

				ossPeerConfig, err := f.ossPeerConfClient.Get(ctx, tt.isoPeerConfig.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				isoPeerConfig, err := f.isoPeerConfClient.Get(ctx, tt.isoPeerConfig.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, tt.expectedOSSPeerConfig.Name, ossPeerConfig.Name)
				assert.Equal(c, tt.expectedOSSPeerConfig.Labels, ossPeerConfig.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: isoPeerConfig.ResourceVersion}, ossPeerConfig.Annotations)
				assertOwnerReferences(c, ossPeerConfig.OwnerReferences, v1.IsovalentBGPPeerConfigKindDefinition, isoPeerConfig)
				assert.True(c, tt.expectedOSSPeerConfig.Spec.DeepEqual(&ossPeerConfig.Spec))
			}, TestTimeout, 50*time.Millisecond)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoAdvert == nil {
					ossAdverts, err := f.ossAdvertClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Empty(c, ossAdverts.Items)
					return
				}

				ossAdvert, err := f.ossAdvertClient.Get(ctx, tt.isoAdvert.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				isoAdvert, err := f.isoAdvertClient.Get(ctx, tt.isoAdvert.Name, meta_v1.GetOptions{})
				if !assert.NoError(c, err) {
					return
				}

				assert.Equal(c, tt.expectedOSSAdvert.Name, ossAdvert.Name)
				assert.Equal(c, tt.expectedOSSAdvert.Labels, ossAdvert.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: isoAdvert.ResourceVersion}, ossAdvert.Annotations)
				assertOwnerReferences(c, ossAdvert.OwnerReferences, v1.IsovalentBGPAdvertisementKindDefinition, isoAdvert)
				assert.True(c, tt.expectedOSSAdvert.Spec.DeepEqual(&ossAdvert.Spec))
			}, TestTimeout, 50*time.Millisecond)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.isoNodeConfigOR == nil {
					ossNodeConfigs, err := f.ossNodeConfORClient.List(ctx, meta_v1.ListOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Empty(c, ossNodeConfigs.Items)
					return
				}

				ossNodeConfigOR, err := f.ossNodeConfORClient.Get(ctx, tt.isoNodeConfigOR.Name, meta_v1.GetOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}

				assert.Equal(c, tt.expectedOSSNodeConfigOR.Name, ossNodeConfigOR.Name)
				assert.Equal(c, tt.expectedOSSNodeConfigOR.Labels, ossNodeConfigOR.Labels)
				assert.Equal(c, map[string]string{ownerVersionAnnotation: tt.isoNodeConfigOR.ResourceVersion}, ossNodeConfigOR.Annotations)
				assertOwnerReferences(c, ossNodeConfigOR.OwnerReferences, v1.IsovalentBGPNodeConfigOverrideKindDefinition, tt.isoNodeConfigOR)
				assert.True(c, tt.expectedOSSNodeConfigOR.Spec.DeepEqual(&ossNodeConfigOR.Spec))
			}, TestTimeout, 50*time.Millisecond)
		})
	}
}

func assertOwnerReferences(c *assert.CollectT, ownerRefs []meta_v1.OwnerReference, kind string, owner meta_v1.Object) {
	assert.Equal(c, []meta_v1.OwnerReference{
		{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       kind,
			Name:       owner.GetName(),
			UID:        owner.GetUID(),
		},
	}, ownerRefs)
}

func upsertIsoBGPCC(req *require.Assertions, ctx context.Context, f *fixture, bgpcc *v1.IsovalentBGPClusterConfig) {
	if bgpcc == nil {
		return
	}

	prev, err := f.isoClusterClient.Get(ctx, bgpcc.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoClusterClient.Create(ctx, bgpcc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		bgpcc.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoClusterClient.Update(ctx, bgpcc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPPC(req *require.Assertions, ctx context.Context, f *fixture, bgppc *v1.IsovalentBGPPeerConfig) {
	if bgppc == nil {
		return
	}

	prev, err := f.isoPeerConfClient.Get(ctx, bgppc.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoPeerConfClient.Create(ctx, bgppc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		bgppc.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoPeerConfClient.Update(ctx, bgppc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPAdvert(req *require.Assertions, ctx context.Context, f *fixture, bgpAdvert *v1.IsovalentBGPAdvertisement) {
	if bgpAdvert == nil {
		return
	}

	prev, err := f.isoAdvertClient.Get(ctx, bgpAdvert.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoAdvertClient.Create(ctx, bgpAdvert, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		bgpAdvert.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoAdvertClient.Update(ctx, bgpAdvert, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPNodeConfigOR(req *require.Assertions, ctx context.Context, f *fixture, bgpNodeConfigOR *v1.IsovalentBGPNodeConfigOverride) {
	if bgpNodeConfigOR == nil {
		return
	}

	prev, err := f.isoBGPNodeConfORClient.Get(ctx, bgpNodeConfigOR.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoBGPNodeConfORClient.Create(ctx, bgpNodeConfigOR, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		bgpNodeConfigOR.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoBGPNodeConfORClient.Update(ctx, bgpNodeConfigOR, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoVrf(req *require.Assertions, ctx context.Context, f *fixture, vrf *v1alpha1.IsovalentVRF) {
	if vrf == nil {
		return
	}

	prev, err := f.isoVrfClient.Get(ctx, vrf.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoVrfClient.Create(ctx, vrf, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		vrf.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoVrfClient.Update(ctx, vrf, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPVrfConfig(req *require.Assertions, ctx context.Context, f *fixture, vrfConfig *v1alpha1.IsovalentBGPVRFConfig) {
	if vrfConfig == nil {
		return
	}

	prev, err := f.isoBGPVrfClient.Get(ctx, vrfConfig.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoBGPVrfClient.Create(ctx, vrfConfig, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		vrfConfig.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoBGPVrfClient.Update(ctx, vrfConfig, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

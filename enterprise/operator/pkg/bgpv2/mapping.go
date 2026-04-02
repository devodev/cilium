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
	"errors"
	"maps"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// ownerVersionAnnotation is used to track the last reconciled version of the owner (parent) CRD object
	ownerVersionAnnotation = annotation.ConfigPrefix + "/owner-version"
)

func (m *BGPResourceMapper) reconcileMappings(ctx context.Context) error {
	// we try to reconcile all resources, even if some fail. Since each resource is independent,
	// we can continue with the next resource if one fails.

	err := m.mapClusterConfigs(ctx)
	if err != nil {
		m.metrics.ReconcileErrorsTotal.WithLabelValues(v2.BGPCCKindDefinition).Inc()
	}

	rErr := m.mapPeerConfigs(ctx)
	if rErr != nil {
		err = errors.Join(err, rErr)
		m.metrics.ReconcileErrorsTotal.WithLabelValues(v2.BGPPCKindDefinition).Inc()
	}

	rErr = m.mapAdvertisements(ctx)
	if rErr != nil {
		err = errors.Join(err, rErr)
		m.metrics.ReconcileErrorsTotal.WithLabelValues(v2.BGPAKindDefinition).Inc()
	}

	rErr = m.mapNodeConfigOverrides(ctx)
	if rErr != nil {
		err = errors.Join(err, rErr)
		m.metrics.ReconcileErrorsTotal.WithLabelValues(v2.BGPNCOKindDefinition).Inc()
	}

	return err
}

func (m *BGPResourceMapper) mapClusterConfigs(ctx context.Context) error {
	entClusterConfigs, err := m.clusterConfig.List()
	if err != nil {
		return err
	}

	for _, entClusterConfig := range entClusterConfigs {
		err = errors.Join(err, m.mapClusterConfig(ctx, entClusterConfig))
	}
	return err
}

func (m *BGPResourceMapper) mapClusterConfig(ctx context.Context, entClusterConfig *v1.IsovalentBGPClusterConfig) error {
	expectedOSSClusterConfig := createOSSClusterConfig(entClusterConfig)
	runningOSSClusterConfig, exists, err := m.ossClusterConfigStore.GetByKey(resource.Key{
		Name:      entClusterConfig.GetName(),
		Namespace: entClusterConfig.GetNamespace(),
	})
	if err != nil {
		return err
	}

	clusterConfigClientSet := m.clientSet.CiliumV2().CiliumBGPClusterConfigs()

	switch {
	case exists && expectedOSSClusterConfig.Spec.DeepEqual(&runningOSSClusterConfig.Spec) &&
		maps.Equal(expectedOSSClusterConfig.Labels, runningOSSClusterConfig.Labels) &&
		maps.Equal(expectedOSSClusterConfig.Annotations, runningOSSClusterConfig.Annotations) &&
		reflect.DeepEqual(expectedOSSClusterConfig.OwnerReferences, runningOSSClusterConfig.OwnerReferences):
		return nil

	case exists:
		// update
		runningOSSClusterConfig.Spec = expectedOSSClusterConfig.Spec
		runningOSSClusterConfig.Labels = expectedOSSClusterConfig.Labels
		runningOSSClusterConfig.Annotations = expectedOSSClusterConfig.Annotations
		runningOSSClusterConfig.OwnerReferences = expectedOSSClusterConfig.OwnerReferences

		_, err = clusterConfigClientSet.Update(ctx, runningOSSClusterConfig, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = clusterConfigClientSet.Create(ctx, expectedOSSClusterConfig, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.Debug("OSS BGP Cluster Config updated", logfields.Name, entClusterConfig.GetName())

	return nil
}

func (m *BGPResourceMapper) mapPeerConfigs(ctx context.Context) error {
	entPeerConfigs, err := m.peerConfig.List()
	if err != nil {
		return err
	}

	for _, entPeerConfig := range entPeerConfigs {
		err = errors.Join(err, m.mapPeerConfig(ctx, entPeerConfig))
	}
	return err
}

func (m *BGPResourceMapper) mapPeerConfig(ctx context.Context, entPeerConfig *v1.IsovalentBGPPeerConfig) error {
	expectedOSSPeerConfig := createOSSPeerConfig(entPeerConfig)
	runningOSSPeerConfig, exists, err := m.ossPeerConfigStore.GetByKey(resource.Key{
		Name:      entPeerConfig.GetName(),
		Namespace: entPeerConfig.GetNamespace(),
	})
	if err != nil {
		return err
	}

	peerConfigClientSet := m.clientSet.CiliumV2().CiliumBGPPeerConfigs()

	switch {
	case exists && expectedOSSPeerConfig.Spec.DeepEqual(&runningOSSPeerConfig.Spec) &&
		maps.Equal(expectedOSSPeerConfig.Labels, runningOSSPeerConfig.Labels) &&
		maps.Equal(expectedOSSPeerConfig.Annotations, runningOSSPeerConfig.Annotations) &&
		reflect.DeepEqual(expectedOSSPeerConfig.OwnerReferences, runningOSSPeerConfig.OwnerReferences):
		return nil

	case exists:
		// update
		runningOSSPeerConfig.Spec = expectedOSSPeerConfig.Spec
		runningOSSPeerConfig.Labels = expectedOSSPeerConfig.Labels
		runningOSSPeerConfig.Annotations = expectedOSSPeerConfig.Annotations
		runningOSSPeerConfig.OwnerReferences = expectedOSSPeerConfig.OwnerReferences

		_, err = peerConfigClientSet.Update(ctx, runningOSSPeerConfig, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = peerConfigClientSet.Create(ctx, expectedOSSPeerConfig, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.Debug("OSS BGP Peer Config updated", logfields.Name, entPeerConfig.GetName())

	return nil
}

func (m *BGPResourceMapper) mapAdvertisements(ctx context.Context) error {
	entAdvertisements, err := m.advertisements.List()
	if err != nil {
		return err
	}

	for _, entAdvertisement := range entAdvertisements {
		err = errors.Join(err, m.mapAdvertisement(ctx, entAdvertisement))
	}
	return err
}

func (m *BGPResourceMapper) mapAdvertisement(ctx context.Context, entAdvertisement *v1.IsovalentBGPAdvertisement) error {
	expectedOSSAdvertisement := createOSSAdvertisement(entAdvertisement)
	runningOSSAdvertisement, exists, err := m.ossAdvertStore.GetByKey(resource.Key{
		Name:      entAdvertisement.GetName(),
		Namespace: entAdvertisement.GetNamespace(),
	})
	if err != nil {
		return err
	}

	advertisementClientSet := m.clientSet.CiliumV2().CiliumBGPAdvertisements()

	switch {
	case exists && expectedOSSAdvertisement.Spec.DeepEqual(&runningOSSAdvertisement.Spec) &&
		maps.Equal(expectedOSSAdvertisement.Labels, runningOSSAdvertisement.Labels) &&
		maps.Equal(expectedOSSAdvertisement.Annotations, runningOSSAdvertisement.Annotations) &&
		reflect.DeepEqual(expectedOSSAdvertisement.OwnerReferences, runningOSSAdvertisement.OwnerReferences):
		return nil

	case exists:
		// update
		runningOSSAdvertisement.Spec = expectedOSSAdvertisement.Spec
		runningOSSAdvertisement.Labels = expectedOSSAdvertisement.Labels
		runningOSSAdvertisement.Annotations = expectedOSSAdvertisement.Annotations
		runningOSSAdvertisement.OwnerReferences = expectedOSSAdvertisement.OwnerReferences

		_, err = advertisementClientSet.Update(ctx, runningOSSAdvertisement, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = advertisementClientSet.Create(ctx, expectedOSSAdvertisement, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.Debug("OSS BGP Advertisement updated", logfields.Name, entAdvertisement.GetName())

	return nil
}

func (m *BGPResourceMapper) mapNodeConfigOverrides(ctx context.Context) error {
	entNodeConfigOverrides, err := m.nodeConfigOverride.List()
	if err != nil {
		return err
	}

	for _, entNodeConfigOverride := range entNodeConfigOverrides {
		err = errors.Join(err, m.mapNodeConfigOverride(ctx, entNodeConfigOverride))
	}
	return err
}

func (m *BGPResourceMapper) mapNodeConfigOverride(ctx context.Context, entNodeConfigOverride *v1.IsovalentBGPNodeConfigOverride) error {
	expectedOSSNodeConfigOverride := createOSSNodeConfigOverride(entNodeConfigOverride)
	runningOSSNodeConfigOverride, exists, err := m.ossNodeConfigOverrideStore.GetByKey(resource.Key{
		Name:      entNodeConfigOverride.GetName(),
		Namespace: entNodeConfigOverride.GetNamespace(),
	})
	if err != nil {
		return err
	}

	nodeConfigOverrideClientSet := m.clientSet.CiliumV2().CiliumBGPNodeConfigOverrides()

	switch {
	case exists && expectedOSSNodeConfigOverride.Spec.DeepEqual(&runningOSSNodeConfigOverride.Spec) &&
		maps.Equal(expectedOSSNodeConfigOverride.Labels, runningOSSNodeConfigOverride.Labels) &&
		maps.Equal(expectedOSSNodeConfigOverride.Annotations, runningOSSNodeConfigOverride.Annotations) &&
		reflect.DeepEqual(expectedOSSNodeConfigOverride.OwnerReferences, runningOSSNodeConfigOverride.OwnerReferences):
		return nil

	case exists:
		// update
		runningOSSNodeConfigOverride.Spec = expectedOSSNodeConfigOverride.Spec
		runningOSSNodeConfigOverride.Labels = expectedOSSNodeConfigOverride.Labels
		runningOSSNodeConfigOverride.Annotations = expectedOSSNodeConfigOverride.Annotations
		runningOSSNodeConfigOverride.OwnerReferences = expectedOSSNodeConfigOverride.OwnerReferences

		_, err = nodeConfigOverrideClientSet.Update(ctx, runningOSSNodeConfigOverride, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

	default:
		// create new resource
		_, err = nodeConfigOverrideClientSet.Create(ctx, expectedOSSNodeConfigOverride, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	m.logger.Debug("OSS BGP Node Config Override updated", logfields.Name, entNodeConfigOverride.GetName())

	return nil
}

func createOSSClusterConfig(entClusterConfig *v1.IsovalentBGPClusterConfig) *v2.CiliumBGPClusterConfig {
	newOSSClusterConfig := &v2.CiliumBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entClusterConfig.GetName(),
			Namespace:   entClusterConfig.GetNamespace(),
			Labels:      entClusterConfig.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entClusterConfig.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       v1.IsovalentBGPClusterConfigKindDefinition,
					Name:       entClusterConfig.GetName(),
					UID:        entClusterConfig.GetUID(),
				},
			},
		},
		Spec: v2.CiliumBGPClusterConfigSpec{
			NodeSelector: entClusterConfig.Spec.NodeSelector,
		},
	}

	for _, bgpInstance := range entClusterConfig.Spec.BGPInstances {
		ossBGPInstance := v2.CiliumBGPInstance{
			Name:      bgpInstance.Name,
			LocalASN:  bgpInstance.LocalASN,
			LocalPort: bgpInstance.LocalPort,
		}

		for _, peer := range bgpInstance.Peers {
			p := v2.CiliumBGPPeer{
				Name:        peer.Name,
				PeerAddress: peer.PeerAddress,
				PeerASN:     peer.PeerASN,
			}
			// only the DefaultGateway auto-discovery mode can be mapped into the OSS resource
			if peer.AutoDiscovery != nil && peer.AutoDiscovery.Mode == v1.BGPADDefaultGateway {
				p.AutoDiscovery = &v2.BGPAutoDiscovery{
					Mode:           v2.BGPDefaultGatewayMode,
					DefaultGateway: peer.AutoDiscovery.DefaultGateway,
				}
			}
			if peer.PeerConfigRef != nil {
				p.PeerConfigRef = &v2.PeerConfigReference{
					Name: peer.PeerConfigRef.Name,
				}
			}
			ossBGPInstance.Peers = append(ossBGPInstance.Peers, p)
		}

		newOSSClusterConfig.Spec.BGPInstances = append(newOSSClusterConfig.Spec.BGPInstances, ossBGPInstance)
	}

	return newOSSClusterConfig
}

func createOSSPeerConfig(entPeerConfig *v1.IsovalentBGPPeerConfig) *v2.CiliumBGPPeerConfig {
	families := []v2.CiliumBGPFamilyWithAdverts{}
	for _, family := range entPeerConfig.Spec.Families {
		families = append(families, v2.CiliumBGPFamilyWithAdverts{
			CiliumBGPFamily: family.CiliumBGPFamily,
			Advertisements:  family.Advertisements,
		})
	}
	newOSSPeerConfig := &v2.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entPeerConfig.GetName(),
			Namespace:   entPeerConfig.GetNamespace(),
			Labels:      entPeerConfig.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entPeerConfig.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       v1.IsovalentBGPPeerConfigKindDefinition,
					Name:       entPeerConfig.GetName(),
					UID:        entPeerConfig.GetUID(),
				},
			},
		},
		Spec: v2.CiliumBGPPeerConfigSpec{
			Timers:          entPeerConfig.Spec.Timers,
			AuthSecretRef:   entPeerConfig.Spec.AuthSecretRef,
			GracefulRestart: entPeerConfig.Spec.GracefulRestart,
			EBGPMultihop:    entPeerConfig.Spec.EBGPMultihop,
			Families:        families,
		},
	}
	if entPeerConfig.Spec.Transport != nil {
		newOSSPeerConfig.Spec.Transport = &v2.CiliumBGPTransport{
			PeerPort:        entPeerConfig.Spec.Transport.PeerPort,
			SourceInterface: entPeerConfig.Spec.Transport.SourceInterface,
		}
	}

	return newOSSPeerConfig
}

func createOSSAdvertisement(entAdvertisement *v1.IsovalentBGPAdvertisement) *v2.CiliumBGPAdvertisement {
	newOSSAdvertisement := &v2.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entAdvertisement.GetName(),
			Namespace:   entAdvertisement.GetNamespace(),
			Labels:      entAdvertisement.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entAdvertisement.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       v1.IsovalentBGPAdvertisementKindDefinition,
					Name:       entAdvertisement.GetName(),
					UID:        entAdvertisement.GetUID(),
				},
			},
		},
		Spec: v2.CiliumBGPAdvertisementSpec{
			Advertisements: []v2.BGPAdvertisement{},
		},
	}

	for _, advert := range entAdvertisement.Spec.Advertisements {
		advertType := ossAdvertTypeFromEnt(advert.AdvertisementType)
		if advertType == "unknown" {
			// skip enterprise advertisement types that are not supported in OSS
			continue
		}

		ossAdvert := v2.BGPAdvertisement{
			AdvertisementType: advertType,
			Service:           ossServiceOptionFromEnt(advert.Service),
			Interface:         advert.Interface,
			Selector:          advert.Selector,
			Attributes:        advert.Attributes,
		}
		newOSSAdvertisement.Spec.Advertisements = append(newOSSAdvertisement.Spec.Advertisements, ossAdvert)
	}

	return newOSSAdvertisement
}

func ossServiceOptionFromEnt(advert *v1.BGPServiceOptions) *v2.BGPServiceOptions {
	if advert == nil {
		return nil
	}

	return &v2.BGPServiceOptions{
		Addresses: advert.Addresses,
	}
}

func ossAdvertTypeFromEnt(advert v1.IsovalentBGPAdvertType) v2.BGPAdvertisementType {
	switch advert {
	case v1.BGPPodCIDRAdvert:
		return v2.BGPPodCIDRAdvert
	case v1.BGPServiceAdvert:
		return v2.BGPServiceAdvert
	case v1.BGPCiliumPodIPPoolAdvert:
		return v2.BGPCiliumPodIPPoolAdvert
	case v1.BGPInterfaceAdvert:
		return v2.BGPInterfaceAdvert
	}
	return "unknown"
}

func createOSSNodeConfigOverride(entNodeConfigOverride *v1.IsovalentBGPNodeConfigOverride) *v2.CiliumBGPNodeConfigOverride {
	newOSSNodeConfigOverride := &v2.CiliumBGPNodeConfigOverride{
		ObjectMeta: metav1.ObjectMeta{
			Name:        entNodeConfigOverride.GetName(),
			Namespace:   entNodeConfigOverride.GetNamespace(),
			Labels:      entNodeConfigOverride.GetLabels(),
			Annotations: map[string]string{ownerVersionAnnotation: entNodeConfigOverride.ResourceVersion},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       v1.IsovalentBGPNodeConfigOverrideKindDefinition,
					Name:       entNodeConfigOverride.GetName(),
					UID:        entNodeConfigOverride.GetUID(),
				},
			},
		},
	}

	for _, bgpInstance := range entNodeConfigOverride.Spec.BGPInstances {
		ossBGPInstance := v2.CiliumBGPNodeConfigInstanceOverride{
			Name:      bgpInstance.Name,
			RouterID:  bgpInstance.RouterID,
			LocalPort: bgpInstance.LocalPort,
			LocalASN:  bgpInstance.LocalASN,
		}

		for _, peer := range bgpInstance.Peers {
			ossBGPInstance.Peers = append(ossBGPInstance.Peers, v2.CiliumBGPNodeConfigPeerOverride{
				Name:         peer.Name,
				LocalAddress: peer.LocalAddress,
				LocalPort:    peer.LocalPort,
			})
		}

		newOSSNodeConfigOverride.Spec.BGPInstances = append(newOSSNodeConfigOverride.Spec.BGPInstances, ossBGPInstance)
	}

	return newOSSNodeConfigOverride
}

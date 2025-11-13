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
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	ceeTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// PeerID identifies the peer within the instance.
type PeerID struct {
	Name    string
	Address string
}

type (
	// PeerAdvertisements is a map of peer ID to its family advertisements
	// This is the top level map that is returned to the consumer with requested advertisements.
	PeerAdvertisements map[PeerID]FamilyAdvertisements

	// VRFAdvertisements is a map of VRF name / private network name to its family advertisements
	VRFAdvertisements map[string]FamilyAdvertisements

	// FamilyAdvertisements is a map of address family to its advertisements
	FamilyAdvertisements map[v2.CiliumBGPFamily][]v1.BGPAdvertisement
)

// AdvertPathAttributes holds BGP path attributes configured in advertisements.
type AdvertPathAttributes struct {
	Communities      []uint32
	LargeCommunities []*bgp.LargeCommunity
	LocalPreference  *uint32
}

// FamilyAdvertPathAttributes is a map of BGP path attributes configured in advertisements per BGP family.
type FamilyAdvertPathAttributes map[v2.CiliumBGPFamily]*AdvertPathAttributes

type AdvertisementIn struct {
	cell.In

	Group           job.Group
	Logger          *slog.Logger
	Config          config.Config
	PeerConfigStore store.BGPCPResourceStore[*v1.IsovalentBGPPeerConfig]
	AdvertStore     store.BGPCPResourceStore[*v1.IsovalentBGPAdvertisement]
	VRFConfigStore  store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]
}

type IsovalentAdvertisement struct {
	logger *slog.Logger

	// we want to trigger BGP reconciliation if there is a change detected in any
	// of these resources, so we use BGPCPResourceStore for them
	peerConfigs store.BGPCPResourceStore[*v1.IsovalentBGPPeerConfig]
	adverts     store.BGPCPResourceStore[*v1.IsovalentBGPAdvertisement]
	vrfs        store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]
}

func newIsovalentAdvertisement(p AdvertisementIn) *IsovalentAdvertisement {
	pa := &IsovalentAdvertisement{
		logger:      p.Logger.With(types.ReconcilerLogField, "Advertisement"),
		peerConfigs: p.PeerConfigStore,
		adverts:     p.AdvertStore,
		vrfs:        p.VRFConfigStore,
	}
	// Check if enterprise BGP control plane is enabled
	if !p.Config.Enabled {
		return pa
	}
	return pa
}

// GetConfiguredPeerAdvertisements can be called to get all configured advertisements of given BGPAdvertisementType for each peer.
// Advertisements are selected based on below criteria:
// Each peer is selected from the BGP node instance configuration. For each peer, the peer configuration is fetched
// from local store.
// Peer configuration contains the list of families and the advertisement selector.
// We iterate over all advertisements ( available from local store ), select only those that match the advertisement
// selector of the family.
// Information of peer -> family -> advertisements is returned to the consumer.
// Linear scan [ Peers ] - O(n) ( number of peers )
// Linear scan [ Families ] - O(m) ( max 2 )
// Linear scan [ Advertisements ] - O(k) ( number of advertisements - 3-4 types, which is again filtered)
func (p *IsovalentAdvertisement) GetConfiguredPeerAdvertisements(conf *v1.IsovalentBGPNodeInstance, selectAdvertTypes ...v1.IsovalentBGPAdvertType) (PeerAdvertisements, error) {
	result := make(PeerAdvertisements)
	l := p.logger.With(types.InstanceLogField, conf.Name)
	for _, peer := range conf.Peers {
		lp := l.With(types.PeerLogField, peer.Name)

		if peer.PeerConfigRef == nil {
			lp.Debug("Peer config ref not set, skipping advertisement check")
			continue
		}

		peerConfig, exist, err := p.peerConfigs.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
		if err != nil {
			if errors.Is(err, store.ErrStoreUninitialized) {
				lp.Error("BUG: Peer config store is not initialized")
			}
			return nil, err
		}

		if !exist {
			lp.Debug("Peer config not found, skipping advertisement check")
			continue
		}

		peerAdverts, err := p.getPeerAdvertisements(peerConfig, selectAdvertTypes...)
		if err != nil {
			return nil, err
		}
		id := PeerID{
			Name:    peer.Name,
			Address: ptr.Deref(peer.PeerAddress, ""),
		}
		result[id] = peerAdverts
	}
	return result, nil
}

func (p *IsovalentAdvertisement) getPeerAdvertisements(peerConfig *v1.IsovalentBGPPeerConfig, selectAdvertTypes ...v1.IsovalentBGPAdvertType) (FamilyAdvertisements, error) {
	result := make(map[v2.CiliumBGPFamily][]v1.BGPAdvertisement)

	for _, family := range peerConfig.Spec.Families {
		advert, err := p.getFamilyAdvertisements(family, selectAdvertTypes...)
		if err != nil {
			return result, err
		}
		result[family.CiliumBGPFamily] = advert
	}
	return result, nil
}

func (p *IsovalentAdvertisement) getFamilyAdvertisements(family v1.IsovalentBGPFamilyWithAdverts, selectAdvertTypes ...v1.IsovalentBGPAdvertType) ([]v1.BGPAdvertisement, error) {
	// get all advertisement CRD objects.
	advertResources, err := p.adverts.List()
	if err != nil {
		return nil, err
	}

	// select only label selected advertisements for the family
	selectedAdvertResources, err := p.familySelectedAdvertisements(family, advertResources)
	if err != nil {
		return nil, err
	}

	// create selectTypeSet for easier lookup
	selectTypesSet := sets.New[string]()
	for _, selectType := range selectAdvertTypes {
		selectTypesSet.Insert(string(selectType))
	}

	var selectedAdvertisements []v1.BGPAdvertisement
	// select advertisements requested by the consumer
	for _, advertResource := range selectedAdvertResources {
		for _, advert := range advertResource.Spec.Advertisements {
			// check if the advertisement type is in the selectType set
			if selectTypesSet.Has(string(advert.AdvertisementType)) {
				selectedAdvertisements = append(selectedAdvertisements, advert)
			}
		}
	}

	return selectedAdvertisements, nil
}

func (p *IsovalentAdvertisement) familySelectedAdvertisements(family v1.IsovalentBGPFamilyWithAdverts, adverts []*v1.IsovalentBGPAdvertisement) ([]*v1.IsovalentBGPAdvertisement, error) {
	var result []*v1.IsovalentBGPAdvertisement
	advertSelector, err := slim_metav1.LabelSelectorAsSelector(family.Advertisements)
	if err != nil {
		return nil, err
	}

	for _, advert := range adverts {
		if advertSelector.Matches(labels.Set(advert.Labels)) {
			result = append(result, advert)
		}
	}
	return result, nil
}

func (p *IsovalentAdvertisement) GetConfiguredVRFAdvertisements(conf *v1.IsovalentBGPNodeInstance, selectAdvertTypes ...v1.IsovalentBGPAdvertType) (VRFAdvertisements, error) {
	result := make(VRFAdvertisements)
	l := p.logger.With(types.InstanceLogField, conf.Name)

	for _, vrf := range conf.VRFs {
		var (
			key string
			log *slog.Logger
		)
		if vrf.VRFRef != nil {
			key = *vrf.VRFRef
			log = l.With(entTypes.VRFLogField, key)
		} else if vrf.PrivateNetworkRef != nil {
			key = vrf.PrivateNetworkRef.Name
			log = l.With(logfields.ClusterwidePrivateNetwork, key)
		} else {
			l.Debug("VRFRef nor PrivateNetworkRef set, skipping advertisement check")
			continue
		}

		if vrf.ConfigRef == nil {
			log.Debug("VRF config key not set, skipping advertisement check")
			continue
		}
		vrfConfig, exist, err := p.vrfs.GetByKey(resource.Key{Name: *vrf.ConfigRef})
		if err != nil {
			if errors.Is(err, store.ErrStoreUninitialized) {
				log.Debug("VRF config store is not initialized")
			}
			return nil, err
		}
		if !exist {
			log.Debug("VRF config not found, skipping advertisement check")
			continue
		}

		vrfAdverts, err := p.getVRFAdvertisements(vrfConfig, selectAdvertTypes...)
		if err != nil {
			return nil, err
		}
		result[key] = vrfAdverts
	}
	return result, nil
}

func (p *IsovalentAdvertisement) getVRFAdvertisements(vrfConfig *v1alpha1.IsovalentBGPVRFConfig, selectAdvertTypes ...v1.IsovalentBGPAdvertType) (FamilyAdvertisements, error) {
	result := make(map[v2.CiliumBGPFamily][]v1.BGPAdvertisement)

	for _, family := range vrfConfig.Spec.Families {
		v1Family := toV1FamilyWithAdverts(family)
		advert, err := p.getFamilyAdvertisements(v1Family, selectAdvertTypes...)
		if err != nil {
			return result, err
		}
		result[v1Family.CiliumBGPFamily] = advert
	}
	return result, nil
}

func PeerAdvertisementsEqual(first, second PeerAdvertisements) bool {
	if len(first) != len(second) {
		return false
	}

	for peer, peerAdverts := range first {
		if !FamilyAdvertisementsEqual(peerAdverts, second[peer]) {
			return false
		}
	}
	return true
}

func VRFAdvertisementsEqual(first, second VRFAdvertisements) bool {
	if len(first) != len(second) {
		return false
	}

	for vrf, vrfAdverts := range first {
		if !FamilyAdvertisementsEqual(vrfAdverts, second[vrf]) {
			return false
		}
	}
	return true
}

func FamilyAdvertisementsEqual(first, second FamilyAdvertisements) bool {
	if len(first) != len(second) {
		return false
	}

	for family, familyAdverts := range first {
		otherFamilyAdverts, exist := second[family]
		if !exist || len(familyAdverts) != len(otherFamilyAdverts) {
			return false
		}

		sort.Slice(familyAdverts, func(i, j int) bool {
			return familyAdverts[i].AdvertisementType < familyAdverts[j].AdvertisementType
		})

		sort.Slice(otherFamilyAdverts, func(i, j int) bool {
			return otherFamilyAdverts[i].AdvertisementType < otherFamilyAdverts[j].AdvertisementType
		})

		for i, advert := range familyAdverts {
			if !advert.DeepEqual(&otherFamilyAdverts[i]) {
				return false
			}
		}
	}
	return true
}

// GetFamilyAdvertPathAttributes aggregates BGP path attributes from all provided BGP advertisements per IP family.
func GetFamilyAdvertPathAttributes(familyAdverts FamilyAdvertisements) (FamilyAdvertPathAttributes, error) {
	res := make(FamilyAdvertPathAttributes, len(familyAdverts))
	for family, adverts := range familyAdverts {
		pathAttrs, err := GetAdvertPathAttributes(adverts)
		if err != nil {
			return nil, err
		}
		res[family] = pathAttrs
	}
	return res, nil
}

// GetAdvertPathAttributes aggregates BGP path attributes from all provided BGP advertisements.
// Communities and large communities are deduplicated and sorted, and conflicting local preference values
// resolve to the highest value to match the route-policy merge behavior.
func GetAdvertPathAttributes(adverts []v1.BGPAdvertisement) (*AdvertPathAttributes, error) {
	res := &AdvertPathAttributes{}
	communitiesSet := sets.New[uint32]()
	largeCommunitiesSet := sets.New[string]()

	for _, advert := range adverts {
		if advert.Attributes != nil {
			if advert.Attributes.Communities != nil {
				for _, standard := range advert.Attributes.Communities.Standard {
					val, err := ceeTypes.ParseCommunity(string(standard))
					if err != nil {
						return nil, fmt.Errorf("failed parsing community value '%s': %w", standard, err)
					}
					communitiesSet.Insert(val)
				}
				for _, wellKnown := range advert.Attributes.Communities.WellKnown {
					val, ok := bgp.WellKnownCommunityValueMap[string(wellKnown)]
					if !ok {
						return nil, fmt.Errorf("unknown well-known community value '%s'", wellKnown)
					}
					communitiesSet.Insert(uint32(val))
				}
				for _, large := range advert.Attributes.Communities.Large {
					val, err := bgp.ParseLargeCommunity(string(large))
					if err != nil {
						return nil, fmt.Errorf("failed parsing large community value '%s': %w", large, err)
					}
					if !largeCommunitiesSet.Has(string(large)) {
						largeCommunitiesSet.Insert(string(large))
						res.LargeCommunities = append(res.LargeCommunities, val)
					}
				}
			}
			if advert.Attributes.LocalPreference != nil {
				if *advert.Attributes.LocalPreference < 0 || *advert.Attributes.LocalPreference > math.MaxUint32 {
					return nil, fmt.Errorf("invalid local preference value %d", *advert.Attributes.LocalPreference)
				}
				lp := uint32(*advert.Attributes.LocalPreference)
				if res.LocalPreference == nil || lp > *res.LocalPreference {
					res.LocalPreference = &lp
				}
			}
		}
	}

	// sort resulting deduplicated communities
	res.Communities = communitiesSet.UnsortedList()
	slices.Sort(res.Communities)

	// sort resulting large communities
	slices.SortFunc(res.LargeCommunities, func(a, b *bgp.LargeCommunity) int {
		if c := cmp.Compare(a.ASN, b.ASN); c != 0 {
			return c
		}
		if c := cmp.Compare(a.LocalData1, b.LocalData1); c != 0 {
			return c
		}
		return cmp.Compare(a.LocalData2, b.LocalData2)
	})

	return res, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// IsovalentBGPAdvertType defines type of advertisement.
//
// Note list of supported advertisements is not exhaustive and can be extended in the future.
// Consumer of this API should be able to handle unknown values.
//
// +kubebuilder:validation:Enum=PodCIDR;CiliumPodIPPool;Service;Interface;EgressGateway;SRv6LocatorPool;PrivateNetwork
type IsovalentBGPAdvertType string

const (
	// BGPEGWAdvert is advertisement of egress gateway.
	BGPEGWAdvert IsovalentBGPAdvertType = "EgressGateway"

	// BGPSRv6LocatorPoolAdvert is advertisement of SRv6 locator pool routes.
	BGPSRv6LocatorPoolAdvert IsovalentBGPAdvertType = "SRv6LocatorPool"

	// BGPPodCIDRAdvert when configured, Cilium will advertise pod CIDRs to BGP peers.
	BGPPodCIDRAdvert IsovalentBGPAdvertType = "PodCIDR"

	// BGPCiliumPodIPPoolAdvert when configured, Cilium will advertise prefixes from CiliumPodIPPools to BGP peers.
	BGPCiliumPodIPPoolAdvert IsovalentBGPAdvertType = "CiliumPodIPPool"

	// BGPServiceAdvert when configured, Cilium will advertise service related routes to BGP peers.
	BGPServiceAdvert IsovalentBGPAdvertType = "Service"

	// BGPInterfaceAdvert when configured, Cilium will advertise IPs applied on the configured local interface.
	BGPInterfaceAdvert IsovalentBGPAdvertType = "Interface"

	// BGPPrivateNetworkAdvert when configured, Cilium will advertise private network related routes to BGP peers.
	BGPPrivateNetworkAdvert IsovalentBGPAdvertType = "PrivateNetwork"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgpadvertisement",path="isovalentbgpadvertisements",scope="Cluster",shortName={ibgpadvert}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// IsovalentBGPAdvertisement is the Schema for the isovalentbgpadvertisements API
type IsovalentBGPAdvertisement struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec IsovalentBGPAdvertisementSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPAdvertisementList contains a list of IsovalentBGPAdvertisement
type IsovalentBGPAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPAdvertisement.
	Items []IsovalentBGPAdvertisement `json:"items"`
}

type IsovalentBGPAdvertisementSpec struct {
	// Advertisements is a list of BGP advertisements.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Advertisements []BGPAdvertisement `json:"advertisements"`
}

// BGPAdvertisement defines which routes Cilium should advertise to BGP peers.
// Optionally, additional attributes can be set to the advertised routes.
//
// +kubebuilder:validation:XValidation:rule="self.advertisementType != 'Service' || has(self.service)", message="service field is required for the 'Service' advertisementType"
// +kubebuilder:validation:XValidation:rule="self.advertisementType == 'Service' || !has(self.service)", message="service field is not allowed for non-'Service' advertisementType"
// +kubebuilder:validation:XValidation:rule="self.advertisementType != 'Interface' || has(self.interface)", message="interface field is required for the 'Interface' advertisementType"
// +kubebuilder:validation:XValidation:rule="self.advertisementType == 'Interface' || !has(self.interface)", message="interface field is not allowed for non-'Interface' advertisementType"
// +kubebuilder:validation:XValidation:rule="self.advertisementType != 'PodCIDR' || !has(self.selector)", message="selector field is not allowed for the 'PodCIDR' advertisementType"
// +kubebuilder:validation:XValidation:rule="self.advertisementType != 'PrivateNetwork' || !has(self.attributes) || !has(self.attributes.asPathPrepend)", message="asPathPrepend cannot be used with the 'PrivateNetwork' advertisementType"
type BGPAdvertisement struct {
	// AdvertisementType defines type of advertisement which has to be advertised.
	//
	// +kubebuilder:validation:Required
	AdvertisementType IsovalentBGPAdvertType `json:"advertisementType"`

	// Service defines configuration options for the "Service" advertisementType.
	//
	// +kubebuilder:validation:Optional
	Service *BGPServiceOptions `json:"service,omitempty"`

	// Interface defines configuration options for the "Interface" advertisementType.
	//
	// +kubebuilder:validation:Optional
	Interface *v2.BGPInterfaceOptions `json:"interface,omitempty"`

	// Selector is a label selector to select objects of the type specified by AdvertisementType.
	// For the PodCIDR AdvertisementType it is not applicable. For other advertisement types,
	// if not specified, no objects of the type specified by AdvertisementType are selected for advertisement.
	//
	// +kubebuilder:validation:Optional
	Selector *slimv1.LabelSelector `json:"selector,omitempty"`

	// Attributes defines additional attributes to set to the advertised routes.
	// If not specified, no additional attributes are set.
	//
	// +kubebuilder:validation:Optional
	Attributes *BGPAttributes `json:"attributes,omitempty"`
}

// BGPAttributes defines additional attributes to set to the advertised NLRIs.
type BGPAttributes struct {
	// Communities sets the community attributes in the route.
	// If not specified, no community attribute is set.
	//
	// +kubebuilder:validation:Optional
	Communities *v2.BGPCommunities `json:"communities,omitempty"`

	// LocalPreference sets the local preference attribute in the route.
	// If not specified, no local preference attribute is set.
	//
	// +kubebuilder:validation:Optional
	LocalPreference *int64 `json:"localPreference,omitempty"`

	// ASPathPrepend contains configuration for prepending AS number to the
	// AS path attribute in the route.
	//
	// +kubebuilder:validation:Optional
	ASPathPrepend *BGPASPathPrepend `json:"asPathPrepend,omitempty"`
}

// BGPASPathPrepend defines the configuration for AS path prepend options.
type BGPASPathPrepend struct {
	// Repeat defines how many times the local AS number should be prepended
	// to the AS path attribute in the route.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	Repeat int32 `json:"repeat"`
}

// BGPServiceOptions defines the configuration for Service advertisement type.
type BGPServiceOptions struct {
	// Addresses is a list of service address types which needs to be advertised via BGP.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Addresses []v2.BGPServiceAddressType `json:"addresses,omitempty"`

	// AggregationLengthIPv4 is the length of the IPv4 prefix to be advertised.
	// If not specified, exact route is advertised with prefix length of 32.
	//
	// This option does not change prefix lengths of VIPs for services which have
	// externalTrafficPolicy set to Local.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=31
	AggregationLengthIPv4 *int32 `json:"aggregationLengthIPv4,omitempty"`

	// AggregationLengthIPv6 is the length of the IPv6 prefix to be advertised.
	// If not specified, exact route is advertised with prefix length 128.
	//
	// This option does not change prefix lengths of VIPs for services which have
	// externalTrafficPolicy set to Local.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=127
	AggregationLengthIPv6 *int32 `json:"aggregationLengthIPv6,omitempty"`
}

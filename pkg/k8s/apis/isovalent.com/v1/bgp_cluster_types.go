// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgpclusterconfig",path="isovalentbgpclusterconfigs",scope="Cluster",shortName={ibgpcluster}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// IsovalentBGPClusterConfig is the Schema for the IsovalentBGPClusterConfig API
type IsovalentBGPClusterConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired cluster configuration of the BGP control plane.
	Spec IsovalentBGPClusterConfigSpec `json:"spec"`

	// Status is a running status of the cluster configuration
	//
	// +kubebuilder:validation:Optional
	Status IsovalentBGPClusterConfigStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPClusterConfigList is a list of IsovalentBGPClusterConfig objects.
type IsovalentBGPClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPClusterConfig.
	Items []IsovalentBGPClusterConfig `json:"items"`
}

type IsovalentBGPClusterConfigSpec struct {
	// NodeSelector selects a group of nodes where this BGP Cluster
	// config applies.
	// If empty / nil this config applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// A list of IsovalentBGPInstance(s) which instructs
	// the BGP control plane how to instantiate virtual BGP routers.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	BGPInstances []IsovalentBGPInstance `json:"bgpInstances"`
}

type IsovalentBGPInstance struct {
	// Name is the name of the BGP instance. It is a unique identifier for the BGP instance
	// within the cluster configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalASN is the ASN of this BGP instance.
	// Supports extended 32bit ASNs.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN *int64 `json:"localASN,omitempty"`

	// LocalPort is the port on which the BGP daemon listens for incoming connections.
	//
	// If not specified, BGP instance will not listen for incoming connections.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	LocalPort *int32 `json:"localPort,omitempty"`

	// Peers is a list of neighboring BGP peers for this virtual router
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []IsovalentBGPPeer `json:"peers,omitempty"`

	// VRFs is a list of VRFs for this instance.
	//
	// +kubebuilder:validation:Optional
	VRFs []BGPVRF `json:"vrfs,omitempty"`

	// RouteReflector defines which route reflector cluster this instance
	// joins. When specified, this instance automatically peers with the
	// route reflectors or route reflector clients in the cluster.
	//
	// +kubebuilder:validation:Optional
	RouteReflector *RouteReflector `json:"routeReflector,omitempty"`

	// VRFRef refers to the IsovalentCoreVRF resource that this BGP instance
	// is associated with.
	//
	// +kubebuilder:validation:Optional
	VRFRef *BGPVRFReference `json:"vrfRef,omitempty"`
}

type BGPVRFReference struct {
	// Name is the name of the VRF resource.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type RouteReflector struct {
	// Role is a role of the instance within the RR cluster
	//
	// +kubebuilder:validation:Required
	Role RouteReflectorRole `json:"role"`

	// ClusterID is the ID of the route reflector cluster that this
	// instance joins.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ipv4
	ClusterID string `json:"clusterID"`

	// PeeringAddressFamily controls the way how route reflectors and
	// clients make peering session(s). Available options are following:
	//
	// - IPv4Only: Makes single IPv4 peering session
	// - IPv6Only: Makes single IPv6 peering session
	// - Dual: Makes both IPv4 and IPv6 peering sessions
	//
	// If omitted, the default value will be selected based on the Cilium's
	// configuration. When Cilium is configured as IPv4 single-stack or
	// IPv6 single-stack, the default are `IPv4Only` and `IPv6Only`
	// respectively. If Cilium is configured as dual-stack, the default is
	// `Dual`.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=IPv4Only;IPv6Only;Dual
	PeeringAddressFamily *RouteReflectorPeeringAddressFamily `json:"peeringAddressFamily,omitempty"`

	// PeerConfigRefV4 is a reference to the IsovalentBGPPeerConfig when
	// this instance peers with other peers in the same route reflector
	// cluster with IPv4. Only valid when the peeringAddressFamily is
	// `IPv4Only` or `Dual`.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRefV4 *PeerConfigReference `json:"peerConfigRefV4,omitempty"`

	// PeerConfigRefV6 is a reference to the IsovalentBGPPeerConfig when
	// this instance peers with other peers in the same route reflector
	// cluster with IPv6. Only valid when the peeringAddressFamily is
	// `IPv6Only` or `Dual`.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRefV6 *PeerConfigReference `json:"peerConfigRefV6,omitempty"`
}

// +kubebuilder:validation:Enum=RouteReflector;Client
type RouteReflectorRole string

const (
	RouteReflectorRoleRouteReflector RouteReflectorRole = "RouteReflector"
	RouteReflectorRoleClient         RouteReflectorRole = "Client"
)

type RouteReflectorPeeringAddressFamily string

const (
	RouteReflectorPeeringAddressFamilyIPv4Only RouteReflectorPeeringAddressFamily = "IPv4Only"
	RouteReflectorPeeringAddressFamilyIPv6Only RouteReflectorPeeringAddressFamily = "IPv6Only"
	RouteReflectorPeeringAddressFamilyDual     RouteReflectorPeeringAddressFamily = "Dual"
)

// IsovalentBGPPeer contains configuration for a BGP peer.
//
// +kubebuilder:validation:XValidation:rule="has(self.peerAddress) || has(self.autoDiscovery)", message="Either peerAddress or autoDiscovery must be specified"
type IsovalentBGPPeer struct {
	// Name is the name of the BGP peer. It is a unique identifier for the peer within the BGP instance.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// PeerAddress is the IP address of the neighbor.
	// Supports IPv4 and IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	PeerAddress *string `json:"peerAddress,omitempty"`

	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs.
	//
	// If peerASN is unspecified or 0, the BGP OPEN message validation of ASN
	// will be disabled and ASN will be determined based on peer's OPEN message.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:default=0
	PeerASN *int64 `json:"peerASN,omitempty"`

	// AutoDiscovery allows auto-discovery of peer's IP address.
	// When a peer auto-discovery mechanism is enabled, the peerAddress field
	// can be empty (and will be ignored if set).
	//
	// +kubebuilder:validation:Optional
	AutoDiscovery *BGPAutoDiscovery `json:"autoDiscovery,omitempty"`

	// PeerConfigRef is a reference to a peer configuration resource.
	// If not specified, the default BGP configuration is used for this peer.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRef *PeerConfigReference `json:"peerConfigRef,omitempty"`
}

// BGPAutoDiscovery contains configuration for the BGP peer auto-discovery mechanism.
//
// +kubebuilder:validation:XValidation:rule="self.mode != 'Unnumbered' || has(self.unnumbered)", message="unnumbered field is required for the 'Unnumbered' mode"
// +kubebuilder:validation:XValidation:rule="self.mode != 'DefaultGateway' || has(self.defaultGateway)", message="defaultGateway field is required for the 'DefaultGateway' mode"
type BGPAutoDiscovery struct {
	// Mode defines the type of BGP peer auto-discovery mechanism.
	//
	// +kubebuilder:validation:Required
	Mode BGPAutoDiscoveryMode `json:"mode"`

	// Unnumbered contains configuration for the BGP Unnumbered peer auto-discovery mode.
	//
	// +kubebuilder:validation:Optional
	Unnumbered *BGPUnnumbered `json:"unnumbered,omitempty"`

	// DefaultGateway contains configuration for the DefaultGateway peer auto-discovery mode.
	//
	// +kubebuilder:validation:Optional
	DefaultGateway *v2.DefaultGateway `json:"defaultGateway,omitempty"`
}

// BGPAutoDiscoveryMode defines the mode of BGP peer auto-discovery.
//
// +kubebuilder:validation:Enum=Unnumbered;DefaultGateway
type BGPAutoDiscoveryMode string

const (
	// BGPADUnnumbered is "BGP Unnumbered" peer auto-discovery mode.
	BGPADUnnumbered BGPAutoDiscoveryMode = "Unnumbered"

	// BGPADDefaultGateway is peer auto-discovery mode using default gateway.
	BGPADDefaultGateway BGPAutoDiscoveryMode = "DefaultGateway"
)

// BGPUnnumbered contains configuration for the BGP Unnumbered peer auto-discovery mechanism.
type BGPUnnumbered struct {
	// Interface is the name of an interface on the Cilium node to use for BGP unnumbered peering.
	//
	// The IPv6 link-local address of a neighbor discovered on the specified interface will be used for peering.
	// Additionally, Router Advertisement messages will be sent out of the configured interface,
	// so that the neighboring router can learn about Cilium node's link-local IPv6 address as well.
	//
	// +kubebuilder:validation:Required
	Interface string `json:"interface,omitempty"`
}

// PeerConfigReference is a reference to a peer configuration resource.
type PeerConfigReference struct {
	// Name is the name of the peer config resource.
	// Name refers to the name of a Kubernetes object (typically a IsovalentBGPPeerConfig).
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type IsovalentBGPClusterConfigStatus struct {
	// The current conditions of the IsovalentBGPClusterConfig
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="has(self.vrfRef) != has(self.privateNetworkRef)", message="either vrfRef or privateNetworkRef must be specified"
type BGPVRF struct {
	// VRFRef is a reference to a IsovalentVRF resource. It should be the
	// same as the name of the IsovalentVRF object to which this BGPVRF is
	// associated. It cannot be set together with privateNetworkRef.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	VRFRef *string `json:"vrfRef"`

	// PrivateNetworkRef is a reference to a ClusterPrivateNetwork
	// resource. It cannot be set together with vrfRef.
	//
	// +kubebuilder:validation:Optional
	PrivateNetworkRef *BGPPrivateNetworkReference `json:"privateNetworkRef,omitempty"`

	// ConfigRef is a reference to a IsovalentBGPVRFConfig resource.
	//
	// +kubebuilder:validation:Optional
	ConfigRef *string `json:"configRef,omitempty"`

	// RD is the Route Distinguisher of the VRF.
	//
	// +kubebuilder:validation:Optional
	RD *string `json:"rd,omitempty"`

	// ImportRTs is a list of route targets to import routes from.
	//
	// +kubebuilder:validation:Optional
	ImportRTs []string `json:"importRTs,omitempty"`

	// ExportRTs is a list of route targets to export routes to.
	//
	// +kubebuilder:validation:Optional
	ExportRTs []string `json:"exportRTs,omitempty"`
}

type BGPPrivateNetworkReference struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// Conditions for IsovalentBGPClusterConfig
const (
	// Node selector selects nothing
	BGPClusterConfigConditionNoMatchingNode = "isovalent.com/NoMatchingNode"
	// Referenced peer configs are missing
	BGPClusterConfigConditionMissingPeerConfigs = "isovalent.com/MissingPeerConfigs"
	// Referenced vrfs are missing
	BGPClusterConfigConditionMissingVRFs = "isovalent.com/MissingVRFs"
	// Referenced vrf configs are missing
	BGPClusterConfigConditionMissingVRFConfigs = "isovalent.com/MissingBGPVRFConfigs"
	// ClusterConfig with conflicting nodeSelector present
	BGPClusterConfigConditionConflictingClusterConfigs = "isovalent.com/ConflictingClusterConfig"
)

var AllBGPClusterConfigConditions = []string{
	BGPClusterConfigConditionNoMatchingNode,
	BGPClusterConfigConditionMissingPeerConfigs,
	BGPClusterConfigConditionMissingVRFs,
	BGPClusterConfigConditionMissingVRFConfigs,
	BGPClusterConfigConditionConflictingClusterConfigs,
}

// PeeringKey returns a key identifying a BGP peer from BGP peering perspective.
// Two peers with different logical name but the same peering address / interface
// would produce the same key. If Interface is specified (unnumbered peer), the PeerAddress is ignored.
func (peer *IsovalentBGPPeer) PeeringKey() string {
	if peer.AutoDiscovery != nil && peer.AutoDiscovery.Mode == BGPADUnnumbered &&
		peer.AutoDiscovery.Unnumbered.Interface != "" {
		return "unnumbered-" + peer.AutoDiscovery.Unnumbered.Interface
	}
	if peer.PeerAddress != nil && *peer.PeerAddress != "" {
		return *peer.PeerAddress
	}
	return "<unknown>"
}

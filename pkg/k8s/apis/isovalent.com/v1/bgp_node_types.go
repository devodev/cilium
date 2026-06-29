// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgpnodeconfig",path="isovalentbgpnodeconfigs",scope="Cluster",shortName={ibgpnode}
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// IsovalentBGPNodeConfig is node local configuration for BGP agent. Name of the object should be node name.
// This resource will be created by Cilium operator and is read-only for the users.
type IsovalentBGPNodeConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the IsovalentBGPNodeConfig.
	Spec IsovalentBGPNodeSpec `json:"spec"`

	// Status is the most recently observed status of the IsovalentBGPNodeConfig.
	// +kubebuilder:validation:Optional
	Status IsovalentBGPNodeStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPNodeConfigList is a list of IsovalentBGPNodeConfig objects.
type IsovalentBGPNodeConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPNodeConfig.
	Items []IsovalentBGPNodeConfig `json:"items"`
}

type IsovalentBGPNodeSpec struct {
	// BGPInstances is a list of BGP router instances on the node.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	BGPInstances []IsovalentBGPNodeInstance `json:"bgpInstances"`
}

// IsovalentBGPNodeInstance is a single BGP router instance configuration on the node.
type IsovalentBGPNodeInstance struct {
	// Name is the name of the BGP instance. This name is used to identify the BGP instance on the node.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalASN is the ASN of this virtual router.
	// Supports extended 32bit ASNs.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN *int64 `json:"localASN,omitempty"`

	// RouterID is the BGP router ID of this virtual router.
	// This configuration is derived from IsovalentBGPNodeConfigOverride resource.
	//
	// If not specified, the router ID will be derived from the node local address.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	RouterID *string `json:"routerID,omitempty"`

	// LocalPort is the port on which the BGP daemon listens for incoming connections.
	//
	// If not specified, BGP instance will not listen for incoming connections.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	LocalPort *int32 `json:"localPort,omitempty"`

	// SRv6Responder is a flag to enable SRv6 responder on the BGP instance.
	//
	// +kubebuilder:validation:Optional
	SRv6Responder *bool `json:"srv6Responder,omitempty"`

	// Peers is a list of neighboring BGP peers for this virtual router
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []IsovalentBGPNodePeer `json:"peers,omitempty"`

	// VRFs is a list of VRFs for this instance.
	//
	// +kubebuilder:validation:Optional
	VRFs []IsovalentBGPNodeVRF `json:"vrfs,omitempty"`

	// RouteReflector indicates whether this BGP instance is a route
	// reflector and which route reflector cluster it is joining.
	//
	// +kubebuilder:validation:Optional
	RouteReflector *NodeRouteReflector `json:"routeReflector,omitempty"`

	// Maintenance allows enabling maintenance mode of this BGP instance.
	//
	// +kubebuilder:validation:Optional
	Maintenance *IsovalentBGPMaintenance `json:"maintenance"`

	// VRFRef refers to the IsovalentCoreVRF resource that this BGP instance
	// is associated with.
	//
	// +kubebuilder:validation:Optional
	VRFRef *BGPVRFReference `json:"vrfRef,omitempty"`
}

type IsovalentBGPNodePeer struct {
	// Name is the name of the BGP peer. This name is used to identify the BGP peer for the BGP instance.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// PeerAddress is the IP address of the neighbor.
	// Supports IPv4 and IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	PeerAddress *string `json:"peerAddress,omitempty"`

	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	PeerASN *int64 `json:"peerASN,omitempty"`

	// AutoDiscovery allows auto-discovery of peer's IP address.
	// When a peer auto-discovery mechanism is enabled, the peerAddress field
	// can be empty (and will be ignored if set).
	//
	// +kubebuilder:validation:Optional
	AutoDiscovery *BGPAutoDiscovery `json:"autoDiscovery,omitempty"`

	// LocalAddress is the IP address of the local interface to use for the peering session.
	// This configuration is derived from IsovalentBGPNodeConfigOverride resource. If not specified, the local address will be used for setting up peering.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	LocalAddress *string `json:"localAddress,omitempty"`

	// PeerConfigRef is a reference to a peer configuration resource.
	// If not specified, the default BGP configuration is used for this peer.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRef *PeerConfigReference `json:"peerConfigRef,omitempty"`

	// RouteReflector indicates whether this peer is a route reflector
	// client and which route reflector cluster it is joining.
	//
	// +kubebuilder:validation:Optional
	RouteReflector *NodeRouteReflector `json:"routeReflector,omitempty"`
}

type NodeRouteReflector struct {
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
}

// IsovalentBGPNodeStatus is the status of the IsovalentBGPNodeConfig.
type IsovalentBGPNodeStatus struct {
	// BGPInstances is the status of the BGP instances on the node.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	BGPInstances []IsovalentBGPNodeInstanceStatus `json:"bgpInstances,omitempty"`

	// The current conditions of the CiliumBGPNodeConfig
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type IsovalentBGPNodeInstanceStatus struct {
	v2.CiliumBGPNodeInstanceStatus `json:",inline"`
}

// +kubebuilder:validation:XValidation:rule="has(self.vrfRef) != has(self.privateNetworkRef)", message="either vrfRef or privateNetworkRef must be specified"
type IsovalentBGPNodeVRF struct {
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

	// RD is the route distinguisher for the VRF.
	//
	// +kubebuilder:validation:Optional
	RD *string `json:"rd,omitempty"`

	// ImportRTs is a list of route targets to import routes from.
	//
	// +kubebuilder:validation:Optional
	// +listType=set
	ImportRTs []string `json:"importRTs,omitempty"`

	// ExportRTs is a list of route targets to export routes to.
	//
	// +kubebuilder:validation:Optional
	// +listType=set
	ExportRTs []string `json:"exportRTs,omitempty"`
}

const (
	BGPInstanceConditionReconcileError = "isovalent.com/BGPReconcileError"
)

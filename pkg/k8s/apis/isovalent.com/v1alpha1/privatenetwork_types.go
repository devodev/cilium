// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="clusterwideprivatenetwork",path="clusterwideprivatenetworks",scope="Cluster",shortName={icpn}
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:JSONPath=".status.vni",name="VNI",type=integer
// +deepequal-gen=false

// ClusterwidePrivateNetwork defines a private network to which workloads can be attached.
type ClusterwidePrivateNetwork struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// The private network specification.
	//
	// +kubebuilder:validation:Required
	Spec PrivateNetworkSpec `json:"spec"`

	// The private network status.
	//
	// +kubebuilder:validation:Optional
	Status *PrivateNetworkStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// ClusterwidePrivateNetworkList is a list of ClusterwidePrivateNetwork objects.
type ClusterwidePrivateNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of ClusterwidePrivateNetwork.
	Items []ClusterwidePrivateNetwork `json:"items"`
}

type PrivateNetworkSpec struct {
	// A 24bit numeric identifier of this private network. Specify this
	// field when you wish to integrate this private network with
	// EVPN/VXLAN. In that case, the value will be reflected to the BGP
	// advertisement and dataplane handling of ingress traffic over VXLAN.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Maximum=16777215
	VNI *uint32 `json:"vni,omitempty"`

	// The list of Isovalent Network Bridges (INBs) serving this private network.
	// This stanza shall be specified in the main workload cluster(s) only, and
	// not in the INB clusters.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=cluster
	INBs []INBRef `json:"networkBridges,omitempty"`

	// The set of subnets (that is, L2 domains) associated with, and directly
	// reachable, from this private network.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=name
	Subnets []SubnetSpec `json:"subnets"`

	// Configures the Multus Network Attachment Definitions integration for
	// this private network.
	//
	// +kubebuilder:validation:Optional
	NetworkAttachmentDefinitions NADSpec `json:"networkAttachmentDefinitions,omitempty"`
}

type NADSpec struct {
	// Selects the namespaces in which to automatically create a Multus Network
	// Attachment Definition (NAD) instance for each subnet associated with this
	// private network. By default, no namespace is selected, and no NAD is
	// automatically created for this private network.
	//
	// +kubebuilder:validation:Optional
	NamespaceSelector *slim_metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="has(self.cidrv4) || has(self.cidrv6)", message="Either cidrv4 or cidrv6 needs to be provided"
type SubnetSpec struct {
	// The name of the subnet.
	//
	// +kubebuilder:validation:Required
	Name SubnetName `json:"name"`

	// The IPv4 CIDRv4 associated with the private network.
	CIDRv4 NetworkCIDRv4 `json:"cidrv4,omitempty"`

	// The IPv6 CIDR associated with the private network.
	CIDRv6 NetworkCIDRv6 `json:"cidrv6,omitempty"`

	// The set of routes configured for this subnet.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	Routes []PrivateNetworkRouteSpec `json:"routes"`

	// DHCP defines DHCP relay configuration for this subnet.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default={mode:"none"}
	DHCP PrivateNetworkSubnetDHCPSpec `json:"dhcp"`
}

type PrivateNetworkDHCPMode string

const (
	PrivateNetworkDHCPModeBroadcast PrivateNetworkDHCPMode = "broadcast"
	PrivateNetworkDHCPModeRelay     PrivateNetworkDHCPMode = "relay"
	PrivateNetworkDHCPModeNone      PrivateNetworkDHCPMode = "none"
)

// +kubebuilder:validation:XValidation:rule="self.mode == 'relay' || !has(self.relay)",message="dhcp.relay can only be configured when mode is 'relay'"
// +kubebuilder:validation:XValidation:rule="self.mode != 'relay' || has(self.relay)",message="dhcp.relay must be configured when mode is 'relay'"
type PrivateNetworkSubnetDHCPSpec struct {
	// Mode selects how DHCP requests are relayed for this subnet.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=broadcast;relay;none
	// +kubebuilder:default=none
	Mode PrivateNetworkDHCPMode `json:"mode"`

	// Relay specifies the relay agent options when mode=relay.
	//
	// +kubebuilder:validation:Optional
	Relay *PrivateNetworkDHCPRelaySpec `json:"relay,omitempty"`
}

type PrivateNetworkDHCPRelaySpec struct {
	// ServerAddress is the DHCP server IP or hostname for relay mode.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	ServerAddress string `json:"serverAddress"`

	// ServerPort is the DHCP server port for relay mode.
	// Defaults to 67 when unset.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=67
	ServerPort uint16 `json:"serverPort"`

	// Option82 configures relay-agent option 82 suboptions.
	//
	// +kubebuilder:validation:Optional
	Option82 *PrivateNetworkDHCPOption82Spec `json:"option82,omitempty"`
}

type PrivateNetworkDHCPOption82Spec struct {
	// CircuitID is option 82 circuit-id value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=255
	CircuitID string `json:"circuitID,omitempty"`

	// RemoteID is option 82 remote-id value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=255
	RemoteID string `json:"remoteID,omitempty"`
}

// NetworkCIDRv4 is an IPv4 network CIDR.
//
// +kubebuilder:validation:MaxLength=18
// +kubebuilder:validation:Format=cidr
// +kubebuilder:validation:XValidation:rule="cidr(self).ip().family() == 4", message="Not an IPv4 CIDR"
// +kubebuilder:validation:XValidation:rule="oldSelf == self", message="Subnet IPv4 CIDR is immutable"
type NetworkCIDRv4 string

// NetworkCIDRv6 is an IPv6 network CIDR.
//
// +kubebuilder:validation:MaxLength=42
// +kubebuilder:validation:Format=cidr
// +kubebuilder:validation:XValidation:rule="cidr(self).ip().family() == 6", message="Not an IPv6 CIDR"
// +kubebuilder:validation:XValidation:rule="oldSelf == self", message="Subnet IPv6 CIDR is immutable"
type NetworkCIDRv6 string

// PrivateNetworkRouteSpec defines a route in the private network.
type PrivateNetworkRouteSpec struct {
	// The destination network.
	//
	// +kubebuilder:validation:Required
	Destination NetworkCIDR `json:"destination"`

	// Gateway is the route's nexthop.
	//
	// +kubebuilder:validation:Required
	Gateway Nexthop `json:"gateway"`
}

// Nexthop is an IP address (IPv4 or IPv6) or "EVPN" for lookup in BGP/EVPN routing table.
//
// +kubebuilder:validation:MaxLength=45
// +kubebuilder:validation:XValidation:rule="self == 'EVPN' || isIP(self)", message="must be a valid IP or 'EVPN'"
type Nexthop string

const (
	EVPNRoute Nexthop = "EVPN"
)

// Subnet names must conform to the RFC 1123 Label Names format.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^([a-z0-9][-a-z0-9]*)?[a-z0-9]$`
type SubnetName = string

type INBRef struct {
	// The name of the cluster hosting the INB nodes.
	//
	// +kubebuilder:validation:Required
	Cluster ClusterName `json:"cluster"`

	// A selector to optionally select a subset of nodes in the target
	// cluster to be elected as INBs for this private network. Defaults to
	// selecting all nodes if unspecified.
	//
	// +kubebuilder:validation:Optional
	NodeSelector INBRefNodeSelector `json:"nodeSelector,omitzero"`
}

// A cluster name must respect the following constraints:
// * It must contain at most 32 characters;
// * It must begin and end with a lower case alphanumeric character;
// * It may contain lower case alphanumeric characters and dashes between.
// See pkg/clustermesh/types/types.go for the corresponding validation.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:Pattern=`^([a-z0-9][-a-z0-9]*)?[a-z0-9]$`
type ClusterName = string

type INBRefNodeSelector struct {
	slim_metav1.LabelSelector `json:",inline"`
}

// Interface names must be less than 16 characters, and not include forward
// slashes, colons and spaces. Additionally, they cannot match "." and "..".
// See https://elixir.bootlin.com/linux/v6.18.6/source/net/core/dev.c#L1297-L1320

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=15
// +kubebuilder:validation:Pattern=`^[^:\s\/]+$`
// +kubebuilder:validation:XValidation:rule="self != '.' && self != '..'", message="'.' and '..' are not valid interface names"
type InterfaceName = string

type PrivateNetworkStatus struct {
	// An allocated VNI value
	//
	// +kubebuilder:validation:Optional
	VNI *uint32 `json:"vni,omitempty"`

	// The current conditions of the PrivateNetwork
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	PrivateNetworkCondTypeVNIConflict        = "VNIConflict"
	PrivateNetworkCondReasonHasVNIConflict   = "PrivateNetworkHasVNIConflict"
	PrivateNetworkCondReasonHasNoVNIConflict = "PrivateNetworkHasNoVNIConflict"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="privatenetworkendpointslice",path="privatenetworkendpointslices",scope="Namespaced",shortName={ipnes}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// PrivateNetworkEndpointSlice contains the list of endpoints and their network mappings.
type PrivateNetworkEndpointSlice struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// The list of managed endpoints. Each entry contains the mapping of an
	// endpoint belonging to a given private network to the corresponding
	// identifiers in the main pod network.
	//
	// +kubebuilder:validation:Optional
	Endpoints []PrivateNetworkEndpointSliceEntry `json:"endpoints"`

	// The name of the node hosting this slice of endpoints. It is the name of
	// the Isovalent Network Bridge when operating in bridge mode.
	//
	// +kubebuilder:validation:Required
	NodeName NodeName `json:"nodeName"`
}

// Node names must conform to the RFC 1123 DNS Subdomain Names format.
//
// +kubebuilder:validation:Required
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type NodeName = string

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// PrivateNetworkEndpointSliceList is a list of PrivateNetworkEndpointSlice objects.
type PrivateNetworkEndpointSliceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of PrivateNetworkEndpointSlice.
	Items []PrivateNetworkEndpointSlice `json:"items"`
}

// +deepequal-gen=false
type PrivateNetworkEndpointSliceEntry struct {
	// The instant in time in which this entry was marked as active. If
	// multiple entries are advertized by different nodes and/or clusters for
	// the same private network endpoint, the latest that has been activated
	// takes precedence.
	//
	// +kubebuilder:validation:Optional
	ActivatedAt metav1.MicroTime `json:"activatedAt,omitzero"`

	// The endpoint identifiers from the pod network point of view.
	//
	// +kubebuilder:validation:Required
	Endpoint PrivateNetworkEndpointSliceEndpoint `json:"endpoint"`

	// The endpoint identifiers from the private network point of view.
	//
	// +kubebuilder:validation:Required
	Interface PrivateNetworkEndpointSliceInterface `json:"interface"`

	// Additional flags to characterize the entry.
	Flags PrivateNetworkEndpointSliceFlags `json:"flags"`
}

// DeepEqual is implemented manually for PrivateNetworkEndpointSliceEntry, because metav1.MicroTime has no DeepEqual
func (in *PrivateNetworkEndpointSliceEntry) DeepEqual(other *PrivateNetworkEndpointSliceEntry) bool {
	if other == nil {
		return false
	}

	if !in.ActivatedAt.Equal(&other.ActivatedAt) {
		return false
	}

	if !in.Endpoint.DeepEqual(&other.Endpoint) {
		return false
	}

	if !in.Interface.DeepEqual(&other.Interface) {
		return false
	}

	return true
}

// +deepequal-gen=false
type PrivateNetworkEndpointSlicePreviousAddressing struct {
	// The Pod IPv4 address.
	//
	// +kubebuilder:validation:Format=ipv4
	IPv4 string `json:"ipv4,omitempty"`

	// The Pod IPv6 address.
	//
	// +kubebuilder:validation:Format=ipv6
	IPv6 string `json:"ipv6,omitempty"`

	// The instant in time when the Pod IPv4/IPv6 address were last known to be valid.
	// If there is an endpoint with the same Pod IPv4/IPv6 and a newer activatedAt
	// timestamp than this lastSeen timestamp, then any state associated with the
	// Pod IPv4/IPv6 address belongs to that newer endpoint and this previousAddressing
	// data should be ignored.
	//
	// +kubebuilder:validation:Required
	LastSeen metav1.MicroTime `json:"lastSeen"`
}

// DeepEqual is implemented manually for PrivateNetworkEndpointSlicePreviousAddressing, because metav1.MicroTime has no DeepEqual
func (in *PrivateNetworkEndpointSlicePreviousAddressing) DeepEqual(other *PrivateNetworkEndpointSlicePreviousAddressing) bool {
	if other == nil {
		return false
	}

	return in.IPv4 == other.IPv4 &&
		in.IPv6 == other.IPv6 &&
		in.LastSeen.Equal(&other.LastSeen)
}

type PrivateNetworkEndpointSliceEndpoint struct {
	// The endpoint addresses (IPv4 and/or IPv6) from the pod network point
	// of view.
	//
	// +kubebuilder:validation:Required
	Addressing PrivateNetworkEndpointAddressing `json:"addressing"`

	// The name identifying the target endpoint.
	//
	// +kubebuilder:validation:Required
	Name EndpointName `json:"name"`

	// Previous endpoint addresses (IPv4 and/or IPv6) from the pod network point
	// of view. This is set if this endpoint's pod IP changed, e.g. due to a
	// migration to a new node.
	//
	// +kubebuilder:validation:Optional
	PreviousAddressing []PrivateNetworkEndpointSlicePreviousAddressing `json:"previousAddressing,omitempty"`
}

// Endpoint names must conform to the RFC 1123 DNS Subdomain Names format.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type EndpointName = string

type PrivateNetworkEndpointSliceInterface struct {
	// The endpoint addresses (IPv4 and/or IPv6) from the private network point
	// of view.
	//
	// +kubebuilder:validation:Required
	Addressing PrivateNetworkEndpointAddressing `json:"addressing"`

	// The MAC address of the endpoint from the private network point of view.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=mac
	MAC string `json:"mac"`

	// Name of the target private network, as defined by a
	// ClusterwidePrivateNetwork resource.
	//
	// +kubebuilder:validation:Required
	Network PrivateNetworkName `json:"network"`
}

// Private network names must conform to the RFC 1123 DNS Subdomain Names format.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type PrivateNetworkName = string

// +kubebuilder:validation:MinProperties=1
type PrivateNetworkEndpointAddressing struct {
	// The IPv4 endpoint address.
	//
	// +kubebuilder:validation:Format=ipv4
	IPv4 string `json:"ipv4,omitempty"`

	// The IPv6 endpoint address.
	//
	// +kubebuilder:validation:Format=ipv6
	IPv6 string `json:"ipv6,omitempty"`
}

type PrivateNetworkEndpointSliceFlags struct {
	// Set when the endpoint is external to the cluster, and the advertising
	// node provides access to it in bridge mode.
	External bool `json:"external,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="privatenetworkexternalendpoint",path="privatenetworkexternalendpoints",scope="Namespaced",shortName={ipnee}
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:JSONPath=".spec.interface.network",name="Network",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.interface.addressing.ipv4",name="IPv4",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.interface.addressing.ipv6",name="IPv6",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.interface.mac",name="Mac",type=string,priority=1
// +kubebuilder:printcolumn:JSONPath=".status.activatedAt",name="Activated",type=date
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +deepequal-gen=false

// PrivateNetworkExternalEndpoint represents an endpoint outside
// of the cilium-managed mesh and contains its addressing information.
type PrivateNetworkExternalEndpoint struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// The specification of an external endpoint.
	//
	// +kubebuilder:validation:Required
	Spec PrivateNetworkExternalEndpointSpec `json:"spec"`

	// The status of an external endpoint.
	//
	// +kubebuilder:validation:Optional
	Status PrivateNetworkExternalEndpointStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
//
// PrivateNetworkExternalEndpointList is a list of PrivateNetworkExternalEndpoint objects.
type PrivateNetworkExternalEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of PrivateNetworkExternalEndpoint.
	Items []PrivateNetworkExternalEndpoint `json:"items"`
}

type PrivateNetworkExternalEndpointSpec struct {
	// Manually marks this endpoint representation as inactive.
	//
	// +kubebuilder:validation:Optional
	Inactive bool `json:"inactive,omitzero"`

	// The endpoint identifiers from the private network point of view.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="External endpoint interface is immutable"
	Interface PrivateNetworkEndpointSliceInterface `json:"interface"`
}

// +deepequal-gen=false
type PrivateNetworkExternalEndpointStatus struct {
	// The instant in time in which this entry was marked as active. If
	// multiple entries are advertised by different nodes and/or clusters for
	// the same private network endpoint, the latest that has been activated
	// takes precedence.
	//
	// +kubebuilder:validation:Optional
	ActivatedAt metav1.MicroTime `json:"activatedAt,omitzero"`
}

// DeepEqual is implemented manually for PrivateNetworkExternalEndpointStatus, because metav1.MicroTime has no DeepEqual
func (in *PrivateNetworkExternalEndpointStatus) DeepEqual(other *PrivateNetworkExternalEndpointStatus) bool {
	if other == nil {
		return false
	}

	if !in.ActivatedAt.Equal(&other.ActivatedAt) {
		return false
	}

	return true
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="privatenetworknodeattachment",path="privatenetworknodeattachments",scope="Cluster",shortName={pnna}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// PrivateNetworkNodeAttachment defines a node device management of private networks.
type PrivateNetworkNodeAttachment struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// The private network specification.
	//
	// +kubebuilder:validation:Required
	Spec PrivateNetworkNodeAttachmentSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// PrivateNetworkNodeAttachmentList is a list of PrivateNetworkNodeAttachment objects.
type PrivateNetworkNodeAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of PrivateNetworkNodeAttachment.
	Items []PrivateNetworkNodeAttachment `json:"items"`
}

type PrivateNetworkNodeAttachmentSpec struct {
	// PrivateNetworkRef identifies the private-network resource that this configuration
	// is linked to.
	//
	// +kubebuilder:validation:Required
	PrivateNetworkRef PrivateNetworkRef `json:"privateNetworkRef"`

	// NodeSelector selects the nodes to which this configuration applies.
	//
	// If empty / omitted then this config will apply to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector slim_metav1.LabelSelector `json:"nodeSelector,omitempty"`

	// Attachments is a list of egress devices to be configured on the selected nodes.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Attachments []PrivateNetworkAttachment `json:"attachments"`
}

type PrivateNetworkRef struct {
	// Name of the ClusterwidePrivateNetwork resource.
	//
	// +kubebuilder:validation:Required
	Name PrivateNetworkName `json:"name"`
}

type PrivateNetworkSubnetRef struct {
	// Name of the Subnet specified in the private-network resource.
	//
	// +kubebuilder:validation:Required
	Name SubnetName `json:"name"`
}

type PrivateNetworkAttachment struct {
	// Interface specifies the network interface used for private network
	// traffic ingress and egress on the selected nodes. This interface must be
	// present on the node and appropriately connected to underlying network
	// infrastructure.
	//
	// +kubebuilder:validation:Required
	Interface InterfaceName `json:"interface"`

	// Subnets is a list of subnets reachable via this attachment.
	//
	// If empty / nil means all subnets configured in the private-network resource
	// are selected.
	//
	// +kubebuilder:validation:Optional
	SubnetRefs []PrivateNetworkSubnetRef `json:"subnetRefs,omitempty"`

	// VlanID, when specified, result in Cilium to create a DOT1Q VLAN subinterface
	// with parent device specified in Interface.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	VlanID *int `json:"vlanID,omitempty"`
}

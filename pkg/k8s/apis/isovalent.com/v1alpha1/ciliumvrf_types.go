// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentcorevrf",path="isovalentcorevrfs",scope="Cluster",shortName={icvrf}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// IsovalentCoreVRF defines a Virtual Routing and Forwarding domain that binds
// selected pods and network interfaces into an isolated routing table.
type IsovalentCoreVRF struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired VRF configuration.
	//
	// +kubebuilder:validation:Required
	Spec IsovalentCoreVRFSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentCoreVRFList is a list of IsovalentCoreVRF objects.
type IsovalentCoreVRFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentCoreVRF.
	Items []IsovalentCoreVRF `json:"items"`
}

// IsovalentCoreVRFSpec defines the desired state of an IsovalentCoreVRF.
type IsovalentCoreVRFSpec struct {
	// ID is used to group a set of IsovalentCoreVRFs into a single VRF instance.
	// This provides decoupling and allows a VRF to utilize different table IDs
	// and interfaces across nodes.
	//
	// The ID zero is used internally and is reserved.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	ID uint16 `json:"id"`

	// Table is the routing table ID for this VRF.
	// Must be provided by the creator (user, BGP controller, or network manager).
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	Table uint32 `json:"table"`

	// NodeSelector selects which nodes this VRF applies to.
	// If nil or empty, the VRF applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// Selectors define which pods are members of this VRF.
	// Each selector can match pods by labels and/or namespace labels.
	//
	// +kubebuilder:validation:Required
	Selector IsovalentCoreVRFPodSelector `json:"selector"`

	// Interfaces is the list of network interface names bound to this VRF.
	//
	// If no interfaces are listed its assumed an underlying control plane is
	// configuring VRF membership for network interfaces.
	//
	// +kubebuilder:validation:Optional
	Interfaces []string `json:"interfaces,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentcorevrfnodestatus",path="isovalentcorevrfnodestatuses",scope="Cluster",shortName={icvrfns}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +deepequal-gen=false

// IsovalentCoreVRFNodeStatus reports the per-node status of each VRF managed by a
// Cilium agent. One CR is created per node, named after the node.
type IsovalentCoreVRFNodeStatus struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Status contains per-VRF status entries keyed by IsovalentCoreVRF CR name.
	//
	// +kubebuilder:validation:Optional
	Status IsovalentCoreVRFNodeStatusStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentCoreVRFNodeStatusList is a list of IsovalentCoreVRFNodeStatus objects.
type IsovalentCoreVRFNodeStatusList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []IsovalentCoreVRFNodeStatus `json:"items"`
}

// IsovalentCoreVRFNodeStatusStatus holds per-VRF status entries.
//
// +deepequal-gen=false
type IsovalentCoreVRFNodeStatusStatus struct {
	// VRFs is the per-VRF status keyed by IsovalentCoreVRF CR name.
	//
	// +kubebuilder:validation:Optional
	VRFs map[string]IsovalentCoreVRFStatus `json:"vrfs,omitempty"`
	// MembershipConflicts lists VRFs which target an overlapping set of
	// Endpoints. The map is keyed by VRF name; the value is a comma-separated
	// list of the other VRF names overlapping with that key.
	//
	// Endpoint behavior under conflict:
	//   - An Endpoint already bound to a VRF when a conflict arises retains
	//     its existing binding. This avoids flapping pod traffic when a
	//     misconfiguration is introduced and gives the operator time to
	//     correct the spec without traffic loss.
	//   - An Endpoint that is unbound at the moment a conflict applies to it
	//     stays unbound (rt_info=0) until the conflict resolves.
	//   - When the conflict resolves (selectors mutated, or a VRF removed),
	//     normal binding logic applies: the Endpoint binds to the single
	//     remaining match, or releases if none match.
	//
	// When this field has values the cluster admin should detect which
	// selectors are producing the overlap and remedy the spec. The cluster
	// admin should not assume that pods caught in an overlap are members of
	// any particular VRF — consult the per-Endpoint state via
	// `cilium-dbg bpf endpoint list` to confirm.
	//
	// This field is orthogonal to IsovalentCoreVRFStatus.Conditions: the
	// underlying VRF infrastructure can be Ready while membership conflicts
	// remain, because conflict is a property of selector overlap, not of
	// kernel/BPF state.
	MembershipConflicts map[string]string `json:"membershipConflicts,omitempty"`
}

// IsovalentCoreVRFStatus represents the status of a single VRF on a particular node.
//
// +deepequal-gen=false
type IsovalentCoreVRFStatus struct {
	// Conditions represent the latest available observations of this VRF's state on this node.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Condition types for VRF status.
const (
	VRFConditionReady              = "isovalent.com/VRFReady"
	VRFConditionInterfaceNotFound  = "isovalent.com/InterfaceNotFound"
	VRFConditionConflictingTableID = "isovalent.com/ConflictingTableID"
	VRFConditionConflictingID      = "isovalent.com/ConflictingID"
	VRFConditionInterfaceFailure   = "isovalent.com/InterfaceFailure"
	VRFConditionUpdateFailure      = "isovalent.com/UpdateFailure"
	VRFMembershipConflict          = "isovalent.com/MembershipConflict"
)

// IsovalentCoreVRFPodSelector selects pods for VRF membership using label selectors.
type IsovalentCoreVRFPodSelector struct {
	// PodSelector selects pods by labels.
	// If present but empty, it selects all pods.
	//
	// +kubebuilder:validation:Optional
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// NamespaceSelector selects namespaces using cluster-scoped labels.
	// If present but empty, it selects all namespaces.
	//
	// +kubebuilder:validation:Optional
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`
}

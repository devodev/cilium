// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/policy/api"
)

const InspectionConfigName = "inspection"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentinspectionconfig",path="isovalentinspectionconfigs",scope="Cluster"
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'inspection'",message="IsovalentInspectionConfig must be named 'inspection'"
// +deepequal-gen=false

// IsovalentInspectionConfig defines cluster-scoped passive inspection
// configuration. The agent consumes the singleton object named "inspection".
type IsovalentInspectionConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec IsovalentInspectionConfigSpec `json:"spec"`
}

type IsovalentInspectionConfigSpec struct {
	// EndpointSelector selects the endpoints whose traffic is mirrored to the
	// inspection interface. It uses the same label selector semantics as
	// CiliumNetworkPolicy: pod labels are matched directly, while namespaces
	// are addressable via the reserved
	// "k8s:io.kubernetes.pod.namespace[.labels.*]" labels. matchExpressions
	// (In/NotIn/Exists/DoesNotExist) can be used to express both opt-in and
	// opt-out selection. If omitted, all endpoints are selected.
	//
	// +kubebuilder:validation:Optional
	EndpointSelector *api.EndpointSelector `json:"endpointSelector,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type IsovalentInspectionConfigList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentInspectionConfig `json:"items"`
}

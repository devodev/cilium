// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sconst.CustomResourceDefinitionGroup

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v1alpha1"

	// IsovalentFQDNGroup (IFG)
	IFGPluralName     = "isovalentfqdngroups"
	IFGKindDefinition = "IsovalentFQDNGroup"
	IFGName           = IFGPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentSRv6SIDManager (SRv6SIDManager)
	SRv6SIDManagerPluralName     = "isovalentsrv6sidmanagers"
	SRv6SIDManagerKindDefinition = "IsovalentSRv6SIDManager"
	SRv6SIDManagerName           = SRv6SIDManagerPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentSRv6LocatorPool (SRv6LocatorPool)
	SRv6LocatorPoolPluralName     = "isovalentsrv6locatorpools"
	SRv6LocatorPoolKindDefinition = "IsovalentSRv6LocatorPool"
	SRv6LocatorPoolName           = SRv6LocatorPoolPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentSRv6EgressPolicy
	SRv6EgressPolicyPluralName     = "isovalentsrv6egresspolicies"
	SRv6EgressPolicyKindDefinition = "IsovalentSRv6EgressPolicy"
	SRv6EgressPolicyName           = SRv6EgressPolicyPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentVRF
	VRFPluralName     = "isovalentvrfs"
	VRFKindDefinition = "IsovalentVRF"
	VRFName           = VRFPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentPodNetwork (IPN)
	IPNPluralName     = "isovalentpodnetworks"
	IPNKindDefinition = "IsovalentPodNetwork"
	IPNName           = IPNPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentMulticastGroup (MulticastGroup)
	MulticastGroupPluralName     = "isovalentmulticastgroups"
	MulticastGroupKindDefinition = "IsovalentMulticastGroup"
	MulticastGroupName           = MulticastGroupPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentMulticastNode (MulticastNode)
	MulticastNodePluralName     = "isovalentmulticastnodes"
	MulticastNodeKindDefinition = "IsovalentMulticastNode"
	MulticastNodeName           = MulticastNodePluralName + "." + CustomResourceDefinitionGroup

	// IsovalentInspectionConfig
	IsovalentInspectionConfigPluralName     = "isovalentinspectionconfigs"
	IsovalentInspectionConfigKindDefinition = "IsovalentInspectionConfig"
	IsovalentInspectionConfigName           = IsovalentInspectionConfigPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentBFDProfile
	IsovalentBFDProfilePluralName     = "isovalentbfdprofiles"
	IsovalentBFDProfileKindDefinition = "IsovalentBFDProfile"
	IsovalentBFDProfileName           = IsovalentBFDProfilePluralName + "." + CustomResourceDefinitionGroup

	// IsovalentBFDNodeConfig
	IsovalentBFDNodeConfigPluralName     = "isovalentbfdnodeconfigs"
	IsovalentBFDNodeConfigKindDefinition = "IsovalentBFDNodeConfig"
	IsovalentBFDNodeConfigName           = IsovalentBFDNodeConfigPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentBFDNodeConfigOverride
	IsovalentBFDNodeConfigOverridePluralName     = "isovalentbfdnodeconfigoverrides"
	IsovalentBFDNodeConfigOverrideKindDefinition = "IsovalentBFDNodeConfigOverride"
	IsovalentBFDNodeConfigOverrideName           = IsovalentBFDNodeConfigOverridePluralName + "." + CustomResourceDefinitionGroup

	// Isovalent BGPv2 CRDs
	IsovalentBGPVRFConfigPluralName     = "isovalentbgpvrfconfigs"
	IsovalentBGPVRFConfigKindDefinition = "IsovalentBGPVRFConfig"
	IsovalentBGPVRFConfigName           = IsovalentBGPVRFConfigPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentEncryptionPolicy (IEP/ICEP)
	ICEPPluralName     = "isovalentclusterwideencryptionpolicies"
	ICEPKindDefinition = "IsovalentClusterwideEncryptionPolicy"
	ICEPName           = ICEPPluralName + "." + CustomResourceDefinitionGroup

	// LBServices
	LBServicePluralName     = "lbservices"
	LBServiceKindDefinition = "LBService"
	LBServiceName           = LBServicePluralName + "." + CustomResourceDefinitionGroup

	// LBBackendPool
	LBBackendPoolPluralName     = "lbbackendpools"
	LBBackendPoolKindDefinition = "LBBackendPool"
	LBBackendPoolName           = LBBackendPoolPluralName + "." + CustomResourceDefinitionGroup

	// LBVIP
	LBVIPPluralName     = "lbvips"
	LBVIPKindDefinition = "LBVIP"
	LBVIPName           = LBVIPPluralName + "." + CustomResourceDefinitionGroup

	// LBDeployment
	LBDeploymentPluralName     = "lbdeployments"
	LBDeploymentKindDefinition = "LBDeployment"
	LBDeploymentName           = LBDeploymentPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentWAFPolicy
	IsovalentWAFPolicyPluralName     = "isovalentwafpolicies"
	IsovalentWAFPolicyKindDefinition = "IsovalentWAFPolicy"
	IsovalentWAFPolicyName           = IsovalentWAFPolicyPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentNetworkPolicy (INP/INCP)
	IsovalentNetworkPolicyPluralName                = "isovalentnetworkpolicies"
	IsovalentClusterwideNetworkPolicyPluralName     = "isovalentclusterwidenetworkpolicies"
	IsovalentNetworkPolicyKindDefinition            = "IsovalentNetworkPolicy"
	IsovalentClusterwideNetworkPolicyKindDefinition = "IsovalentClusterwideNetworkPolicy"
	IsovalentNetworkPolicyName                      = IsovalentNetworkPolicyPluralName + "." + CustomResourceDefinitionGroup
	IsovalentClusterwideNetworkPolicyName           = IsovalentClusterwideNetworkPolicyPluralName + "." + CustomResourceDefinitionGroup

	// ClusterwidePrivateNetwork
	ClusterwidePrivateNetworkPluralName     = "clusterwideprivatenetworks"
	ClusterwidePrivateNetworkKindDefinition = "ClusterwidePrivateNetwork"
	ClusterwidePrivateNetworkName           = ClusterwidePrivateNetworkPluralName + "." + CustomResourceDefinitionGroup

	// PrivateNetworkEndpointSlice
	PrivateNetworkEndpointSlicePluralName     = "privatenetworkendpointslices"
	PrivateNetworkEndpointSliceKindDefinition = "PrivateNetworkEndpointSlice"
	PrivateNetworkEndpointSliceName           = PrivateNetworkEndpointSlicePluralName + "." + CustomResourceDefinitionGroup

	// PrivateNetworkExternalEndpoint
	PrivateNetworkExternalEndpointPluralName     = "privatenetworkexternalendpoints"
	PrivateNetworkExternalEndpointKindDefinition = "PrivateNetworkExternalEndpoint"
	PrivateNetworkExternalEndpointName           = PrivateNetworkExternalEndpointPluralName + "." + CustomResourceDefinitionGroup

	// PrivateNetworkNodeAttachment
	PrivateNetworkNodeAttachmentPluralName     = "privatenetworknodeattachments"
	PrivateNetworkNodeAttachmentKindDefinition = "PrivateNetworkNodeAttachment"
	PrivateNetworkNodeAttachmentName           = PrivateNetworkNodeAttachmentPluralName + "." + CustomResourceDefinitionGroup

	// LBK8sBackendCluster
	LBK8sBackendClusterPluralName     = "lbk8sbackendclusters"
	LBK8sBackendClusterKindDefinition = "LBK8sBackendCluster"
	LBK8sBackendClusterName           = LBK8sBackendClusterPluralName + "." + CustomResourceDefinitionGroup

	// FabricSecurityGroup
	FabricSecurityGroupPluralName     = "fabricsecuritygroups"
	FabricSecurityGroupKindDefinition = "FabricSecurityGroup"
	FabricSecurityGroupName           = FabricSecurityGroupPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentCoreVRF (ICVRF)
	ICVRFPluralName     = "isovalentcorevrfs"
	ICVRFKindDefinition = "IsovalentCoreVRF"
	ICVRFName           = ICVRFPluralName + "." + CustomResourceDefinitionGroup

	// IsovalentCoreVRFNodeStatus (ICVRFNS)
	ICVRFNSPluralName     = "isovalentcorevrfnodestatuses"
	ICVRFNSKindDefinition = "IsovalentCoreVRFNodeStatus"
	ICVRFNSName           = ICVRFNSPluralName + "." + CustomResourceDefinitionGroup
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{
	Group:   CustomResourceDefinitionGroup,
	Version: CustomResourceDefinitionVersion,
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder is needed by DeepCopy generator.
	SchemeBuilder runtime.SchemeBuilder
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds all types of this clientset into the given scheme.
	// This allows composition of clientsets, like in:
	//
	//   import (
	//     "k8s.io/client-go/kubernetes"
	//     clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	//     aggregatorclientsetscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	//   )
	//
	//   kclientset, _ := kubernetes.NewForConfig(c)
	//   aggregatorclientsetscheme.AddToScheme(clientsetscheme.Scheme)
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&IsovalentFQDNGroup{},
		&IsovalentFQDNGroupList{},
		&IsovalentSRv6SIDManager{},
		&IsovalentSRv6LocatorPool{},
		&IsovalentSRv6LocatorPoolList{},
		&IsovalentSRv6SIDManagerList{},
		&IsovalentVRF{},
		&IsovalentVRFList{},
		&IsovalentSRv6EgressPolicy{},
		&IsovalentSRv6EgressPolicyList{},
		&IsovalentPodNetwork{},
		&IsovalentPodNetworkList{},
		&IsovalentMulticastGroup{},
		&IsovalentMulticastGroupList{},
		&IsovalentMulticastNode{},
		&IsovalentMulticastNodeList{},
		&IsovalentInspectionConfig{},
		&IsovalentInspectionConfigList{},
		&IsovalentBFDProfile{},
		&IsovalentBFDProfileList{},
		&IsovalentBFDNodeConfig{},
		&IsovalentBFDNodeConfigList{},
		&IsovalentBFDNodeConfigOverride{},
		&IsovalentBFDNodeConfigOverrideList{},
		&IsovalentBGPClusterConfig{},
		&IsovalentBGPClusterConfigList{},
		&IsovalentBGPPeerConfig{},
		&IsovalentBGPPeerConfigList{},
		&IsovalentBGPAdvertisement{},
		&IsovalentBGPAdvertisementList{},
		&IsovalentBGPNodeConfig{},
		&IsovalentBGPNodeConfigList{},
		&IsovalentBGPNodeConfigOverride{},
		&IsovalentBGPNodeConfigOverrideList{},
		&IsovalentBGPVRFConfig{},
		&IsovalentBGPVRFConfigList{},
		&IsovalentClusterwideEncryptionPolicy{},
		&LBService{},
		&LBServiceList{},
		&LBBackendPool{},
		&LBBackendPoolList{},
		&LBVIP{},
		&LBVIPList{},
		&LBDeployment{},
		&LBDeploymentList{},
		&IsovalentWAFPolicy{},
		&IsovalentWAFPolicyList{},
		&IsovalentNetworkPolicy{},
		&IsovalentNetworkPolicyList{},
		&IsovalentClusterwideNetworkPolicy{},
		&IsovalentClusterwideNetworkPolicyList{},
		&ClusterwidePrivateNetwork{},
		&ClusterwidePrivateNetworkList{},
		&PrivateNetworkEndpointSlice{},
		&PrivateNetworkEndpointSliceList{},
		&PrivateNetworkExternalEndpoint{},
		&PrivateNetworkExternalEndpointList{},
		&PrivateNetworkNodeAttachment{},
		&PrivateNetworkNodeAttachmentList{},
		&LBK8sBackendCluster{},
		&LBK8sBackendClusterList{},
		&FabricSecurityGroup{},
		&FabricSecurityGroupList{},
		&IsovalentCoreVRF{},
		&IsovalentCoreVRFList{},
		&IsovalentCoreVRFNodeStatus{},
		&IsovalentCoreVRFNodeStatusList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	_ "embed"
	"fmt"
	"log/slog"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s/apis/crdhelpers"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com"
	k8sconstv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sconstv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	// IFGCRDName is the full name of the IsovalentFQDNGroup CRD.
	IFGCRDName = k8sconstv1alpha1.IFGKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IEGPCRDName is the full name of the IsovalentEgressGatewayPolicy CRD.
	IEGPCRDName = k8sconstv1.IEGPKindDefinition + "/" + k8sconstv1.CustomResourceDefinitionVersion

	// SRv6SIDManagerName is the full name of the IsovalentSRv6SIDManager CRD.
	SRv6SIDManagerName = k8sconstv1alpha1.SRv6SIDManagerKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// SRv6LocatorPoolName is the full name of the SRv6LocatorPool CRD.
	SRv6LocatorPoolName = k8sconstv1alpha1.SRv6LocatorPoolKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// SRv6EgressPolicyName is the full name of the IsovalentSRv6EgressPolicy CRD.
	SRv6EgressPolicyName = k8sconstv1alpha1.SRv6EgressPolicyKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// VRFName is the full name of the IsovalentSRv6EgressPolicy CRD.
	VRFName = k8sconstv1alpha1.VRFKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// MulticastGroupCRDName is the full name of the MulticastGroup CRD.
	MulticastGroupCRDName = k8sconstv1alpha1.MulticastGroupKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// MulticastNodeCRDName is the full name of the MulticastNode CRD.
	MulticastNodeCRDName = k8sconstv1alpha1.MulticastNodeKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentBFDProfileCRDName is the full name of the IsovalentBFDProfile CRD.
	IsovalentBFDProfileCRDName = k8sconstv1alpha1.IsovalentBFDProfileKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentBFDNodeConfigCRDName is the full name of the IsovalentBFDNodeConfig CRD.
	IsovalentBFDNodeConfigCRDName = k8sconstv1alpha1.IsovalentBFDNodeConfigKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentBFDNodeConfigOverrideCRDName is the full name of the IsovalentBFDNodeConfigOverride CRD.
	IsovalentBFDNodeConfigOverrideCRDName = k8sconstv1alpha1.IsovalentBFDNodeConfigOverrideKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentBGPClusterConfigCRDName is the full name of the IsovalentBGPClusterConfig CRD.
	IsovalentBGPClusterConfigCRDName = k8sconstv1.IsovalentBGPClusterConfigKindDefinition + "/" + k8sconstv1.CustomResourceDefinitionVersion

	// IsovalentBGPPeerConfigCRDName is the full name of the IsovalentBGPPeerConfig CRD.
	IsovalentBGPPeerConfigCRDName = k8sconstv1.IsovalentBGPPeerConfigKindDefinition + "/" + k8sconstv1.CustomResourceDefinitionVersion

	// IsovalentBGPAdvertisementCRDName is the full name of the IsovalentBGPAdvertisement CRD.
	IsovalentBGPAdvertisementCRDName = k8sconstv1.IsovalentBGPAdvertisementKindDefinition + "/" + k8sconstv1.CustomResourceDefinitionVersion

	// IsovalentBGPNodeConfigCRDName is the full name of the IsovalentBGPNodeConfig CRD.
	IsovalentBGPNodeConfigCRDName = k8sconstv1.IsovalentBGPNodeConfigKindDefinition + "/" + k8sconstv1.CustomResourceDefinitionVersion

	// IsovalentBGPPolicyCRDName is the full name of the IsovalentBGPPolicy CRD.
	IsovalentBGPPolicyCRDName = k8sconstv1.IsovalentBGPPolicyKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentBGPNodeConfigOverrideCRDName is the full name of the IsovalentBGPNodeConfigOverride CRD.
	IsovalentBGPNodeConfigOverrideCRDName = k8sconstv1.IsovalentBGPNodeConfigOverrideKindDefinition + "/" + k8sconstv1.CustomResourceDefinitionVersion

	// IsovalentBGPVRFConfigCRDName is the full name of the IsovalentBGPVRFConfig CRD.
	IsovalentBGPVRFConfigCRDName = k8sconstv1alpha1.IsovalentBGPVRFConfigKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentClusterwideEncryptionPolicyCRDName is the full name of the IsovalentClusterwideEncryptionPolicyCRDName CRD.
	IsovalentClusterwideEncryptionPolicyCRDName = k8sconstv1alpha1.ICEPKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentInspectionConfigCRDName is the full name of the IsovalentInspectionConfig CRD.
	IsovalentInspectionConfigCRDName = k8sconstv1alpha1.IsovalentInspectionConfigKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// LBServiceCRDName is the full name of the LBService CRD.
	LBServiceCRDName = k8sconstv1alpha1.LBServiceKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// LBBackendPoolCRDName is the full name of the LBBackendPool CRD.
	LBBackendPoolCRDName = k8sconstv1alpha1.LBBackendPoolKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// LBVIPCRDName is the full name of the LBVIP CRD.
	LBVIPCRDName = k8sconstv1alpha1.LBVIPKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// LBDeploymentCRDName is the full name of the LBDeployment CRD.
	LBDeploymentCRDName = k8sconstv1alpha1.LBDeploymentKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// LBK8sBackendClusterCRDName is the full name of the LBK8sBackendCluster CRD.
	LBK8sBackendClusterCRDName = k8sconstv1alpha1.LBK8sBackendClusterKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentWAFPolicyCRDName is the full name of the IsovalentWAFPolicy CRD.
	IsovalentWAFPolicyCRDName = k8sconstv1alpha1.IsovalentWAFPolicyKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentNetworkPolicyName is the full name of the IsovalentNetworkPolicy CRD.
	IsovalentNetworkPolicyCRDName = k8sconstv1alpha1.IsovalentNetworkPolicyKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentClusterwideNetworkPolicyName is the full name of the IsovalentClusterwideNetworkPolicy CRD.
	IsovalentClusterwideNetworkPolicyCRDName = k8sconstv1alpha1.IsovalentClusterwideNetworkPolicyKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// ClusterwidePrivateNetworkCRDName is the full name of the ClusterwidePrivateNetwork CRD.
	ClusterwidePrivateNetworkCRDName = k8sconstv1alpha1.ClusterwidePrivateNetworkKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// PrivateNetworkEndpointSliceCRDName is the full name of the PrivateNetworkEndpointSlice CRD.
	PrivateNetworkEndpointSliceCRDName = k8sconstv1alpha1.PrivateNetworkEndpointSliceKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// PrivateNetworkExternalEndpointCRDName is the full name of the PrivateNetworkExternalEndpoint CRD.
	PrivateNetworkExternalEndpointCRDName = k8sconstv1alpha1.PrivateNetworkExternalEndpointKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// PrivateNetworkNodeAttachmentCRDName is the full name of the PrivateNetworkNodeAttachment CRD.
	PrivateNetworkNodeAttachmentCRDName = k8sconstv1alpha1.PrivateNetworkNodeAttachmentKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// FabricSecurityGroupCRDName is the full name of the FabricSecurityGroup CRD.
	FabricSecurityGroupCRDName = k8sconstv1alpha1.FabricSecurityGroupKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// ICVRFCRDName is the full name of the IsovalentCoreVRF CRD.
	ICVRFCRDName = k8sconstv1alpha1.ICVRFKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// ICVRFNSCRDName is the full name of the IsovalentCoreVRFNodeStatus CRD.
	ICVRFNSCRDName = k8sconstv1alpha1.ICVRFNSKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion
)

type CRDList struct {
	Name     string
	FullName string
}

// CustomResourceDefinitionList returns a map of CRDs
func CustomResourceDefinitionList() map[string]*CRDList {
	return map[string]*CRDList{
		synced.CRDResourceName(k8sconstv1alpha1.IFGName): {
			Name:     IFGCRDName,
			FullName: k8sconstv1alpha1.IFGName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.SRv6SIDManagerName): {
			Name:     SRv6SIDManagerName,
			FullName: k8sconstv1alpha1.SRv6SIDManagerName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.SRv6LocatorPoolName): {
			Name:     SRv6LocatorPoolName,
			FullName: k8sconstv1alpha1.SRv6LocatorPoolName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.SRv6EgressPolicyName): {
			Name:     SRv6EgressPolicyName,
			FullName: k8sconstv1alpha1.SRv6EgressPolicyName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.VRFName): {
			Name:     VRFName,
			FullName: k8sconstv1alpha1.VRFName,
		},
		synced.CRDResourceName(k8sconstv1.IEGPName): {
			Name:     IEGPCRDName,
			FullName: k8sconstv1.IEGPName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.MulticastGroupName): {
			Name:     MulticastGroupCRDName,
			FullName: k8sconstv1alpha1.MulticastGroupName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.MulticastNodeName): {
			Name:     MulticastNodeCRDName,
			FullName: k8sconstv1alpha1.MulticastNodeName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentBFDProfileName): {
			Name:     IsovalentBFDProfileCRDName,
			FullName: k8sconstv1alpha1.IsovalentBFDProfileName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentBFDNodeConfigName): {
			Name:     IsovalentBFDNodeConfigCRDName,
			FullName: k8sconstv1alpha1.IsovalentBFDNodeConfigName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentBFDNodeConfigOverrideName): {
			Name:     IsovalentBFDNodeConfigOverrideCRDName,
			FullName: k8sconstv1alpha1.IsovalentBFDNodeConfigOverrideName,
		},
		synced.CRDResourceName(k8sconstv1.IsovalentBGPClusterConfigName): {
			Name:     IsovalentBGPClusterConfigCRDName,
			FullName: k8sconstv1.IsovalentBGPClusterConfigName,
		},
		synced.CRDResourceName(k8sconstv1.IsovalentBGPPeerConfigName): {
			Name:     IsovalentBGPPeerConfigCRDName,
			FullName: k8sconstv1.IsovalentBGPPeerConfigName,
		},
		synced.CRDResourceName(k8sconstv1.IsovalentBGPAdvertisementName): {
			Name:     IsovalentBGPAdvertisementCRDName,
			FullName: k8sconstv1.IsovalentBGPAdvertisementName,
		},
		synced.CRDResourceName(k8sconstv1.IsovalentBGPNodeConfigName): {
			Name:     IsovalentBGPNodeConfigCRDName,
			FullName: k8sconstv1.IsovalentBGPNodeConfigName,
		},
		synced.CRDResourceName(k8sconstv1.IsovalentBGPNodeConfigOverrideName): {
			Name:     IsovalentBGPNodeConfigOverrideCRDName,
			FullName: k8sconstv1.IsovalentBGPNodeConfigOverrideName,
		},
		synced.CRDResourceName(k8sconstv1.IsovalentBGPPolicyName): {
			Name:     IsovalentBGPPolicyCRDName,
			FullName: k8sconstv1.IsovalentBGPPolicyName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentBGPVRFConfigName): {
			Name:     IsovalentBGPVRFConfigCRDName,
			FullName: k8sconstv1alpha1.IsovalentBGPVRFConfigName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.ICEPName): {
			Name:     IsovalentClusterwideEncryptionPolicyCRDName,
			FullName: k8sconstv1alpha1.ICEPName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentInspectionConfigName): {
			Name:     IsovalentInspectionConfigCRDName,
			FullName: k8sconstv1alpha1.IsovalentInspectionConfigName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.LBServiceName): {
			Name:     LBServiceCRDName,
			FullName: k8sconstv1alpha1.LBServiceName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.LBBackendPoolName): {
			Name:     LBBackendPoolCRDName,
			FullName: k8sconstv1alpha1.LBBackendPoolName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.LBVIPName): {
			Name:     LBVIPCRDName,
			FullName: k8sconstv1alpha1.LBVIPName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.LBDeploymentName): {
			Name:     LBDeploymentCRDName,
			FullName: k8sconstv1alpha1.LBDeploymentName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.LBK8sBackendClusterName): {
			Name:     LBK8sBackendClusterCRDName,
			FullName: k8sconstv1alpha1.LBK8sBackendClusterName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentWAFPolicyName): {
			Name:     IsovalentWAFPolicyCRDName,
			FullName: k8sconstv1alpha1.IsovalentWAFPolicyName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentNetworkPolicyName): {
			Name:     IsovalentNetworkPolicyCRDName,
			FullName: k8sconstv1alpha1.IsovalentNetworkPolicyName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentClusterwideNetworkPolicyName): {
			Name:     IsovalentClusterwideNetworkPolicyCRDName,
			FullName: k8sconstv1alpha1.IsovalentClusterwideNetworkPolicyName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.ClusterwidePrivateNetworkName): {
			Name:     ClusterwidePrivateNetworkCRDName,
			FullName: k8sconstv1alpha1.ClusterwidePrivateNetworkName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.PrivateNetworkEndpointSliceName): {
			Name:     PrivateNetworkEndpointSliceCRDName,
			FullName: k8sconstv1alpha1.PrivateNetworkEndpointSliceName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.PrivateNetworkExternalEndpointName): {
			Name:     PrivateNetworkExternalEndpointCRDName,
			FullName: k8sconstv1alpha1.PrivateNetworkExternalEndpointName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.PrivateNetworkNodeAttachmentName): {
			Name:     PrivateNetworkNodeAttachmentCRDName,
			FullName: k8sconstv1alpha1.PrivateNetworkNodeAttachmentName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.FabricSecurityGroupName): {
			Name:     FabricSecurityGroupCRDName,
			FullName: k8sconstv1alpha1.FabricSecurityGroupName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.ICVRFName): {
			Name:     ICVRFCRDName,
			FullName: k8sconstv1alpha1.ICVRFName,
		},
		synced.CRDResourceName(k8sconstv1alpha1.ICVRFNSName): {
			Name:     ICVRFNSCRDName,
			FullName: k8sconstv1alpha1.ICVRFNSName,
		},
	}
}

// CreateCustomResourceDefinitions creates our CRD objects in the Kubernetes
// cluster.
func CreateCustomResourceDefinitions(logger *slog.Logger, clientset apiextensionsclient.Interface) error {
	crds := CustomResourceDefinitionList()
	for _, r := range synced.AllIsovalentCRDResourceNames() {
		if crd, ok := crds[r]; ok {
			if err := createCRD(logger, crd.Name, crd.FullName)(clientset); err != nil {
				return err
			}
		} else {
			logging.Fatal(logger, fmt.Sprintf("Unknown resource %s. Please update pkg/k8s/apis/isovalent.com/client to understand this type.", r))
		}
	}

	return nil
}

var (
	//go:embed crds/v1alpha1/isovalentfqdngroups.yaml
	crdsv1Alpha1IsovalentFQDNGroups []byte

	//go:embed crds/v1alpha1/isovalentsrv6sidmanagers.yaml
	crdsv1Alpha1IsovalentSRv6SIDManagers []byte

	//go:embed crds/v1alpha1/isovalentsrv6locatorpools.yaml
	crdsv1Alpha1IsovalentSRv6LocatorPools []byte

	//go:embed crds/v1alpha1/isovalentsrv6egresspolicies.yaml
	crdsv1Alpha1IsovalentSRv6EgressPolicies []byte

	//go:embed crds/v1alpha1/isovalentvrfs.yaml
	crdsv1Alpha1IsovalentVRFs []byte

	//go:embed crds/v1/isovalentegressgatewaypolicies.yaml
	crdsv1IsovalentEgressGatewayPolicies []byte

	//go:embed crds/v1alpha1/isovalentmulticastgroups.yaml
	crdsv1Alpha1IsovalentMulticastGroups []byte

	//go:embed crds/v1alpha1/isovalentmulticastnodes.yaml
	crdsv1Alpha1IsovalentMulticastNodes []byte

	//go:embed crds/v1alpha1/isovalentbfdprofiles.yaml
	crdsv1Alpha1IsovalentBFDProfile []byte

	//go:embed crds/v1alpha1/isovalentbfdnodeconfigs.yaml
	crdsv1Alpha1IsovalentBFDNodeConfig []byte

	//go:embed crds/v1alpha1/isovalentbfdnodeconfigoverrides.yaml
	crdsv1Alpha1IsovalentBFDNodeConfigOverride []byte

	//go:embed crds/v1/isovalentbgpclusterconfigs.yaml
	crdsv1IsovalentBGPClusterConfigs []byte

	//go:embed crds/v1/isovalentbgppeerconfigs.yaml
	crdsv1IsovalentBGPPeerConfigs []byte

	//go:embed crds/v1/isovalentbgpadvertisements.yaml
	crdsv1IsovalentBGPAdvertisements []byte

	//go:embed crds/v1/isovalentbgpnodeconfigs.yaml
	crdsv1IsovalentBGPNodeConfigs []byte

	//go:embed crds/v1/isovalentbgpnodeconfigoverrides.yaml
	crdsv1IsovalentBGPNodeConfigOverrides []byte

	//go:embed crds/v1/isovalentbgppolicies.yaml
	crdsv1IsovalentBGPPolicies []byte

	//go:embed crds/v1alpha1/isovalentbgpvrfconfigs.yaml
	crdsv1Alpha1IsovalentBGPVRFConfigs []byte

	//go:embed crds/v1alpha1/isovalentclusterwideencryptionpolicies.yaml
	crdsv1Alpha1IsovalentClusterwideEncryptionPolicyOverrides []byte

	//go:embed crds/v1alpha1/isovalentinspectionconfigs.yaml
	crdsv1Alpha1IsovalentInspectionConfigs []byte

	//go:embed crds/v1alpha1/lbservices.yaml
	crdsv1Alpha1LBServices []byte

	//go:embed crds/v1alpha1/lbbackendpools.yaml
	crdsv1Alpha1LBBackendPools []byte

	//go:embed crds/v1alpha1/lbvips.yaml
	crdsv1Alpha1LBVIPs []byte

	//go:embed crds/v1alpha1/lbdeployments.yaml
	crdsv1Alpha1LBDeployments []byte

	//go:embed crds/v1alpha1/lbk8sbackendclusters.yaml
	crdsv1Alpha1LBK8sBackendClusters []byte

	//go:embed crds/v1alpha1/isovalentwafpolicies.yaml
	crdsv1Alpha1IsovalentWAFPolicies []byte

	//go:embed crds/v1alpha1/isovalentnetworkpolicies.yaml
	crdsv1Alpha1IsovalentNetworkPolicies []byte

	//go:embed crds/v1alpha1/isovalentclusterwidenetworkpolicies.yaml
	crdsv1Alpha1IsovalentClusterwideNetworkPolicies []byte

	//go:embed crds/v1alpha1/clusterwideprivatenetworks.yaml
	crdsv1Alpha1ClusterwidePrivateNetworks []byte

	//go:embed crds/v1alpha1/privatenetworkendpointslices.yaml
	crdsv1Alpha1PrivateNetworkEndpointSlices []byte

	//go:embed crds/v1alpha1/privatenetworkexternalendpoints.yaml
	crdsv1Alpha1PrivateNetworkExternalEndpoints []byte

	//go:embed crds/v1alpha1/privatenetworknodeattachments.yaml
	crdsv1Alpha1PrivateNetworkNodeAttachments []byte

	//go:embed crds/v1alpha1/fabricsecuritygroups.yaml
	crdsv1Alpha1FabricSecurityGroups []byte

	//go:embed crds/v1alpha1/isovalentcorevrfs.yaml
	crdsv1Alpha1IsovalentCoreVRFs []byte

	//go:embed crds/v1alpha1/isovalentcorevrfnodestatuses.yaml
	crdsv1Alpha1IsovalentCoreVRFNodeStatuses []byte
)

// GetPregeneratedCRD returns the pregenerated CRD based on the requested CRD
// name. The pregenerated CRDs are generated by the controller-gen tool and
// serialized into binary form by go-bindata. This function retrieves CRDs from
// the binary form.
func GetPregeneratedCRD(logger *slog.Logger, crdName string) apiextensionsv1.CustomResourceDefinition {
	var (
		err      error
		crdBytes []byte
	)

	scopedLog := logger.With(logfields.Name, crdName)

	switch crdName {
	case IFGCRDName:
		crdBytes = crdsv1Alpha1IsovalentFQDNGroups
	case SRv6SIDManagerName:
		crdBytes = crdsv1Alpha1IsovalentSRv6SIDManagers
	case SRv6LocatorPoolName:
		crdBytes = crdsv1Alpha1IsovalentSRv6LocatorPools
	case SRv6EgressPolicyName:
		crdBytes = crdsv1Alpha1IsovalentSRv6EgressPolicies
	case VRFName:
		crdBytes = crdsv1Alpha1IsovalentVRFs
	case IEGPCRDName:
		crdBytes = crdsv1IsovalentEgressGatewayPolicies
	case MulticastGroupCRDName:
		crdBytes = crdsv1Alpha1IsovalentMulticastGroups
	case MulticastNodeCRDName:
		crdBytes = crdsv1Alpha1IsovalentMulticastNodes
	case IsovalentBFDProfileCRDName:
		crdBytes = crdsv1Alpha1IsovalentBFDProfile
	case IsovalentBFDNodeConfigCRDName:
		crdBytes = crdsv1Alpha1IsovalentBFDNodeConfig
	case IsovalentBFDNodeConfigOverrideCRDName:
		crdBytes = crdsv1Alpha1IsovalentBFDNodeConfigOverride
	case IsovalentBGPClusterConfigCRDName:
		crdBytes = crdsv1IsovalentBGPClusterConfigs
	case IsovalentBGPPeerConfigCRDName:
		crdBytes = crdsv1IsovalentBGPPeerConfigs
	case IsovalentBGPAdvertisementCRDName:
		crdBytes = crdsv1IsovalentBGPAdvertisements
	case IsovalentBGPNodeConfigCRDName:
		crdBytes = crdsv1IsovalentBGPNodeConfigs
	case IsovalentBGPNodeConfigOverrideCRDName:
		crdBytes = crdsv1IsovalentBGPNodeConfigOverrides
	case IsovalentBGPPolicyCRDName:
		crdBytes = crdsv1IsovalentBGPPolicies
	case IsovalentBGPVRFConfigCRDName:
		crdBytes = crdsv1Alpha1IsovalentBGPVRFConfigs
	case IsovalentClusterwideEncryptionPolicyCRDName:
		crdBytes = crdsv1Alpha1IsovalentClusterwideEncryptionPolicyOverrides
	case IsovalentInspectionConfigCRDName:
		crdBytes = crdsv1Alpha1IsovalentInspectionConfigs
	case LBServiceCRDName:
		crdBytes = crdsv1Alpha1LBServices
	case LBBackendPoolCRDName:
		crdBytes = crdsv1Alpha1LBBackendPools
	case LBVIPCRDName:
		crdBytes = crdsv1Alpha1LBVIPs
	case LBDeploymentCRDName:
		crdBytes = crdsv1Alpha1LBDeployments
	case LBK8sBackendClusterCRDName:
		crdBytes = crdsv1Alpha1LBK8sBackendClusters
	case IsovalentWAFPolicyCRDName:
		crdBytes = crdsv1Alpha1IsovalentWAFPolicies
	case IsovalentNetworkPolicyCRDName:
		crdBytes = crdsv1Alpha1IsovalentNetworkPolicies
	case IsovalentClusterwideNetworkPolicyCRDName:
		crdBytes = crdsv1Alpha1IsovalentClusterwideNetworkPolicies
	case ClusterwidePrivateNetworkCRDName:
		crdBytes = crdsv1Alpha1ClusterwidePrivateNetworks
	case PrivateNetworkEndpointSliceCRDName:
		crdBytes = crdsv1Alpha1PrivateNetworkEndpointSlices
	case PrivateNetworkExternalEndpointCRDName:
		crdBytes = crdsv1Alpha1PrivateNetworkExternalEndpoints
	case PrivateNetworkNodeAttachmentCRDName:
		crdBytes = crdsv1Alpha1PrivateNetworkNodeAttachments
	case FabricSecurityGroupCRDName:
		crdBytes = crdsv1Alpha1FabricSecurityGroups
	case ICVRFCRDName:
		crdBytes = crdsv1Alpha1IsovalentCoreVRFs
	case ICVRFNSCRDName:
		crdBytes = crdsv1Alpha1IsovalentCoreVRFNodeStatuses
	default:
		logging.Fatal(scopedLog, "Pregenerated CRD does not exist")
	}

	ciliumCRD := apiextensionsv1.CustomResourceDefinition{}
	err = yaml.Unmarshal(crdBytes, &ciliumCRD)
	if err != nil {
		logging.Fatal(scopedLog, "Error unmarshalling pregenerated CRD", logfields.Error, err)
	}

	return ciliumCRD
}

// createCRD returns a function that creates and updates a CRD.
func createCRD(logger *slog.Logger, crdName, fullName string) func(clientset apiextensionsclient.Interface) error {
	return func(clientset apiextensionsclient.Interface) error {
		ciliumCRD := GetPregeneratedCRD(logger, crdName)

		return crdhelpers.CreateUpdateCRD(
			logger,
			clientset,
			constructV1CRD(fullName, ciliumCRD),
			crdhelpers.NewDefaultPoller(),
			crdhelpers.NeedsUpdateV1Factory(
				k8sconst.CustomResourceDefinitionSchemaVersionKey,
				versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
			),
		)
	}
}

func constructV1CRD(
	name string,
	template apiextensionsv1.CustomResourceDefinition,
) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				k8sconst.CustomResourceDefinitionSchemaVersionKey: k8sconst.CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: k8sconst.CustomResourceDefinitionGroup,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:       template.Spec.Names.Kind,
				Plural:     template.Spec.Names.Plural,
				ShortNames: template.Spec.Names.ShortNames,
				Singular:   template.Spec.Names.Singular,
				Categories: template.Spec.Names.Categories,
			},
			Scope:    template.Spec.Scope,
			Versions: template.Spec.Versions,
		},
	}
}

// RegisterCRDs registers all CRDs with the K8s apiserver.
func RegisterCRDs(logger *slog.Logger, clientset client.Clientset) error {
	if err := CreateCustomResourceDefinitions(logger, clientset); err != nil {
		return fmt.Errorf("Unable to create custom resource definition: %w", err)
	}

	return nil
}

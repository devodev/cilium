//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package synced

import (
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/option"
)

// AllIsovalentCRDResourceNames returns a list of all Isovalent CRD resource
// names.
func AllIsovalentCRDResourceNames() []string {
	result := []string{
		CRDResourceName(v1alpha1.IFGName),
		CRDResourceName(v1alpha1.ICEPName),
		CRDResourceName(v1alpha1.IsovalentInspectionConfigName),
		CRDResourceName(v1alpha1.IsovalentNetworkPolicyName),
		CRDResourceName(v1alpha1.IsovalentClusterwideNetworkPolicyName),
		CRDResourceName(v1alpha1.IsovalentWAFPolicyName),
	}

	if option.Config.EnableSRv6 {
		result = append(result, CRDResourceName(v1alpha1.SRv6SIDManagerName))
		result = append(result, CRDResourceName(v1alpha1.SRv6LocatorPoolName))
		result = append(result, CRDResourceName(v1alpha1.SRv6EgressPolicyName))
		result = append(result, CRDResourceName(v1alpha1.VRFName))
	}

	if option.Config.EnableMulticast {
		result = append(result, CRDResourceName(v1alpha1.MulticastGroupName))
		result = append(result, CRDResourceName(v1alpha1.MulticastNodeName))
	}

	if option.Config.EnableBFD {
		result = append(result, CRDResourceName(v1alpha1.IsovalentBFDProfileName))
		result = append(result, CRDResourceName(v1alpha1.IsovalentBFDNodeConfigName))
		result = append(result, CRDResourceName(v1alpha1.IsovalentBFDNodeConfigOverrideName))
	}

	if option.Config.EnableEnterpriseBGPControlPlane {
		result = append(result, CRDResourceName(v1.IsovalentBGPClusterConfigName))
		result = append(result, CRDResourceName(v1.IsovalentBGPPeerConfigName))
		result = append(result, CRDResourceName(v1.IsovalentBGPAdvertisementName))
		result = append(result, CRDResourceName(v1.IsovalentBGPNodeConfigName))
		result = append(result, CRDResourceName(v1.IsovalentBGPNodeConfigOverrideName))
		result = append(result, CRDResourceName(v1.IsovalentBGPPolicyName))
		result = append(result, CRDResourceName(v1alpha1.IsovalentBGPVRFConfigName))
	}

	if option.Config.EnableIPv4EgressGatewayHA {
		result = append(result, CRDResourceName(v1.IEGPName))
	}

	if option.Config.LoadbalancerControlplaneEnabled {
		result = append(result, CRDResourceName(v1alpha1.LBVIPName))
		result = append(result, CRDResourceName(v1alpha1.LBServiceName))
		result = append(result, CRDResourceName(v1alpha1.LBBackendPoolName))
		result = append(result, CRDResourceName(v1alpha1.LBDeploymentName))
		result = append(result, CRDResourceName(v1alpha1.LBK8sBackendClusterName))
	}

	if option.Config.EnablePrivateNetworks {
		result = append(result, CRDResourceName(v1alpha1.ClusterwidePrivateNetworkName))
		result = append(result, CRDResourceName(v1alpha1.PrivateNetworkEndpointSliceName))
		result = append(result, CRDResourceName(v1alpha1.PrivateNetworkExternalEndpointName))
		result = append(result, CRDResourceName(v1alpha1.PrivateNetworkNodeAttachmentName))
	}

	if option.Config.EnableEVPN {
		result = append(result, CRDResourceName(v1alpha1.FabricSecurityGroupName))
	}

	if option.Config.EnableVRF {
		result = append(result, CRDResourceName(v1alpha1.ICVRFName))
		result = append(result, CRDResourceName(v1alpha1.ICVRFNSName))
	}

	return result
}

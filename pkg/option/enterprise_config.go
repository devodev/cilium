//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package option

import (
	"github.com/spf13/viper"

	bgpconfig "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	bfdtypes "github.com/cilium/cilium/enterprise/pkg/bfd/types"
)

// Enterprise specific command line arguments.
const (
	// EnableIPv4EgressGateway enables the IPv4 egress gateway
	EnableIPv4EgressGatewayHA = "enable-ipv4-egress-gateway-ha"

	// LoadbalancerControlplaneEnabled enables Loadbalancer control plane
	LoadbalancerControlplaneEnabled = "loadbalancer-cp-enabled"

	// MulticastEnabled enables the Multicast feature
	MulticastEnabled = "multicast-enabled"

	// EVPNEnabled flag enables the EVPN feature
	EVPNEnabled = "enable-evpn"

	// VRFEnabled enables the VRF feature
	VRFEnabled = "enable-vrf"

	// PrivateNetworksEnabled enables private networks.
	PrivateNetworksEnabled = "private-networks-enabled"
)

type EnterpriseDaemonConfig struct {
	// Enable the HA egress gateway
	EnableIPv4EgressGatewayHA bool

	// LoadbalancerControlplaneEnabled enables Loadbalancer controlplane
	LoadbalancerControlplaneEnabled bool

	// Enable Enterprise BGP control plane
	EnableEnterpriseBGPControlPlane bool

	// Enable multicast feature
	EnableMulticast bool

	// Enable BFD subsystem
	EnableBFD bool

	// Enable private networks support
	EnablePrivateNetworks bool

	// Enable EVPN feature
	EnableEVPN bool

	// Enable VRF feature
	EnableVRF bool
}

func (ec *EnterpriseDaemonConfig) Populate(vp *viper.Viper) {
	ec.EnableIPv4EgressGatewayHA = vp.GetBool(EnableIPv4EgressGatewayHA)
	ec.LoadbalancerControlplaneEnabled = vp.GetBool(LoadbalancerControlplaneEnabled)
	ec.EnableEnterpriseBGPControlPlane = vp.GetBool(bgpconfig.EnterpriseBGPEnabled)
	ec.EnableMulticast = vp.GetBool(MulticastEnabled)
	ec.EnableBFD = vp.GetBool(bfdtypes.EnableBFDFlag)
	ec.EnablePrivateNetworks = vp.GetBool(PrivateNetworksEnabled)
	ec.EnableEVPN = vp.GetBool(EVPNEnabled)
	ec.EnableVRF = vp.GetBool(VRFEnabled)
}

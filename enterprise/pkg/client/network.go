//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package client

import (
	"github.com/cilium/cilium/enterprise/api/v1/client/network"
	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

func (c *EnterpriseClient) PrivateNetworkAddressing(net, subnet, podNamespace, podName, podUID, ifname string) (*models.PrivateNetworkAddressingResponse, error) {
	params := network.NewGetNetworkPrivateAddressingParams().
		WithPodNamespace(podNamespace).
		WithPodName(podName).
		WithPodUID(podUID).
		WithIfname(ifname).
		WithTimeout(api.ClientTimeout)

	if net != "" {
		params.SetNetwork(&net)
	}

	if subnet != "" {
		params.SetSubnet(&subnet)
	}

	resp, err := c.Network.GetNetworkPrivateAddressing(params)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

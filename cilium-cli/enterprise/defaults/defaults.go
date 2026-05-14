//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package defaults

import "time"

const (
	// EgressGatewayConnectRetryDefault is the default number of retries on connection failure for EGW IPAM tests
	EgressGatewayConnectRetryDefault = 5
	// EgressGatewayConnectRetryDelayDefault is the default delay between retries on connection failure for EGW IPAM tests
	EgressGatewayConnectRetryDelayDefault = 5 * time.Second

	// ExternalCiliumDNSProxyName is the prefix for the external Cilium DNS proxy pods (and the daemonset).
	ExternalCiliumDNSProxyName = "cilium-dnsproxy"

	// EgressGatewayPeerASN is the default number of BGP ASN
	EgressGatewayPeerASN = 65000

	EgressGatewayPeerAddress = ""
)

var (
	// EgressGatewayCIDRsDefault is the default list of CIDRs to use when allocating egress IPs for EGW IPAM tests
	EgressGatewayCIDRsDefault = []string{"172.18.0.8/30"}

	PrivnetTestImages = map[string]string{
		// renovate: datasource=docker
		"VMImage": "quay.io/kubevirt/alpine-with-test-tooling-container-disk:v1.8.2@sha256:814999dc874b6bc34ac2d809779cb92301cdb1f8a6fc100ce9eb386482b5d1df",
		// renovate: datasource=docker
		"MockVMImage": "ghcr.io/nicolaka/netshoot:v0.15@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61",
	}
)

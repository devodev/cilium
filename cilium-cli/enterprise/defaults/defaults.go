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
		"VMImage": "quay.io/kubevirt/alpine-with-test-tooling-container-disk:v1.8.4@sha256:a6f3d9ffffa7d1e4cd19aa80aae21abfc09dd289db854b4098c7ed2e14e21b55",
		// renovate: datasource=docker
		"MockVMImage": "ghcr.io/nicolaka/netshoot:v0.16@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70",
	}
)

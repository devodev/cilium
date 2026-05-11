//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/features"
	"github.com/cilium/cilium/enterprise/operator/dnsclient"
	"github.com/cilium/cilium/enterprise/operator/dnsresolver"
	enterpriseOperatorK8s "github.com/cilium/cilium/enterprise/operator/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bfd"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2"
	"github.com/cilium/cilium/enterprise/operator/pkg/evpn"
	enterprisegatewayapi "github.com/cilium/cilium/enterprise/operator/pkg/gateway-api"
	"github.com/cilium/cilium/enterprise/operator/pkg/lb"
	"github.com/cilium/cilium/enterprise/operator/pkg/multinetwork"
	"github.com/cilium/cilium/enterprise/operator/pkg/networkpolicy"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet"
	"github.com/cilium/cilium/enterprise/operator/pkg/srv6/locatorpool"
	"github.com/cilium/cilium/enterprise/operator/pkg/wafpolicy"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/phantom"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/operator/cmd"

	metricsFeatures "github.com/cilium/cilium/pkg/metrics/features/operator"
)

var (
	EnterpriseOperator = cell.Module(
		"enterprise-operator",
		"Cilium Operator Enterprise",

		cmd.Operator(),

		// enterprise-only cells here

		// Part of the private-networks functionalities need to run in all
		// replicas, and not just the leader. Hence, the Lifecycle
		// decoration is performed internally.
		privnet.Cell,

		cell.Decorate(
			func(lc *cmd.LeaderLifecycle) cell.Lifecycle {
				return lc
			},

			// enterprise-only cells to be started after leader election here
			enterpriseOperatorK8s.ResourcesCell,

			features.OperatorCell,

			locatorpool.Cell,

			dnsclient.Cell,
			dnsresolver.Cell,

			egressgatewayha.OperatorCell,
			egressgatewayha.PolicyCell,
			healthcheck.Cell,
			cell.Invoke(func(*egressgatewayha.OperatorManager) {}),

			multinetwork.Cell,
			bgpv2.Cell,
			bfd.Cell,
			evpn.Cell,

			wafpolicy.Cell,

			// Isovalent Loadbalancer controlplane
			lb.Cell,

			// Enterprise Gateway API extensions & controllers
			enterprisegatewayapi.Cell,

			networkpolicy.Cell,

			clustercfg.Cell,
			phantom.Cell,

			metricsFeatures.EnterpriseCell,
		),
	)
)

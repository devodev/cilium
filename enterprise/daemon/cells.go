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

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/api/v1/server"
	"github.com/cilium/cilium/enterprise/features"
	"github.com/cilium/cilium/enterprise/pkg/api"
	"github.com/cilium/cilium/enterprise/pkg/bfd"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1"
	cecm "github.com/cilium/cilium/enterprise/pkg/clustermesh"
	"github.com/cilium/cilium/enterprise/pkg/config"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	segw "github.com/cilium/cilium/enterprise/pkg/egressgatewayha/standalone"
	encryptionPolicy "github.com/cilium/cilium/enterprise/pkg/encryption/policy"
	"github.com/cilium/cilium/enterprise/pkg/evpn"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha"
	"github.com/cilium/cilium/enterprise/pkg/healthconfig"
	"github.com/cilium/cilium/enterprise/pkg/hubble"
	cecIngressPolicy "github.com/cilium/cilium/enterprise/pkg/ingresspolicy"
	"github.com/cilium/cilium/enterprise/pkg/inspection"
	"github.com/cilium/cilium/enterprise/pkg/lb"
	cemaps "github.com/cilium/cilium/enterprise/pkg/maps"
	"github.com/cilium/cilium/enterprise/pkg/mixedrouting"
	"github.com/cilium/cilium/enterprise/pkg/multicast"
	"github.com/cilium/cilium/enterprise/pkg/nat/stats"
	policyK8s "github.com/cilium/cilium/enterprise/pkg/policy/k8s"
	"github.com/cilium/cilium/enterprise/pkg/privnet"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/enterprise/pkg/service/healthchecker"
	srv6dataplane "github.com/cilium/cilium/enterprise/pkg/srv6/dataplane"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/enterprise/pkg/tunnelip"
	"github.com/cilium/cilium/enterprise/pkg/vrf"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/k8s/synced"
	metricsFeatures "github.com/cilium/cilium/pkg/metrics/features"
)

var (
	EnterpriseAgent = cell.Module(
		"enterprise-agent",
		"Cilium Agent Enterprise",

		cmd.Agent,

		// enterprise-only cells here
		Infrastructure,
		ControlPlane,
		Datapath,

		// Self-diagnostics
		agentDiagnostics,

		// Feature gating to prevent use of unsupported features
		features.AgentCell,
	)

	Infrastructure = cell.Module(
		"enterprise-infra",
		"Infrastructure Enterprise",

		// Ensure that we also wait for the enterprise CRDs to appear.
		cell.Provide(func() synced.CRDSyncResourceNamesOut {
			return synced.NewCRDSyncResourceNamesOut(synced.AllIsovalentCRDResourceNames()...)
		}),
	)

	ControlPlane = cell.Module(
		"enterprise-controlplane",
		"Control Plane Enterprise",

		api.Cell,
		server.SpecCell,
		server.APICell,

		policyK8s.Cell,

		cecm.Cell,
		sidmanager.SIDManagerCell,
		srv6manager.Cell,
		srv6dataplane.Cell,
		bgpv1.Cell,
		bfd.Cell,
		rib.Cell,
		egressgatewayha.Cell,
		egressgatewayha.PolicyCell,
		segw.Cell,
		cell.Invoke(func(*egressgatewayha.Manager) {}),

		privnet.Cell,
		evpn.Cell,

		inspection.Cell,

		mixedrouting.Cell,
		tunnelip.Cell,
		encryptionPolicy.Cell,

		multicast.Cell,

		vrf.Cell,

		fqdnha.Cell,

		healthchecker.Cell,

		// stats cell adds CE specific metrics, such as the top-k nat stats metric
		// that depends on the OSS maps/nat/stats.Cell.
		stats.Cell,

		config.Cell,

		lb.Cell,

		hubble.Cell,

		cecIngressPolicy.Cell,

		metricsFeatures.EnterpriseCell,

		healthconfig.Cell,
	)

	Datapath = cell.Module(
		"enterprise-datapath",
		"Datapath Enterprise",

		cemaps.Cell,

		loader.EnterpriseCell,
	)
)

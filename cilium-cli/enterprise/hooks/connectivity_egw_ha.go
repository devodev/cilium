// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package hooks

import (
	"context"
	_ "embed"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/enterprise/defaults"
	enterpriseCheck "github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/check"
	enterpriseTests "github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/tests"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

//go:embed manifests/egw-ha/client-egress-icmp.yaml
var clientEgressICMPYAML string

//go:embed manifests/egw-ha/client-egress-l7-http-external-node.yaml
var clientEgressL7HTTPAnywhereYAML string

func (ec *EnterpriseConnectivity) addEgressGatewayHAFlags(flags *pflag.FlagSet) {
	flags.StringSliceVar(&enterpriseTests.Params.EgressGateway.CIDRs, "egw-ipam-cidrs", nil, "CIDRs to use to allocate Egress IPs in egress gateway ha ipam connectivity tests")
	flags.UintVar(&enterpriseTests.Params.EgressGateway.Retry, "egw-ipam-retry", defaults.EgressGatewayConnectRetryDefault, "Number of retries on connection failure to external targets for egress gateway ha IPAM tests")
	flags.DurationVar(&enterpriseTests.Params.EgressGateway.RetryDelay, "egw-ipam-retry-delay", defaults.EgressGatewayConnectRetryDelayDefault, "Delay between retries to external targets for egress gateway ha IPAM tests")
	flags.Int64Var(&enterpriseTests.Params.EgressGateway.PeerASN, "egw-bgp-asn", defaults.EgressGatewayPeerASN, "Number of peer ASN")
	flags.StringSliceVar(&enterpriseTests.Params.EgressGateway.PeerAddresses, "egw-bgp-peer-addresses", nil, "")
	flags.BoolVar(&enterpriseTests.Params.ConnDisrupt.IncludeConnDisruptTestEGWHA, "include-conn-disrupt-test-egw-ha", false, "Include conn disrupt test for Egress Gateway HA")
	flags.StringSliceVar(&enterpriseTests.Params.ConnDisrupt.EgressCIDRs, "conn-disrupt-egw-ha-egress-cidrs", nil, "CIDRs to use to allocate Egress IPs in EGW HA conn disrupt IEGPs")
}

func (ec *EnterpriseConnectivity) addEgressGatewayHATests(ct *check.ConnectivityTest, templates map[string]string) (err error) {
	newTest := func(ct *check.ConnectivityTest, name string) *enterpriseCheck.EnterpriseTest {
		return enterpriseCheck.NewEnterpriseConnectivityTest(ct).
			NewEnterpriseTest(name).
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.EgressGatewayHA),
				features.RequireEnabled(features.NodeWithoutCilium))
	}

	// prefix the test name with `seq-` to run it sequentially
	newTest(ct, "seq-egress-gateway-ha").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.SingleGateway,
		}).
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-echo",
			PodSelectorKind: "echo",
			EgressGroup:     enterpriseCheck.SingleGateway,
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(enterpriseTests.EgressGatewayHA())

	// prefix the test name with `seq-` to run it sequentially
	newTest(ct, "seq-egress-gateway-ha-with-l7-policy").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.SingleGateway,
		}).
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-echo",
			PodSelectorKind: "echo",
			EgressGroup:     enterpriseCheck.SingleGateway,
		}).
		WithCiliumPolicy(clientEgressICMPYAML).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).  // DNS resolution only
		WithCiliumPolicy(templates["clientEgressL7HTTPAnywhereYAML"]). // L7 allow policy with HTTP introspection
		WithIPRoutesFromOutsideToPodCIDRs().
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithScenarios(enterpriseTests.EgressGatewayHA())

	// prefix the test name with `seq-` to run it sequentially
	newTest(ct, "seq-egress-gateway-ha-excluded-cidrs").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.SingleGateway,
			ExcludedCIDRs:   enterpriseCheck.ExternalNodeExcludedCIDRs,
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(enterpriseTests.EgressGatewayExcludedCIDRs())

	// prefix the test name with `seq-` to run it sequentially
	newTest(ct, "seq-egress-gateway-ha-multiple-gateways").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.AllCiliumNodes,
		}).
		WithScenarios(enterpriseTests.EgressGatewayMultipleGateways())

	// prefix the test name with `seq-` to run it sequentially
	newTest(ct, "seq-egress-gateway-ha-multiple-gateways-with-l7-policy").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.AllCiliumNodes,
		}).
		WithCiliumPolicy(clientEgressICMPYAML).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).  // DNS resolution only
		WithCiliumPolicy(templates["clientEgressL7HTTPAnywhereYAML"]). // L7 allow policy with HTTP introspection
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithScenarios(enterpriseTests.EgressGatewayMultipleGateways())

	// prefix the test name with `seq-` to run it sequentially
	egwHAAZAffinityTest := newTest(ct, "seq-egress-gateway-ha-az-affinity").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client-az-affinity",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.AllCiliumNodesWithAZAffinity,
			// We update the AZAffinity: "localOnly" setting after topology.kubernetes.io/zone has been set on the
			// Gateway nodes. This prevents error logs about missing node AZs from being emitted.
		})
	egwHAAZAffinityTest.WithScenarios(enterpriseTests.EgressGatewayAZAffinity(egwHAAZAffinityTest.Context().EntClients()))

	newIPAMTest := func(ct *check.ConnectivityTest, name string) *enterpriseCheck.EnterpriseTest {
		et := enterpriseCheck.NewEnterpriseConnectivityTest(ct).
			NewEnterpriseTestWithoutSetup(name).
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.EgressGatewayHA),
				features.RequireEnabled(features.NodeWithoutCilium))
		et.WithSetupFunc(func(ctx context.Context, t *check.Test, ct *check.ConnectivityTest) error {
			// get egress CIDRs to be used for IPAM before applying the policies
			egressCIDRs := enterpriseTests.IPAMEgressCIDRs(ctx, t, ct)
			if len(egressCIDRs) == 0 {
				egressCIDRs = defaults.EgressGatewayCIDRsDefault
			}
			t.Logf("Using egress CIDRs %v for IEGP IPAM", egressCIDRs)
			et.WithEgressCIDRsforIEGP("iegp-sample-client", egressCIDRs)
			return et.Setup(ctx)
		})
		return et
	}

	// prefix the test name with `seq-` to run it sequentially
	newIPAMTest(ct, "seq-egress-gateway-ha-ipam").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.SingleGateway,
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(enterpriseTests.EgressGatewayHAIPAM())

	// prefix the test name with `seq-` to run it sequentially
	newIPAMTest(ct, "seq-egress-gateway-ha-ipam-multiple-gateways").
		WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
			Name:            "iegp-sample-client",
			PodSelectorKind: "client",
			EgressGroup:     enterpriseCheck.AllCiliumNodes,
		}).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(enterpriseTests.EgressGatewayHAIPAMMultipleGateways())

	// This test depends on the Route Reflector feature of the BGP CP, which requires using
	// v1.18.1 or later.
	if versioncheck.MustCompile(">=1.18.1")(ct.CiliumVersion) {
		bfdEnabled, _ := ct.Features.MatchRequirements(features.RequireEnabled(enterpriseFeatures.BFD))
		// prefix the test name with `seq-` to run it sequentially
		newIPAMTest(ct, "seq-egress-gateway-ha-ipam-bgp-advertisement").
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.EnterpriseBGPControlPlane),
			).
			WithCondition(func() bool { return len(enterpriseTests.Params.EgressGateway.PeerAddresses) != 0 }).
			WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
				Name:            "iegp-sample-client",
				Labels:          map[string]string{"egw": "bgp-advertise"},
				PodSelectorKind: "client",
				EgressGroup:     enterpriseCheck.AllCiliumNodes,
			}).
			WithScenarios(enterpriseTests.EgressGatewayHABGPAdvertisement(bfdEnabled, false))
	}

	if versioncheck.MustCompile(">=1.18.1")(ct.CiliumVersion) {
		bfdEnabled, _ := ct.Features.MatchRequirements(features.RequireEnabled(enterpriseFeatures.BFD))
		// prefix the test name with `seq-` to run it sequentially
		newIPAMTest(ct, "seq-egress-gateway-ha-ipam-bgp-advertisement-with-l7-policy").
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.EnterpriseBGPControlPlane),
				features.RequireEnabled(enterpriseFeatures.CiliumDNSProxyHA),
				features.RequireEnabled(features.L7Proxy),
			).
			WithCondition(func() bool { return len(enterpriseTests.Params.EgressGateway.PeerAddresses) != 0 }).
			WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
				Name:            "iegp-sample-client",
				Labels:          map[string]string{"egw": "bgp-advertise"},
				PodSelectorKind: "client",
				EgressGroup:     enterpriseCheck.AllCiliumNodes,
			}).
			WithCiliumPolicy(clientEgressICMPYAML).
			WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).  // DNS resolution only
			WithCiliumPolicy(templates["clientEgressL7HTTPAnywhereYAML"]). // L7 allow policy with HTTP introspection
			WithScenarios(enterpriseTests.EgressGatewayHABGPAdvertisement(bfdEnabled, false))
	}

	if versioncheck.MustCompile(">=1.20.0")(ct.CiliumVersion) {
		bfdEnabled, _ := ct.Features.MatchRequirements(features.RequireEnabled(enterpriseFeatures.BFD))
		// prefix the test name with `seq-` to run it sequentially
		newIPAMTest(ct, "seq-egress-gateway-ha-ipam-bgp-advertisement-virtual-ip").
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.EnterpriseBGPControlPlane),
			).
			WithCondition(func() bool { return len(enterpriseTests.Params.EgressGateway.PeerAddresses) != 0 }).
			WithIsovalentEgressGatewayPolicy(enterpriseCheck.IsovalentEgressGatewayPolicyParams{
				Name:            "iegp-sample-client",
				Labels:          map[string]string{"egw": "bgp-advertise"},
				Annotations:     map[string]string{"egw.isovalent.com/virtual-ip": "true"},
				PodSelectorKind: "client",
				EgressGroup:     enterpriseCheck.AllCiliumNodes,
			}).
			WithScenarios(enterpriseTests.EgressGatewayHABGPAdvertisement(bfdEnabled, true))
	}

	return nil
}

func (ec *EnterpriseConnectivity) addEgressGatewayHAConnDisruptTest(ct *check.ConnectivityTest) error {
	enterpriseCheck.NewEnterpriseConnectivityTest(ct).
		NewEnterpriseTestWithoutSetup("no-interrupted-connections-for-enterprise").
		WithFeatureRequirements(
			features.RequireEnabled(enterpriseFeatures.EgressGatewayHA),
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(enterpriseTests.EnterpriseNoInterruptedConnections()).
		WithFinalizer(func(ctx context.Context) error {
			if !ct.Params().ConnDisruptTestSetup {
				return enterpriseCheck.NewEnterpriseConnectivityTest(ct).CleanupConnDisruptEGWHA(ctx)
			}
			return nil
		})

	return nil
}

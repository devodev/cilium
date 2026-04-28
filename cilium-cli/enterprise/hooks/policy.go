//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package hooks

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/network-policy/client-ingress-to-echo-ordered-ns.yaml
var clientIngressToEchoOrderedNS string

//go:embed manifests/network-policy/client-ingress-to-echo-ordered-wildcard.yaml
var clientIngressToEchoOrderedWildcard string

//go:embed manifests/network-policy/client-ingress-to-echo-tiered-ns.yaml
var clientIngressToEchoTieredNS string

//go:embed manifests/network-policy/client-ingress-to-echo-tiered-wildcard.yaml
var clientIngressToEchoTieredWildcard string

//go:embed manifests/network-policy/client-ingress-to-echo-tiered-wildcard-pass.yaml
var clientIngressToEchoTieredWildcardPass string

//go:embed manifests/network-policy/client-ingress-to-echo-ordered-portrange.yaml
var clientIngressToEchoOrderedPortrange string

var (
	clientLabel  = map[string]string{"name": "client"}
	client2Label = map[string]string{"name": "client2"}
)

func (ec *EnterpriseConnectivity) addOrderedPolicyTests(ct *check.ConnectivityTest, templates map[string]string) error {
	test1 := check.NewTest("ordered-policy-ns", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test1).
		WithResources(templates["clientIngressToEchoOrderedNS"]).
		WithCiliumVersion(">=1.17.0 !1.19.0"). // v1.19.0 didn't have ordered policy
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	test2 := check.NewTest("ordered-policy-wildcard", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test2).
		WithResources(templates["clientIngressToEchoOrderedWildcard"]).
		WithCiliumVersion(">=1.17.0 !1.19.0").
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	// This test triggered a latent proxylib bug -- not an ordered policy bug.
	// Proxylib was removed in v1.20
	test3 := check.NewTest("ordered-policy-portrange", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test3).
		WithResources(templates["clientIngressToEchoOrderedPortrange"]).
		WithCiliumVersion(">=1.20.0").
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	test4 := check.NewTest("tiered-policy-ns", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test4).
		WithResources(templates["clientIngressToEchoTieredNS"]).
		WithCiliumVersion(">=1.20.0").
		WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.NetworkPolicyTier)).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	test5 := check.NewTest("tiered-policy-wildcard", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test5).
		WithResources(templates["clientIngressToEchoTieredWildcard"]).
		WithCiliumVersion(">=1.20.0").
		WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.NetworkPolicyTier)).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	test6 := check.NewTest("tiered-policy-wildcard-pass", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test6).
		WithResources(templates["clientIngressToEchoTieredWildcardPass"]).
		WithCiliumVersion(">=1.20.0").
		WithFeatureRequirements(features.RequireEnabled(enterpriseFeatures.NetworkPolicyTier)).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	return nil
}

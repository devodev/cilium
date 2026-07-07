// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/cli"
	"github.com/cilium/cilium/cilium-cli/defaults"
	enterpriseDefaults "github.com/cilium/cilium/cilium-cli/enterprise/defaults"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/privnet"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func newClient(params cli.RootParameters) (*enterpriseK8s.EnterpriseClient, error) {
	ossClient, err := k8s.NewClient(
		params.ContextName,
		params.KubeConfig,
		params.Namespace,
		params.ImpersonateAs,
		params.ImpersonateGroups,
	)
	if err != nil {
		return &enterpriseK8s.EnterpriseClient{}, err
	}

	return enterpriseK8s.NewEnterpriseClient(ossClient)
}

func newCmdPrivNetTest() *cobra.Command {
	var (
		params              privnet.Params
		printImageArtifacts bool
	)

	cmd := &cobra.Command{
		Use:    "test",
		Short:  "Run Private Network tests",
		Long:   "",
		Hidden: true,
		RunE: func(c *cobra.Command, _ []string) error {
			params.CiliumNamespace = cli.RootParams.Namespace

			// Output the image artifacts and exit.
			if printImageArtifacts {
				fmt.Println(params.VMImage)
				fmt.Println(params.MockVMImage)
				return nil
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			c.SetContext(ctx)

			clusterClient, err := enterpriseK8s.NewEnterpriseClient(cli.RootK8sClient)
			if err != nil {
				return fmt.Errorf("failed to construct local client: %w", err)
			}

			inbClients := make([]*enterpriseK8s.EnterpriseClient, len(params.INBContexts))
			for i, context := range params.INBContexts {
				rootParams := cli.RootParameters{
					ContextName:       context,
					Namespace:         cli.RootParams.Namespace,
					ImpersonateAs:     cli.RootParams.ImpersonateAs,
					ImpersonateGroups: cli.RootParams.ImpersonateGroups,
					KubeConfig:        cli.RootParams.KubeConfig,
				}
				inbClients[i], err = newClient(rootParams)
				if err != nil {
					return fmt.Errorf("failed to construct INB client %q: %w", context, err)
				}
			}

			t := privnet.NewTestRun(ctx, cancel, params, clusterClient, inbClients)
			err = t.SetupAndValidate(ctx)
			if err != nil {
				return err
			}

			defer func() {
				// Use a separate context, as we want cleanup to run if terminating
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				t.Cleanup(ctx)
				cancel()
			}()

			vmClientA := t.VM(privnet.NetworkA, privnet.ClientVM(privnet.NetworkA))
			vmEchoA := t.VM(privnet.NetworkA, privnet.EchoVM(privnet.NetworkA))
			vmEchoOtherA := t.VM(privnet.NetworkA, privnet.EchoOtherVM(privnet.NetworkA))
			vmEchoAIPv4only := t.VM(privnet.NetworkA, privnet.EchoOtherVM(privnet.NetworkA)+"-ipv4-only")
			vmEchoAIPv6only := t.VM(privnet.NetworkA, privnet.EchoOtherVM(privnet.NetworkA)+"-ipv6-only")

			vmClientB := t.VM(privnet.NetworkB, privnet.ClientVM(privnet.NetworkB))
			vmEchoOtherB := t.VM(privnet.NetworkB, privnet.EchoOtherVM(privnet.NetworkB))

			vmClientC := t.VM(privnet.NetworkC, privnet.ClientVM(privnet.NetworkC))
			vmClientCIPv4Only := t.VM(privnet.NetworkC, privnet.ClientVM(privnet.NetworkC)+"-ipv4-only")
			vmClientCIPv6Only := t.VM(privnet.NetworkC, privnet.ClientVM(privnet.NetworkC)+"-ipv6-only")
			vmEchoOtherC := t.VM(privnet.NetworkC, privnet.EchoOtherVM(privnet.NetworkC))
			podEchoOtherC := t.VirtLauncherPodForVM(vmEchoOtherC)

			vmClientD := t.VM(privnet.NetworkD, privnet.ClientVM(privnet.NetworkD))

			externalTarget := params.ExternalTarget
			externalIPTarget := params.ExternalIPTarget

			// Network E: local-access network (VLAN-attached, no INB).
			vmClientDHCPE := t.VM(privnet.NetworkE, privnet.DHCPVM(privnet.NetworkE))
			vmEchoE := t.VM(privnet.NetworkE, privnet.EchoVM(privnet.NetworkE))
			vmEchoOtherE := t.VM(privnet.NetworkE, privnet.EchoOtherVM(privnet.NetworkE))
			vmUnknownE1 := t.UnknownVM(privnet.NetworkE, privnet.FakeVM(privnet.NetworkE).WithID(1))
			vmUnknownE2 := t.UnknownVM(privnet.NetworkE, privnet.FakeVM(privnet.NetworkE).WithID(2))
			vmBridgeE := t.VM(privnet.NetworkE, privnet.L2EchoVM(privnet.NetworkE))
			vmBridgeOtherE := t.VM(privnet.NetworkE, privnet.L2EchoOtherVM(privnet.NetworkE))

			// DHCP validation for network-a and network-b via inb0.
			for idx, net := range []privnet.NetworkName{privnet.NetworkB, privnet.NetworkA} {
				t.Run(ctx, privnet.NewDHCP(t,
					t.VM(net, privnet.VMName("client-dhcp-network-b-a").ForInterface(fmt.Sprintf("eth%d", idx))),
				), privnet.ExpectationOK)
			}

			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoA), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoOtherA), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoAIPv4only), privnet.ExpectationOK, features.IPFamilyV4)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoAIPv6only), privnet.ExpectationOK, features.IPFamilyV6)

			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoOtherB), privnet.ExpectationCurlTimeout)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB, vmEchoOtherB), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientC, vmEchoOtherC), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv4Only, vmEchoOtherC), privnet.ExpectationOK, features.IPFamilyV4)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv4Only, vmEchoOtherC), privnet.ExpectationCurlFailedToConnect, features.IPFamilyV6)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv6Only, vmEchoOtherC), privnet.ExpectationOK, features.IPFamilyV6)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv6Only, vmEchoOtherC), privnet.ExpectationCurlTimeout, features.IPFamilyV4)

			// Test connectivity via secondary interfaces
			t.Run(ctx, privnet.NewClientToEcho(t,
				t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth1")),
				t.VM(privnet.NetworkF, privnet.EchoVM(privnet.NetworkA).ForInterface("eth1")),
				privnet.WithNetworkOverride(privnet.NetworkA),
			), privnet.ExpectationOK)

			t.Run(ctx, privnet.NewClientToEcho(t,
				t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth2")),
				t.VM(privnet.NetworkF, privnet.EchoOtherVM(privnet.NetworkB).ForInterface("eth1")),
				privnet.WithNetworkOverride(privnet.NetworkB),
			), privnet.ExpectationOK)

			t.Run(ctx, privnet.NewClientToEcho(t,
				t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth3")),
				t.VM(privnet.NetworkF, privnet.EchoOtherVM(privnet.NetworkC).ForInterface("eth1")),
				privnet.WithNetworkOverride(privnet.NetworkC),
			), privnet.ExpectationOK)

			// Traffic to world with DNS resolution should not be allowed from private network, since it does not have
			// a route for it.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientA, externalTarget), privnet.ExpectationCurlTimeout)

			// Traffic to world should not be allowed from private network, since it does not have
			// a route for it.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientA, externalIPTarget), privnet.ExpectationCurlTimeout)

			// Network C has default route via the INB, which can exit to the world.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientC, externalTarget), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientCIPv4Only, externalTarget), privnet.ExpectationOK, features.IPFamilyV4)

			// Test multi subnet privnet communication
			vmClientB2 := t.VM(privnet.NetworkB, privnet.ClientVM(privnet.NetworkB)+"-2")
			vmEchoExtB1 := t.ExternalVM(privnet.NetworkB, privnet.FakeVM(privnet.NetworkB).WithID(1))
			vmEchoExtB2 := t.ExternalVM(privnet.NetworkB, privnet.FakeVM(privnet.NetworkB).WithID(2))

			// Network B subnet-2 has default route via the INB, which can exit to the world.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientB2, externalTarget), privnet.ExpectationOK)
			//// Network B subnet-1 has no route via the INB. Traffic should be dropped.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientB, externalTarget), privnet.ExpectationCurlTimeout)

			// Network B subnet-1 to external endpoint in subnet-1 should work
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB, vmEchoExtB1), privnet.ExpectationOK)
			// Network B subnet-1 to external endpoint in subnet-2 should fail
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB, vmEchoExtB2), privnet.ExpectationCurlTimeout)

			// Network B subnet-2 to external endpoint in subnet-2 should work
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB, vmEchoExtB1), privnet.ExpectationOK)
			// Traffic to an external endpoint in subnet-1 should work via unknown flow
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB2, vmEchoExtB2), privnet.ExpectationOK)

			// Network B subnet-2 to subnet-1 should work through intra-privnet peering routes
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB2, vmEchoOtherB), privnet.ExpectationOK)

			// Ensure traffic via P-IP is dropped
			t.Run(ctx, privnet.NewClientToPod(t, vmClientA, podEchoOtherC), privnet.ExpectationCurlTimeout)

			// A list of extEPs that are not reachable from the client VM
			ignoreExternal := []string{
				privnet.FakeVM(privnet.NetworkB).WithID(2).String(),
			}

			// Test access to external endpoints and unknown VMs
			for net := range t.Networks() {
				for ext := range t.AllExternalVMs(net) {
					if slices.Contains(ignoreExternal, ext.Name.String()) {
						continue
					}
					t.Run(ctx, privnet.NewClientToEcho(t, t.VM(net, privnet.ClientVM(net)), ext), privnet.ExpectationOK)
				}
				for unk := range t.AllUnknownVMs(net) {
					t.Run(ctx, privnet.NewClientToEcho(t, t.VM(net, privnet.ClientVM(net)), unk), privnet.ExpectationOK)
				}
			}

			// Local access tests without policy - network-e.

			// DHCP validation, check VM gets an IP from local-access based DHCP server.
			t.Run(ctx, privnet.NewDHCP(t, vmClientDHCPE), privnet.ExpectationOK)
			// Intra-cluster connectivity within network-e (same node and other node).
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmEchoE), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmEchoOtherE), privnet.ExpectationOK)
			// Connectivity to unknown-vms on same network.
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmUnknownE1), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmUnknownE2), privnet.ExpectationOK)
			// Connectivity to VMs hosted on the cluster and attached to the same L2 bridge
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmBridgeE), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmBridgeOtherE), privnet.ExpectationOK)
			// Connectivity to external target via default gateway.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientDHCPE, externalTarget), privnet.ExpectationOK)

			// Policy tests using specific external and unknown VMs
			vmExtA1 := t.ExternalVM(privnet.NetworkA, privnet.FakeVM(privnet.NetworkA).WithID(1))
			vmExtA2 := t.ExternalVM(privnet.NetworkA, privnet.FakeVM(privnet.NetworkA).WithID(2))
			vmExtB1 := t.ExternalVM(privnet.NetworkB, privnet.FakeVM(privnet.NetworkB).WithID(1))
			vmExtC1 := t.ExternalVM(privnet.NetworkC, privnet.FakeVM(privnet.NetworkC).WithID(1))

			vmUnknownA1 := t.UnknownVM(privnet.NetworkA, privnet.FakeVM(privnet.NetworkA).WithID(1)) // using alt interface
			vmUnknownA2 := t.UnknownVM(privnet.NetworkA, privnet.FakeVM(privnet.NetworkC).WithID(1)) // using router
			vmUnknownC1 := t.UnknownVM(privnet.NetworkC, privnet.FakeVM(privnet.NetworkA).WithID(1)) // using router
			vmUnknownC2 := t.UnknownVM(privnet.NetworkC, privnet.FakeVM(privnet.NetworkC).WithID(1)) // using alt interface
			vmUnknownD1 := t.UnknownVM(privnet.NetworkD, privnet.FakeVM(privnet.NetworkD).WithID(1)) // using alt interface

			//
			// Network A
			//
			t.ApplyPolicies(ctx,
				t.PolicyFor(vmClientA, "allow-egress-all-endpoints.yaml"),
				t.PolicyFor(vmEchoA, "allow-ingress-l4.yaml", privnet.WithPolicyPort(privnet.EchoServerPort)),
				t.PolicyFor(vmEchoOtherA, "allow-ingress-cidr.yaml", privnet.WithPolicyCIDRsForVM(vmUnknownA1)),
				t.PolicyFor(vmExtA1, "allow-ingress-l4.yaml", privnet.WithPolicyPort(privnet.EchoServerPort)),
				t.PolicyFor(vmExtA2, "allow-ingress-all-endpoints.yaml"),
				t.PolicyFor(vmExtA2, "deny-egress.yaml"),

				t.PolicyFor(
					// All secondary interfaces are attached to the same network, hence this policy applies to all of them.
					t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth1")),
					"allow-egress-endpoint.yaml",
					privnet.WithPolicyPeer(t.VM(privnet.NetworkF, privnet.EchoVM(privnet.NetworkA).ForInterface("eth1"))),
				),

				t.PolicyFor(
					// All secondary interfaces are attached to the same network, hence this policy applies to all of them.
					t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth1")),
					"allow-egress-endpoint.yaml",
					privnet.WithPolicyPeer(t.VM(privnet.NetworkF, privnet.EchoOtherVM(privnet.NetworkB).ForInterface("eth1"))),
				),

				t.PolicyFor(
					t.VM(privnet.NetworkF, privnet.EchoVM(privnet.NetworkA).ForInterface("eth1")),
					"allow-ingress-l4.yaml",
					privnet.WithPolicyPort(privnet.EchoServerPort),
				),
			)

			// egress allowed by toEndpoints, ingress allowed by toPorts
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoA), privnet.ExpectationOK)
			// egress allowed by toEndpoints, ingress denied by fromCIDR
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoOtherA), privnet.ExpectationCurlTimeout)

			// egress allowed by toEndpoints, ingress allowed by toPorts
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmExtA1), privnet.ExpectationOK)
			// egress allowed by toEndpoints, ingress allowed by fromEndpoints
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmExtA2), privnet.ExpectationOK)

			// egress denied by toEndpoints for both
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmUnknownA1), privnet.ExpectationCurlTimeout)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmUnknownA2), privnet.ExpectationCurlTimeout)

			// egress allowed because no policy, ingress allowed by toPorts
			t.Run(ctx, privnet.NewClientToEcho(t, vmExtA1, vmEchoA), privnet.ExpectationOK)
			// egress allowed because no policy, ingress denied by fromCIDR
			t.Run(ctx, privnet.NewClientToEcho(t, vmExtA1, vmEchoOtherA), privnet.ExpectationCurlTimeout)
			// egress denied by catch-all
			t.Run(ctx, privnet.NewClientToEcho(t, vmExtA2, vmEchoA), privnet.ExpectationCurlTimeout)

			// egress allowed by toEndpoints, ingress allowed by toPorts
			t.Run(ctx, privnet.NewClientToEcho(t,
				t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth1")),
				t.VM(privnet.NetworkF, privnet.EchoVM(privnet.NetworkA).ForInterface("eth1")),
				privnet.WithNetworkOverride(privnet.NetworkA),
			), privnet.ExpectationOK)

			//
			// Network B
			//
			t.ApplyPolicies(ctx,
				t.PolicyFor(vmClientB, "allow-egress-endpoint.yaml", privnet.WithPolicyPeer(vmEchoOtherB)),
				t.PolicyFor(vmExtB1, "allow-egress-endpoint.yaml", privnet.WithPolicyPeer(vmClientB)),

				t.PolicyFor(
					t.VM(privnet.NetworkF, privnet.EchoOtherVM(privnet.NetworkB).ForInterface("eth1")),
					"allow-ingress-l4.yaml",
					privnet.WithPolicyPort(privnet.EchoServerPort+1),
				),
			)

			// egress allowed by toEndpoints, ingress allowed because no policy
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB, vmEchoOtherB), privnet.ExpectationOK)
			// egress denied by toEndpoints (only matches echo-other)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB, vmExtB1), privnet.ExpectationCurlTimeout)
			// egress denied by toEndpoints (only matches client-b)
			t.Run(ctx, privnet.NewClientToEcho(t, vmExtB1, vmEchoOtherB), privnet.ExpectationCurlTimeout)

			// egress allowed by toEndpoints, ingress denied by toPorts
			t.Run(ctx, privnet.NewClientToEcho(t,
				t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth2")),
				t.VM(privnet.NetworkF, privnet.EchoOtherVM(privnet.NetworkB).ForInterface("eth1")),
				privnet.WithNetworkOverride(privnet.NetworkB),
			), privnet.ExpectationCurlTimeout)

			//
			// Network C
			//
			t.ApplyPolicies(ctx,
				t.PolicyFor(vmClientC, "allow-egress-cidr.yaml", privnet.WithPolicyCIDRsForVM(vmUnknownC1)),
				t.PolicyFor(vmClientCIPv4Only, "allow-egress-cidr.yaml", privnet.WithPolicyCIDRsForVM(vmUnknownC1)),
				t.PolicyFor(vmClientCIPv6Only, "allow-egress-cidr.yaml", privnet.WithPolicyCIDRsForVM(vmUnknownC1)),
				t.PolicyFor(vmEchoOtherC, "allow-ingress-all-endpoints.yaml"),
			)
			// egress denied by toCIDR
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientC, vmExtC1), privnet.ExpectationCurlTimeout)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv4Only, vmExtC1), privnet.ExpectationCurlTimeout, features.IPFamilyV4)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv6Only, vmExtC1), privnet.ExpectationCurlTimeout, features.IPFamilyV6)
			// egress allowed by toCIDR, ingress (unknown-c1 is alias of a1) allowed by toPorts
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientC, vmUnknownC1), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv4Only, vmUnknownC1), privnet.ExpectationOK, features.IPFamilyV4)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientCIPv6Only, vmUnknownC1), privnet.ExpectationOK, features.IPFamilyV6)
			// egress denied by toCIDR
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientC, vmUnknownC2), privnet.ExpectationCurlTimeout)

			// ingress allowed by fromEndpoints
			t.Run(ctx, privnet.NewClientToEcho(t, vmExtC1, vmEchoOtherC), privnet.ExpectationOK)
			// ingress allowed by toPort
			t.Run(ctx, privnet.NewClientToEcho(t, vmExtC1, vmEchoA), privnet.ExpectationOK)
			// ingress denied by fromCIDR
			t.Run(ctx, privnet.NewClientToEcho(t, vmExtC1, vmEchoOtherA), privnet.ExpectationCurlTimeout)

			// egress denied by toEndpoints
			t.Run(ctx, privnet.NewClientToEcho(t,
				t.VM(privnet.NetworkF, privnet.ClientVM(privnet.NetworkA).ForInterface("eth3")),
				t.VM(privnet.NetworkF, privnet.EchoOtherVM(privnet.NetworkC).ForInterface("eth1")),
				privnet.WithNetworkOverride(privnet.NetworkC),
			), privnet.ExpectationCurlTimeout)

			//
			// Network D
			//
			t.ApplyPolicies(ctx,
				t.PolicyFor(vmClientD, "allow-egress-l7.yaml", privnet.WithPolicyPort(privnet.EchoServerPort)),
			)
			// egress denied by toPorts (unknown flow drops L7)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientD, vmUnknownD1), privnet.ExpectationCurlTimeout)

			//
			// Network E (local-access) tests with policy.
			//
			t.ApplyPolicies(ctx,
				t.PolicyFor(vmClientDHCPE, "allow-egress-cidr.yaml",
					privnet.WithPolicyCIDRsForVM(vmUnknownE2),
					privnet.WithPolicyCIDRsForVM(vmBridgeOtherE),
				),
				t.PolicyFor(vmEchoOtherE, "allow-ingress-cidr.yaml", privnet.WithPolicyCIDRsForVM(vmUnknownE1)),
			)

			// egress allowed by toCIDR (vmUnknownE2 in allowed CIDR)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmUnknownE2), privnet.ExpectationOK)
			// egress denied by toCIDR (vmUnknownE1 not in allowed CIDR)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmUnknownE1), privnet.ExpectationCurlTimeout)
			// egress denied by toCIDR (external target not in allowed CIDR)
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientDHCPE, externalTarget), privnet.ExpectationCurlTimeout)

			// egress denied by toCIDR (vmBridgeE not in allowed CIDR)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmBridgeE), privnet.ExpectationCurlTimeout)
			// egress allowed by toCIDR (vmBridgeOtherE in allowed CIDR)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientDHCPE, vmBridgeOtherE), privnet.ExpectationOK)

			// ingress allowed by fromCIDR (vmUnknownE1 in allowed CIDR)
			t.Run(ctx, privnet.NewClientToEcho(t, vmUnknownE1, vmEchoOtherE), privnet.ExpectationOK)
			// ingress denied by fromCIDR (vmUnknownE2 not in allowed CIDR)
			t.Run(ctx, privnet.NewClientToEcho(t, vmUnknownE2, vmEchoOtherE), privnet.ExpectationCurlTimeout)

			// Remove all policies before proceeding with the INB failover tests,
			// unless the context got canceled, in which case we let the deferred
			// function take care of it.
			if ctx.Err() == nil {
				t.Cleanup(ctx)
			}

			// Trigger a bunch of failovers.
			for inb := range t.INBNodeNames() {
				t.Run(ctx, privnet.NewFailover(t, inb), privnet.ExpectationOK)
			}

			// Check connectivity to external endpoints again.
			for net := range t.Networks() {
				for ext := range t.AllExternalVMs(net) {
					if slices.Contains(ignoreExternal, ext.Name.String()) {
						continue
					}

					t.Run(ctx, privnet.NewClientToEcho(t, t.VM(net, privnet.ClientVM(net)), ext), privnet.ExpectationOK)
				}
			}

			if t.Failed() {
				return errors.New("one or more tests failed")
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.Debug, "debug", "d", false, "Show debug messages")
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to perform the connectivity test in")
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label selector for Cilium Agent pods")
	cmd.Flags().StringVar(&params.ExternalTarget, "external-target", "one.one.one.one.", "External curl target")
	cmd.Flags().StringVar(&params.ExternalIPTarget, "external-ip-target", "1.1.1.1", "External curl IP target")
	cmd.Flags().StringSliceVar(&params.INBContexts, "inb-contexts", nil, "List of Kubernetes contexts of the Isovalent Network Bridges")
	cmd.Flags().StringVar(&params.VMImage, "vm-image", enterpriseDefaults.PrivnetTestImages["VMImage"], "Name of the VM image")
	cmd.Flags().StringVar(&params.MockVMImage, "mock-vm-image", enterpriseDefaults.PrivnetTestImages["MockVMImage"], "Name of the mock VM image")
	cmd.Flags().StringVar(&params.ForkliftPlanName, "forklift-plan-name", "mock", "Name of the forklift/MTV plan")
	cmd.Flags().BoolVar(&printImageArtifacts, "print-image-artifacts", false, "Prints the used image artifacts and exits")

	return cmd
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/ilb"
	ilbCli "github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/ilb"
)

// Execute Isovalent Loadbalancer E2E Tests
//
// Usage:
//
// cilium lb test test [ilb-test-flags]
//
// ILB test flags:
//
//  --app-image string
//        app container image name (default "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.14")
//  --cleanup
//        Cleanup created resources after each test case run (default true)
//  --client-image string
//        client container image name (default "quay.io/isovalent-dev/lb-frr-client:v0.0.17")
//  --ensure-images bool
//        Ensure images by checking and pre-pulling images (default true)
//  --mode string
//        Testing mode ('multi-node' or 'single-node'). 'multi-node' deploys client and LB app containers in separate network namespaces (to simulate multi-node LB environments). 'single-node' deploys the containers on a single node in the same host network namespace. (default "multi-node")
//  --single-node-ip string
//        The IP addr of the test runner node. The IP addr should be reachable by T1 and T2 nodes. Required when --mode=single-node.
//	--use-remote-address bool
//        Use remote address for client IP in HTTP requests (default true)
//  --xff-num-trusted-hops int
//        Number of trusted hops in X-Forwarded-For header (default 0)
//  --run string
//        Run only the tests matching the regular expression (only respecting top level test functions)
//  --network-name string
//        The network name where external test containers (client & backends) should be attached to
//  --verbose bool
//        Verbose log output (default false)
//
// One can run in the --mode=single-node using a remote node for deploying client
// and LB app containers, and then running test requests from them. To do so,
// set DOCKER_HOST= to point to the remote node.

func newCmdLoadbalancerTest() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run Loadbalancer tests",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			c.SetContext(ctx)

			if ilbCli.FlagMode != "single-node" && ilbCli.FlagMode != "multi-node" {
				return fmt.Errorf("invalid --mode: %s", ilbCli.FlagMode)
			}

			lbTestRun := ilbCli.NewLBTestRun(c.Context(), ciliumNamespace(c))
			ciliumCli, k8sCli := ilbCli.NewCiliumAndK8sCli(lbTestRun)
			dockerCli := ilbCli.NewDockerCli(lbTestRun)
			ipv4Enabled, ipv6Enabled, err := ilb.IPFamilyInfo(ctx, k8sCli, ciliumNamespace(c))
			if err != nil {
				return err
			}

			lbTestRun.SetIPInfo(ipv4Enabled, ipv6Enabled)

			for _, img := range []string{ilbCli.FlagAppImage, ilbCli.FlagClientImage, ilbCli.FlagCoreDNSImage, ilbCli.FlagNginxImage, ilbCli.FlagMariaDBImage} {
				if err := dockerCli.EnsureImage(c.Context(), img); err != nil {
					return fmt.Errorf("failed to ensure Docker image %s: %w", img, err)
				}
			}

			if ilbCli.IsSingleNode() {
				if err := ilbCli.SetupSingleNodeMode(c.Context(), dockerCli, k8sCli); err != nil {
					return fmt.Errorf("failed to set up single-node mode: %w", err)
				}
			}

			defer lbTestRun.RunCleanup()

			// Create IsovalentBGPClusterConfig (each test case will append its peer to it)
			if err := ciliumCli.EnsureBGPClusterConfig(c.Context()); err != nil {
				return fmt.Errorf("failed to install BGP peering: %w", err)
			}
			lbTestRun.RegisterCleanup(func(ctx context.Context) error {
				return ciliumCli.DeleteBGPClusterConfig(ctx)
			})

			// Run tests
			return lbTestRun.ExecuteTestFuncs(c.Context())
		},
	}

	cmd.Flags().StringVar(&ilbCli.FlagAppImage, "app-image", "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.14", "app container image name")
	cmd.Flags().StringVar(&ilbCli.FlagClientImage, "client-image", "quay.io/isovalent-dev/lb-frr-client:v0.0.17", "client container image name")
	cmd.Flags().StringVar(&ilbCli.FlagUtilsImage, "utils-image", "busybox:1.37.0-musl", "utils container image name")
	cmd.Flags().StringVar(&ilbCli.FlagCoreDNSImage, "coredns-image", "coredns/coredns:1.11.1", "coredns container image name")
	cmd.Flags().StringVar(&ilbCli.FlagNginxImage, "nginx-image", "library/nginx:1.27.2", "nginx container image name")
	cmd.Flags().StringVar(&ilbCli.FlagMariaDBImage, "mariadb-image", "library/mariadb:11.7.2", "mariadb container image name")
	cmd.Flags().BoolVar(&ilbCli.FlagEnsureImages, "ensure-images", true, "Ensure images by checking and pre-pulling images")

	cmd.Flags().BoolVar(&ilbCli.FlagCleanup, "cleanup", true, "Cleanup created resources after each test case run")
	cmd.Flags().BoolVar(&ilbCli.FlagContinueOnFailure, "continue-on-failure", false, "Continue tests execution on test failure")
	// maybeSysdump is only effective when this option is specified.
	cmd.Flags().BoolVar(&ilbCli.FlagSysdumpOnFailure, "sysdump-on-failure", false, "Collect sysdump on test failure")
	cmd.Flags().StringVar(&ilbCli.FlagSysdumpOutputFilename, "sysdump-output-filename", "ilb-sysdump", "Name of the outputfile for the sysdump sysdump")
	cmd.Flags().BoolVar(&ilbCli.FlagVerbose, "verbose", false, "Verbose logging")

	// By default, we assume cilium-cli is in the PATH. In the CI, we may want to specify custom path.
	cmd.Flags().StringVar(&ilbCli.FlagCiliumCLIPath, "cilium-cli-path", "cilium", "cilium-cli binary path")

	cmd.Flags().StringVar(&ilbCli.FlagMode, "mode", "multi-node", "Testing mode ('multi-node' or 'single-node'). 'multi-node' deploys client and LB app containers in separate network namespaces (to simulate multi-node LB environments). 'single-node' deploys the containers on a single node in the same host network namespace.")
	cmd.Flags().StringVar(&ilbCli.FlagSingleNodeIPAddr, "single-node-ip", "", "The IP addr of the test runner node. The IP addr should be reachable by T1 and T2 nodes. Required when --mode=single-node.")
	cmd.Flags().StringVar(&ilbCli.FlagSingleNodeIPv6Addr, "single-node-ip-v6", "", "The IPv6 addr of the test runner node. The IP addr should be reachable by T1 and T2 nodes. Required when --mode=single-node.")
	cmd.Flags().StringVar(&ilbCli.FlagNetworkName, "network-name", ilb.DefaultContainerNetwork, "The network name where external test containers (client & backends) should be attached to")

	// TODO (sayboras): Remove these flags once we have feature auto-detection
	cmd.Flags().BoolVar(&ilbCli.FlagUseRemoteAddress, "use-remote-address", true, "Use remote address for client IP in HTTP requests")
	cmd.Flags().IntVar(&ilbCli.FlagXffNumTrustedHops, "xff-num-trusted-hops", 2, "Number of trusted hops in X-Forwarded-For header")

	cmd.Flags().StringSliceVar(&ilbCli.FlagRun, "run", []string{}, "Run tests that match one of the given regular expressions. If an expression starts with '!', then instead, it specifies tests to be skipped. Provide multiple expressions by providing this flag multiple times.")
	cmd.Flags().Var(&ilbCli.FlagShard, "shard", "Run only the tests assigned to the given shard in the form CURRENT-of-TOTAL, for example 1-of-2 or 3-of-4.")

	cmd.AddCommand(newCmdLoadbalancerTestList())
	cmd.AddCommand(newCmdLoadbalancerTestCleanup())

	return cmd
}

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
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	ossCli "github.com/cilium/cilium/cilium-cli/cli"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/evpn"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
)

func newCmdEVPNTest() *cobra.Command {
	params := evpn.TestParams{}

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run EVPN tests",
		Long:  "",
		RunE: func(cmd *cobra.Command, _ []string) error {
			params.CiliumNamespace = ossCli.RootParams.Namespace

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			cmd.SetContext(ctx)

			clusterClient, err := enterpriseK8s.NewEnterpriseClient(ossCli.RootK8sClient)
			if err != nil {
				return fmt.Errorf("failed to construct local client: %w", err)
			}

			evpnTestRun := evpn.NewTestRun(cmd.OutOrStdout(), params, clusterClient)
			return evpnTestRun.Execute(ctx)
		},
	}

	cmd.Flags().StringVar(&params.TestFilter, "test", "", "Only run EVPN tests whose name matches this regular expression")
	cmd.Flags().UintSliceVar(&params.VNIs, "vnis", nil, "Comma-separated list of EVPN VNIs to use for testing; when set, only private networks matching these VNIs are used")
	cmd.Flags().StringSliceVar(&params.VNIContainers, "vni-containers", nil, "Comma-separated list of Docker containers to use for connectivity testing, positionally mapped to --vnis entries")
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label selecting cilium-agent pods")
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", "evpn-test", "Namespace for the resources used by the test")
	cmd.Flags().BoolVar(&params.SkipCleanupOnFailure, "skip-cleanup-on-failure", false, "Terminate test execution and skip test cleanup on failure")
	cmd.Flags().DurationVar(&params.PreflightTimeout, "preflight-timeout", 5*time.Minute, "Preflight checks timeout")
	cmd.Flags().DurationVar(&params.TestTimeout, "test-timeout", 30*time.Minute, "Total test timeout")

	cmd.Flags().StringVar(&params.CurlImage, "curl-image", defaults.ConnectivityCheckImagesTest["ConnectivityCheckAlpineCurlImage"], "Image path to use for curl")
	cmd.Flags().StringVar(&params.JSONMockImage, "json-mock-image", defaults.ConnectivityCheckImagesTest["ConnectivityCheckJSONMockImage"], "Image path to use for json mock")

	return cmd
}

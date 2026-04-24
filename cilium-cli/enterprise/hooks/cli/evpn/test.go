// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package evpn

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
)

const (
	preflightMinPrivateNetworks = 2
	preflightPollInterval       = 5 * time.Second
	testCleanupTimeout          = 30 * time.Second
)

// allTests holds all EVPN connectivity tests.
// The tests are expected to be run in a k8s cluster where privnet and EVPN BGP configuration already exists,
// BGP sessions with EVPN router(s) is established, and some RT-5 routes are learned for each privnet.
// This is verified in the pre-flight check, which will not pass if these preconditions are not met.
var allTests = []evpnTest{
	newBasicConnectivityTest(),
}

type evpnTest interface {
	Name() string
	Run(ctx context.Context, run *TestRun, env *testEnv) error
	Cleanup(ctx context.Context, run *TestRun, env *testEnv) error
}

type TestParams struct {
	CiliumNamespace  string
	AgentPodSelector string

	TestNamespace string
	CurlImage     string

	PreflightTimeout     time.Duration
	TestTimeout          time.Duration
	SkipCleanupOnFailure bool
}

type TestRun struct {
	out    io.Writer
	params TestParams
	client *k8s.EnterpriseClient
	env    *testEnv
}

type testEnv struct {
	evpnConfig   evpnConfig
	evpnPrivnets map[string]privnetInfo
	bgpNodeInfo  map[string]bgpNodeInfo
}

type evpnConfig struct {
	evpnEnabled              bool
	privateNetworksEnabled   bool
	securityGroupTagsEnabled bool
	defaultSecurityGroupID   uint16
}

func NewTestRun(out io.Writer, params TestParams, client *k8s.EnterpriseClient) *TestRun {
	return &TestRun{
		out:    out,
		client: client,
		params: params,
	}
}

// Execute runs all EVPN tests sequentially in the k8s cluster.
// Before test execution, the preflight check verifies whether the tests can be executed in the target cluster.
func (r *TestRun) Execute(ctx context.Context) error {
	testCtx, cancel := context.WithTimeout(ctx, r.params.TestTimeout)
	defer cancel()

	// run preflight checks and populate r.env
	if err := r.runPreflight(testCtx); err != nil {
		return fmt.Errorf("❌ pre-flight checks failed: %w", err)
	}

	// ensure evpnTest namespace exists
	if err := ensureNamespace(testCtx, r.client, r.params.TestNamespace); err != nil {
		return err
	}

	executedTests := 0
	failedTests := 0
testLoop:
	for i, test := range allTests {
		select {
		case <-testCtx.Done():
			switch err := ctx.Err(); err {
			case context.DeadlineExceeded:
				return fmt.Errorf("❌ test execution timed out: %w", err)
			case context.Canceled:
				return fmt.Errorf("❌ test execution cancelled: %w", err)
			default:
				return nil
			}
		default:
			executedTests++
			fmt.Fprintf(r.out, "\n=== [%d/%d] %s ===\n", i+1, len(allTests), test.Name())
			// Perform test cleanup before running
			if err := test.Cleanup(testCtx, r, r.env); err != nil {
				fmt.Fprintf(r.out, "Warning: %s test cleanup failed: %v\n", test.Name(), err)
			}
			// Run the test
			err := test.Run(testCtx, r, r.env)
			if err == nil {
				fmt.Fprintf(r.out, "✅ %s test passed\n", test.Name())
			} else {
				fmt.Fprintf(r.out, "❌ %s test failed: %s\n", test.Name(), err)
				failedTests++
			}
			if err == nil || !r.params.SkipCleanupOnFailure {
				// Run test cleanup, use a separate context as we want cleanup to run even if terminating
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), testCleanupTimeout)
				if err := test.Cleanup(cleanupCtx, r, r.env); err != nil {
					fmt.Fprintf(r.out, "Warning: %s test cleanup failed: %v\n", test.Name(), err)
				}
				cleanupCancel()
			} else {
				fmt.Fprintln(r.out, "Skipping test cleanup and breaking test execution")
				break testLoop // break test execution on error with SkipCleanupOnFailure
			}
		}
	}

	fmt.Fprintf(r.out, "\n=== Results ===\n")
	if failedTests > 0 {
		return fmt.Errorf("❌ %d/%d tests failed", failedTests, executedTests)
	}
	fmt.Fprintf(r.out, "✅ %d/%d tests passed.\n", executedTests, executedTests)
	return nil
}

// runPreflight checks whether the tests can be executed in the target cluster.
// It does it in a loop until the preflight timeout expires.
// The discovered privnets and BGP state is saved in r.env.
func (r *TestRun) runPreflight(ctx context.Context) error {
	pfCtx, cancel := context.WithTimeout(ctx, r.params.PreflightTimeout)
	defer cancel()

	fmt.Fprintf(r.out, "=== Pre-flight checks ===\n")

	ticker := time.NewTicker(preflightPollInterval)
	defer ticker.Stop()

	for {
		config, err := retrieveEVPNConfig(pfCtx, r.client, r.params.CiliumNamespace)
		if err != nil {
			return err
		}
		if !config.privateNetworksEnabled {
			return fmt.Errorf("private networks are disabled in the agent configuration")
		}
		if !config.evpnEnabled {
			return fmt.Errorf("EVPN is disabled in the agent configuration")
		}

		evpnPrivnets, err := r.retrieveEVPNPrivateNetworks(pfCtx)
		if err != nil {
			return err
		}
		bgpNodeInfo, err := r.retrieveBGPNodeInfo(pfCtx)
		if err != nil {
			return err
		}
		nodesMissingRT5s := nodesMissingLearnedRT5(evpnPrivnets, bgpNodeInfo)

		if len(evpnPrivnets) < preflightMinPrivateNetworks {
			fmt.Fprintf(r.out, "Pre-flight not ready yet: %d EVPN-enabled private networks found, %d needed\n", len(evpnPrivnets), preflightMinPrivateNetworks)
		} else if len(nodesMissingRT5s) > 0 {
			fmt.Fprintf(r.out, "Pre-flight not ready yet: missing learned RT-5 routes on nodes %v\n", nodesMissingRT5s)
		} else {
			r.env = &testEnv{
				evpnPrivnets: evpnPrivnets,
				bgpNodeInfo:  bgpNodeInfo,
				evpnConfig:   config,
			}
			fmt.Fprintf(r.out, "Pre-flight checks passed\n")
			return nil
		}

		select {
		case <-pfCtx.Done():
			return pfCtx.Err()
		case <-ticker.C:
		}
	}
}

func nodesMissingLearnedRT5(privateNetworks map[string]privnetInfo, infos map[string]bgpNodeInfo) []string {
	missing := make([]string, 0, len(infos))
	for nodeName, info := range infos {
		for _, privateNetwork := range privateNetworks {
			if len(info.LearnedRT5[privateNetwork.VNI]) == 0 {
				missing = append(missing, nodeName)
				break
			}
		}
	}
	return missing
}

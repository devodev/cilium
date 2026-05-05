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
	"regexp"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/enterprise/pkg/vni"
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
	newFabricSecurityGroupsTest(),
	newPolicyEgressTest(),
}

type evpnTest interface {
	Name() string
	Run(ctx context.Context, run *TestRun, env *testEnv) error
	Cleanup(ctx context.Context, run *TestRun, env *testEnv) error
}

type TestParams struct {
	TestFilter    string
	VNIs          []uint
	VNIContainers []string

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
	evpnConfig    evpnConfig
	evpnPrivnets  map[string]privnetInfo
	bgpNodeInfo   map[string]bgpNodeInfo
	vniContainers map[uint32]string
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

	// select tests to run
	selectedTests, err := filterTests(allTests, r.params.TestFilter)
	if err != nil {
		return fmt.Errorf("❌ invalid EVPN test filter %q: %w", r.params.TestFilter, err)
	}
	if len(selectedTests) == 0 {
		return fmt.Errorf("❌ no EVPN tests match filter %q", r.params.TestFilter)
	}

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
	for i, test := range selectedTests {
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
			fmt.Fprintf(r.out, "\n=== [%d/%d] %s ===\n", i+1, len(selectedTests), test.Name())
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

func filterTests(tests []evpnTest, filter string) ([]evpnTest, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return tests, nil
	}
	matcher, err := regexp.Compile(filter)
	if err != nil {
		return nil, err
	}

	var filtered []evpnTest
	for _, test := range tests {
		if matcher.MatchString(test.Name()) {
			filtered = append(filtered, test)
		}
	}
	return filtered, nil
}

// runPreflight checks whether the tests can be executed in the target cluster.
// It does it in a loop until the preflight timeout expires.
// The discovered privnets and BGP state is saved in r.env.
func (r *TestRun) runPreflight(ctx context.Context) error {
	pfCtx, cancel := context.WithTimeout(ctx, r.params.PreflightTimeout)
	defer cancel()

	fmt.Fprintf(r.out, "=== Pre-flight checks ===\n")

	requestedVNIs, err := parseRequestedVNIs(r.params.VNIs)
	if err != nil {
		return err
	}
	if len(requestedVNIs) > 0 {
		fmt.Fprintf(r.out, "Using requested EVPN VNIs: %v\n", r.params.VNIs)
	}
	vniContainers, err := parseVNIContainers(requestedVNIs, r.params.VNIContainers)
	if err != nil {
		return err
	}
	for _, vni := range requestedVNIs {
		if containerName, ok := vniContainers[vni]; ok {
			fmt.Fprintf(r.out, "Using Docker container %s for VNI %d connectivity tests\n", containerName, vni)
		}
	}

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

		evpnPrivnets, err := r.retrieveEVPNPrivateNetworks(pfCtx, requestedVNIs)
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
				evpnPrivnets:  evpnPrivnets,
				bgpNodeInfo:   bgpNodeInfo,
				evpnConfig:    config,
				vniContainers: vniContainers,
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

func parseRequestedVNIs(inputVNIs []uint) ([]uint32, error) {
	if len(inputVNIs) == 0 {
		return nil, nil
	}
	res := make([]uint32, 0, len(inputVNIs))
	for _, inputVNI := range inputVNIs {
		vniVal, err := vni.FromUint32(uint32(inputVNI))
		if err != nil {
			return nil, fmt.Errorf("invalid --vnis value %d: %w", inputVNI, err)
		}
		res = append(res, vniVal.AsUint32())
	}
	if len(res) == 0 {
		return nil, nil
	}
	if len(res) < preflightMinPrivateNetworks {
		return nil, fmt.Errorf("--vnis must contain at least %d VNIs", preflightMinPrivateNetworks)
	}
	return res, nil
}

func parseVNIContainers(vniList []uint32, containers []string) (map[uint32]string, error) {
	if len(containers) == 0 {
		return nil, nil
	}
	if len(vniList) == 0 {
		return nil, fmt.Errorf("--vni-containers can only be used with --vnis")
	}
	if len(containers) != len(vniList) {
		return nil, fmt.Errorf("--vni-containers must contain the same number of entries as --vnis")
	}

	vniContainers := make(map[uint32]string, len(containers))
	for i, vni := range vniList {
		containerName := strings.TrimSpace(containers[i])
		if containerName == "" {
			return nil, fmt.Errorf("invalid --vni-containers value %q", containers[i])
		}
		if _, exists := vniContainers[vni]; exists {
			return nil, fmt.Errorf("--vni-containers requires unique --vnis values, duplicate VNI %d", vni)
		}
		vniContainers[vni] = containerName
	}
	return vniContainers, nil
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

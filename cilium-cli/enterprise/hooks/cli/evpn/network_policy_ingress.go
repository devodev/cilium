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
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

const (
	policyIngressHTTPPort = 8080
)

// policyIngressTest verifies ingress policy enforcement from remote EVPN destinations (external Docker containers)
// into privnet-attached pods. For each VNI with mapped external Docker container it runs the following scenario:
//   - Deploys a pod in the EVPN-enabled private network for that VNI.
//   - Discovers source IP of the mapped Docker container.
//   - Verifies baseline connectivity from the external container to the pod.
//   - Applies an ingress fromCIDR policy that does not match the container source IP and verifies that ingress traffic is denied.
//   - Removes the deny policy and verifies that the connectivity recovers.
//   - Applies an ingress fromCIDR policy matching the container source IP and verifies that the traffic is allowed.
//   - Removes the allow policy and verifies baseline connectivity remains intact.
type policyIngressTest struct{}

type policyIngressScenario struct {
	privnet         string
	testPod         *policyIngressTestPod
	dockerContainer string
	containerIPs    []netip.Addr
}

type policyIngressTestPod struct {
	config *privnetPodConfig
	labels map[string]string
	k8sPod *corev1.Pod
}

func newPolicyIngressTest() *policyIngressTest {
	return &policyIngressTest{}
}

func (t *policyIngressTest) Name() string {
	return "network-policy-ingress"
}

func (t *policyIngressTest) CanRun(ctx context.Context, run *TestRun, env *testEnv) (bool, string) {
	if len(env.vniContainers) == 0 {
		return false, "requires --vni-containers argument"
	}
	return true, ""
}

func (t *policyIngressTest) Run(ctx context.Context, run *TestRun, env *testEnv) error {
	// load test scenarios (one per privnet) and deploy test pods
	scenarios, err := t.newScenarios(ctx, run, env)
	if err != nil {
		return err
	}
	if err := t.deployPods(ctx, run, scenarios); err != nil {
		return err
	}

	for _, scenario := range scenarios {
		sourceCIDRs := hostCIDRsForAddrs(scenario.containerIPs)
		denyCIDRs, err := nonMatchingHostCIDRsForAddrs(scenario.containerIPs)
		if err != nil {
			return err
		}
		descriptionPrefix := fmt.Sprintf("container %s (privnet %s)", scenario.dockerContainer, scenario.privnet)
		fmt.Fprintf(run.out, "Using deny CIDRs for %s: %v\n", descriptionPrefix, denyCIDRs)
		fmt.Fprintf(run.out, "Using allow CIDRs for %s: %v\n", descriptionPrefix, sourceCIDRs)

		// verify baseline connectivity - all traffic should be allowed
		if err := t.waitForExpectation(ctx, run, scenario, descriptionPrefix+" baseline connectivity", true); err != nil {
			return err
		}

		// deploy policy allowing CIDRs that are NOT matching external source IPs - traffic from the external container should be denied
		denyPolicy := t.buildIngressCIDRPolicy(run, scenario, "deny", denyCIDRs)
		if err := createNetworkPolicy(ctx, run, denyPolicy); err != nil {
			return err
		}
		if err := t.waitForExpectation(ctx, run, scenario, descriptionPrefix+" denied ingress connectivity", false); err != nil {
			return err
		}

		// delete deny policy - traffic from the external container should be allowed
		if err := deleteNetworkPolicy(ctx, run, denyPolicy.Name); err != nil {
			return err
		}
		if err := t.waitForExpectation(ctx, run, scenario, descriptionPrefix+" connectivity after policy deletion", true); err != nil {
			return err
		}

		// deploy policy allowing CIDRs matching external source IPs - traffic from the external container should be allowed
		allowPolicy := t.buildIngressCIDRPolicy(run, scenario, "allow", sourceCIDRs)
		if err := createNetworkPolicy(ctx, run, allowPolicy); err != nil {
			return err
		}
		if err := t.waitForExpectation(ctx, run, scenario, descriptionPrefix+" allowed ingress connectivity", true); err != nil {
			return err
		}

		// delete allow policy - all traffic should be allowed
		if err := deleteNetworkPolicy(ctx, run, allowPolicy.Name); err != nil {
			return err
		}
		if err := t.waitForExpectation(ctx, run, scenario, descriptionPrefix+" connectivity after allow policy deletion", true); err != nil {
			return err
		}
	}
	return nil
}

func (t *policyIngressTest) Cleanup(ctx context.Context, run *TestRun, env *testEnv) error {
	fmt.Fprintf(run.out, "Cleaning up test resources...\n")

	if err := cleanupPods(ctx, run.client, run.params.TestNamespace, testResourceLabels(t.Name())); err != nil {
		return fmt.Errorf("failed to clean up test pods: %w", err)
	}
	if err := cleanupTestPolicies(ctx, run, t.Name()); err != nil {
		return fmt.Errorf("failed to clean up IsovalentNetworkPolicies: %w", err)
	}
	return nil
}

func (t *policyIngressTest) newScenarios(ctx context.Context, run *TestRun, env *testEnv) ([]*policyIngressScenario, error) {
	scenarios := make([]*policyIngressScenario, 0)
	for _, privnet := range env.evpnPrivnets {
		containerName, ok := env.vniContainers[privnet.VNI]
		if !ok {
			continue
		}
		config, err := getPrivnetTestPodConfig(privnet, t.Name(), 1)
		if err != nil {
			return nil, err
		}
		labels := testResourceLabels(t.Name())
		labels[appLabelKey] = fmt.Sprintf("%s-%s", appLabelValuePrefix, privnet.Name)

		containerIPs, err := discoverContainerSourceIPs(ctx, containerName, config)
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, &policyIngressScenario{
			privnet:         privnet.Name,
			dockerContainer: containerName,
			testPod: &policyIngressTestPod{
				config: config,
				labels: labels,
			},
			containerIPs: containerIPs,
		})
	}
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("no EVPN private networks matched the configured --vni-containers")
	}
	return scenarios, nil
}

func (t *policyIngressTest) deployPods(ctx context.Context, run *TestRun, scenarios []*policyIngressScenario) error {
	for _, scenario := range scenarios {
		k8sPod, err := buildPrivnetK8sPod(scenario.testPod.config, run.params, scenario.testPod.labels)
		if err != nil {
			return err
		}
		configurePolicyIngressHTTPServerPod(k8sPod, run.params)
		scenario.testPod.k8sPod = k8sPod

		fmt.Fprintf(run.out, "Creating pod %s/%s for privnet %s...\n",
			k8sPod.Namespace, k8sPod.Name, scenario.privnet)

		if _, err := run.client.CreatePod(ctx, run.params.TestNamespace, k8sPod, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating pod %s/%s: %w", k8sPod.Namespace, k8sPod.Name, err)
		}
	}

	for _, scenario := range scenarios {
		k8sPod, err := waitForPodReady(ctx, run.client, run.params.TestNamespace, scenario.testPod.config.name)
		if err != nil {
			return err
		}
		scenario.testPod.k8sPod = k8sPod
		fmt.Fprintf(run.out, "Pod %s/%s is running on node %s\n", k8sPod.Namespace, k8sPod.Name, k8sPod.Spec.NodeName)
	}
	return nil
}

func (t *policyIngressTest) buildIngressCIDRPolicy(run *TestRun, scenario *policyIngressScenario, nameSuffix string, cidrs policyapi.CIDRSlice) *isovalentv1alpha1.IsovalentNetworkPolicy {
	return &isovalentv1alpha1.IsovalentNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s-%s", t.Name(), scenario.testPod.config.privnet.Name, nameSuffix),
			Namespace: run.params.TestNamespace,
			Labels:    testResourceLabels(t.Name()),
		},
		Spec: &isovalentv1alpha1.IsovalentNetworkPolicyRule{
			Rule: policyapi.Rule{
				EndpointSelector: policyapi.EndpointSelector{
					LabelSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							appLabelKey:             scenario.testPod.labels[appLabelKey],
							privnetNetworkNameLabel: scenario.testPod.config.privnet.Name,
						},
					},
				},
				Ingress: []policyapi.IngressRule{
					{
						IngressCommonRule: policyapi.IngressCommonRule{
							FromCIDR: cidrs,
						},
					},
				},
			},
		},
	}
}

func (t *policyIngressTest) waitForExpectation(ctx context.Context, run *TestRun, scenario *policyIngressScenario, description string, expectReachable bool) error {
	fmt.Fprintf(run.out, "Verifying %s...\n", description)

	for _, target := range []netip.Addr{scenario.testPod.config.ipv4, scenario.testPod.config.ipv6} {
		if !target.IsValid() {
			continue
		}

		err := waitForExpectedPolicyResult(ctx, description, func(ctx context.Context) error {
			if err := curlFromExternalContainerWithExpectedResult(ctx, run, scenario.dockerContainer, target, expectReachable); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	fmt.Fprintf(run.out, "Passed %s expectation\n", description)
	return nil
}

func configurePolicyIngressHTTPServerPod(pod *corev1.Pod, params TestParams) {
	pod.Spec.Containers[0].Image = params.JSONMockImage
	pod.Spec.Containers[0].Command = nil
	pod.Spec.Containers[0].Args = nil
	pod.Spec.Containers[0].Env = []corev1.EnvVar{
		{Name: "PORT", Value: fmt.Sprintf("%d", policyIngressHTTPPort)},
		{Name: "NAMED_PORT", Value: "http"},
	}
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: policyIngressHTTPPort,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

func curlFromExternalContainerWithExpectedResult(ctx context.Context, run *TestRun, containerName string, targetIP netip.Addr, expectReachable bool) error {
	curlCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	expectation := "expect fail"
	if expectReachable {
		expectation = "expect pass"
	}

	fmt.Fprintf(run.out, "Curl to %s from Docker container %s... (%s)\n",
		targetIP, containerName, expectation)

	curlArgs := []string{
		"curl",
		"--fail",
		"--silent",
		"--show-error",
		"--output", "/dev/null",
		"--connect-timeout", "2",
		"--max-time", "10",
		"--retry", "2",
		"--retry-all-errors",
		"--retry-delay", "1",
		externalTargetURL(targetIP),
	}
	stdout, err := execInDockerContainer(curlCtx, containerName, curlArgs...)
	curlSucceeded := err == nil
	if curlCtx.Err() != nil && errors.Is(curlCtx.Err(), context.Canceled) {
		err = curlCtx.Err()
		curlSucceeded = false
	}

	if expectReachable {
		if err != nil || !curlSucceeded {
			if err == nil {
				err = fmt.Errorf("curl command exited unsuccessfully")
			}
			return fmt.Errorf("curl to %s from Docker container %s failed: %w\n%s", targetIP, containerName, err, strings.TrimSpace(stdout))
		}
		return nil
	}
	if curlSucceeded {
		return fmt.Errorf("curl to %s from Docker container %s succeeded, but failure expected", targetIP, containerName)
	}
	return nil
}

func externalTargetURL(target netip.Addr) string {
	host := target.String()
	if target.Is6() {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("http://%s:%d/", host, policyIngressHTTPPort)
}

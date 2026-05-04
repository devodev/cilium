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
	"maps"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

const (
	networkPolicyEgressPollInterval = 2 * time.Second
	networkPolicyEgressPollTimeout  = 2 * time.Minute
)

// policyEgressTest tests egress policy enforcement for remote EVPN destinations.
// It deploys 2 pods in one discovered EVPN-enabled privnet:
//   - a subject pod selected by IsovalentNetworkPolicy,
//   - a control pod in the same privnet that is intentionally not selected by the policy and always maintains connectivity.
//
// Then performs these steps:
//   - Verifies baseline connectivity from both pods to their selected ping target.
//   - Applies an egress toCIDR policy on the subject pod that allows a different CIDR than the ping target,
//     and validates that the subject pod loses connectivity to its ping target.
//   - Deletes the deny policy and validates that connectivity recovers.
//   - Applies an egress toCIDR policy on the subject pod that allows its actual ping target,
//     and validates both pods can reach the ping target.
//   - Deletes the allow policy and validates baseline connectivity remains intact.
type policyEgressTest struct {
	subjectPod *policyEgressTestPod
	controlPod *policyEgressTestPod
}

type policyEgressTestPod struct {
	config  *privnetPodConfig
	labels  map[string]string
	k8sPod  *corev1.Pod
	targets []netip.Addr
}

type policyEgressPodConnectivity map[*policyEgressTestPod]bool // maps test pod to its expected connectivity result

func newPolicyEgressTest() *policyEgressTest {
	return &policyEgressTest{}
}

func (t *policyEgressTest) Name() string {
	return "network-policy-egress"
}

func (t *policyEgressTest) CanRun(ctx context.Context, run *TestRun, env *testEnv) (bool, string) {
	return true, ""
}

func (t *policyEgressTest) Run(ctx context.Context, run *TestRun, env *testEnv) error {
	// select one test privnet
	privnet, err := t.selectPrivnet(env.evpnPrivnets)
	if err != nil {
		return err
	}

	// deploy pods and select one remote ping target per advertised family
	t.subjectPod, err = t.newTestPod(privnet, "subject", 1)
	if err != nil {
		return err
	}
	t.controlPod, err = t.newTestPod(privnet, "control", 2)
	if err != nil {
		return err
	}
	if err := t.deployPods(ctx, run); err != nil {
		return err
	}
	if t.subjectPod.targets, err = getRemoteTargetsForPod(ctx, run, env, t.subjectPod.config, t.subjectPod.k8sPod.Spec.NodeName); err != nil {
		return err
	}
	if t.controlPod.targets, err = getRemoteTargetsForPod(ctx, run, env, t.controlPod.config, t.controlPod.k8sPod.Spec.NodeName); err != nil {
		return err
	}

	// verify baseline connectivity - all traffic should be allowed
	if err := t.waitForExpectation(ctx, run, "baseline connectivity", map[*policyEgressTestPod]bool{
		t.subjectPod: true,
		t.controlPod: true,
	}); err != nil {
		return err
	}

	// deploy policy allowing CIDRs that are NOT matching ping targets - traffic from the subject pod should be denied
	denyCIDRs, err := nonMatchingHostCIDRsForAddrs(t.subjectPod.targets)
	fmt.Fprintf(run.out, "Using deny CIDRs for policy: %v\n", denyCIDRs)
	if err != nil {
		return err
	}
	denyPolicy := t.buildEgressCIDRPolicy(run, "deny", t.subjectPod, denyCIDRs)
	if err := createNetworkPolicy(ctx, run, denyPolicy); err != nil {
		return err
	}
	if err := t.waitForExpectation(ctx, run, "denied egress from subject pod", policyEgressPodConnectivity{
		t.subjectPod: false,
		t.controlPod: true,
	}); err != nil {
		return err
	}

	// delete deny policy - traffic from the subject pod should be allowed
	if err := deleteNetworkPolicy(ctx, run, denyPolicy.Name); err != nil {
		return err
	}
	if err := t.waitForExpectation(ctx, run, "baseline connectivity after deny policy deletion", policyEgressPodConnectivity{
		t.subjectPod: true,
		t.controlPod: true,
	}); err != nil {
		return err
	}

	// deploy policy allowing CIDRs that are matching ping targets - traffic from the subject pod should be allowed
	allowCIDRs := hostCIDRsForAddrs(t.subjectPod.targets)
	fmt.Fprintf(run.out, "Using allow CIDRs for policy: %v\n", allowCIDRs)
	allowPolicy := t.buildEgressCIDRPolicy(run, "allow", t.subjectPod, allowCIDRs)
	if err := createNetworkPolicy(ctx, run, allowPolicy); err != nil {
		return err
	}
	if err := t.waitForExpectation(ctx, run, "allowed egress from subject pod", policyEgressPodConnectivity{
		t.subjectPod: true,
		t.controlPod: true,
	}); err != nil {
		return err
	}

	// delete allow policy - all traffic should be allowed
	if err := deleteNetworkPolicy(ctx, run, allowPolicy.Name); err != nil {
		return err
	}
	return t.waitForExpectation(ctx, run, "baseline connectivity after allow policy deletion", policyEgressPodConnectivity{
		t.subjectPod: true,
		t.controlPod: true,
	})
}

func (t *policyEgressTest) Cleanup(ctx context.Context, run *TestRun, env *testEnv) error {
	fmt.Fprintf(run.out, "Cleaning up test resources...\n")

	if err := cleanupPods(ctx, run.client, run.params.TestNamespace, testResourceLabels(t.Name())); err != nil {
		return fmt.Errorf("failed to clean up test pods: %w", err)
	}

	if err := cleanupTestPolicies(ctx, run, t.Name()); err != nil {
		return fmt.Errorf("failed to clean up IsovalentNetworkPolicies: %w", err)
	}
	return nil
}

func (t *policyEgressTest) selectPrivnet(privnets map[string]privnetInfo) (privnetInfo, error) {
	for _, privnet := range privnets {
		return privnet, nil
	}
	return privnetInfo{}, fmt.Errorf("no EVPN-enabled private network found")
}

func (t *policyEgressTest) newTestPod(privnet privnetInfo, role string, ordinal uint32) (*policyEgressTestPod, error) {
	config, err := getPrivnetTestPodConfig(privnet, fmt.Sprintf("%s-%s", t.Name(), role), ordinal)
	if err != nil {
		return nil, err
	}

	labels := testResourceLabels(t.Name())
	labels[appLabelKey] = role

	return &policyEgressTestPod{
		config: config,
		labels: labels,
	}, nil
}

func (t *policyEgressTest) deployPods(ctx context.Context, run *TestRun) error {
	for _, testPod := range []*policyEgressTestPod{t.subjectPod, t.controlPod} {
		pod, err := buildPrivnetK8sPod(testPod.config, run.params, testPod.labels)
		if err != nil {
			return err
		}
		testPod.k8sPod = pod

		fmt.Fprintf(run.out, "Creating pod %s/%s for privnet %s with %s=%s...\n",
			pod.Namespace, pod.Name, testPod.config.privnet.Name, appLabelKey, testPod.labels[appLabelKey])

		if _, err := run.client.CreatePod(ctx, run.params.TestNamespace, pod, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}

	for _, testPod := range []*policyEgressTestPod{t.subjectPod, t.controlPod} {
		k8sPod, err := waitForPodReady(ctx, run.client, run.params.TestNamespace, testPod.config.name)
		if err != nil {
			return err
		}
		testPod.k8sPod = k8sPod
		fmt.Fprintf(run.out, "Pod %s/%s is running on node %s\n", k8sPod.Namespace, k8sPod.Name, k8sPod.Spec.NodeName)
	}
	return nil
}

func (t *policyEgressTest) buildEgressCIDRPolicy(run *TestRun, nameSuffix string, pod *policyEgressTestPod, cidrs policyapi.CIDRSlice) *isovalentv1alpha1.IsovalentNetworkPolicy {
	return &isovalentv1alpha1.IsovalentNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", t.Name(), nameSuffix),
			Namespace: run.params.TestNamespace,
			Labels:    testResourceLabels(t.Name()),
		},
		Spec: &isovalentv1alpha1.IsovalentNetworkPolicyRule{
			Rule: policyapi.Rule{
				EndpointSelector: policyapi.EndpointSelector{
					LabelSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							appLabelKey:             pod.labels[appLabelKey],
							privnetNetworkNameLabel: pod.config.privnet.Name,
						},
					},
				},
				Egress: []policyapi.EgressRule{
					{
						EgressCommonRule: policyapi.EgressCommonRule{
							ToCIDR: cidrs,
						},
					},
				},
			},
		},
	}
}

func (t *policyEgressTest) waitForExpectation(ctx context.Context, run *TestRun, description string, expected policyEgressPodConnectivity) error {
	fmt.Fprintf(run.out, "Verifying %s...\n", description)

	pending := maps.Clone(expected)
	var lastErr error

	err := wait.PollUntilContextTimeout(ctx, networkPolicyEgressPollInterval, networkPolicyEgressPollTimeout, true, func(ctx context.Context) (bool, error) {
		for _, testPod := range []*policyEgressTestPod{t.controlPod, t.subjectPod} {
			expectReachable, ok := pending[testPod]
			if !ok {
				continue
			}
			for _, target := range testPod.targets {
				err := pingWithExpectedResult(ctx, run, testPod.k8sPod, target, expectReachable)
				if err != nil {
					lastErr = err
					return false, nil
				}
			}
			delete(pending, testPod)
		}
		lastErr = nil
		return len(pending) == 0, nil
	})
	if err != nil {
		if lastErr != nil {
			return fmt.Errorf("failed waiting for %s: %w", description, lastErr)
		}
		return fmt.Errorf("failed waiting for %s: %w", description, err)
	}

	fmt.Fprintf(run.out, "Passed %s expectation\n", description)
	return nil
}

func pingWithExpectedResult(ctx context.Context, run *TestRun, pod *corev1.Pod, target netip.Addr, expectReachable bool) error {
	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	expectation := "expect fail"
	if expectReachable {
		expectation = "expect pass"
	}

	fmt.Fprintf(run.out, "Pinging %s from pod %s/%s... (%s)\n", target, pod.Namespace, pod.Name, expectation)
	_, err := run.client.ExecInPod(pingCtx, pod.Namespace, pod.Name, evpnTestContainerName, []string{"ping", "-c", "1", "-W", "1", target.String()})
	if expectReachable {
		if err != nil {
			return fmt.Errorf("ping to %s from pod %s/%s failed: %w", target, pod.Namespace, pod.Name, err)
		}
		return nil
	}
	if err == nil {
		return fmt.Errorf("ping to %s from pod %s/%s succeeded, but failure expected", target, pod.Namespace, pod.Name)
	}
	return nil
}

func nonMatchingHostCIDRsForAddrs(addrs []netip.Addr) (policyapi.CIDRSlice, error) {
	cidrs := make(policyapi.CIDRSlice, 0, len(addrs))
	for _, addr := range addrs {
		cidr, err := nonMatchingHostCIDRForAddr(addr)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs, nil
}

func nonMatchingHostCIDRForAddr(addr netip.Addr) (policyapi.CIDR, error) {
	for _, candidate := range []netip.Addr{addr.Next(), addr.Prev()} {
		if candidate.IsValid() {
			return hostCIDRForAddr(candidate), nil
		}
	}
	return "", fmt.Errorf("could not derive non-matching host CIDR for %s", addr)
}

func hostCIDRsForAddrs(addrs []netip.Addr) policyapi.CIDRSlice {
	cidrs := make(policyapi.CIDRSlice, 0, len(addrs))
	for _, addr := range addrs {
		cidrs = append(cidrs, hostCIDRForAddr(addr))
	}
	return cidrs
}

func hostCIDRForAddr(addr netip.Addr) policyapi.CIDR {
	return policyapi.CIDR(fmt.Sprintf("%s/%d", addr.String(), addr.BitLen()))
}

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// basicConnectivityTest tests basic EVPN connectivity:
//   - deploys a pod in each discovered EVPN-enabled privnet (in an EVPN-enabled subnet),
//   - determines a ping target for each learned RT-5 route of the privnet
//     (preferring /32 or /128 prefixes if available, otherwise using first non-network IP of larger prefixes),
//   - pings the remote target.
type basicConnectivityTest struct{}

func newBasicConnectivityTest() *basicConnectivityTest {
	return &basicConnectivityTest{}
}

func (t *basicConnectivityTest) Name() string {
	return "basic-connectivity"
}

func (t *basicConnectivityTest) Run(ctx context.Context, run *TestRun, env *testEnv) error {
	testPods, err := t.getPodsForPrivnets(env.evpnPrivnets)
	if err != nil {
		return err
	}

	for _, testPod := range testPods {
		pod, err := buildPrivnetK8sPod(testPod, run.params, testPodLabels(t.Name()))
		if err != nil {
			return err
		}

		fmt.Fprintf(run.out, "Creating pod %s/%s for privnet %s on subnet %s...\n",
			pod.Namespace, pod.Name, testPod.privnet.Name, testPod.subnetName)

		if _, err := run.client.CreatePod(ctx, run.params.TestNamespace, pod, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}

	for _, testPod := range testPods {
		pod, err := waitForPodReady(ctx, run.client, run.params.TestNamespace, testPod.name)
		if err != nil {
			return err
		}

		fmt.Fprintf(run.out, "Pod %s/%s is running on node %s\n", pod.Namespace, pod.Name, pod.Spec.NodeName)

		targets, err := getPingTargetsForVNI(env.bgpNodeInfo, pod.Spec.NodeName, testPod.privnet.VNI)
		if err != nil {
			return err
		}
		for _, target := range targets {
			if (target.Is4() && testPod.ipv4.IsValid()) || (target.Is6() && testPod.ipv6.IsValid()) {
				if err := pingFromPod(ctx, run, pod, target); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (t *basicConnectivityTest) Cleanup(ctx context.Context, run *TestRun, env *testEnv) error {
	fmt.Fprintf(run.out, "Cleaning up test resources...\n")

	if err := cleanupPods(ctx, run.client, run.params.TestNamespace, testPodLabels(t.Name())); err != nil {
		return fmt.Errorf("failed to clean up EVPN test pods: %w", err)
	}
	return nil
}

func (t *basicConnectivityTest) getPodsForPrivnets(privnets map[string]privnetInfo) ([]*privnetPodConfig, error) {
	var pods []*privnetPodConfig
	for _, privnet := range privnets {
		pod, err := getPrivnetTestPodConfig(privnet, t.Name(), 1)
		if err != nil {
			return nil, err
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

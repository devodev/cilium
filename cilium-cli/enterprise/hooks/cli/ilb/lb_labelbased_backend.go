//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestLabelBasedBackend_T1T2(t T) {
	testLabelBasedBackend(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1T2))
}

func TestLabelBasedBackend_T1Only(t T) {
	testLabelBasedBackend(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1Only))
}

func testLabelBasedBackend(t T, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// label based backends are only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	testName := "labelbased-backend-" + string(mode)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	nodeSelector, err := appNodeSelector(t.Context(), k8sCli, mode)
	if err != nil {
		t.Failedf("failed to lookup node selector: %s", err)
	}

	backendApp := backendApplication{
		name:         testName,
		replicas:     2,
		nodeSelector: nodeSelector,
	}
	t.Log("Creating backend apps with nodeSelector: %s ...", nodeSelector["service.cilium.io/node"])
	desiredBackends := scenario.AddAndWaitForK8sBackendApplications(backendApp)

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	backends = append(backends, withK8sServiceBackend(testName, 8080))
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	observedBackends := make(map[string]struct{})
	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}

		// Response from the health check server contains instance name (Pod name in this case)
		appResponse, err := toTestAppResponse(stdout)
		if err != nil {
			return err
		}

		for _, pod := range desiredBackends.Items {
			if appResponse.InstanceName == pod.Name {
				observedBackends[pod.Name] = struct{}{}
			}
		}

		// Check if we have observed all backends
		if len(observedBackends) != len(desiredBackends.Items) {
			return fmt.Errorf("have not observed all backends yet: %d/%d", len(observedBackends), len(desiredBackends.Items))
		}

		return nil
	}, longTimeout, pollInterval)
}

func TestHTTPMultiNamespaceLabelBased(t T) {
	if skipIfOnSingleNode(">1 FRR clients are not supported") {
		return
	}

	testName := "http-multi-namespace-labelbased"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// label based backends are only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n",
			minVersion, currentVersion.String())
		return
	}

	// 0. Setup test scenario (backends, clients & LB resources)
	// Using multiple scenarios to test the multi-namespace aspect within the same test
	scenarios := []*lbTestScenario{
		newLBTestScenario(t, testName+"-1", ciliumCli, k8sCli, dockerCli),
		newLBTestScenario(t, testName+"-2", ciliumCli, k8sCli, dockerCli),
		newLBTestScenario(t, testName+"-3", ciliumCli, k8sCli, dockerCli),
	}

	t.Log("Creating backend apps in separate namespaces...")
	for i, scenario := range scenarios {
		backendApp := backendApplication{
			name:     "backend-" + strconv.Itoa(i+1),
			replicas: 1,
		}
		scenario.AddAndWaitForK8sBackendApplications(backendApp)
	}

	t.Log("Creating clients and add BGP peering ...")
	clients := []*frrContainer{}
	for _, scenario := range scenarios {
		clients = append(clients, scenario.addFRRClients(1, frrClientConfig{})[0])
	}

	t.Log("Creating LB VIP resources in separate namespaces...")
	for i, scenario := range scenarios {
		vip := lbVIP(testName + "-" + strconv.Itoa(i+1))
		scenario.createLBVIP(vip)
	}

	t.Log("Creating LB BackendPool resources in separate namespaces...")
	for i, scenario := range scenarios {
		backendPool := lbBackendPool("pool-"+strconv.Itoa(i+1),
			withK8sServiceBackend("backend-"+strconv.Itoa(i+1), 8080))
		scenario.createLBBackendPool(backendPool)
	}

	deploymentMode := isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(
		isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1T2)

	t.Log("Creating LB Service resources in separate namespaces...")
	for i, scenario := range scenarios {
		vipName := fmt.Sprintf("%s-%d", testName, i+1)
		service := lbService(testName, withPort(80),
			withVIPRef(vipName),
			withTCPProxyApplication(
				withTCPForceDeploymentMode(deploymentMode),
				withTCPProxyRoute(fmt.Sprintf("pool-%d", i+1))))
		scenario.createLBService(service)
	}

	t.Log("Waiting for full VIP connectivity...")
	vips := []string{}
	for i, scenario := range scenarios {
		vipName := fmt.Sprintf("%s-%d", testName, i+1)
		vips = append(vips, scenario.waitForFullVIPConnectivity(vipName))
	}

	for i := range scenarios {
		backendHostname := fmt.Sprintf("backend-%d.acme.io", i+1)
		t.Log("Testing backend %d connectivity via hostname %s...", i+1, backendHostname)
		testCmd := curlCmd(
			fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' --resolve %s:80:%s http://%s:80",
				backendHostname, vips[i], backendHostname))
		stdout, stderr, err := clients[i].Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed for backend %d (cmd: %q, stdout: %q, stderr: %q): %s",
				i+1, testCmd, stdout, stderr, err)
		}

		resp, err := toTestAppResponse(stdout)
		if err != nil {
			t.Failedf("%s", err)
		}
		expectedServiceName := fmt.Sprintf("backend-%d", i+1)
		if resp.ServiceName != expectedServiceName {
			t.Failedf("unexpected backend service name for backend %d: got %q, expected %q",
				i+1, resp.ServiceName, expectedServiceName)
		}
		t.Log("Backend %d responded with service name %s", i+1, resp.ServiceName)
	}
}

// appNodeSelector function returns k8s node selector:
// - `t1` selector if mode is `t1-only` and cluster has T1 nodes
// - `t2` selector if mode is NOT `t1-only` and cluster has T2 nodes
// - `t1-t2` selector in all other cases
func appNodeSelector(ctx context.Context, k8sCli *k8s.Clientset, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) (map[string]string, error) {
	tier := "t2"
	if mode == isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1Only) {
		tier = "t1"
	}
	nodeList, err := k8sCli.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("service.cilium.io/node in ( %s )", tier)})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve %s k8s nodes: %w", tier, err)
	}

	if len(nodeList.Items) > 0 {
		return map[string]string{"service.cilium.io/node": tier}, nil
	}
	return map[string]string{"service.cilium.io/node": "t1-t2"}, nil
}

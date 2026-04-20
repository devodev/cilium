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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestSharedVIP(t T) {
	testName := "shared-vip-1"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	sharedVIPName := testName + "-shared"
	vip := lbVIP(sharedVIPName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port))
	}
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service1 := lbService(testName+"-1", withVIPRef(sharedVIPName), withPort(80), withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(service1)

	service2 := lbService(testName+"-2", withVIPRef(sharedVIPName), withPort(81), withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(service2)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(sharedVIPName)

	// 1. Send two HTTP requests on VIP for both services
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' http://%s:81/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}
}

func TestRequestedVIP(t T) {
	testName := "requested-vip-1"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	requestedVIP := "100.64.0.250"
	vip := lbVIP(testName, withRequestedIPv4(requestedVIP))
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port))
	}
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service1 := lbService(testName, withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(service1)

	t.Log("Waiting for full VIP connectivity...")
	_ = scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to requested VIP
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' http://%s:80/", requestedVIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
	if stdout != "200" {
		t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
	}
}

func TestMultipleIPPools(t T) {
	testName := "multiple-ip-pools"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)

	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	clbi, err := ciliumCli.GetCiliumLoadBalancerIPPool(t.Context(), testName, metav1.GetOptions{})
	if err != nil {
		t.Failedf("failed to get LBIPPool (%s): %s", testName, err)
	}

	clbi.Spec.ServiceSelector = &slimmetav1.LabelSelector{
		MatchExpressions: []slimmetav1.LabelSelectorRequirement{
			// Exclude services from test "TestMultipleIPPools" from using the default IP Pool,
			// because it doesn't define a service label selector and would select all services.
			{
				Key:      "io.kubernetes.service.namespace",
				Operator: slimmetav1.LabelSelectorOpNotIn,
				Values:   []string{"ilb-test-" + testName},
			},
		},
	}

	if err := ciliumCli.UpdateCiliumLoadBalancerIPPool(t.Context(), clbi, metav1.UpdateOptions{}); err != nil {
		t.Failedf("failed to update LBIPPool (%s): %s", clbi.ObjectMeta.String(), err)
	}

	t.Log("Creating additional IP Pools ...")
	// 1
	additionalPoolName1 := LbIPPoolName + "-1"
	lbIPPool1 := LbIPPool(additionalPoolName1, scenario.k8sNamespace, "100.63.1.0/24")
	lbIPPool1.Spec.ServiceSelector = &slimmetav1.LabelSelector{
		MatchLabels: map[string]slimmetav1.MatchLabelsValue{
			"io.kubernetes.service.namespace":     scenario.k8sNamespace,
			"loadbalancer.isovalent.com/vip-name": testName + "-1",
		},
	}
	if err := ciliumCli.EnsureLBIPPool(t.Context(), lbIPPool1); err != nil {
		t.Failedf("failed to ensure LBIPPool (%s): %s", additionalPoolName1, err)
	}

	t.RegisterCleanup(func(ctx context.Context) error {
		return ciliumCli.DeleteLBIPPool(ctx, additionalPoolName1, metav1.DeleteOptions{})
	})

	// 2
	additionalPoolName2 := LbIPPoolName + "-2"
	lbIPPool2 := LbIPPool(additionalPoolName2, scenario.k8sNamespace, "100.63.2.0/24")
	lbIPPool2.Spec.ServiceSelector = &slimmetav1.LabelSelector{
		MatchLabels: map[string]slimmetav1.MatchLabelsValue{
			"io.kubernetes.service.namespace":     scenario.k8sNamespace,
			"loadbalancer.isovalent.com/vip-name": testName + "-2",
		},
	}
	if err := ciliumCli.EnsureLBIPPool(t.Context(), lbIPPool2); err != nil {
		t.Failedf("failed to ensure LBIPPool (%s): %s", additionalPoolName2, err)
	}

	t.RegisterCleanup(func(ctx context.Context) error {
		return ciliumCli.DeleteLBIPPool(ctx, additionalPoolName2, metav1.DeleteOptions{})
	})

	// additional lbipam pool 1
	{
		name := testName + "-1"
		t.Log("Creating LB VIP resources...")
		vip := lbVIP(name)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backends := []backendPoolOption{}
		for _, b := range scenario.backendApps {
			backends = append(backends, withIPBackend(b.ipv4, b.port))
		}
		backendPool := lbBackendPool(name, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		service1 := lbService(name, withVIPRef(vip.Name), withHTTPProxyApplication(withHttpRoute(name)))
		scenario.createLBService(service1)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(vip.Name)
		if !strings.HasPrefix(vipIP, "100.63.1.") {
			t.Failedf("wrong ip pool - expected prefix %q - got %q", "100.63.1", vipIP)
		}

		// 1. Send HTTP request to requested VIP
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}

	// additional lbipam pool 2
	{
		name := testName + "-2"
		t.Log("Creating LB VIP resources...")
		vip := lbVIP(name)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backends := []backendPoolOption{}
		for _, b := range scenario.backendApps {
			backends = append(backends, withIPBackend(b.ipv4, b.port))
		}
		backendPool := lbBackendPool(name, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		service1 := lbService(name, withVIPRef(vip.Name), withHTTPProxyApplication(withHttpRoute(name)))
		scenario.createLBService(service1)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(vip.Name)
		if !strings.HasPrefix(vipIP, "100.63.2.") {
			t.Failedf("wrong ip pool - expected prefix %q - got %q", "100.63.2", vipIP)
		}

		// 1. Send HTTP request to requested VIP
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}
}

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
	"fmt"
	"strconv"
)

func TestHTTP2(t T) {
	testName := "http2-1"
	hostName := "mixed.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port))
	}
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withHTTPProxyApplication(
		withHttpRoute(testName, withHttpHostname(hostName)),
	))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --http2-prior-knowledge -o/dev/null -w '%%{http_version}' --resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// Check HTTP H2
	if stdout != "2" {
		t.Failedf("Expected HTTP 2, got: %s", stdout)
	}
}

func TestHTTPPath(t T) {
	testName := "http-path-1"
	hostName := "insecure.acme.io"
	path := "/api/foo-insecure"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port))
	}
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withHTTPProxyApplication(
		withHttpRoute(testName, withHttpHostname(hostName), withHttpPath(path)),
	))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' --resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, path))
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
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' --resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, "/other"))
		t.Log("Testing 404 on other path %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed unexpectedly (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "404" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}
}

func TestHTTPRoutes(t T) {
	testName := "http-routes"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	serviceBackendMappings := map[string]struct {
		hostname         string
		testCallHostname string
		path             string
	}{
		"-0": {hostname: "first.acme.io", testCallHostname: "first.acme.io", path: "first"},
		"-1": {hostname: "first.acme.io", testCallHostname: "first.acme.io", path: "second"},
		"-2": {hostname: "second.acme.io", testCallHostname: "second.acme.io", path: "third"},
		"-3": {hostname: "*.second.acme.io", testCallHostname: "sub.second.acme.io", path: "fourth"},
	}

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(4, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	// one backendpool per backend app
	for postfix := range serviceBackendMappings {
		backend := scenario.backendApps[testName+"-app"+postfix]
		scenario.createLBBackendPool(lbBackendPool(testName+postfix, withIPBackend(backend.ipv4, backend.port)))
	}

	t.Log("Creating LB Service resources...")
	// one route per backendpool (backend app)
	routes := []httpApplicationOption{}
	for postfix, rhost := range serviceBackendMappings {
		routes = append(routes, withHttpRoute(testName+postfix, withHttpHostname(rhost.hostname), withHttpPath(fmt.Sprintf("/%s", rhost.path))))
	}
	service := lbService(testName, withHTTPProxyApplication(routes...))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// calling each route once
	for postfix, rhost := range serviceBackendMappings {
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' --resolve %s:80:%s http://%s:80%s", rhost.testCallHostname, vipIP, rhost.testCallHostname, fmt.Sprintf("/%s", rhost.path)))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}

		t.Log("Check that request is handled by the correct backend")
		appResponse, err := toTestAppResponse(stdout)
		if err != nil {
			t.Failedf("%s", err)
		}
		if appResponse.ServiceName != testName+"-app"+postfix {
			t.Failedf("request not handled by the expected backend %s != %s (cmd: %q, stdout: %q, stderr: %q): %s", appResponse.ServiceName, testName+"-app"+postfix, testCmd, stdout, stderr, err)
		}
	}
}

func TestHTTPMultiNamespaceInClusterHostname(t T) {
	if skipIfOnSingleNode(">1 FRR clients are not supported") {
		return
	}
	testName := "http-multi-namespace-incluster-hostname"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

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
		backendSvcHostname := fmt.Sprintf("backend-%d.%s.svc.cluster.local", i+1, scenario.k8sNamespace)
		backendPool := lbBackendPool("pool-"+strconv.Itoa(i+1),
			withHostnameBackend(backendSvcHostname, 8080))
		scenario.createLBBackendPool(backendPool)
	}

	t.Log("Creating LB Service resources in separate namespaces...")
	for i, scenario := range scenarios {
		vipName := fmt.Sprintf("%s-%d", testName, i+1)
		service := lbService("service-"+strconv.Itoa(i+1), withPort(80),
			withVIPRef(vipName),
			withHTTPProxyApplication(
				withHttpRoute("pool-"+strconv.Itoa(i+1),
					withHttpHostname(fmt.Sprintf("backend-%d.acme.io", i+1)))))
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

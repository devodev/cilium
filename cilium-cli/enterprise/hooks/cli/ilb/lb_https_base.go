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
)

func TestHTTPS(t T) {
	testName := "https-1"
	hostName := "secure.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createLBServerCertificate(testName, hostName)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{hostName}})[0]

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
	service := lbService(testName, withPort(443), withHTTPSProxyApplication(withHttpsRoute(testName, withHttpsHostname(hostName)), withCertificate(testName)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTPs request
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' --cacert /tmp/"+hostName+".crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
	if stdout != "200" {
		t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
	}
}

func TestHTTPSRoutes(t T) {
	testName := "https-routes"

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

	t.Log("Creating cert and secret...")
	// create a secret per hostname (filtering out multiple routes for the same hostname)
	alreadyCoveredHostnames := map[string]string{}
	for postfix, rhost := range serviceBackendMappings {
		if _, ok := alreadyCoveredHostnames[rhost.hostname]; !ok {
			scenario.createLBServerCertificate(testName+postfix, rhost.hostname)
			alreadyCoveredHostnames[rhost.hostname] = postfix
		}
	}

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(4, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	hostnames := []string{}
	for _, rhost := range serviceBackendMappings {
		hostnames = append(hostnames, rhost.hostname)
	}
	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: hostnames})[0]

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
	routesAndCertificates := []httpsApplicationOption{}
	for postfix, rhost := range serviceBackendMappings {
		routesAndCertificates = append(routesAndCertificates, withHttpsRoute(testName+postfix, withHttpsHostname(rhost.hostname), withHttpsPath(fmt.Sprintf("/%s", rhost.path))))

		// only use the reference it the TLS secret was created for this route
		if alreadyCoveredHostnames[rhost.hostname] == postfix {
			routesAndCertificates = append(routesAndCertificates, withCertificate(testName+postfix))
		}
	}
	service := lbService(testName, withPort(443), withHTTPSProxyApplication(routesAndCertificates...))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// calling each route once
	for postfix, rhost := range serviceBackendMappings {
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 --cacert /tmp/"+rhost.hostname+".crt -H 'Content-Type: application/json' --resolve %s:443:%s https://%s:443%s", rhost.testCallHostname, vipIP, rhost.testCallHostname, fmt.Sprintf("/%s", rhost.path)))
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

func TestHTTPS_H2(t T) {
	testName := "http2s-1"
	hostName := "secure-http2.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createLBServerCertificate(testName, hostName)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{hostName}})[0]

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
	service := lbService(testName, withPort(443), withHTTPSProxyApplication(withHttpsRoute(testName, withHttpsHostname(hostName)), withCertificate(testName), withHTTPSH2(true), withHTTPSH11(true)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTPs request
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o/dev/null -w '%%{http_version}' --cacert /tmp/%s --resolve %s:443:%s https://%s:443/", hostName+".crt", hostName, vipIP, hostName))
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

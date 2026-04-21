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
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	core_v1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestTCPProxyT1Only(t T) {
	testTCPProxy(t, "tcp-proxy-t1-only", isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, 8080, 0, false)
}

func TestTCPProxyT1OnlyHealthCheckCustomPort(t T) {
	testTCPProxy(t, "tcp-proxy-t1-only-health-check-custom-port", isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, 8181, 8080, false)
}

func TestTCPProxyT1T2(t T) {
	testTCPProxy(t, "tcp-proxy-t1-t2", isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2, 8080, 0, false)
}

func TestTCPProxyAuto(t T) {
	testTCPProxy(t, "tcp-proxy-auto", isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto, 8080, 0, false)
}

func TestTCPProxyT1OnlyHTTPSHealthCheck(t T) {
	testTCPProxy(t, "tcp-proxy-t1-only-https-health-check", isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, 8080, 0, true)
}

func TestTCPProxyT1OnlyPreferSameZone(t T) {
	testName := "tcp-proxy-t1-only-prefer-same-zone"
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	if skipIfOnSingleNode(">1 backends are not supported") {
		return
	}

	t.RunTestCase(func(t T) {
		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

		t.Log("Creating backend apps...")

		zones := []string{"zone-a", "zone-b"}
		scenario.addBackendApplications(len(zones),
			backendApplicationConfig{
				h2cEnabled: true,
				listenPort: 8080,
			})

		t.Log("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(1, frrClientConfig{})[0]

		t.Log("Creating LB VIP resources...")
		vip := lbVIP(testName)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backends := []backendPoolOption{}
		zoneBackend := make(map[string]*hcAppContainer, len(zones))
		index := 0
		for _, b := range scenario.backendApps {
			zone := zones[index]
			backends = append(backends, withIPBackendAndZone(b.ipv4, b.port, zone))
			zoneBackend[zone] = b
			index++
		}
		backendPool := lbBackendPool(testName, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1), withTCPProxyRoute(backendPool.Name)), withPreferSameZone())
		scenario.createLBService(service)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
		testCmd := curlCmdVerbose(getURL("", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}

		t.Log("Collecting T1 nodes...")
		t1Nodes, err := getT1Nodes(t, k8sCli)
		if err != nil {
			t.Failedf("failed to get T1 nodes: %s", err)
		}
		if len(t1Nodes) == 0 {
			t.Failedf("T1 nodes not found")
		}

		t.Log("Labeling T1 nodes with zones...")
		zoneT1Node := make(map[string]core_v1.Node, len(t1Nodes))
		for i, node := range t1Nodes {
			zone := zones[i%2]
			if err := addNodeToZone(t.Context(), k8sCli, node, zone); err != nil {
				t.Failedf("failed to label T1 node with zone: %s", err)
			}
			zoneT1Node[zone] = node
			t.Log("Labeled node %s with %s zone", node.Name, zone)

			t.RegisterCleanup(func(ctx context.Context) error {
				return removeNodeFromZone(t.Context(), k8sCli, node)
			})
		}

		t.Log("Starting zone testing...")
		for zone, node := range zoneT1Node {
			testZone(t, client, zone, node, vipIP, zoneBackend)
		}
	})
}

func testTCPProxy(t T, testName string, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType, listenPort, healthCheckPort uint32, useTLS bool) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// custom health check port is only supported in v1.18 and newer
	if healthCheckPort != 0 || useTLS {
		minVersion := ">=1.18.0"
		currentVersion := GetCiliumVersion(t, k8sCli)
		if !versioncheck.MustCompile(minVersion)(currentVersion) {
			fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
			return
		}
	}

	t.RunTestCase(func(t T) {
		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

		hostName := ""
		if useTLS {
			hostName = "secure.acme.io"
			t.Log("Creating cert and secret...")
			scenario.createBackendServerCertificate(hostName)
		}

		t.Log("Creating backend apps...")

		backendNum := 2
		// TCPProxy does not support backends with different ports, so create just 1 backend.
		if IsSingleNode() {
			backendNum = 1
		}
		scenario.addBackendApplications(backendNum,
			backendApplicationConfig{
				h2cEnabled:      true,
				listenPort:      listenPort,
				healthCheckPort: healthCheckPort,
				tlsCertHostname: hostName,
			})

		t.Log("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: trustedCertsHostnames(hostName)})[0]

		t.Log("Creating LB VIP resources...")
		vip := lbVIP(testName)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backends := []backendPoolOption{}
		for _, b := range scenario.backendApps {
			backends = append(backends, withIPBackend(b.ipv4, b.port), withHealthCheckPort(int32(healthCheckPort)))
			if useTLS {
				backends = append(backends, withHealthCheckTLS())
			}
		}
		backendPool := lbBackendPool(testName, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
		scenario.createLBService(service)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
		testCmd := curlCmdVerbose(getURL(hostName, vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	})
}

func trustedCertsHostnames(hostName string) []string {
	if hostName != "" {
		return []string{hostName}
	}
	return nil
}

func getURL(hostName, vipIP string) string {
	if hostName != "" {
		return fmt.Sprintf("--max-time 10 --cacert /tmp/%s --resolve %s:80:%s https://%s:80/", hostName+".crt", hostName, vipIP, hostName)
	}
	return fmt.Sprintf("--max-time 10 http://%s:80/", vipIP)
}

func getT1Nodes(t T, client *kubernetes.Clientset) ([]core_v1.Node, error) {
	t1Nodes, err := client.CoreV1().Nodes().List(t.Context(), v1.ListOptions{
		LabelSelector: "service.cilium.io/node in (t1, t1-t2)",
	})
	if err != nil {
		return nil, err
	}
	return t1Nodes.Items, nil
}

func addNodeToZone(ctx context.Context, k8sCli *kubernetes.Clientset, node core_v1.Node, zone string) error {
	node.Labels[core_v1.LabelTopologyZone] = zone
	_, err := k8sCli.CoreV1().Nodes().Update(ctx, &node, v1.UpdateOptions{})
	return err
}

func removeNodeFromZone(ctx context.Context, k8sCli *kubernetes.Clientset, node core_v1.Node) error {
	actualNode, err := k8sCli.CoreV1().Nodes().Get(ctx, node.Name, v1.GetOptions{})
	if err != nil {
		return err
	}

	if _, ok := actualNode.Labels[core_v1.LabelTopologyZone]; !ok {
		return nil // nothing to do
	}
	delete(actualNode.Labels, core_v1.LabelTopologyZone)
	if _, err := k8sCli.CoreV1().Nodes().Update(ctx, actualNode, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to unlabel node %s: %w", node.Name, err)
	}
	return nil
}

func testZone(t T, client *frrContainer, zone string, node core_v1.Node, vipIP string, zoneBackend map[string]*hcAppContainer) {
	t.Log("[%s] targeting traffic from client to %s via T1 %s node...", zone, vipIP, node.Name)
	nodeIP := lookupNodeInternalIP(node)
	if nodeIP == "" {
		t.Failedf("failed to lookup %v node internal IP address", node)
	}

	routeCmd := fmt.Sprintf("ip route add %s/32 via %s metric 1", vipIP, nodeIP)
	stdout, stderr, err := client.Exec(t.Context(), routeCmd)
	if err != nil {
		t.Failedf("'ip route add' failed (cmd: %q, stdout: %q, stderr: %q): %s", routeCmd, stdout, stderr, err)
	}
	defer func() {
		routeCmd := fmt.Sprintf("ip route del %s/32 via %s metric 1", vipIP, nodeIP)
		stdout, stderr, err := client.Exec(t.Context(), routeCmd)
		if err != nil {
			t.Failedf("'ip route del' failed (cmd: %q, stdout: %q, stderr: %q): %s", routeCmd, stdout, stderr, err)
		}
	}()

	requestCount := 10
	requestID := fmt.Sprintf("e2e-test-%s-%d", zone, time.Now().Unix())

	t.Log("[%s] sending %d request to T1 %s node...", zone, requestCount, node.Name)
	for range requestCount {
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/ -H \"x-request-id: %s\"", vipIP, requestID))
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	for z, beApp := range zoneBackend {
		var assertFn func(matchCount int)
		if z == zone {
			t.Log("[%s] asserting %d requests reached out backend in the same zone...", zone, requestCount)
			assertFn = func(matchCount int) {
				if requestCount != matchCount {
					t.Failedf("zone %s test failed [sent %d requests, found %d requests]", zone, requestCount, matchCount)
				}
			}
		} else {
			t.Log("[%s] asserting 0 requests reached out backend in different zone...", zone)
			assertFn = func(matchCount int) {
				if matchCount > 0 {
					t.Failedf("zone %s test failed [sent %d requests, found %d requests]", zone, requestCount, matchCount)
				}
			}
		}
		assertZoneRequestsInBackendLogs(t, beApp, requestID, assertFn)
	}
}

func assertZoneRequestsInBackendLogs(t T, beApp *hcAppContainer, requestID string, assertFn func(int)) {
	beLog, err := beApp.dockerCli.ContainerLogs(t.Context(), beApp.id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		t.Failedf("failed to read backend container [%s] logs: %s", beApp.id, err)
	}
	defer func() { _ = beLog.Close() }()

	logBuf := bufio.NewReader(beLog)
	matchCount := 0
	for {
		line, err := logBuf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Failedf("failed to read logs: %s", err)
		}
		if strings.Contains(line, requestID) {
			matchCount++
		}
	}
	assertFn(matchCount)
}

func lookupNodeInternalIP(node core_v1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type != core_v1.NodeInternalIP {
			continue
		}
		ipAddr, err := netip.ParseAddr(a.Address)
		if err != nil {
			continue
		}
		if ipAddr.Is4() {
			return a.Address
		}
	}
	return ""
}

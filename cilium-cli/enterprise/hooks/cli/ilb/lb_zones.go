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
	"fmt"
	"io"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	core_v1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

type t1ZoneScenario struct {
	client      *frrContainer
	vipIP       string
	t1ZoneNodes map[string][]core_v1.Node
	zoneBackend map[string]*hcAppContainer
}

func TestTCPProxyT1OnlyPreferSameZone(t T) {
	testName := "tcp-proxy-t1-only-prefer-same-zone"
	scenario, ok := setupT1ZoneScenario(t, testName, withPreferSameZone())
	if !ok {
		return
	}

	testCmd := curlCmdVerbose(getURL("", scenario.vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := scenario.client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	t.Log("Starting same zone routing testing...")
	for zone, nodes := range scenario.t1ZoneNodes {
		assertSameZoneRouting(t, scenario.client, zone, nodes[0], scenario.vipIP, scenario.zoneBackend, sendWithInjectedRequestID)
	}
}

func TestTCPProxyT1OnlyRequireSameZone(t T) {
	testName := "tcp-proxy-t1-only-require-same-zone"
	scenario, ok := setupT1ZoneScenario(t, testName, withRequireSameZone())
	if !ok {
		return
	}

	testCmd := curlCmdVerbose(getURL("", scenario.vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := scenario.client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	t.Log("Starting same zone routing testing...")
	for zone, nodes := range scenario.t1ZoneNodes {
		assertSameZoneRouting(t, scenario.client, zone, nodes[0], scenario.vipIP, scenario.zoneBackend, sendWithInjectedRequestID)
	}

	t.Log("Starting same zone failover testing...")
	for zone, nodes := range scenario.t1ZoneNodes {
		assertFailoverZoneRouting(t, scenario.client, zone, nodes[0], scenario.vipIP, scenario.zoneBackend)
	}
}

func setupT1ZoneScenario(t T, testName string, zoneAwareOpt serviceOption) (t1ZoneScenario, bool) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return t1ZoneScenario{}, false
	}

	if skipIfOnSingleNode(">1 backends are not supported") {
		return t1ZoneScenario{}, false
	}

	t.Log("Collecting T1 nodes...")
	t1Nodes, err := getT1Nodes(t, k8sCli)
	if err != nil {
		t.Failedf("failed to get T1 nodes: %s", err)
	}

	t1ZoneNodes := getZoneNodes(t1Nodes)
	if len(t1ZoneNodes) < 2 {
		fmt.Printf("skipping due to not enough T1 nodes in different zones [%d < 2]\n", len(t1ZoneNodes))
		return t1ZoneScenario{}, false
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(len(t1ZoneNodes),
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
	backends, zoneBackend := zonedBackendsForScenario(scenario.backendApps, slices.Collect(maps.Keys(t1ZoneNodes)))
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName,
		withPort(80),
		withTCPProxyApplication(
			withTCPForceDeploymentMode(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1),
			withTCPProxyRoute(backendPool.Name),
		),
		zoneAwareOpt,
	)
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	return t1ZoneScenario{
		client:      client,
		vipIP:       vipIP,
		t1ZoneNodes: t1ZoneNodes,
		zoneBackend: zoneBackend,
	}, true
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

func getZoneNodes(nodes []core_v1.Node) map[string][]core_v1.Node {
	zoneNodes := make(map[string][]core_v1.Node)
	for _, node := range nodes {
		zone := node.Labels[core_v1.LabelTopologyZone]
		if zone == "" {
			continue
		}
		nodes, ok := zoneNodes[zone]
		if !ok {
			nodes = make([]core_v1.Node, 0)
		}
		zoneNodes[zone] = append(nodes, node)
	}
	return zoneNodes
}

func zonedBackendsForScenario(backends map[string]*hcAppContainer, zones []string) ([]backendPoolOption, map[string]*hcAppContainer) {
	backendOptions := make([]backendPoolOption, 0, len(zones))
	zoneBackend := make(map[string]*hcAppContainer, len(zones))
	index := 0
	for _, b := range backends {
		zone := zones[index]
		backendOptions = append(backendOptions, withIPBackendAndZone(b.ipv4, b.port, zone))
		zoneBackend[zone] = b
		index++
	}
	return backendOptions, zoneBackend
}

func assertSameZoneRouting(t T, client *frrContainer, zone string, node core_v1.Node, vipIP string, zoneBackend map[string]*hcAppContainer, collectRequestLogMatcher func(t T, client *frrContainer, zone, nodeName, vipIP string, requestCount int) requestLogMatcher) {
	t.Log("[%s] targeting traffic from client to %s via T1 %s node...", zone, vipIP, node.Name)
	requestCount := 10
	defer routeTrafficViaT1Node(t, client, vipIP, node)()
	matchRequestLog := collectRequestLogMatcher(t, client, zone, node.Name, vipIP, requestCount)

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
		assertRequestsInBackendLogs(t, beApp, matchRequestLog, assertFn)
	}
}

func assertFailoverZoneRouting(t T, client *frrContainer, zone string, node core_v1.Node, vipIP string, zoneBackend map[string]*hcAppContainer) {
	t.Log("[%s] targeting traffic from client to %s via T1 %s node...", zone, vipIP, node.Name)
	defer routeTrafficViaT1Node(t, client, vipIP, node)()

	beApp, ok := zoneBackend[zone]
	if !ok {
		t.Failedf("backend app not found for zone: %s", zone)
	}
	beApp.SetHC(t, hcFail)
	defer beApp.SetHC(t, hcOK)

	requestID := fmt.Sprintf("e2e-test-%s-fail-%d", zone, time.Now().Unix())
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/ -H \"%s: %s\"", vipIP, requestIDHeader, requestID))
	matchRequestLog := func(line string) bool { return strings.Contains(line, requestID) }
	hitCount := waitForFailClosedResult(t, client, zone, testCmd)
	assertFailoverBackendLogs(t, zone, zoneBackend, matchRequestLog, hitCount)
}

func waitForFailClosedResult(t T, client *frrContainer, zone, testCmd string) int {
	hitCount := 0
	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return nil
		}
		hitCount++
		return fmt.Errorf("curl still succeeded unexpectedly (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
	}, longTimeout, longPollInterval)
	return hitCount
}

func assertFailoverBackendLogs(t T, zone string, zoneBackend map[string]*hcAppContainer, matchRequestLog requestLogMatcher, hitCount int) {
	for z, beApp := range zoneBackend {
		if z == zone {
			assertSameZoneFailoverHits(t, zone, z, beApp, matchRequestLog, hitCount)
			continue
		}
		assertNoCrossZoneFailoverHits(t, zone, z, beApp, matchRequestLog)
	}
}

func assertSameZoneFailoverHits(t T, zone, backendZone string, beApp *hcAppContainer, matchRequestLog requestLogMatcher, hitCount int) {
	t.Log("[%s] asserting that only %d requests reached backend in zone %s before fail...", zone, hitCount, backendZone)
	assertRequestsInBackendLogs(t, beApp, matchRequestLog, func(matchCount int) {
		if matchCount != hitCount {
			t.Failedf("zone %s failover test failed [found %d requests in zone %s backend]", zone, matchCount, backendZone)
		}
	})
}

func assertNoCrossZoneFailoverHits(t T, zone, backendZone string, beApp *hcAppContainer, matchRequestLog requestLogMatcher) {
	t.Log("[%s] asserting 0 requests reached backend in zone %s after fail...", zone, backendZone)
	assertRequestsInBackendLogs(t, beApp, matchRequestLog, func(matchCount int) {
		if matchCount > 0 {
			t.Failedf("zone %s failover test failed [found %d requests in zone %s backend]", zone, matchCount, backendZone)
		}
	})
}

func routeTrafficViaT1Node(t T, client *frrContainer, vipIP string, node core_v1.Node) func() {
	nodeIP := lookupNodeInternalIP(node)
	if nodeIP == "" {
		t.Failedf("failed to lookup %s node internal IP address", node.Name)
	}

	routeCmd := fmt.Sprintf("ip route add %s/32 via %s metric 1", vipIP, nodeIP)
	stdout, stderr, err := client.Exec(t.Context(), routeCmd)
	if err != nil {
		t.Failedf("'ip route add' failed (cmd: %q, stdout: %q, stderr: %q): %s", routeCmd, stdout, stderr, err)
	}

	return func() {
		routeCmd := fmt.Sprintf("ip route del %s/32 via %s metric 1", vipIP, nodeIP)
		stdout, stderr, err := client.Exec(t.Context(), routeCmd)
		if err != nil {
			t.Failedf("'ip route del' failed (cmd: %q, stdout: %q, stderr: %q): %s", routeCmd, stdout, stderr, err)
		}
	}
}

type requestLogMatcher func(line string) bool

func sendWithInjectedRequestID(t T, client *frrContainer, zone, nodeName, vipIP string, requestCount int) requestLogMatcher {
	requestID := uuid.New().String()

	t.Log("[%s] sending %d request to T1 %s node...", zone, requestCount, nodeName)
	for range requestCount {
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/ -H \"%s: %s\"", vipIP, requestIDHeader, requestID))
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	return func(line string) bool {
		return getRequestIDValue(line) == requestID
	}
}

func assertRequestsInBackendLogs(t T, beApp *hcAppContainer, matchRequestLog requestLogMatcher, assertFn func(int)) {
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
		if matchRequestLog(line) {
			matchCount++
		}
	}
	assertFn(matchCount)
}

const requestIDHeader = "x-request-id"

var matcher = regexp.MustCompile(`\b` + requestIDHeader + `\s*[:=]\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

func getRequestIDValue(line string) string {
	if m := matcher.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	return ""
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

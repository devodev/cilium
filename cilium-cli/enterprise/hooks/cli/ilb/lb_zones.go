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
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	core_v1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/cilium-cli/defaults"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

type t1ZoneScenario struct {
	client      *frrContainer
	vipIP       string
	t1ZoneNodes map[string][]core_v1.Node
	zoneBackend map[string]*hcAppContainer
}

type zoneFailoverAssert func(t T, client *frrContainer, zone string, node core_v1.Node, vipIP string, zoneBackend map[string]*hcAppContainer, requestCount int)

func TestTCPProxyT1OnlyPreferSameZone(t T) {
	runT1ZoneTest(t, "tcp-proxy-t1-only-prefer-same-zone", withPreferSameZone(), assertPreferZoneFailover, 10)
}

func TestTCPProxyT1OnlyRequireSameZone(t T) {
	runT1ZoneTest(t, "tcp-proxy-t1-only-require-same-zone", withRequireSameZone(), assertRequireZoneFailover, 10)
}

func TestT2HTTPPreferSameZone(t T) {
	runT2HTTPZoneTest(t, "t2-http-prefer-same-zone", withPreferSameZone(), assertPreferZoneFailover, 10)
}

func TestT2HTTPRequireSameZone(t T) {
	runT2HTTPZoneTest(t, "t2-http-require-same-zone", withRequireSameZone(), assertRequireZoneFailover, 10)
}

func runT1ZoneTest(t T, testName string, zoneAwareOpt zoneAware, failoverAssert zoneFailoverAssert, requestCount int) {
	scenario, ok := setupT1ZoneScenario(t,
		testName,
		withTrafficPolicy(
			withZoneAware(
				zoneAwareOpt,
			),
		),
	)
	if !ok {
		return
	}

	assertVIPConnectivity(t, scenario.client, scenario.vipIP)

	t.Log("Zone routing testing...")
	for zone, nodes := range scenario.t1ZoneNodes {
		withTrafficViaT1Node(t, scenario.client, zone, nodes[0], scenario.vipIP, func() {
			t.Log("[%s] sending %d request to T1 %s node...", zone, requestCount, nodes[0].Name)
			matcher, err := sendRequestsWithID(t, scenario.client, scenario.vipIP, requestCount)
			if err != nil {
				t.Failedf("failed to send request: %s", err)
			}

			assertSameZoneRequests(t, zone, scenario.zoneBackend, requestCount, matcher)
		})
	}

	t.Log("Zone failover testing...")
	for zone, nodes := range scenario.t1ZoneNodes {
		withTrafficViaT1Node(t, scenario.client, zone, nodes[0], scenario.vipIP, func() {
			withFailedZoneBackend(t, zone, scenario.zoneBackend, func() {
				failoverAssert(t, scenario.client, zone, nodes[0], scenario.vipIP, scenario.zoneBackend, requestCount)
			})
		})
	}
}

func runT2HTTPZoneTest(t T, testName string, mode zoneAware, failoverAssert zoneFailoverAssert, requestCount int) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	if skipIfUnsupportedZoneTests(t, k8sCli) {
		return
	}

	t1ZoneNodes, ok := collectZoneNodes(t, k8sCli, "T1", getT1Nodes)
	if !ok {
		return
	}

	t2ZoneNodes, ok := collectZoneNodes(t, k8sCli, "T2", getT2Nodes)
	if !ok {
		return
	}

	if skipIfT2ZoneAwarenessDisabled(t, k8sCli) {
		return
	}

	if skipIfT1AndT2ZonesMistmatch(t1ZoneNodes, t2ZoneNodes) {
		return
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
		withHTTPProxyApplication(withHttpRoute(testName)),
		withTrafficPolicy(
			withZoneAware(mode),
		),
	)
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	assertVIPConnectivity(t, client, vipIP)

	if skipIfRequestIDUnavailable(t, client, vipIP) {
		return
	}

	t.Log("Zone routing testing...")
	for zone, nodes := range t1ZoneNodes {
		withTrafficViaT1Node(t, client, zone, nodes[0], vipIP, func() {
			t.Log("[%s] sending %d request to T1 %s node...", zone, requestCount, nodes[0].Name)
			matcher, err := sendRequestsWithID(t, client, vipIP, requestCount)
			if err != nil {
				t.Failedf("failed to send request: %s", err)
			}

			assertSameZoneRequests(t, zone, zoneBackend, requestCount, matcher)
		})
	}

	t.Log("Zone failover testing...")
	for zone, nodes := range t1ZoneNodes {
		withTrafficViaT1Node(t, client, zone, nodes[0], vipIP, func() {
			withFailedZoneBackend(t, zone, zoneBackend, func() {
				failoverAssert(t, client, zone, nodes[0], vipIP, zoneBackend, requestCount)
			})
		})
	}
}

func setupT1ZoneScenario(t T, testName string, zoneAwareOpt serviceOption) (t1ZoneScenario, bool) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	if skipIfUnsupportedZoneTests(t, k8sCli) {
		return t1ZoneScenario{}, false
	}

	t1ZoneNodes, ok := collectZoneNodes(t, k8sCli, "T1", getT1Nodes)
	if !ok {
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

func assertVIPConnectivity(t T, client *frrContainer, vipIP string) {
	testCmd := curlCmdVerbose(getURL("", vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
}

func getT1Nodes(t T, client *kubernetes.Clientset) ([]core_v1.Node, error) {
	return getNodesBySelector(t, client, "service.cilium.io/node in (t1, t1-t2)")
}

func getT2Nodes(t T, client *kubernetes.Clientset) ([]core_v1.Node, error) {
	return getNodesBySelector(t, client, "service.cilium.io/node in (t2, t1-t2)")
}

func getNodesBySelector(t T, client *kubernetes.Clientset, labelSelector string) ([]core_v1.Node, error) {
	nodes, err := client.CoreV1().Nodes().List(t.Context(), v1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, err
	}
	return nodes.Items, nil
}

func skipIfUnsupportedZoneTests(t T, k8sCli *kubernetes.Clientset) bool {
	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return true
	}

	if skipIfOnSingleNode(">1 backends are not supported") {
		return true
	}

	return false
}

func collectZoneNodes(t T, client *kubernetes.Clientset, nodeKind string, getNodes func(T, *kubernetes.Clientset) ([]core_v1.Node, error)) (map[string][]core_v1.Node, bool) {
	t.Log("Collecting %s nodes...", nodeKind)
	nodes, err := getNodes(t, client)
	if err != nil {
		t.Failedf("failed to get %s nodes: %s", nodeKind, err)
	}

	zoneNodes := getZoneNodes(nodes)
	if len(zoneNodes) < 2 {
		fmt.Printf("skipping due to not enough %s nodes in different zones [%d < 2]\n", nodeKind, len(zoneNodes))
		return nil, false
	}

	return zoneNodes, true
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

func skipIfT2ZoneAwarenessDisabled(t T, k8sCli *kubernetes.Clientset) bool {
	cm, err := k8sCli.CoreV1().ConfigMaps(t.CiliumNamespace()).Get(t.Context(), defaults.ConfigMapName, v1.GetOptions{})
	if err != nil {
		t.Failedf("failed to get Cilium ConfigMap [%s/%s]: %s", t.CiliumNamespace(), defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		t.Failedf("Cilium ConfigMap [%s/%s] is empty", t.CiliumNamespace(), defaults.ConfigMapName)
	}

	if cm.Data["envoy-node-locality-enabled"] != "true" {
		fmt.Printf("skipping due to Envoy node locality config disabled\n")
		return true
	}

	return false
}

func skipIfT1AndT2ZonesMistmatch(t1ZoneNodes, t2ZoneNodes map[string][]core_v1.Node) bool {
	for zone := range t1ZoneNodes {
		if _, ok := t2ZoneNodes[zone]; !ok {
			fmt.Printf("skipping due to missing T2 nodes for zone: %s\n", zone)
			return true
		}
	}
	return false
}

func skipIfRequestIDUnavailable(t T, client *frrContainer, vipIP string) bool {
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/ -I -H \"%s: %s\"", vipIP, requestIDHeader, uuid.New().String()))
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
	if getRequestIDValue(stdout) == "" {
		fmt.Printf("skipping due to missing %q in HTTP response; test requires request-id in response propagation\n", requestIDHeader)
		return true
	}
	return false
}

func withTrafficViaT1Node(t T, client *frrContainer, zone string, node core_v1.Node, vipIP string, run func()) {
	t.Log("[%s] targeting traffic from client to %s via T1 %s node...", zone, vipIP, node.Name)
	nodeIP := lookupNodeInternalIP(node)
	if nodeIP == "" {
		t.Failedf("failed to lookup %s node internal IP address", node.Name)
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
	run()
}

func withFailedZoneBackend(t T, zone string, zoneBackend map[string]*hcAppContainer, run func()) {
	beApp, ok := zoneBackend[zone]
	if !ok {
		t.Failedf("backend app not found for zone: %s", zone)
	}

	beApp.SetHC(t, hcFail)
	defer beApp.SetHC(t, hcOK)
	run()
}

func assertSameZoneRequests(t T, zone string, zoneBackend map[string]*hcAppContainer, requestCount int, matcher logMatcher) {
	for beZone, beApp := range zoneBackend {
		count := countRequestsInBackendLogs(t, beApp, matcher)
		if beZone == zone {
			t.Log("[%s] asserting %d requests reached out backend in the same zone...", zone, requestCount)
			if requestCount != count {
				t.Failedf("zone %s test failed [sent %d requests, found %d requests]", zone, requestCount, count)
			}
			continue
		}

		t.Log("[%s] asserting 0 requests reached out backend in different zone...", zone)
		if count > 0 {
			t.Failedf("zone %s test failed [sent %d requests, found %d requests]", zone, requestCount, count)
		}
	}
}

func assertOtherZonesRequests(t T, zone string, zoneBackend map[string]*hcAppContainer, requestCount int, matcher logMatcher) {
	totalCount := 0
	for beZone, beApp := range zoneBackend {
		count := countRequestsInBackendLogs(t, beApp, matcher)
		if beZone == zone {
			t.Log("[%s] asserting 0 requests reached out backend in the same zone...", zone)
			if count > 0 {
				t.Failedf("zone %s test failed [sent %d requests, found %d requests]", zone, requestCount, count)
			}
			continue
		}

		totalCount += count
	}

	t.Log("[%s] asserting %d requests reached out backend in different zones...", zone, requestCount)
	if requestCount != totalCount {
		t.Failedf("zone %s test failed [sent %d requests, found %d requests]", zone, requestCount, totalCount)
	}
}

func assertRequireZoneFailover(t T, client *frrContainer, zone string, node core_v1.Node, vipIP string, zoneBackend map[string]*hcAppContainer, requestCount int) {
	hitCount := 0
	matchers := []logMatcher{}
	eventually(t, func() error {
		t.Log("[%s] waiting for request to fail ...", zone)
		matcher, err := sendRequestsWithID(t, client, vipIP, 1)
		if err != nil {
			if errors.Is(err, errFailClosed) {
				return nil
			}
			t.Log("[%s] unexpected error received: %v", zone, err)
			return err
		}

		hitCount++
		matchers = append(matchers, matcher)
		return fmt.Errorf("curl still succeeded unexpectedly")
	}, longTimeout, longPollInterval)

	matcher := func(line string) bool {
		for _, matcher := range matchers {
			if matcher(line) {
				return true
			}
		}
		return false
	}
	assertRequireZoneFailoverBackendLogs(t, zone, zoneBackend, matcher, hitCount)

	t.Log("[%s] sending %d request to T1 %s node, all must fail...", zone, requestCount, node.Name)
	for range requestCount {
		if _, err := sendRequestsWithID(t, client, vipIP, 1); err != nil {
			if errors.Is(err, errFailClosed) {
				continue
			}
			t.Failedf("request failed with unexpected error: %s", err)
		}
		t.Failedf("request must fail")
	}
}

func assertRequireZoneFailoverBackendLogs(t T, zone string, zoneBackend map[string]*hcAppContainer, matcher logMatcher, hitCount int) {
	for beZone, beApp := range zoneBackend {
		count := countRequestsInBackendLogs(t, beApp, matcher)
		if beZone == zone {
			t.Log("[%s] asserting that only %d requests reached backend in zone %s before fail...", zone, hitCount, beZone)
			if count != hitCount {
				t.Failedf("[%s] failover test failed [found %d requests in zone %s backend]", zone, count, beZone)
			}
			continue
		}

		t.Log("[%s] asserting 0 requests reached backend in zone %s after fail...", zone, beZone)
		if count > 0 {
			t.Failedf("zone %s failover test failed [found %d requests in zone %s backend]", zone, count, beZone)
		}
	}
}

func assertPreferZoneFailover(t T, client *frrContainer, zone string, node core_v1.Node, vipIP string, zoneBackend map[string]*hcAppContainer, requestCount int) {
	// wait for failover first
	eventually(t, func() error {
		t.Log("[%s] waiting for request to fail...", zone)
		matcher, err := sendRequestsWithID(t, client, vipIP, 1)
		if err != nil {
			return err
		}

		matchedZones := make([]string, 0, len(zoneBackend))
		for beZone, app := range zoneBackend {
			hitCount := countRequestsInBackendLogs(t, app, matcher)
			if hitCount == 0 {
				continue
			}
			if hitCount != 1 {
				t.Failedf("unexpectedly matched %d log lines in zone %s", hitCount, beZone)
			}

			matchedZones = append(matchedZones, beZone)
		}

		if len(matchedZones) == 1 && matchedZones[0] != zone {
			t.Log("[%s] request failed over to backend zone %s", zone, matchedZones[0])
			return nil
		}

		return fmt.Errorf("[%s] failover is still in progress...", zone)
	}, longTimeout, longPollInterval)

	// asserting cross zone routing
	matcher, err := sendRequestsWithID(t, client, vipIP, requestCount)
	if err != nil {
		t.Failedf("failed to send request: %s", err)
	}

	assertOtherZonesRequests(t, zone, zoneBackend, requestCount, matcher)
}

type logMatcher func(line string) bool

var errFailClosed = errors.New("request failed closed")

func sendRequestsWithID(t T, client *frrContainer, vipIP string, count int) (logMatcher, error) {
	ids := make([]string, 0, count)
	for range count {
		rqID := uuid.NewString()
		testCmd := curlCmdVerbose(fmt.Sprintf("--fail --max-time 10 http://%s:80/ -I -H \"%s: %s\"", vipIP, requestIDHeader, rqID))
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			if strings.Contains(stderr, "Could not connect to server") || strings.Contains(stderr, "requested URL returned error: 5") {
				return nil, errFailClosed
			}
			return nil, fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}

		// for T2 service we must collect ID from response header
		if rsID := getRequestIDValue(stdout); rsID != "" {
			ids = append(ids, rsID)
			continue
		}
		// for T1 service we must collect ID from request header
		ids = append(ids, rqID)
	}
	return func(line string) bool {
		return slices.Contains(ids, getRequestIDValue(line))
	}, nil
}

func countRequestsInBackendLogs(t T, beApp *hcAppContainer, matcher logMatcher) int {
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
		if matcher(line) {
			matchCount++
		}
	}
	return matchCount
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

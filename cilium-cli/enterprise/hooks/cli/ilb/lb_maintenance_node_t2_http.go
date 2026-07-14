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
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestNodeMaintenance_T2_T1T2_HTTP(t T) {
	testName := "node-maintenance-t2-http2"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// node maintenance is only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	// Skip test in environments with only one T2 node instance because this breaks connection
	// because VIP will no longer be announced on T1 nodes if there's no healthy T2 node
	t2NodeList, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: "service.cilium.io/node in ( t2, t1-t2 )"})
	if err != nil {
		t.Failedf("failed to retrieve t2 k8s nodes: %s", err)
	}

	if len(t2NodeList.Items) < 2 {
		fmt.Printf("skipping due to not at least 2 T2 nodes available\n")
		return
	}

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{})

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
		withHttpRoute(testName),
	))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	testCmd := fmt.Sprintf("lb-test-client http http://%s:%s", vipIP, "80")
	t.Log("Starting HTTP client that opens TCP connection %q...", testCmd)
	testClientOutputReader, err := client.ExecDetached(t.Context(), []string{"lb-test-client", "http", fmt.Sprintf("http://%s:%s", vipIP, "80")})
	if err != nil {
		t.Failedf("failed to start http client (cmd: %q): %s", testCmd, err)
	}

	// convert io.Reader to strings.Builder for easier assertion against the full output
	testClientOutput := toTestClientOutput(testClientOutputReader)

	t.Log("Looking for T2 node IP in test app output...")
	t2NodeIP := waitForInitialConnection(t, testClientOutput)

	t.Log("Loading T2 node with IP %s that is handling the http connection", t2NodeIP)
	t2Node := getK8sNodeWithIP(t, k8sCli, t2NodeIP)

	t.Log("Marking T2 node %s that is handling the http connection as unschedulable", t2Node.Name)
	markNodeAsUnschedulable(t, k8sCli, t2Node.Name)

	//  register cleanup to revert all k8s nodes to be schedulable (in case we abort early due to an error)
	t.RegisterCleanup(markAllNodesAsSchedulable(k8sCli))

	t.Log("Waiting for HTTP reconnect with new connection to another T2 instance")
	waitForReconnect(t, testClientOutput, vipIP)

	t.Log("Waiting until 100 consecutive new HTTP requests don't use T2 node %s that is marked as unschedulable", t2Node.Name)
	testCmd2 := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/test2", vipIP))
	waitUntil100NewHTTPRequestsDontUseT2Node(t, client, testCmd2, t2NodeIP)

	t.Log("Marking T2 node %s as schedulable", t2Node.Name)
	markNodeAsSchedulable(t, k8sCli, t2Node.Name)

	t.Log("Checking that new HTTP requests eventually use T2 node %s again", t2Node.Name)
	checkNewHTTPRequestsUseT2(t, client, testCmd2, t2NodeIP)
}

func toTestClientOutput(testClientOutputReader io.Reader) *strings.Builder {
	testClientOutput := new(strings.Builder)

	go func() {
		var writer io.Writer = testClientOutput

		if FlagVerbose {
			writer = io.MultiWriter(os.Stdout, writer)
		}

		if _, err := io.Copy(writer, testClientOutputReader); err != nil {
			fmt.Printf("failed to copy test app output: %s\n", err)
		}
	}()

	return testClientOutput
}

func waitForInitialConnection(t T, testClientOutput *strings.Builder) string {
	t2NodeIP := ""

	regex := regexp.MustCompile("t2-ip-port: ([^:]*):")

	eventually(t, func() error {
		output := testClientOutput.String()

		if strings.Contains(output, "connection-close: true") {
			return errors.New("output already contains a connection: close")
		}

		s := regex.FindStringSubmatch(output)
		if len(s) > 1 {
			t2NodeIP = s[1]
			return nil
		}

		return errors.New("t2 ip not found")
	}, shortTimeout, pollInterval)

	return t2NodeIP
}

func waitForReconnect(t T, testClientOutput *strings.Builder, vipIP string) {
	eventually(t, func() error {
		output := testClientOutput.String()

		// Check whether Envoy already successfully drained the open connection. This is either detected by the
		// response header `connection: close` or the presence of the logoutput `HTTP transport creates new connection to <VIP>:80`
		// (It needs to present twice - once for the initial connection setup and once for the reconnect).
		if !strings.Contains(output, "connection-close: true") && strings.Count(output, fmt.Sprintf("HTTP transport creates new connection to %s:80", vipIP)) != 2 {
			return errors.New("T2 Envoy didn't terminated http connection yet")
		}

		if strings.Count(output, fmt.Sprintf("HTTP transport creates new connection to %s:%s", vipIP, "80")) != 2 {
			return errors.New("No HTTP reconnect yet (1 initial, 2 re-connect")
		}

		// connection terminated by T2 Envoy - and reconnected to new T2 instance
		return nil
	}, shortTimeout, pollInterval)
}

func waitUntil100NewHTTPRequestsDontUseT2Node(t T, client *frrContainer, testCmd string, t2NodeIP string) {
	eventually(t, func() error {
		for range 100 {
			stdout, stderr, err := client.Exec(t.Context(), testCmd)
			if err != nil {
				return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}

			resp, err := toTestAppResponse(stdout)
			if err != nil {
				return err
			}

			if strings.Contains(resp.RemoteAddr, t2NodeIP) {
				return fmt.Errorf("new connection still using unschedulable node as T2 node")
			}
		}

		return nil
	}, shortTimeout, pollInterval)
}

func checkNewHTTPRequestsUseT2(t T, client *frrContainer, testCmd string, t2NodeIP string) {
	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}

		resp, err := toTestAppResponse(stdout)
		if err != nil {
			return err
		}

		if !strings.Contains(resp.RemoteAddr, t2NodeIP) {
			return fmt.Errorf("new connection not using node as T2 again")
		}

		return nil
	}, longTimeout, pollInterval)
}

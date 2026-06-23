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
	"time"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestUDPProxyT1OnlySession(t T) {
	testUDPProxySession(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1)
}

func TestUDPProxyT1T2Session(t T) {
	testUDPProxySession(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2)
}

func TestUDPProxyAutoSession(t T) {
	testUDPProxySession(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto)
}

func testUDPProxySession(t T, forceDeploymentMode isovalentv1alpha1.LBUDPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	if skipIfOnSingleNode(">1 backends are not supported") {
		return
	}

	testName := "udp-proxy-session-" + string(forceDeploymentMode)

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
	service := lbService(testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// Send UDP request to test basic `client -> LB T1 -> app` connectivity.
	// Do a few attempts, as neither UDP nor nc are reliable.
	testCmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 -p 55555 %s 80", vipIP)

	// waitForFullVIPConnectivity only guarantees that the VIP route is present;
	// it does not guarantee that backend selection has settled. The control
	// plane may still be converging (operator -> CiliumEnvoyConfig -> Envoy EDS
	// for T2, or the maglev table for T1), and a backend-set update racing the
	// first packets can remap an established UDP session to the other backend.
	// Warm up until selection is stable before asserting strict persistence,
	// otherwise the very first response pins an "expected" backend that a still
	// in-flight update may move.
	t.Log("Warming up UDP flow until backend selection is stable...")
	stabilizeUDPSessionBackend(t, client, testCmd, 5)

	t.Log("Testing UDP session with 10 requests from same source port: %q...", testCmd)
	testUDPSessionWithNRequests(t, client, testCmd, 10)
}

// stabilizeUDPSessionBackend warms up the UDP flow until backend selection has
// converged, i.e. until it observes `stable` consecutive responses from the same
// backend. Unlike testUDPSessionWithNRequests below, a backend change here is not
// treated as a failure but as a signal that the datapath is still settling, so we
// reset the streak and keep polling. This gates the strict persistence assertion
// on a quiescent datapath without masking a real stickiness regression: if the
// backend never stabilizes, this simply times out as a failure.
func stabilizeUDPSessionBackend(t T, client *frrContainer, testCmd string, stable int) {
	streak := 0
	previousServiceName := ""
	eventually(t, func() error {
		stdout, _, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// we never expect an error (netcat doesn't return error in case of timeout)
			return fmt.Errorf("unexpected error %w", err)
		}

		if stdout == "" {
			// e.g. technical issue - we're only interested in sessions (-> backend selection)
			return fmt.Errorf("empty response")
		}

		resp := toTestAppL4Response(t, stdout)
		if resp.ServiceName == "" {
			return fmt.Errorf("no service name in response")
		}

		if resp.ServiceName != previousServiceName {
			// Backend selection not converged yet; reset the streak.
			previousServiceName = resp.ServiceName
			streak = 1
			return fmt.Errorf("backend not stable yet, now serviced by %s", resp.ServiceName)
		}

		streak++
		if streak >= stable {
			return nil
		}

		return fmt.Errorf("backend stable for %d/%d responses", streak, stable)
	}, longTimeout, time.Millisecond*1) // As fast as possible
}

func testUDPSessionWithNRequests(t T, client *frrContainer, testCmd string, total int) {
	successCount := 0
	previousServiceName := ""
	eventually(t, func() error {
		stdout, _, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// we never expect an error (netcat doesn't return error in case of timeout)
			return fmt.Errorf("unexpected error %w", err)
		}

		if stdout == "" {
			// e.g. technical issue - we're only interested in sessions (-> backend  selection)
			return fmt.Errorf("empty response %w", err)
		}

		resp := toTestAppL4Response(t, stdout)

		assertPersistentBackend(t, previousServiceName, resp.ServiceName)
		previousServiceName = resp.ServiceName

		successCount++
		if successCount == total {
			return nil
		}

		return fmt.Errorf("condition is not satisfied yet (%d/%d)", successCount, total)
	}, longTimeout, time.Millisecond*1) // As fast as possible
}

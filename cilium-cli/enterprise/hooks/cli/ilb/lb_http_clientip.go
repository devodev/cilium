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
	"strings"
)

type testClientIPCall struct {
	blocked bool
}

type runIfFunc func() bool

func TestHTTPClientIP(t T) {
	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) httpApplicationOption
		runIfs    map[string]runIfFunc
		testCalls []testClientIPCall
	}{
		// Test cases for use-remote-address=true and xff-num-trusted-hops=0
		{
			desc: "remote-deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringDenyBySourceIP(clients[0].ipv4 + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":    useRemoteAddressEnabled,
				"xff-num-trusted-hops must be disabled": xffNumTrustedHopsDisabled,
			},
			testCalls: []testClientIPCall{
				{blocked: true},
			},
		},
		{
			desc: "remote-allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringAllowBySourceIP(clients[0].ipv4 + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":    useRemoteAddressEnabled,
				"xff-num-trusted-hops must be disabled": xffNumTrustedHopsDisabled,
			},
			testCalls: []testClientIPCall{
				{blocked: false},
			},
		},

		// Test cases for use-remote-address=true + xff-num-trusted-hops > 0
		{
			desc: "remote-hops-deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringDenyBySourceIP(clients[0].ipv4 + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":   useRemoteAddressEnabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: true},
			},
		},
		{
			desc: "remote-hops-allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringAllowBySourceIP(clients[0].ipv4 + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":   useRemoteAddressEnabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: false},
			},
		},

		// Test cases for use-remote-address=false + xff-num-trusted-hops > 0
		{
			desc: "hops-deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringDenyBySourceIP(clients[0].ipv4 + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be disabled":  useRemoteAddressDisabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: true},
			},
		},
		{
			desc: "hops-allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringAllowBySourceIP(clients[0].ipv4 + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be disabled":  useRemoteAddressDisabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: false},
			},
		},
	}

	for _, tC := range testCases {
		t.Log("Checking %s", tC.desc)

		if !shouldRun(t, tC.runIfs) {
			continue
		}

		testName := fmt.Sprintf("http-clientip-%s", tC.desc)

		ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
		dockerCli := NewDockerCli(t)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

		t.Log("Creating backend apps...")
		scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})

		t.Log("Creating clients and add BGP peering ...")
		clients := scenario.addFRRClients(1, frrClientConfig{})

		t.Log("Creating LB VIP resources...")
		vip := lbVIP(testName)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		var backends []backendPoolOption
		for _, b := range scenario.backendApps {
			backends = append(backends, withIPBackend(b.ipv4, b.port))
		}
		backendPool := lbBackendPool(testName, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		opts := []httpApplicationOption{}
		opts = append(opts, withHttpRoute(testName))
		opts = append(opts, tC.appOpt(clients))
		service := lbService(testName, withHTTPProxyApplication(opts...))
		scenario.createLBService(service)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		for _, tt := range tC.testCalls {
			t.RunTestCase(func(t T) {
				testCmd := curlCmd(fmt.Sprintf("--max-time 10 %s --resolve insecure.acme.io:80:%s http://insecure.acme.io:80/", generateHeaders(FlagXffNumTrustedHops), vipIP))
				t.Log("Testing %q...", testCmd)
				eventually(t, func() error {
					stdout, stderr, err := clients[0].Exec(t.Context(), testCmd)
					if tt.blocked {
						if err == nil || (err.Error() != "cmd failed: 52" && err.Error() != "cmd failed: 22") {
							return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
						}
					} else {
						if err != nil {
							return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
						}
						resp, err := toTestAppResponse(stdout)
						if err != nil {
							return err
						}
						t.Log("Response: %v", resp)
						if useRemoteAddressEnabled() && !strings.Contains(resp.XFF, clients[0].ipv4) {
							return fmt.Errorf("expected %q not to contain %q", resp.XFF, clients[0].ipv4)
						}
					}

					return nil
				}, shortTimeout, pollInterval)
			})
		}
	}
}

// generateHeaders generates headers including X-Forwarded-For IPs
// The list of IP addresses is generated from 1.0.0.0 to 1.0.0.<numOfIps+1>
func generateHeaders(numOfIps int) string {
	var xffIPs []string
	// Generate numOfIps + 1 IPs
	for i := 0; i <= numOfIps; i++ {
		xffIPs = append(xffIPs, fmt.Sprintf("1.0.0.%d", i))
	}

	headers := map[string]string{
		"Content-Type":    "application/json",
		"X-Forwarded-For": strings.Join(xffIPs, ", "),
	}

	res := strings.Builder{}
	for k, v := range headers {
		res.WriteString(fmt.Sprintf(" -H '%s: %s'", k, v))
	}

	return res.String()
}

func shouldRun(t T, runIfs map[string]runIfFunc) bool {
	for name, runIf := range runIfs {
		if !runIf() {
			t.Log("skipping test because of runIfs condition %q", name)
			return false
		}
	}

	return true
}

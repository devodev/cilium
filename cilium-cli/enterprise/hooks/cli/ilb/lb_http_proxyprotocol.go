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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type testPPCall struct {
	clientIP  string
	blocked   bool
	invisible bool // if the client IP is not visible in the backend
}

func TestHTTPProxyProtocol(t T) {
	testCases := []struct {
		desc               string
		appOpt             func(clients []*frrContainer) httpApplicationOption
		backendOpt         backendPoolOption
		disallowedVersions []int
		testCalls          []testPPCall
		notAccepted        bool
	}{
		{
			desc: "allow-all-versions",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {}
			},
			backendOpt: withProxyProtocolConfig(1, nil),
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1"},
				{clientIP: "10.0.0.2"},
			},
		},
		{
			desc: "disallow-version-2",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {}
			},
			backendOpt:         withProxyProtocolConfig(1, nil),
			disallowedVersions: []int{2}, // curl command only supports version 1
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1"},
				{clientIP: "10.0.0.2"},
			},
		},
		{
			desc: "disallow-version-2-backendversion-2",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {}
			},
			backendOpt:         withProxyProtocolConfig(2, nil),
			disallowedVersions: []int{2}, // curl command only supports version 1
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1"},
				{clientIP: "10.0.0.2"},
			},
			notAccepted: true,
		},
		{
			desc: "disallow-version-1",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {}
			},
			backendOpt:         withProxyProtocolConfig(1, nil),
			disallowedVersions: []int{1}, // curl command only supports version 1
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1", blocked: true},
				{clientIP: "10.0.0.2", blocked: true},
			},
			notAccepted: true,
		},
		{
			desc: "deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringDenyBySourceIP("10.0.0.1/32")
			},
			backendOpt: withProxyProtocolConfig(1, nil),
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1", blocked: true},
				{clientIP: "10.0.0.2", blocked: false},
			},
		},
		{
			desc: "deny-by-sourceip-backend-no-pp",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringDenyBySourceIP("10.0.0.1/32")
			},
			backendOpt: func(o *isovalentv1alpha1.LBBackendPool) {},
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1", blocked: true},
				{clientIP: "10.0.0.2", blocked: false, invisible: true},
			},
		},
		{
			desc: "allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringAllowBySourceIP("10.0.0.1/32")
			},
			backendOpt: withProxyProtocolConfig(1, nil),
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1", blocked: false},
				{clientIP: "10.0.0.2", blocked: true},
			},
		},
		{
			desc: "allow-by-sourceip-backend-no-pp",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringAllowBySourceIP("10.0.0.1/32")
			},
			backendOpt: func(o *isovalentv1alpha1.LBBackendPool) {},
			testCalls: []testPPCall{
				{clientIP: "10.0.0.1", blocked: false, invisible: true},
				{clientIP: "10.0.0.2", blocked: true},
			},
		},
	}
	for _, tC := range testCases {
		t.RunTestCase(func(t T) {
			t.Log("Checking %s", tC.desc)

			testName := fmt.Sprintf("http-proxyprotocol-%s", tC.desc)

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
			backends := []backendPoolOption{}
			for _, b := range scenario.backendApps {
				backends = append(backends, withIPBackend(b.ipv4, b.port), tC.backendOpt)
			}
			backendPool := lbBackendPool(testName, backends...)
			scenario.createLBBackendPool(backendPool)

			t.Log("Creating LB Service resources...")
			opts := []httpApplicationOption{}
			opts = append(opts, withHttpRoute(testName))
			opts = append(opts, tC.appOpt(clients))
			service := lbService(testName, withProxyProtocol(tC.disallowedVersions, nil), withHTTPProxyApplication(opts...))
			scenario.createLBService(service)

			if tC.notAccepted {
				t.Log("Waiting for proxy protocol version validation error...")
				waitForProxyProtocolVersionValidationError(t, *ciliumCli, scenario.k8sNamespace, testName)
				return
			}

			t.Log("Waiting for full VIP connectivity...")
			vipIP := scenario.waitForFullVIPConnectivity(testName)

			for _, tt := range tC.testCalls {
				testCmd := curlCmd(fmt.Sprintf(`--haproxy-protocol --haproxy-clientip %s --ipv4 --max-time 10 -H "Content-Type: application/json" --resolve insecure.acme.io:80:%s http://insecure.acme.io:80/`, tt.clientIP, vipIP))
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
						// Unlike XFF, the remote address should be the client IP
						if !tt.invisible && !strings.Contains(resp.RemoteAddr, tt.clientIP) {
							return fmt.Errorf("expected response to contain remote address %q, got %q", tt.clientIP, resp.RemoteAddr)
						}

						// XFF should contain the client IP
						if useRemoteAddressEnabled() && xffNumTrustedHopsDisabled() && !tt.invisible && !strings.Contains(resp.XFF, tt.clientIP) {
							return fmt.Errorf("expected response to contain X-Forwarded-For %q, got %q", tt.clientIP, resp.XFF)
						}
					}
					return nil
				}, shortTimeout, pollInterval)
			}
		})
	}
}

func waitForProxyProtocolVersionValidationError(t T, ciliumCli ciliumCli, testK8sNamespace string, testName string) {
	eventually(t, func() error {
		lbsvc, err := ciliumCli.GetLBService(t.Context(), testK8sNamespace, testName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		c := lbsvc.GetStatusCondition(isovalentv1alpha1.ConditionTypeBackendsCompatible)
		if c == nil {
			return errors.New("incompatible backends condition doesn't exist yet")
		}

		if c.Status != metav1.ConditionFalse || !strings.Contains(c.Message, "incompatible: ProxyProtocolConfig version") {
			return errors.New("invalid proxyprotocol not detected yet")
		}

		return nil
	}, shortTimeout, pollInterval)
}

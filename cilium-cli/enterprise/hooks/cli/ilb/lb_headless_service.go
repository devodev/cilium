// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ilb

import (
	"fmt"
)

func TestHeadlessService(t T) {
	if skipIfOnSingleNode("DNS backend test uses k8s-based backend services which is not supported in single-node mode") {
		return
	}

	testName := "headless-service"
	backendReplicas := int32(2)

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	tests := []struct {
		name           string
		suffix         string
		serviceHost    string
		backendHost    string
		serviceOptions []serviceOption
		serviceTLS     bool
		backendTLS     bool
	}{
		{
			name:        "HTTPProxy",
			suffix:      "-http-proxy",
			serviceHost: "insecure.acme.io",
			serviceOptions: []serviceOption{
				withPort(80),
				withHTTPProxyApplication(withHttpRoute(testName + "-http-proxy")),
			},
		},
		{
			name:        "HTTPSProxy",
			suffix:      "-https-proxy",
			serviceHost: "secure.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withHTTPSProxyApplication(
					withHttpsRoute(testName+"-https-proxy"),
					withCertificate(testName+"-https-proxy"),
				),
			},
			serviceTLS: true,
		},
		{
			name:        "TLSPassthrough",
			suffix:      "-tls-passthrough",
			serviceHost: "secure-backend.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withTLSPassthroughApplication(withTLSPassthroughRoute(testName + "-tls-passthrough")),
			},
			serviceTLS: true,
			backendTLS: true,
		},
		{
			name:        "TLSProxy",
			suffix:      "-tls-proxy",
			serviceHost: "secure.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withTLSProxyApplication(withTLSCertificate(testName+"-tls-proxy"), withTLSProxyRoute(testName+"-tls-proxy", withHostname("secure.acme.io"))),
			},
			serviceTLS: true,
		},
		{
			name:        "TCPProxy",
			suffix:      "-tcp-proxy",
			serviceHost: "secure.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withTCPProxyApplication(withTCPProxyRoute(testName + "-tcp-proxy")),
			},
		},
	}

	for _, tt := range tests {
		t.Log("Checking %s", tt.name)

		resourceName := testName + tt.suffix

		scenario := newLBTestScenario(t, resourceName, ciliumCli, k8sCli, dockerCli)

		t.Log("Creating backend apps...")
		backendTLSHostname := ""
		if tt.backendTLS {
			backendTLSHostname = "secure-backend.acme.io"
		}
		backendApp := backendApplication{
			name:            testName + tt.suffix,
			replicas:        backendReplicas,
			tlsCertHostname: backendTLSHostname,
		}
		desiredBackends := scenario.AddAndWaitForK8sBackendApplications(backendApp)

		t.Log("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(1, frrClientConfig{})[0]

		t.Log("Creating LB VIP resources...")
		vip := lbVIP(resourceName)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backendHostName := fmt.Sprintf("%s.%s.svc.cluster.local", testName+tt.suffix, scenario.k8sNamespace)

		backendOpts := []backendPoolOption{withHostnameBackend(backendHostName, 8080)}

		if tt.backendTLS {
			backendOpts = append(backendOpts, withHealthCheckTLS())
		}

		scenario.createLBBackendPool(lbBackendPool(resourceName, backendOpts...))

		t.Log("Creating LB Service resources...")
		if tt.serviceTLS {
			// Server certificate
			scenario.createLBServerCertificate(resourceName, "secure.acme.io")
		}

		service := lbService(resourceName, tt.serviceOptions...)
		scenario.createLBService(service)
		svcPort := service.Spec.Port

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(vip.Name)

		var testCmd string
		if tt.serviceTLS {
			testCmd = curlCmd(fmt.Sprintf("-k --max-time 10 -H 'Content-Type: application/json' --resolve %s:%d:%s https://%s:%d/", tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
		} else {
			testCmd = curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' --resolve %s:%d:%s http://%s:%d/", tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
		}

		t.Log("Testing %q until observing response from all backends bound to %s", testCmd, tt.backendHost)

		observedBackends := make(map[string]struct{})
		eventually(t, func() error {
			stdout, stderr, err := client.Exec(t.Context(), testCmd)
			if err != nil {
				return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}

			// Response from the health check server contains instance name (Pod name in this case)
			appResponse, err := toTestAppResponse(stdout)
			if err != nil {
				return err
			}

			for _, pod := range desiredBackends.Items {
				if appResponse.InstanceName == pod.Name {
					observedBackends[pod.Name] = struct{}{}
				}
			}

			// Check if we have observed all backends
			if len(observedBackends) != int(backendReplicas) {
				return fmt.Errorf("have not observed all backends yet: %d/%d", len(observedBackends), backendReplicas)
			}

			return nil
		}, longTimeout, pollInterval)
	}
}

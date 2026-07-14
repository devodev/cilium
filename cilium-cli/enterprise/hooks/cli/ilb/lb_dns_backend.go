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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestDNSBackend(t T) {
	testNameBase := "dns-backend"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	t.Log("Creating backend apps...")

	tests := []struct {
		name           string
		suffix         string
		serviceHost    string
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
				withHTTPProxyApplication(withHttpRoute(testNameBase + "-http-proxy")),
			},
		},
		{
			name:        "HTTPSProxy",
			suffix:      "-https-proxy",
			serviceHost: "secure.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withHTTPSProxyApplication(
					withHttpsRoute(testNameBase+"-https-proxy"),
					withCertificate(testNameBase+"-https-proxy"),
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
				withTLSPassthroughApplication(
					withTLSPassthroughRoute(testNameBase + "-tls-passthrough"),
				),
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
				withTLSProxyApplication(
					withTLSCertificate(testNameBase+"-tls-proxy"),
					withTLSProxyRoute(testNameBase+"-tls-proxy", withHostname("secure.acme.io")),
				),
			},
			serviceTLS: true,
		},
	}

	for _, tt := range tests {
		t.RunTestCase(func(t T) {
			t.Log("Checking %s", tt.name)

			testName := testNameBase + tt.suffix
			backendHostName := fmt.Sprintf("backend.%s.local", testName)

			scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating backend apps...")

			// FIXME: In the single node mode, we cannot bind two or more backends
			// to the same name because the port number of the backends are
			// different and DNS-based backend cannot tell the port number
			// (possibly, SRV record, but Envoy doesn't support it as of
			// 2024-10-07). So, we only create only one backend in the single node
			// mode. Better than testing nothing.
			var nbackends int
			if IsSingleNode() {
				nbackends = 1
			} else {
				nbackends = 2
			}

			var beContainers []*hcAppContainer
			if tt.backendTLS {
				scenario.createBackendServerCertificate(backendHostName)
				beContainers = scenario.addBackendApplications(nbackends, backendApplicationConfig{
					tlsCertHostname: backendHostName,
				})
			} else {
				beContainers = scenario.addBackendApplications(nbackends, backendApplicationConfig{
					h2cEnabled: true,
				})
			}

			t.Log("Registering backend apps in CoreDNS...")
			coredns := scenario.addCoreDNS()

			records := []*coreDNSRecord{}
			for _, be := range beContainers {
				records = append(records, &coreDNSRecord{
					Hostname: "backend",
					IP:       be.ipv4,
				})
			}
			if err := coredns.AddDNSRecords(t.Context(), records); err != nil {
				t.Failedf("failed to add DNS records: %v", err)
			}

			t.Log("Creating clients and add BGP peering ...")
			client := scenario.addFRRClients(1, frrClientConfig{})[0]

			t.Log("Creating LB VIP resources...")
			vip := lbVIP(testName)
			scenario.createLBVIP(vip)

			t.Log("Creating LB BackendPool resources...")
			var backendPool *isovalentv1alpha1.LBBackendPool
			if tt.backendTLS {
				backendPool = lbBackendPool(testName,
					withHostnameBackend(backendHostName, 8080),
					withDNSResolver(coredns.ipv4, coredns.port),
					withHealthCheckTLS(),
				)
			} else {
				backendPool = lbBackendPool(testName,
					withHostnameBackend(backendHostName, 8080),
					withDNSResolver(coredns.ipv4, coredns.port),
				)
			}
			scenario.createLBBackendPool(backendPool)

			t.Log("Creating LB Service resources...")
			if tt.serviceTLS {
				// Server certificate
				scenario.createLBServerCertificate(testName, "secure.acme.io")
			}

			service := lbService(testName, tt.serviceOptions...)
			scenario.createLBService(service)
			svcPort := service.Spec.Port

			t.Log("Waiting for full VIP connectivity...")
			vipIP := scenario.waitForFullVIPConnectivity(vip.Name)

			var testCmd string
			if tt.serviceTLS {
				testCmd = curlCmd(fmt.Sprintf(`-k --max-time 10 -H "Content-Type: application/json" --resolve %s:%d:%s https://%s:%d/`, tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
			} else {
				testCmd = curlCmd(fmt.Sprintf(`--max-time 10 -H "Content-Type: application/json" --resolve %s:%d:%s http://%s:%d/`, tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
			}

			observedBackends := make(map[string]struct{})
			eventually(t, func() error {
				stdout, stderr, err := client.Exec(t.Context(), testCmd)
				if err != nil {
					return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				}

				resp, err := toTestAppResponse(stdout)
				if err != nil {
					return err
				}
				observedBackends[resp.InstanceName] = struct{}{}

				if len(observedBackends) != nbackends {
					return fmt.Errorf("have not observed all backends yet: %d/%d", len(observedBackends), nbackends)
				}

				return nil
			}, shortTimeout, pollInterval)
		})
	}
}

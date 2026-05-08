//
//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestHTTPSProxyMutualTLS(t T) {
	testName := "https-proxy-mtls"
	serviceHostName := "secure.acme.io"
	clientCAName := "acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")

	scenario.createLBServerCertificate(testName, serviceHostName)

	templateOpts := []certTemplateOpts{
		withCertificateSANDNSNames(clientHostName),
		withCertificateSANURIs("https://acme.io"),
		withCertificateSANIPs("192.168.1.100", "192.168.2.200"),
		withCertificateSANMails("test@acme.io"),
		// withCertificateSANOtherNameUPN(hostName),
	}

	scenario.createLBClientCertificate(clientCAName, clientHostName, templateOpts...)

	t.Log("Creating client and add BGP peering...")

	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

	t.Log("Creating LB VIP resources...")

	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating backend app...")

	backends := scenario.addBackendApplications(1, backendApplicationConfig{})

	t.Log("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(testName, withIPBackend(backends[0].ipv4, backends[0].port))
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(testName, withPort(10443), withHTTPSProxyApplication(withCertificate(testName), withHttpsRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 3. Test basic connectivity
	t.Log("Checking Basic Connectivity")
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", serviceHostName, vipIP))

	t.Log("Testing %q...", testCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// Enrich error with curl output
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			return fmt.Errorf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
		return nil
	}, shortTimeout, 100*time.Millisecond)

	// 4. Test mTLS connectivity
	t.Log("Checking mTLS Connectivity")
	curSvc, err := ciliumCli.GetLBService(t.Context(), scenario.k8sNamespace, testName, metav1.GetOptions{})
	if err != nil {
		t.Failedf("failed to get LB service (%s): %s", testName, err)
	}

	// curl's TLS1.3 implementation doesn't return handshake error
	// (35) on certificate validation failure. TLS1.2 does, so
	// easier to handle.
	curSvc.Spec.Applications.HTTPSProxy.TLSConfig.MaxTLSVersion = ptr.To(isovalentv1alpha1.LBTLSProtocolVersion("TLSv1_2"))

	// Add validation context to the TLS config and update

	// FIXME: Don't expose internal naming convention. Get it from the scenario instead.
	caCertSecretName := testName + "-client-ca"

	curSvc.Spec.Applications.HTTPSProxy.TLSConfig.Validation = &isovalentv1alpha1.LBTLSValidationConfig{
		SecretRef: isovalentv1alpha1.LBServiceSecretRef{
			Name: caCertSecretName,
		},
		SubjectAlternativeNames: []isovalentv1alpha1.LBTLSValidationConfigSAN{
			{
				Exact: "client.acme.io",
			},
		},
	}

	if err := ciliumCli.UpdateLBService(t.Context(), scenario.k8sNamespace, curSvc, metav1.UpdateOptions{}); err != nil {
		t.Failedf("failed to update LB service (%s): %s", testName, err)
	}

	failTestCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", serviceHostName, vipIP))

	t.Log("Testing %q...", failTestCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), failTestCmd)
		if err == nil {
			// Enrich error with curl output
			return fmt.Errorf("curl should have failed but succeeded (cmd: %q, stdout: %q, stderr: %q)", failTestCmd, stdout, stderr)
		} else {
			if err.Error() != "cmd failed: 35" {
				return fmt.Errorf("curl failed with unexpected error (cmd: %q, stdout: %q, stderr: %q): %w", failTestCmd, stdout, stderr, err)
			}
		}
		return nil
	}, shortTimeout, 100*time.Millisecond)

	testCmd = curlCmdVerbose(fmt.Sprintf("--max-time 10 --cert /tmp/%s.crt --key /tmp/%s.key --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/",
		clientHostName, clientHostName, serviceHostName, vipIP))

	t.Log("Testing %q...", testCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// Enrich error with curl output
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return nil
	}, shortTimeout, 100*time.Millisecond)
}

func TestHTTPSProxyMutualTLSRequestFiltering(t T) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	testCases := []struct {
		desc           string
		clientCertOpts []certTemplateOpts
		appOpt         func(clients []*frrContainer) httpsApplicationRouteOption
		testCalls      []testCall
	}{
		{
			desc: "dns-ok",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANDNS("client.acme.io")
			},
			testCalls: []testCall{
				{
					blocked: false,
				},
			},
		},
		{
			desc: "dns-blocked",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANDNS("client2.acme.io")
			},
			testCalls: []testCall{
				{
					blocked: true,
				},
			},
		},
		{
			desc: "ip-ok",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANIP("192.168.1.100")
			},
			testCalls: []testCall{
				{
					blocked: false,
				},
			},
		},
		{
			desc: "ip-blocked",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANIP("192.168.1.200")
			},
			testCalls: []testCall{
				{
					blocked: true,
				},
			},
		},
		{
			desc: "uri-ok",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANURI("https://acme.io")
			},
			testCalls: []testCall{
				{
					blocked: false,
				},
			},
		},
		{
			desc: "uri-blocked",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANURI("https://other-acme.io")
			},
			testCalls: []testCall{
				{
					blocked: true,
				},
			},
		},
		{
			desc: "email-ok",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANEmail("test@acme.io")
			},
			testCalls: []testCall{
				{
					blocked: false,
				},
			},
		},
		{
			desc: "blocked",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANDNSNames("client.acme.io"),
				withCertificateSANURIs("https://acme.io"),
				withCertificateSANIPs("192.168.1.100"),
				withCertificateSANMails("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANEmail("other@acme.io")
			},
			testCalls: []testCall{
				{
					blocked: true,
				},
			},
		},
		{
			desc: "othername-ok",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANOtherNameUPN("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANOtherNameUPN("test@acme.io")
			},
			testCalls: []testCall{
				{
					blocked: false,
				},
			},
		},
		{
			desc: "othername-blocked",
			clientCertOpts: []certTemplateOpts{
				withCertificateSANOtherNameUPN("test@acme.io"),
			},
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowByExactClientCertSANOtherNameUPN("other@acme.io")
			},
			testCalls: []testCall{
				{
					blocked: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.RunTestCase(func(t T) {
			testName := fmt.Sprintf("https-mtls-requestfiltering-%s", tc.desc)
			serviceHostName := "secure.acme.io"
			clientCAName := "acme.io"
			clientHostName := "client.acme.io"

			scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating cert and secret...")

			scenario.createLBServerCertificate(testName, serviceHostName)

			scenario.createLBClientCertificate(clientCAName, clientHostName, tc.clientCertOpts...)

			t.Log("Creating client and add BGP peering...")

			client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

			t.Log("Creating LB VIP resources...")

			vip := lbVIP(testName)
			scenario.createLBVIP(vip)

			t.Log("Creating backend app...")

			backends := scenario.addBackendApplications(1, backendApplicationConfig{})

			t.Log("Creating LB BackendPool resources...")

			backendPool := lbBackendPool(testName, withIPBackend(backends[0].ipv4, backends[0].port))
			scenario.createLBBackendPool(backendPool)

			t.Log("Creating LB Service resources...")

			service := lbService(testName, withPort(10443), withHTTPSProxyApplication(withCertificate(testName), withClientCertificateValidation(testName+"-client-ca"), withHttpsRoute(backendPool.Name, tc.appOpt([]*frrContainer{client}))))
			scenario.createLBService(service)

			t.Log("Waiting for full VIP connectivity...")
			vipIP := scenario.waitForFullVIPConnectivity(testName)

			// 3. Test basic connectivity
			for _, tt := range tc.testCalls {
				testCmd := curlCmdWithHeaders(curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' --cert /tmp/%s.crt --key /tmp/%s.key --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", clientHostName, clientHostName, serviceHostName, vipIP)), tt.headers)
				t.Log("Testing %q...", testCmd)
				eventually(t, func() error {
					stdout, stderr, err := client.Exec(t.Context(), testCmd)
					if !tt.blocked && err != nil {
						return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					} else if tt.blocked && (err != nil || stdout != "403") {
						return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					}

					return nil
				}, longTimeout, pollInterval)
			}
		})
	}
}

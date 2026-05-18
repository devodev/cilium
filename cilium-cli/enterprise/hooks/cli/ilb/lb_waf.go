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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	wafLabelKey   = "waf"
	wafLabelValue = "match"
)

var attacks = []struct {
	name    string
	query   string
	headers map[string]string
}{
	{
		name:  "classic-sqli-query",
		query: "?id=1%27%20OR%201%3D1--%20",
	},
	{
		name:  "null-byte-query",
		query: "?x=hello%00world",
	},
	{
		name:    "scanner-user-agent",
		headers: map[string]string{"User-Agent": "Nessus"},
	},
}

type wafTestEnv struct {
	scenario *lbTestScenario
	client   *frrContainer
	vipAddr  string
}

type wafResponse struct {
	status  string
	headers string
	body    string
	stderr  string
	cmd     string
}

type wafPolicyOption func(*isovalentv1alpha1.IsovalentWAFPolicy)

func TestWAFBlocksManagedProfileAttacks(t T) {
	testName := "waf-blocks-managed-profile-attacks"
	hostName := "insecure.acme.io"
	path := "/api/foo-insecure"

	env := newWAFTestEnv(t,
		testName,
		hostName,
		path,
		wafPolicy(
			testName,
			wafLabelValue,
			withWAFEnabled(true),
			withWAFMode(isovalentv1alpha1.IsovalentWAFPolicyModeEnforce),
			withWAFManagedProfile(isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced),
		))
	if env == nil {
		return
	}

	t.Log("Testing benign request...")
	env.expectStatus(hostName, path, "200")

	for _, tt := range attacks {
		t.Log("Testing WAF attack: %s...", tt.name)
		env.eventuallyResponseWithHeaders(hostName, path+tt.query, tt.headers, "403", "blocked by waf", nil)
	}
}

func TestWAFMonitorsManagedProfileAttacks(t T) {
	testName := "waf-monitors-managed-profile-attacks"
	hostName := "insecure.acme.io"
	path := "/api/foo-insecure"

	env := newWAFTestEnv(t,
		testName,
		hostName,
		path,
		wafPolicy(
			testName,
			wafLabelValue,
			withWAFEnabled(true),
			withWAFMode(isovalentv1alpha1.IsovalentWAFPolicyModeMonitor),
			withWAFManagedProfile(isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced),
		))
	if env == nil {
		return
	}

	t.Log("Testing benign request...")
	env.expectStatus(hostName, path, "200")

	for _, tt := range attacks {
		t.Log("Testing WAF attack: %s...", tt.name)
		env.eventuallyResponseWithHeaders(hostName, path+tt.query, tt.headers, "200", "", []string{"x-waf-intervention: detection"})
	}
}

func newWAFTestEnv(t T, testName, hostName, path string, policy *isovalentv1alpha1.IsovalentWAFPolicy) *wafTestEnv {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	if skipIfWAFDisabled(t, k8sCli, "WAF is not enabled in cilium-config") {
		return nil
	}
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	scenario.createLBVIP(lbVIP(testName))

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port))
	}
	scenario.createLBBackendPool(lbBackendPool(testName, backends...))

	t.Log("Creating LB Service resources...")
	service := lbService(
		testName,
		withLabels(map[string]string{wafLabelKey: wafLabelValue}),
		withHTTPProxyApplication(
			withHttpRoute(testName, withHttpHostname(hostName), withHttpPath(path)),
		),
	)
	scenario.createLBService(service)

	t.Log("Creating IsovalentWAFPolicy resources...")
	scenario.createWAFPolicy(policy)

	t.Log("Waiting for policy acceptance and full VIP connectivity...")
	scenario.waitForWAFPolicyAccepted(testName)
	vip := scenario.waitForFullVIPConnectivityInclIPv6(testName)

	vipIP := vip.IPv4Formatted()
	if vipIP == "" {
		vipIP = vip.IPv6Formatted()
	}

	return &wafTestEnv{
		scenario: scenario,
		client:   client,
		vipAddr:  vipIP,
	}
}

func (e *wafTestEnv) expectStatus(hostName, path, expected string) {
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' --resolve %s:80:%s http://%s:80%s", hostName, e.vipAddr, hostName, path))
	stdout, stderr, err := e.client.Exec(e.scenario.t.Context(), testCmd)
	if err != nil {
		e.scenario.t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
	if stdout != expected {
		e.scenario.t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
	}
}

func (e *wafTestEnv) eventuallyResponseWithHeaders(
	hostName,
	path string,
	requestHeaders map[string]string,
	expectedStatus,
	expectedBody string,
	requiredHeaders []string,
) {
	eventually(e.scenario.t, func() error {
		resp, err := e.sendWithHeaders(hostName, path, requestHeaders)
		if err != nil {
			return fmt.Errorf("curl failed (cmd: %q, stderr: %q): %w", resp.cmd, resp.stderr, err)
		}
		if resp.status != expectedStatus {
			return fmt.Errorf("unexpected response code (cmd: %q, status: %q, headers: %q, body: %q, stderr: %q)", resp.cmd, resp.status, resp.headers, resp.body, resp.stderr)
		}
		if expectedBody != "" && !strings.Contains(resp.body, expectedBody) {
			return fmt.Errorf("unexpected response body (cmd: %q, status: %q, headers: %q, body: %q, stderr: %q)", resp.cmd, resp.status, resp.headers, resp.body, resp.stderr)
		}
		for _, header := range requiredHeaders {
			if !strings.Contains(strings.ToLower(resp.headers), strings.ToLower(header)) {
				return fmt.Errorf("missing response header %q (cmd: %q, status: %q, headers: %q, body: %q, stderr: %q)", header, resp.cmd, resp.status, resp.headers, resp.body, resp.stderr)
			}
		}
		return nil
	}, longTimeout, pollInterval)
}

func (e *wafTestEnv) sendWithHeaders(hostName, path string, requestHeaders map[string]string) (wafResponse, error) {
	testCmd := curlCmdWithHeaders(
		curlCmd(fmt.Sprintf("--max-time 10 -D - -o - --resolve %s:80:%s http://%s:80%s", hostName, e.vipAddr, hostName, path)),
		requestHeaders,
	)
	stdout, stderr, err := e.client.Exec(e.scenario.t.Context(), testCmd)
	if err != nil {
		return wafResponse{stderr: stderr, cmd: testCmd}, err
	}

	payload := strings.ReplaceAll(stdout, "\r\n", "\n")
	parts := strings.SplitN(payload, "\n\n", 2)
	responseHeaders := parts[0]
	body := ""
	if len(parts) == 2 {
		body = parts[1]
	}

	statusLine := strings.TrimSpace(strings.SplitN(responseHeaders, "\n", 2)[0])
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return wafResponse{stderr: stderr, cmd: testCmd}, fmt.Errorf("failed to parse response status from %q", stdout)
	}

	return wafResponse{
		status:  fields[1],
		headers: responseHeaders,
		body:    body,
		stderr:  stderr,
		cmd:     testCmd,
	}, nil
}

func wafPolicy(name, selectorValue string, opts ...wafPolicyOption) *isovalentv1alpha1.IsovalentWAFPolicy {
	policy := &isovalentv1alpha1.IsovalentWAFPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{TestResourceLabelName: "true"},
		},
		Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
			Targets: []isovalentv1alpha1.IsovalentWAFPolicyTarget{{
				APIGroup: isovalentv1alpha1.CustomResourceDefinitionGroup,
				Kind:     isovalentv1alpha1.LBServiceKindDefinition,
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]slim_metav1.MatchLabelsValue{
						wafLabelKey: selectorValue,
					},
				},
			}},
		},
	}

	for _, opt := range opts {
		opt(policy)
	}

	return policy
}

func withWAFMode(mode isovalentv1alpha1.IsovalentWAFPolicyModeType) wafPolicyOption {
	return func(p *isovalentv1alpha1.IsovalentWAFPolicy) {
		p.Spec.Mode = ptr.To(mode)
	}
}

func withWAFManagedProfile(profile isovalentv1alpha1.IsovalentWAFPolicyProfileType) wafPolicyOption {
	return func(p *isovalentv1alpha1.IsovalentWAFPolicy) {
		if p.Spec.Rules == nil {
			p.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{}
		}
		if p.Spec.Rules.Managed == nil {
			p.Spec.Rules.Managed = &isovalentv1alpha1.IsovalentWAFManagedRules{}
		}
		p.Spec.Rules.Managed.Profile = profile
	}
}

func withWAFEnabled(enabled bool) wafPolicyOption {
	return func(p *isovalentv1alpha1.IsovalentWAFPolicy) {
		p.Spec.Enabled = enabled
	}
}

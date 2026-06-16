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
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	ciliumiov2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestLabelBasedBackend_CNP_T1T2(t T) {
	testLabelBasedBackendCNP(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1T2))
}

func testLabelBasedBackendCNP(t T, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// label based backends are only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	testName := "labelbased-backend-cnp-" + string(mode)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	nodeSelector, err := appNodeSelector(t.Context(), k8sCli, mode)
	if err != nil {
		t.Failedf("failed to lookup node selector: %s", err)
	}

	t.Log("Creating backend apps with nodeSelector: %s ...", nodeSelector["service.cilium.io/node"])
	backendApp := backendApplication{
		name:         testName,
		replicas:     2,
		nodeSelector: nodeSelector,
	}
	_ = scenario.AddAndWaitForK8sBackendApplications(backendApp)

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	backends = append(backends, withK8sServiceBackend(testName, 8080), withFastHealthCheck())
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withPort(80), withHTTPProxyApplication(withHttpRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	t.Log("Checking connectivity without CNP applied ...")
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' -H 'Content-Type: application/json' http://%s:80/special", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}

	t2NodeList, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: "service.cilium.io/node in ( t2, t1-t2 )"})
	if err != nil {
		t.Failedf("failed to retrieve t2 k8s nodes: %s", err)
	}

	t.Log("Applying Ingress CNP...")
	cnp := podIngressL7CNP(scenario.k8sNamespace)

	_, err = ciliumCli.CiliumV2().CiliumNetworkPolicies(scenario.k8sNamespace).Create(t.Context(), cnp, metav1.CreateOptions{})
	if err != nil {
		t.Failedf("failed to create CNP")
	}
	t.RegisterCleanup(func(ctx context.Context) error {
		return ciliumCli.CiliumV2().CiliumNetworkPolicies(scenario.k8sNamespace).Delete(ctx, cnp.Name, metav1.DeleteOptions{})
	})

	// T2 backend healthchecks do not use the Ingress IP. Instead, each T2 node
	// healthchecks the backend Pods using its own cilium_host IP. See
	// https://github.com/isovalent/cilium/issues/10242 for more details.
	//
	// The installed CNP allows traffic only from reserved:ingress. Hence, T2
	// healthchecks are expected to fail on nodes which do not run the backend Pods.
	//
	// The healthchecks are expected to pass on T2 nodes which run the backend Pods.
	// This is because those healthchecks get reserved:host identity, which is allowed by
	// default.
	//
	// This is only observable with more than one T2 node. On a single T2 node
	// all healthchecks are local (reserved:host) and thus always allowed.
	if len(t2NodeList.Items) >= 2 {
		t.Log("Checking that T2 healthchecks to remote backends are denied by the Ingress CNP...")
		eventually(t, func() error {
			active, inactive, err := scenario.t2BackendStates(t2NodeList)
			if err != nil {
				return err
			}
			if inactive == 0 {
				return fmt.Errorf("expected some T2 healthchecks to be denied, but all %d are still passing", active)
			}
			return nil
		}, shortTimeout, pollInterval)
	}

	t.Log("Extending the CNP to allow remote healthchecks...")
	err = retry.RetryOnConflict(bgpUpdateBackoff, func() error {
		latestCNP, err := ciliumCli.CiliumV2().CiliumNetworkPolicies(scenario.k8sNamespace).Get(t.Context(), cnp.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to retrieve CNP: %w", err)
		}

		latestCNP.Spec.Ingress = append(latestCNP.Spec.Ingress, remoteNodeHealthCheckIngressRule())
		_, err = ciliumCli.CiliumV2().CiliumNetworkPolicies(scenario.k8sNamespace).Update(t.Context(), latestCNP, metav1.UpdateOptions{})

		return err
	})
	if err != nil {
		t.Failedf("failed to update CNP: %s", err)
	}

	t.Log("Checking that all T2 healthchecks pass with the extended Ingress CNP...")
	eventually(t, func() error {
		active, inactive, err := scenario.t2BackendStates(t2NodeList)
		if err != nil {
			return err
		}
		if inactive != 0 {
			return fmt.Errorf("expected all T2 healthchecks to pass, but %d are still failing (%d passing)", inactive, active)
		}
		return nil
	}, longTimeout, pollInterval)

	t.Log("Checking that CNP matches Ingress identity and blocks path != / ...")
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
		if stdout != "200" {
			t.Failedf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
	}

	eventually(t, func() error {
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -o /dev/null -w '%%{response_code}' -H 'Content-Type: application/json' http://%s:80/special", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return fmt.Errorf("curl failed unexpectedly (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		if stdout != "403" {
			return fmt.Errorf("unexpected response code (cmd: %q, stdout: %q, stderr: %q)", testCmd, stdout, stderr)
		}
		return nil
	}, shortTimeout, pollInterval)
}

func podIngressL7CNP(namespace string) *ciliumiov2.CiliumNetworkPolicy {
	return &ciliumiov2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "labelbased-backend-cnp-t1-t2",
		},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]slim_metav1.MatchLabelsValue{
						"app": "labelbased-backend-cnp-t1-t2",
					},
				},
			},
			Ingress: []policyapi.IngressRule{
				{
					IngressCommonRule: policyapi.IngressCommonRule{
						FromEntities: policyapi.EntitySlice{
							policyapi.EntityIngress,
						},
					},
					ToPorts: policyapi.PortRules{
						{
							Ports: []policyapi.PortProtocol{
								{
									Protocol: policyapi.ProtoTCP,
									Port:     "8080",
								},
							},
							Rules: &policyapi.L7Rules{
								HTTP: []policyapi.PortRuleHTTP{
									{
										Path: "/",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func remoteNodeHealthCheckIngressRule() policyapi.IngressRule {
	return policyapi.IngressRule{
		IngressCommonRule: policyapi.IngressCommonRule{
			FromEntities: policyapi.EntitySlice{
				policyapi.EntityRemoteNode,
				policyapi.EntityHost,
			},
		},
		ToPorts: policyapi.PortRules{
			{
				Ports: []policyapi.PortProtocol{
					{
						Protocol: policyapi.ProtoTCP,
						Port:     "8080",
					},
				},
				Rules: &policyapi.L7Rules{
					HTTP: []policyapi.PortRuleHTTP{
						{
							Path: "/health",
						},
					},
				},
			},
		},
	}
}

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
	"github.com/cilium/cilium/pkg/versioncheck"
)

// TestTCPProxyT1OnlyDSR exercises a "forceDeploymentMode: t1-only" TCPProxy
// LBService configured with "forceForwardingMode: dsr" against in-cluster
// Kubernetes Pod backends spread across nodes.
//
// With DSR the load balancer encapsulates the original request in an IPIP tunnel
// towards the selected backend; the backend node terminates the tunnel, DNATs
// the decapsulated packet to the local Pod and replies directly to the client,
// reverse-NAT'ing the source back to the VIP. Because the backends are spread
// across the T1 nodes and the VIP is advertised from all of them (ECMP), the
// requests exercise both the local path (backend co-located on the ingress node)
// and the remote path (backend on another node, reached via IPIP). All requests
// are expected to succeed across both paths.
//
// Two requirements are baked into the setup:
//
//   - DSR reverse-NAT relies on the service being programmed on the backend node
//     (it looks up the rev_nat_index there). This holds here because all T1 nodes
//     run the LB by default; the test deliberately does not pin the deployment to
//     a subset of nodes, which would starve some backend node of the service.
//   - Under DSR IPIP the inner packet is shipped to remote backends unchanged, so
//     there is no L4 port translation: the frontend port must equal the backend
//     port (8080).
func TestTCPProxyT1OnlyDSR(t T) {
	// With DSR the backend replies directly to the client. In single-node mode the
	// client only has connectivity with the single ingress node, so a backend
	// scheduled on any other node would be unreachable.
	if skipIfOnSingleNode("DSR backends scheduled on a non-ingress node can't reply to the client in single-node mode") {
		return
	}

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// In-cluster (label based) Pod backends are only supported in v1.18 and newer.
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	mode := isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1

	testName := "tcp-proxy-t1only-dsr"

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	nodeSelector, err := appNodeSelector(t.Context(), k8sCli, mode)
	if err != nil {
		t.Failedf("failed to lookup node selector: %s", err)
	}

	backendApp := backendApplication{
		name:         testName,
		replicas:     2,
		nodeSelector: nodeSelector,
	}
	t.Log("Creating in-cluster Pod backend apps with nodeSelector: %s ...", nodeSelector["service.cilium.io/node"])
	scenario.AddAndWaitForK8sBackendApplications(backendApp)

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backendPool := lbBackendPool(testName, withK8sServiceBackend(testName, 8080))
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources (t1-only, dsr)...")
	// Frontend port must equal the backend port (8080, see withK8sServiceBackend
	// above): under DSR IPIP the inner packet reaches remote backends unchanged,
	// so the Pod receives traffic on the frontend port with no L4 translation.
	service := lbService(testName, withPort(8080),
		withTCPProxyApplication(
			withTCPForceDeploymentMode(mode),
			withTCPForceForwardingMode(isovalentv1alpha1.LBTCPProxyForceForwardingModeDSR),
			withTCPProxyRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// Send a series of requests, each from a fresh connection so they spread across
	// the T1 nodes via ECMP and thus across both the local and remote (IPIP-
	// terminated) DSR paths. All of them must succeed.
	const numRequests = 20
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:8080/", vipIP))
	t.Log("Sending %d requests, all of which must succeed: %q...", numRequests, testCmd)
	for i := range numRequests {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl request %d/%d failed (cmd: %q, stdout: %q, stderr: %q): %s", i+1, numRequests, testCmd, stdout, stderr, err)
		}
	}
}

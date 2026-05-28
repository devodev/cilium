// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	gojson "encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

const (
	KindConnDisruptEGWHA = "test-conn-disrupt-egw-ha"

	ConnDisruptEGWHAIEGPGWNodeName                = "test-conn-disrupt-egw-ha-gw-node"
	ConnDisruptEGWHAIEGPNonGWNodeName             = "test-conn-disrupt-egw-ha-non-gw-node"
	ConnDisruptEGWHAServerDeploymentName          = "test-conn-disrupt-server-egw-ha"
	ConnDisruptEGWHAServiceName                   = "test-conn-disrupt-egw-ha"
	ConnDisruptEGWHAClientGWNodeDeploymentName    = "test-conn-disrupt-client-egw-ha-gw-node"
	ConnDisruptEGWHAClientNonGWNodeDeploymentName = "test-conn-disrupt-client-egw-ha-non-gw-node"
	ConnDisruptEGWHACNPName                       = "test-conn-disrupt-egw-ha"
	ConnDisruptEGWHAServerAppLabel                = "test-conn-disrupt-server-egw-ha"
	ConnDisruptEGWHAClientGWNodeAppLabel          = "test-conn-disrupt-client-egw-ha-gw-node"
	ConnDisruptEGWHAClientNonGWNodeAppLabel       = "test-conn-disrupt-client-egw-ha-non-gw-node"
)

// EnterpriseNoInterruptedConnections returns a scenario that checks whether
// there are no interruptions in long-lived connections going through the
// EGW HA data path. The test case is used to validate Cilium upgrades.
//
// During setup (--conn-disrupt-test-setup): collects and stores restart counts.
// During check: compares current restart counts against the stored values.
func EnterpriseNoInterruptedConnections() check.Scenario {
	return &enterpriseNoInterruptedConnections{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type enterpriseNoInterruptedConnections struct {
	check.ScenarioBase
}

func (n *enterpriseNoInterruptedConnections) Name() string {
	return "no-interrupted-connections-for-enterprise"
}

func enterpriseConnDisruptRestartsPath(ct *check.ConnectivityTest) string {
	p := ct.Params().ConnDisruptTestRestartsPath
	return filepath.Join(filepath.Dir(p), "enterprise-"+filepath.Base(p))
}

func (n *enterpriseNoInterruptedConnections) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	restartCount := make(map[string]string)
	for _, client := range ct.Clients() {
		pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + KindConnDisruptEGWHA})
		if err != nil {
			t.Fatalf("Unable to list %s pods: %s", KindConnDisruptEGWHA, err)
		}
		if len(pods.Items) == 0 {
			t.Fatalf("No %s pods found", KindConnDisruptEGWHA)
		}

		for _, pod := range pods.Items {
			if len(pod.Status.ContainerStatuses) == 0 {
				t.Fatalf("Pod %s has no container statuses (phase=%s)", pod.GetObjectMeta().GetName(), pod.Status.Phase)
			}
			restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
		}
	}

	// Only store restart counters which will be used later when running the same
	// test case, but w/o --conn-disrupt-test-setup.
	if ct.Params().ConnDisruptTestSetup {
		file, err := os.Create(enterpriseConnDisruptRestartsPath(ct))
		if err != nil {
			t.Fatalf("Failed to create %q file for writing enterprise conn disrupt test results: %s",
				enterpriseConnDisruptRestartsPath(ct), err)
		}
		defer file.Close()

		j, err := gojson.Marshal(restartCount)
		if err != nil {
			t.Fatalf("Failed to marshal JSON: %s", err)
		}

		if _, err := file.Write(j); err != nil {
			t.Fatalf("Failed to write enterprise conn disrupt test result into file: %s", err)
		}

		return
	}

	b, err := os.ReadFile(enterpriseConnDisruptRestartsPath(ct))
	if err != nil {
		t.Fatalf("Failed to read enterprise conn disrupt test result file: %s", err)
	}
	prevRestartCount := make(map[string]string)
	if err := gojson.Unmarshal(b, &prevRestartCount); err != nil {
		t.Fatalf("Failed to unmarshal JSON test result file: %s", err)
	}

	for pod, count := range restartCount {
		if prevCount, found := prevRestartCount[pod]; !found {
			t.Fatalf("Could not find Pod %s restart count", pod)
		} else if prevCount != count {
			t.Fatalf("Pod %s flow was interrupted (restart count does not match %s != %s)",
				pod, prevCount, count)
		}
	}
}

// WaitForConnDisruptBPFEntries waits for the BPF egress-ha policy entries
// for the EGW HA conn-disrupt test pods to be populated.
func WaitForConnDisruptBPFEntries(ctx context.Context, ct *check.ConnectivityTest) error {
	gwIEGPEgressIPs, nonGWIEGPEgressIPs, err := resolveConnDisruptAllocatedEgressIPs(ctx, ct)
	if err != nil {
		return fmt.Errorf("failed to resolve conn-disrupt allocated egress IPs: %w", err)
	}

	return waitForBpfPolicyEntriesWithEntryMatcher(ctx, ct.CiliumPods(),
		func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
			entries, _ := getConnDisruptEgressHAPolicyEntries(ctx, ct, ciliumPod, gwIEGPEgressIPs, nonGWIEGPEgressIPs)
			return entries
		}, nil, nil)
}

// resolveConnDisruptAllocatedEgressIPs resolves allocated egress IPs for both
// conn-disrupt IEGPs at once. Returns nil maps for IEGPs that either don't
// exist or aren't configured with EgressCIDRs.
func resolveConnDisruptAllocatedEgressIPs(ctx context.Context, ct *check.ConnectivityTest) (
	gwIEGPEgressIPs, nonGWIEGPEgressIPs map[string]string, err error) {
	if !connDisruptEGWIEGPsExist(ctx, ct) {
		return nil, nil, nil
	}

	gwNode1, gwNode2, _, err := GetNodesForConnDisrupt(ct)
	if err != nil {
		return nil, nil, fmt.Errorf("conn-disrupt IEGP is present but no eligible gateway nodes: %w", err)
	}
	gwNode1IP := ct.GetGatewayNodeInternalIP(gwNode1, false)
	gwNode2IP := ct.GetGatewayNodeInternalIP(gwNode2, false)
	if !gwNode1IP.IsValid() || !gwNode2IP.IsValid() {
		return nil, nil, fmt.Errorf("invalid gateway node internal IPs: gwNode1=%v gwNode2=%v", gwNode1IP, gwNode2IP)
	}

	gwIEGPEgressIPs, err = resolveAllocatedEgressIPsForPolicy(ctx, ct,
		ConnDisruptEGWHAIEGPGWNodeName, []string{gwNode1IP.String()})
	if err != nil {
		return nil, nil, err
	}
	nonGWIEGPEgressIPs, err = resolveAllocatedEgressIPsForPolicy(ctx, ct,
		ConnDisruptEGWHAIEGPNonGWNodeName, []string{gwNode1IP.String(), gwNode2IP.String()})
	if err != nil {
		return nil, nil, err
	}
	return gwIEGPEgressIPs, nonGWIEGPEgressIPs, nil
}

// resolveAllocatedEgressIPsForPolicy fetches the given conn-disrupt IEGP and, if it
// has EgressCIDRs configured (IPAM mode), returns a map from gateway internal IP to
// allocated egress IP. If EgressCIDRs is empty (non-IPAM mode) or the IEGP does not
// exist (conn-disrupt not set up), it returns nil to signal that callers should use
// the gateway node's own internal IP as the EgressIP.
func resolveAllocatedEgressIPsForPolicy(ctx context.Context, ct *check.ConnectivityTest,
	policyName string, gatewayIPs []string) (map[string]string, error) {
	iegpClient := ct.K8sClient().CiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies()

	iegp, err := iegpClient.Get(ctx, policyName, metav1.GetOptions{})
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get policy %s: %w", policyName, err)
	}
	if len(iegp.Spec.EgressCIDRs) == 0 {
		return nil, nil
	}

	result := make(map[string]string, len(gatewayIPs))
	for i, gatewayIP := range gatewayIPs {
		allocated, err := waitForAllocatedEgressIPErr(ctx, ct, policyName, i, gatewayIP)
		if err != nil {
			return nil, err
		}
		result[gatewayIP] = allocated.String()
	}
	return result, nil
}

func connDisruptEGWIEGPsExist(ctx context.Context, ct *check.ConnectivityTest) bool {
	iegpClient := ct.K8sClient().CiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies()
	for _, name := range []string{ConnDisruptEGWHAIEGPGWNodeName, ConnDisruptEGWHAIEGPNonGWNodeName} {
		if _, err := iegpClient.Get(ctx, name, metav1.GetOptions{}); err == nil {
			return true
		}
	}
	return false
}

// GetNodesForConnDisrupt picks 3 Cilium nodes for EGW HA conn-disrupt:
// gwNode1 and gwNode2 serve as gateways, nonGWNode hosts the non-gateway client.
// Nodes labeled as route reflectors (rr-role=route-reflector) are excluded so
// that only EGW-capable nodes are picked on clusters that separate RR and EGW
// node roles (e.g. EKS/AKS). On kind clusters where no node has this label,
// all Cilium nodes remain eligible.
func GetNodesForConnDisrupt(ct *check.ConnectivityTest) (gwNode1, gwNode2, nonGWNode string, err error) {
	var nodeNames []string
	for _, node := range ct.Nodes() {
		if node.GetLabels()[egwBGPRRRoleLabelKey] == egwBGPRRRoleLabelRouteReflector {
			continue
		}
		nodeNames = append(nodeNames, node.Name)
	}
	if len(nodeNames) < 3 {
		return "", "", "", fmt.Errorf("unable to pick gateway and non-gateway nodes: need at least 3 nodes with Cilium, got %d", len(nodeNames))
	}
	slices.Sort(nodeNames)
	return nodeNames[0], nodeNames[1], nodeNames[2], nil
}

// getConnDisruptEgressHAPolicyEntries constructs the expected BPF egress-ha policy entries
// for the EGW HA conn-disrupt test pods on a given Cilium node. This is used both for
// validating BPF entries during setup and for excluding conn-disrupt entries in EGW HA
// connectivity tests (similar to OSS GetConnDisruptEgressPolicyEntries).
//
// gwIEGPEgressIPs and nonGWIEGPEgressIPs map gateway internal IPs to the egress IPs
// allocated by the operator from each IEGP's EgressCIDRs pool. A nil map means the
// corresponding IEGP is not in IPAM mode, so the gateway's own internal IP is used.
func getConnDisruptEgressHAPolicyEntries(ctx context.Context, ct *check.ConnectivityTest, ciliumPod check.Pod,
	gwIEGPEgressIPs, nonGWIEGPEgressIPs map[string]string) ([]bpfEgressGatewayPolicyEntry, error) {
	gwNode1, gwNode2, _, err := GetNodesForConnDisrupt(ct)
	if err != nil {
		return nil, err
	}

	gwNode1IP := ct.GetGatewayNodeInternalIP(gwNode1, false)
	gwNode2IP := ct.GetGatewayNodeInternalIP(gwNode2, false)
	if !gwNode1IP.IsValid() || !gwNode2IP.IsValid() {
		return nil, nil
	}

	// Get conn-disrupt client pod IPs per app label.
	// Clients are deployed on dst; in single-cluster dst == src == ct.K8sClient().
	dst := ct.K8sClient()
	if ct.Params().MultiCluster != "" {
		dst = ct.Clients()[1]
	}

	gwClientPodIPs, err := getConnDisruptClientPodIPs(ctx, dst, ct, ConnDisruptEGWHAClientGWNodeAppLabel)
	if err != nil {
		return nil, err
	}
	nonGWClientPodIPs, err := getConnDisruptClientPodIPs(ctx, dst, ct, ConnDisruptEGWHAClientNonGWNodeAppLabel)
	if err != nil {
		return nil, err
	}

	gatewayEgressIP := func(gwIP string, allocatedIPs map[string]string) string {
		if allocatedIPs != nil {
			return allocatedIPs[gwIP]
		}
		return gwIP
	}

	var entries []bpfEgressGatewayPolicyEntry

	// IEGP-1: single gateway (gwNode1), GW-node client
	egressIP := "0.0.0.0"
	if ciliumPod.Pod.Spec.NodeName == gwNode1 {
		egressIP = gatewayEgressIP(gwNode1IP.String(), gwIEGPEgressIPs)
	}
	for _, podIP := range gwClientPodIPs {
		entries = append(entries, bpfEgressGatewayPolicyEntry{
			SourceIP:   podIP,
			DestCIDR:   "0.0.0.0/0",
			EgressIP:   egressIP,
			GatewayIPs: []string{gwNode1IP.String()},
		})
	}

	// IEGP-2: two gateways (gwNode1, gwNode2), non-GW-node client
	egressIP2 := "0.0.0.0"
	if ciliumPod.Pod.Spec.NodeName == gwNode1 {
		egressIP2 = gatewayEgressIP(gwNode1IP.String(), nonGWIEGPEgressIPs)
	} else if ciliumPod.Pod.Spec.NodeName == gwNode2 {
		egressIP2 = gatewayEgressIP(gwNode2IP.String(), nonGWIEGPEgressIPs)
	}
	for _, podIP := range nonGWClientPodIPs {
		entries = append(entries, bpfEgressGatewayPolicyEntry{
			SourceIP:   podIP,
			DestCIDR:   "0.0.0.0/0",
			EgressIP:   egressIP2,
			GatewayIPs: []string{gwNode1IP.String(), gwNode2IP.String()},
		})
	}

	return entries, nil
}

func getConnDisruptClientPodIPs(ctx context.Context, client *k8s.Client, ct *check.ConnectivityTest, appLabel string) ([]string, error) {
	pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", appLabel),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to list pods with label app=%s: %w", appLabel, err)
	}

	var podIPs []string
	for _, pod := range pods.Items {
		podIPs = append(podIPs, pod.Status.PodIP)
	}
	return podIPs, nil
}

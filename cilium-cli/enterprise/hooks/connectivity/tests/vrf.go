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
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	"github.com/cilium/cilium/cilium-cli/defaults"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	vrfScenarioName = "vrf-pod-egress"

	vrfName       = "blue"
	vrfID         = 1
	vrfTable      = 100
	vrfEgressIntf = "eth1"
	vrfGateway    = "192.168.200.1"
	vrfLabelKey   = "vrf"
	vrfLabelVal   = "blue"

	vrfClientPodName    = "vrf-client"
	vrfServerPodName    = "vrf-server"
	vrfClientImage      = "quay.io/cilium/alpine-curl:v1.10.0@sha256:913e8c9f3d960dde03882defa0edd3a919d529c2eb167caa7f54194528bde364"
	vrfPodContainerName = "client"

	vrfStatusTimeout = 3 * time.Minute
	vrfPodTimeout    = 3 * time.Minute
	vrfPollInterval  = 2 * time.Second
	vrfPingAttempts  = 5
)

// VRF returns a scenario that exercises pod-level VRF egress.
//
// The scenario creates an IsovalentCoreVRF that binds pods labeled vrf=blue
// to table 100 on each node's eth1 interface, schedules a client and server
// pod with that label on distinct workers, programs the per-node VRF routing
// table via the cilium-agent pod, then validates that ICMP from client to
// server is observable on the egress interface of the client node.
func VRF() check.Scenario {
	return &vrfScenario{ScenarioBase: check.NewScenarioBase()}
}

type vrfScenario struct {
	check.ScenarioBase
}

func (s *vrfScenario) Name() string {
	return vrfScenarioName
}

func (s *vrfScenario) Run(ctx context.Context, t *check.Test) {
	vt, err := newVRFTest(t)
	if err != nil {
		t.Fatalf("%s", err)
	}
	vt.run(ctx, s)
}

type vrfRoute struct {
	dst string
	via string
}

type vrfTest struct {
	ct *check.ConnectivityTest
	t  *check.Test

	clientNode  *slimcorev1.Node
	serverNode  *slimcorev1.Node
	clientAgent check.Pod
	serverAgent check.Pod

	client *corev1.Pod
	server *corev1.Pod

	clientEth1 string
	serverEth1 string
}

func newVRFTest(t *check.Test) (*vrfTest, error) {
	ct := t.Context()

	workers := workerNodes(ct)
	if len(workers) < 2 {
		return nil, fmt.Errorf("vrf scenario requires at least 2 worker nodes, found %d", len(workers))
	}
	vt := &vrfTest{
		ct:         ct,
		t:          t,
		clientNode: workers[0],
		serverNode: workers[1],
	}

	var ok bool
	if vt.clientAgent, ok = agentForNode(ct, vt.clientNode.Name); !ok {
		return nil, fmt.Errorf("no cilium-agent pod found on node %s", vt.clientNode.Name)
	}
	if vt.serverAgent, ok = agentForNode(ct, vt.serverNode.Name); !ok {
		return nil, fmt.Errorf("no cilium-agent pod found on node %s", vt.serverNode.Name)
	}
	return vt, nil
}

func (vt *vrfTest) run(ctx context.Context, s *vrfScenario) {
	if err := vt.applyCR(ctx); err != nil {
		vt.t.Fatalf("error encountered when applying IsovalentCoreVRF: %s", err)
	}
	defer vt.deleteCR()

	var err error
	vt.client, err = vt.createPod(ctx, vrfClientPodName, vt.clientNode.Name)
	if err != nil {
		vt.t.Fatalf("error encountered when creating client pod: %s", err)
	}
	defer vt.deletePod(vrfClientPodName)

	vt.server, err = vt.createPod(ctx, vrfServerPodName, vt.serverNode.Name)
	if err != nil {
		vt.t.Fatalf("error encountered when creating server pod: %s", err)
	}
	defer vt.deletePod(vrfServerPodName)

	if err := vt.waitReady(ctx, vt.clientNode.Name, vt.serverNode.Name); err != nil {
		vt.t.Fatalf("error encountered when waiting for VRF ready on workers: %s", err)
	}

	vt.clientEth1, err = vt.discoverIfaceIP(ctx, vt.clientAgent, vrfEgressIntf)
	if err != nil {
		vt.t.Fatalf("error encountered when discovering %s on %s: %s", vrfEgressIntf, vt.clientNode.Name, err)
	}
	vt.serverEth1, err = vt.discoverIfaceIP(ctx, vt.serverAgent, vrfEgressIntf)
	if err != nil {
		vt.t.Fatalf("error encountered when discovering %s on %s: %s", vrfEgressIntf, vt.serverNode.Name, err)
	}
	vt.t.Debugf("VRF eth1 IPs: %s=%s, %s=%s", vt.clientNode.Name, vt.clientEth1, vt.serverNode.Name, vt.serverEth1)

	if err := vt.installRoutes(ctx, vt.clientAgent, []vrfRoute{
		{dst: "default", via: vrfGateway},
		{dst: vt.serverNode.Spec.PodCIDR, via: vt.serverEth1},
	}); err != nil {
		vt.t.Fatalf("error encountered when installing VRF routes on %s: %s", vt.clientNode.Name, err)
	}
	if err := vt.installRoutes(ctx, vt.serverAgent, []vrfRoute{
		{dst: "default", via: vrfGateway},
		{dst: vt.clientNode.Spec.PodCIDR, via: vt.clientEth1},
	}); err != nil {
		vt.t.Fatalf("error encountered when installing VRF routes on %s: %s", vt.serverNode.Name, err)
	}
	defer vt.flushRoutes(vt.clientAgent)
	defer vt.flushRoutes(vt.serverAgent)

	filter := fmt.Sprintf("icmp and host %s", vt.server.Status.PodIP)
	clientHost, ok := vt.ct.HostNetNSPodsByNode()[vt.clientNode.Name]
	if !ok {
		vt.t.Fatalf("no host-netns pod found on node %s", vt.clientNode.Name)
	}
	sniffer, stop, err := sniff.Sniff(ctx, vrfScenarioName, &clientHost, vrfEgressIntf, filter, sniff.ModeSanity, sniff.SniffKillTimeout, vt.t)
	if err != nil {
		vt.t.Fatalf("error encountered when starting sniffer on %s: %s", vt.clientNode.Name, err)
	}

	vt.t.NewGenericAction(s, vrfScenarioName).Run(func(a *check.Action) {
		cmd := []string{"ping", "-c", fmt.Sprintf("%d", vrfPingAttempts), "-W", "2", vt.server.Status.PodIP}
		_, err := vt.ct.K8sClient().ExecInPod(ctx, vt.client.Namespace, vt.client.Name, vrfPodContainerName, cmd)
		if err != nil {
			if stopErr := stop(); stopErr != nil {
				a.Logf("error encountered when stopping sniffer: %s", stopErr)
			}
			a.Failf("error encountered when pinging from %s to %s via VRF: %s", vt.client.Name, vt.server.Status.PodIP, err)
			return
		}
		sniffer.Validate(a)
	})
}

func workerNodes(ct *check.ConnectivityTest) []*slimcorev1.Node {
	var workers []*slimcorev1.Node
	for _, n := range ct.Nodes() {
		if _, isCP := n.Labels["node-role.kubernetes.io/control-plane"]; isCP {
			continue
		}
		workers = append(workers, n)
	}
	return workers
}

func agentForNode(ct *check.ConnectivityTest, nodeName string) (check.Pod, bool) {
	for _, p := range ct.CiliumPods() {
		if p.Pod.Spec.NodeName == nodeName {
			return p, true
		}
	}
	return check.Pod{}, false
}

func (vt *vrfTest) applyCR(ctx context.Context) error {
	vrf := &isovalentv1alpha1.IsovalentCoreVRF{
		ObjectMeta: metav1.ObjectMeta{Name: vrfName},
		Spec: isovalentv1alpha1.IsovalentCoreVRFSpec{
			ID:    vrfID,
			Table: vrfTable,
			Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
				PodSelector: &slimv1.LabelSelector{
					MatchLabels: map[string]slimv1.MatchLabelsValue{vrfLabelKey: vrfLabelVal},
				},
			},
			Interfaces: []string{vrfEgressIntf},
		},
	}
	vrfs := vt.ct.K8sClient().CiliumClientset.IsovalentV1alpha1().IsovalentCoreVRFs()
	_, err := vrfs.Create(ctx, vrf, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		existing, getErr := vrfs.Get(ctx, vrfName, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("error encountered when getting existing IsovalentCoreVRF %s: %w", vrfName, getErr)
		}
		existing.Spec = vrf.Spec
		if _, err = vrfs.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error encountered when updating IsovalentCoreVRF %s: %w", vrfName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("error encountered when creating IsovalentCoreVRF %s: %w", vrfName, err)
	}
	return nil
}

func (vt *vrfTest) deleteCR() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vrfs := vt.ct.K8sClient().CiliumClientset.IsovalentV1alpha1().IsovalentCoreVRFs()
	_ = vrfs.Delete(ctx, vrfName, metav1.DeleteOptions{})
}

func (vt *vrfTest) createPod(ctx context.Context, name, nodeName string) (*corev1.Pod, error) {
	ns := vt.ct.Params().TestNamespace
	spec := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{vrfLabelKey: vrfLabelVal},
		},
		Spec: corev1.PodSpec{
			NodeName:                      nodeName,
			TerminationGracePeriodSeconds: ptr.To[int64](1),
			Containers: []corev1.Container{{
				Name:    vrfPodContainerName,
				Image:   vrfClientImage,
				Command: []string{"sh", "-c", "sleep infinity"},
			}},
		},
	}
	if _, err := vt.ct.K8sClient().CreatePod(ctx, ns, spec, metav1.CreateOptions{}); err != nil && !k8serrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("error encountered when creating pod %s/%s: %w", ns, name, err)
	}

	var ready *corev1.Pod
	err := wait.PollUntilContextTimeout(ctx, vrfPollInterval, vrfPodTimeout, true, func(ctx context.Context) (bool, error) {
		p, err := vt.ct.K8sClient().GetPod(ctx, ns, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" {
			return false, nil
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready = p
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error encountered when waiting for pod %s/%s to become ready: %w", ns, name, err)
	}
	return ready, nil
}

func (vt *vrfTest) deletePod(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = vt.ct.K8sClient().DeletePod(ctx, vt.ct.Params().TestNamespace, name, metav1.DeleteOptions{})
}

func (vt *vrfTest) waitReady(ctx context.Context, nodes ...string) error {
	statuses := vt.ct.K8sClient().CiliumClientset.IsovalentV1alpha1().IsovalentCoreVRFNodeStatuses()
	pending := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		pending[n] = true
	}
	return wait.PollUntilContextTimeout(ctx, vrfPollInterval, vrfStatusTimeout, true, func(ctx context.Context) (bool, error) {
		for node := range pending {
			ns, err := statuses.Get(ctx, node, metav1.GetOptions{})
			if k8serrors.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			vrfStatus, ok := ns.Status.VRFs[vrfName]
			if !ok {
				return false, nil
			}
			for _, cond := range vrfStatus.Conditions {
				if cond.Type == isovalentv1alpha1.VRFConditionReady && cond.Status == metav1.ConditionTrue {
					delete(pending, node)
					break
				}
			}
		}
		return len(pending) == 0, nil
	})
}

func (vt *vrfTest) discoverIfaceIP(ctx context.Context, agent check.Pod, iface string) (string, error) {
	cmd := []string{"ip", "-4", "-o", "addr", "show", "dev", iface}
	out, err := agent.K8sClient.ExecInPod(ctx, agent.Pod.Namespace, agent.Pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return "", fmt.Errorf("error encountered when reading %s addresses on %s/%s: %w\n%s", iface, agent.Pod.Namespace, agent.Pod.Name, err, out.String())
	}
	for line := range strings.SplitSeq(out.String(), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				ip, _, _ := strings.Cut(fields[i+1], "/")
				if ip != "" {
					return ip, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no IPv4 address on %s in %s/%s", iface, agent.Pod.Namespace, agent.Pod.Name)
}

func (vt *vrfTest) installRoutes(ctx context.Context, agent check.Pod, routes []vrfRoute) error {
	tbl := fmt.Sprintf("%d", vrfTable)
	for _, rt := range routes {
		cmd := []string{"ip", "route", "replace", rt.dst, "via", rt.via, "dev", vrfEgressIntf, "table", tbl}
		out, err := agent.K8sClient.ExecInPod(ctx, agent.Pod.Namespace, agent.Pod.Name, defaults.AgentContainerName, cmd)
		if err != nil {
			return fmt.Errorf("error encountered when adding route %s via %s table %s on %s: %w\n%s", rt.dst, rt.via, tbl, agent.Pod.Spec.NodeName, err, out.String())
		}
	}
	return nil
}

func (vt *vrfTest) flushRoutes(agent check.Pod) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := []string{"ip", "route", "flush", "table", fmt.Sprintf("%d", vrfTable)}
	_, _ = agent.K8sClient.ExecInPod(ctx, agent.Pod.Namespace, agent.Pod.Name, defaults.AgentContainerName, cmd)
}

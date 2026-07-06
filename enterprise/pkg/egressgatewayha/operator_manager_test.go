// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/pkg/hive"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	k8sFake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type EgressGatewayOperatorTestSuite struct {
	manager           *OperatorManager
	fakeSet           *k8sFake.FakeClientset
	healthcheckerMock *healthcheckerMock

	policies      fakeResource[*Policy]
	nodeResources fakeResource[*slim_corev1.Node]
	ciliumNodes   fakeResource[*cilium_api_v2.CiliumNode]
}

func setupEgressGatewayOperatorTestSuite(t *testing.T) *EgressGatewayOperatorTestSuite {
	k := &EgressGatewayOperatorTestSuite{}
	k.fakeSet = &k8sFake.FakeClientset{CiliumFakeClientset: cilium_fake.NewSimpleClientset()}
	k.policies = make(fakeResource[*Policy])
	k.nodeResources = make(fakeResource[*slim_corev1.Node])
	k.ciliumNodes = make(fakeResource[*cilium_api_v2.CiliumNode])
	k.healthcheckerMock = newHealthcheckerMock()

	var (
		db      *statedb.DB
		pcTable statedb.RWTable[*PolicyConfig]
	)

	// create a hive to provide statedb, egress-ips table and a mock reconcile
	h := hive.New(
		cell.Provide(newOperatorTables),
		cell.Invoke(func(db_ *statedb.DB, pt statedb.RWTable[*PolicyConfig]) {
			db = db_
			pcTable = pt
		}),
	)

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, context.TODO()))

	t.Cleanup(func() {
		require.NoError(t, h.Stop(tlog, context.TODO()))
	})

	hr, _ := cell.NewSimpleHealth()
	k.manager = newEgressGatewayOperatorManager(OperatorParams{
		Logger:        hivetest.Logger(t),
		Config:        OperatorConfig{1 * time.Millisecond},
		Health:        hr,
		Clientset:     k.fakeSet,
		Policies:      k.policies,
		Nodes:         k.nodeResources,
		CiliumNodes:   k.ciliumNodes,
		Healthchecker: k.healthcheckerMock,
		Lifecycle:     hivetest.Lifecycle(t),

		DB:                 db,
		PolicyConfigsTable: pcTable,
		Metrics:            newMetrics(),
	})

	k.healthcheckerMock.nodes = map[string]healthcheck.NodeHealth{
		"k8s1": {Reachable: true, AgentUp: true},
		"k8s2": {Reachable: true, AgentUp: true},
		"k8s3": {Reachable: true, AgentUp: true},
		"k8s4": {Reachable: true, AgentUp: true},
		"k8s5": {Reachable: true, AgentUp: true},
		"k8s6": {Reachable: true, AgentUp: true},
	}

	require.NotNil(t, k.manager)

	k.policies.sync(t)
	k.nodeResources.sync(t)
	k.ciliumNodes.sync(t)

	return k
}

func (k *EgressGatewayOperatorTestSuite) addNode(t *testing.T, name, nodeIP string, nodeLabels map[string]string) *cilium_api_v2.CiliumNode {
	node := newCiliumNode(name, nodeIP, nodeLabels)
	addNode(t, k.nodeResources, k.ciliumNodes, node, nil)

	return node
}

func (k *EgressGatewayOperatorTestSuite) updateNodeLabels(t *testing.T, node *cilium_api_v2.CiliumNode, labels map[string]string) *cilium_api_v2.CiliumNode {
	node.Labels = labels
	addNode(t, k.nodeResources, k.ciliumNodes, node, nil)

	return node
}

func (k *EgressGatewayOperatorTestSuite) updateNodeAnnotations(t *testing.T, node *cilium_api_v2.CiliumNode, annotations map[string]string) *cilium_api_v2.CiliumNode {
	node.Annotations = annotations
	addNode(t, k.nodeResources, k.ciliumNodes, node, nil)

	return node
}

func (k *EgressGatewayOperatorTestSuite) updateNodeTaints(t *testing.T, node *cilium_api_v2.CiliumNode, taints []slim_corev1.Taint) *cilium_api_v2.CiliumNode {
	addNode(t, k.nodeResources, k.ciliumNodes, node, taints)

	return node
}

func (k *EgressGatewayOperatorTestSuite) addPolicy(t *testing.T, policy *policyParams) *policyParams {
	addPolicy(t, k.fakeSet, k.policies, policy)
	return policy
}

func (k *EgressGatewayOperatorTestSuite) updateEgressGroupMaxGatewayNodes(t *testing.T, policy *policyParams, group, n int) *policyParams {
	require.True(t, 0 <= group && group < len(policy.egressGroups))
	policy.egressGroups[group].maxGatewayNodes = n

	return k.addPolicy(t, policy)
}

func (k *EgressGatewayOperatorTestSuite) getCurrentStatusForUpdate(t *testing.T, policy *policyParams) *policyParams {
	iegp, err := k.fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), policy.name, metav1.GetOptions{})
	assert.NoError(t, err)

	policy.generation = iegp.Generation + 1

	for i, iegpGs := range iegp.Status.GroupStatuses {
		target := &policy.egressGroups[i]
		target.activeGatewayIPs = iegpGs.ActiveGatewayIPs
		target.activeGatewayIPsByAZ = iegpGs.ActiveGatewayIPsByAZ
		target.healthyGatewayIPs = iegpGs.HealthyGatewayIPs
	}

	// The operator is responsible for updating the ObservedGeneration
	policy.observedGeneration = iegp.Status.ObservedGeneration

	return policy
}

func (k *EgressGatewayOperatorTestSuite) makeNodesHealthy(nodes ...string) {
	k.healthcheckerMock.addNodes(nodes...)
	k.manager.reconciliationTrigger.Trigger()
}

func (k *EgressGatewayOperatorTestSuite) makeNodesUnhealthy(nodes ...string) {
	k.healthcheckerMock.deleteNodes(nodes...)
	k.manager.reconciliationTrigger.Trigger()
}

func (k *EgressGatewayOperatorTestSuite) makeNodesAgentDown(nodes ...string) {
	k.healthcheckerMock.addAgentDownNodes(nodes...)
	k.manager.reconciliationTrigger.Trigger()
}

func (k *EgressGatewayOperatorTestSuite) makeNodeUnschedulableByTaint(t *testing.T, node *cilium_api_v2.CiliumNode) {
	k.updateNodeTaints(t, node, []slim_corev1.Taint{
		{
			Key:    core_v1.TaintNodeUnschedulable,
			Effect: slim_corev1.TaintEffectNoSchedule,
		},
	})
}

func (k *EgressGatewayOperatorTestSuite) makeNodeUnschedulableByAnnotation(t *testing.T, node *cilium_api_v2.CiliumNode) {
	k.updateNodeAnnotations(t, node, map[string]string{
		nodeEgressGatewayKey: nodeEgressGatewayUnschedulableValue,
	})
}

type gatewayStatus struct {
	activeGatewayIPs     []string
	activeGatewayIPsByAZ map[string][]string
	healthyGatewayIPs    []string
	egressIPByGatewayIP  map[string]string
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatus(tb testing.TB, gs gatewayStatus) {
	k.assertIegpGatewayStatusFromPolicy(tb, "policy-1", gs)
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatuses(tb testing.TB, gatewayStatuses []gatewayStatus) {
	k.assertIegpGatewayStatusesFromPolicy(tb, "policy-1", gatewayStatuses)
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatusFromPolicy(tb testing.TB, policy string, gs gatewayStatus) {
	k.assertIegpGatewayStatusesFromPolicy(tb, policy, []gatewayStatus{gs})
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatusesFromPolicy(tb testing.TB, policy string, gatewayStatuses []gatewayStatus) {
	var err error
	for range 10 {
		if err = tryAssertIegpGatewayStatuses(k.fakeSet, policy, gatewayStatuses); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.NoError(tb, err)
}

func tryAssertIegpGatewayStatuses(fakeSet *k8sFake.FakeClientset, policy string, gatewayStatuses []gatewayStatus) error {
	iegp, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), policy, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if len(iegp.Status.GroupStatuses) != len(gatewayStatuses) {
		return fmt.Errorf(
			"groupStatuses length mismatch: actual: %+v vs expected: %+v",
			iegp.Status.GroupStatuses,
			gatewayStatuses,
		)
	}

	for i, iegpGs := range iegp.Status.GroupStatuses {
		gs := gatewayStatuses[i]
		if !cmp.Equal(gs.activeGatewayIPs, iegpGs.ActiveGatewayIPs, cmpopts.EquateEmpty()) {
			return fmt.Errorf("active gateway IPs don't match expected ones: %v vs expected %v", iegpGs.ActiveGatewayIPs, gs.activeGatewayIPs)
		}

		if !cmp.Equal(gs.activeGatewayIPsByAZ, iegpGs.ActiveGatewayIPsByAZ, cmpopts.EquateEmpty()) {
			return fmt.Errorf("active gateway IPs by AZ don't match expected ones: %v vs expected %v", iegpGs.ActiveGatewayIPsByAZ, gs.activeGatewayIPsByAZ)
		}

		if !cmp.Equal(gs.healthyGatewayIPs, iegpGs.HealthyGatewayIPs, cmpopts.EquateEmpty()) {
			return fmt.Errorf("healthy gateway IPs don't match expected ones: %v vs expected %v", iegpGs.HealthyGatewayIPs, gs.healthyGatewayIPs)
		}

		if !cmp.Equal(gs.egressIPByGatewayIP, iegpGs.EgressIPByGatewayIP, cmpopts.EquateEmpty()) {
			return fmt.Errorf("egress IPs by gateway IPs don't match expected ones: %v vs expected %v", iegpGs.EgressIPByGatewayIP, gs.egressIPByGatewayIP)
		}
	}

	return nil
}

func (k *EgressGatewayOperatorTestSuite) assertIegpStatusConditions(tb testing.TB, conds []metav1.Condition) {
	k.assertIegpStatusConditionsFromPolicy(tb, "policy-1", conds)
}

func (k *EgressGatewayOperatorTestSuite) assertIegpStatusConditionsFromPolicy(tb testing.TB, policy string, conds []metav1.Condition) {
	var err error
	for range 10 {
		if err = tryAssertIegpStatusConditions(k.fakeSet, policy, conds); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	assert.NoError(tb, err)
}

func tryAssertIegpStatusConditions(fakeSet *k8sFake.FakeClientset, policy string, conds []metav1.Condition) error {
	iegp, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), policy, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if len(conds) != len(iegp.Status.Conditions) {
		return fmt.Errorf("expected %d conditions, got %d", len(conds), len(iegp.Status.Conditions))
	}
	for _, cond := range conds {
		found := meta.FindStatusCondition(iegp.Status.Conditions, cond.Type)
		if found == nil {
			return fmt.Errorf("unable to find expected condition type %s", cond.Type)
		}
		if found.Status != cond.Status {
			return fmt.Errorf("expected condition type %s to have status %s, got %s", cond.Type, cond.Status, found.Status)
		}
	}

	return nil
}

type gatewayMetrics struct {
	activeGatewaysCount  float64
	activeGatewaysByAZ   []activeGatewaysByAZMetrics
	healthyGatewaysCount float64
}

type activeGatewaysByAZMetrics struct {
	az                            string
	activeGatewaysByAZLocalCount  float64
	activeGatewaysByAZRemoteCount float64
}

func (k *EgressGatewayOperatorTestSuite) assertIegpMetrics(tb testing.TB, policy string, expected gatewayMetrics) {
	var err error
	for range 10 {
		if err = tryAssertIegpGatewayMetrics(k.manager.metrics, policy, expected); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	assert.NoError(tb, err)
}

func tryAssertIegpGatewayMetrics(metrics *Metrics, policy string, expected gatewayMetrics) error {
	g, err := metrics.ActiveGateways.GetMetricWithLabelValues(policy)
	if err != nil {
		return err
	}
	if expected.activeGatewaysCount != g.Get() {
		return fmt.Errorf("active_gateways metrics value doesn't match expected one: %v vs expected %v", g.Get(), expected.activeGatewaysCount)
	}

	for _, ac := range expected.activeGatewaysByAZ {
		g, err = metrics.ActiveGatewaysByAZ.GetMetricWithLabelValues(policy, ac.az, labelValueScopeLocal)
		if err != nil {
			return err
		}
		if ac.activeGatewaysByAZLocalCount != g.Get() {
			return fmt.Errorf("active_gateways_by_az scope=local metrics value doesn't match expected one: %v vs expected %v", g.Get(), ac.activeGatewaysByAZLocalCount)
		}

		g, err = metrics.ActiveGatewaysByAZ.GetMetricWithLabelValues(policy, ac.az, labelValueScopeRemote)
		if err != nil {
			return err
		}
		if ac.activeGatewaysByAZRemoteCount != g.Get() {
			return fmt.Errorf("active_gateways_by_az scope=remote metrics value doesn't match expected one: %v vs expected %v", g.Get(), ac.activeGatewaysByAZRemoteCount)
		}
	}

	g, err = metrics.HealthyGateways.GetMetricWithLabelValues(policy)
	if err != nil {
		return err
	}
	if expected.healthyGatewaysCount != g.Get() {
		return fmt.Errorf("healthy_gateways metrics value doesn't match expected one: %v vs expected %v", g.Get(), expected.healthyGatewaysCount)
	}

	return nil
}

func TestEgressGatewayOperatorManagerHAGroup(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)
	policyName := "policy-1"

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             policyName,
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(2), healthyGatewaysCount: float64(2)})

	k.makeNodesUnhealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(1), healthyGatewaysCount: float64(1)})

	k.makeNodesHealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(2), healthyGatewaysCount: float64(2)})

	// Remove k8s1 from node-group-1
	k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(1), healthyGatewaysCount: float64(1)})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1Labels)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(2), healthyGatewaysCount: float64(2)})

	k.makeNodesAgentDown(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.makeNodeUnschedulableByTaint(t, node1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(1), healthyGatewaysCount: float64(2)})

	// Add back k8s1
	node1 = k.updateNodeTaints(t, node1, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(2), healthyGatewaysCount: float64(2)})

	k.makeNodeUnschedulableByAnnotation(t, node1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(1), healthyGatewaysCount: float64(2)})

	// Add back k8s1
	k.updateNodeAnnotations(t, node1, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(2), healthyGatewaysCount: float64(2)})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(1), healthyGatewaysCount: float64(2)})

	k.makeNodesUnhealthy("k8s2")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(1), healthyGatewaysCount: float64(1)})

	k.makeNodesHealthy("k8s2")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(1), healthyGatewaysCount: float64(2)})

	// Allow all gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 0)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{activeGatewaysCount: float64(2), healthyGatewaysCount: float64(2)})
}

func TestEgressGatewayOperatorManagerHAGroupNodeRestartScenario(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs twice when an active GW restarts
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2 and node3
	// Even if node1 is up again , activeGWs, node2 and node3 stay.
	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)
	node3 := k.addNode(t, node3Name, node3IP, nodeGroup1Labels)

	// Create a new HA policy that selects k8s1, k8s2 and k8s3 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:           testInterface1,
			nodeLabels:      nodeGroup1Labels,
			maxGatewayNodes: 2,
		}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})

	k.makeNodesUnhealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node3IP},
		healthyGatewayIPs: []string{node2IP, node3IP},
	})

	k.makeNodesHealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node3IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})

	// Check if we don't recalculate the active GWs twice when an active GW is removed and added
	k.updateNodeLabels(t, node3, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.updateNodeLabels(t, node3, nodeGroup1Labels)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnly(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)
	policyName := "policy-1"

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             policyName,
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalOnly,
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(4)})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  1,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(3)})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  0,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(2)})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  1,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(3)})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(4)})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	node1 = k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	node2 = k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesAgentDown(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodeUnschedulableByTaint(t, node1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodeUnschedulableByTaint(t, node2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Add back k8s1
	node1 = k.updateNodeTaints(t, node1, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Add back k8s2
	node2 = k.updateNodeTaints(t, node2, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 0)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerNodeRestartScenarioLocalOnly(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs for az-1 twice when an active GW restarts
	//
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2, node3
	// Even if node1 is up again, the activeGWs, node2 and node3 stay.
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalOnlyFirst,
		egressGroups: []egressGroupParams{{
			iface:           testInterface1,
			nodeLabels:      nodeGroup1Labels,
			maxGatewayNodes: 2,
		}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnlyFirstInMultipleEgressGroups(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)
	policyName := "policy-1"

	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create an HA policy with azAffinity=localOnlyFirst and two egress groups:
	// - one group selects only AZ1 nodes
	// - the other selects only AZ2 nodes
	k.addPolicy(t, &policyParams{
		name:             policyName,
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalOnlyFirst,
		egressGroups: []egressGroupParams{
			{
				iface:      testInterface1,
				nodeLabels: nodeGroup1LabelsAZ1,
			},
			{
				iface:      testInterface2,
				nodeLabels: nodeGroup1LabelsAZ2,
			},
		},
	})

	// Initial state: all nodes are healthy.
	//
	// egressGroup1 selects nodes in AZ1 (node1, node2)
	// egressGroup2 selects nodes in AZ2 (node3, node4)
	//
	// Since both AZ1 and AZ2 have local gateways across the entire policy,
	// no non-local fallback should be used by any group.
	k.assertIegpGatewayStatuses(t, []gatewayStatus{
		{
			activeGatewayIPs: []string{node1IP, node2IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {node1IP, node2IP},
				"az-2": {},
			},
			healthyGatewayIPs: []string{node1IP, node2IP},
		},
		{
			activeGatewayIPs: []string{node3IP, node4IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {},
				"az-2": {node3IP, node4IP},
			},
			healthyGatewayIPs: []string{node3IP, node4IP},
		},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(4)})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatuses(t, []gatewayStatus{
		{
			activeGatewayIPs: []string{node2IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {node2IP},
				"az-2": {},
			},
			healthyGatewayIPs: []string{node2IP},
		},
		{
			activeGatewayIPs: []string{node3IP, node4IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {},
				"az-2": {node3IP, node4IP},
			},
			healthyGatewayIPs: []string{node3IP, node4IP},
		},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  1,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(3)})

	// Mark node2 (AZ1) as unhealthy.
	// Now, both node1 and node2 are unhealthy, so AZ1 has no local gateways.
	//
	// Since no egress group has local gateways in AZ1 anymore,
	// AZ1 is now eligible for non-local fallback.
	//
	// egressGroup2 is therefore allowed to assign node3 and node4 (AZ2) as active gateways for AZ1,
	// despite them being non-local to that zone.
	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatuses(t, []gatewayStatus{
		{
			activeGatewayIPs: []string{},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {},
				"az-2": {},
			},
			healthyGatewayIPs: []string{},
		},
		{
			activeGatewayIPs: []string{node3IP, node4IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {node3IP, node4IP},
				"az-2": {node3IP, node4IP},
			},
			healthyGatewayIPs: []string{node3IP, node4IP},
		},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  0,
				activeGatewaysByAZRemoteCount: 2,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(2)})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatuses(t, []gatewayStatus{
		{
			activeGatewayIPs: []string{node1IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {node1IP},
				"az-2": {},
			},
			healthyGatewayIPs: []string{node1IP},
		},
		{
			activeGatewayIPs: []string{node3IP, node4IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {},
				"az-2": {node3IP, node4IP},
			},
			healthyGatewayIPs: []string{node3IP, node4IP},
		},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  1,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(3)})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatuses(t, []gatewayStatus{
		{
			activeGatewayIPs: []string{node1IP, node2IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {node1IP, node2IP},
				"az-2": {},
			},
			healthyGatewayIPs: []string{node1IP, node2IP},
		},
		{
			activeGatewayIPs: []string{node3IP, node4IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {},
				"az-2": {node3IP, node4IP},
			},
			healthyGatewayIPs: []string{node3IP, node4IP},
		},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(4)})

	k.makeNodesUnhealthy(node1Name, node2Name, node3Name, node4Name)
	k.assertIegpGatewayStatuses(t, []gatewayStatus{
		{
			activeGatewayIPs: []string{},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {},
				"az-2": {},
			},
			healthyGatewayIPs: []string{},
		},
		{
			activeGatewayIPs: []string{},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {},
				"az-2": {},
			},
			healthyGatewayIPs: []string{},
		},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  0,
				activeGatewaysByAZRemoteCount: 0,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  0,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(0)})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnlyFirst(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalOnlyFirst,
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	node1 = k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	node2 = k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesAgentDown(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodeUnschedulableByTaint(t, node1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodeUnschedulableByTaint(t, node2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Add back k8s1
	node1 = k.updateNodeTaints(t, node1, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Add back k8s2
	node2 = k.updateNodeTaints(t, node2, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s1 healthy again
	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Make k8s2 healthy again
	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 0)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerNodeRestartScenarioLocalOnlyFirst(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs for az-1 twice when an active GW restarts
	//
	// For local GWs:
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2 and node3
	// Even if node1 is up again, the activeGWs, node2 and node3 stay.
	//
	// For non-local GWs:
	// When all local GWs go down, activeGWs are node4 and node5, if node4 goes down, then activeGWs are node5 and  node6
	// Even if node5 is up again, the activeGWs, node5 and node6 stay,
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node5Name, node5IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node6Name, node6IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4,5,6} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalOnlyFirst,
		egressGroups: []egressGroupParams{{
			iface:           testInterface1,
			nodeLabels:      nodeGroup1Labels,
			maxGatewayNodes: 2,
		}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node5IP, node6IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP, node6IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node5IP, node6IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP, node5IP, node6IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node5IP, node6IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP, node6IP},
	})

	k.makeNodesUnhealthy(node1Name, node2Name, node3Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node6IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node4IP, node5IP},
			"az-2": {node5IP, node6IP},
		},
		healthyGatewayIPs: []string{node4IP, node5IP, node6IP},
	})

	k.makeNodesUnhealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node6IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node5IP, node6IP},
			"az-2": {node5IP, node6IP},
		},
		healthyGatewayIPs: []string{node5IP, node6IP},
	})

	k.makeNodesHealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node6IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node5IP, node6IP},
			"az-2": {node5IP, node6IP},
		},
		healthyGatewayIPs: []string{node4IP, node5IP, node6IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node4IP, node5IP},
			"az-2": {node5IP, node6IP},
		},
		healthyGatewayIPs: []string{node4IP, node5IP, node6IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalPriority(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)
	policyName := "policy-1"

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalPriority,
		egressGroups: []egressGroupParams{{
			iface:           testInterface1,
			nodeLabels:      nodeGroup1Labels,
			maxGatewayNodes: 4,
		}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node1IP, node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 2,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 2,
			},
		},
		healthyGatewaysCount: float64(4)})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  1,
				activeGatewaysByAZRemoteCount: 2,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 1,
			},
		},
		healthyGatewaysCount: float64(3)})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  0,
				activeGatewaysByAZRemoteCount: 2,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 0,
			},
		},
		healthyGatewaysCount: float64(2)})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node3IP, node4IP},
			"az-2": {node1IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  1,
				activeGatewaysByAZRemoteCount: 2,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 1,
			},
		},
		healthyGatewaysCount: float64(3)})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node1IP, node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
	k.assertIegpMetrics(t, policyName, gatewayMetrics{
		activeGatewaysByAZ: []activeGatewaysByAZMetrics{
			{
				az:                            "az-1",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 2,
			},
			{
				az:                            "az-2",
				activeGatewaysByAZLocalCount:  2,
				activeGatewaysByAZRemoteCount: 2,
			},
		},
		healthyGatewaysCount: float64(4)})

	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node3IP, node4IP},
			"az-2": {node1IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node1IP, node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node3IP, node4IP},
			"az-2": {node1IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node1IP, node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesAgentDown(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node1IP, node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodeUnschedulableByTaint(t, node1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodeUnschedulableByTaint(t, node2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Add back k8s1
	node1 = k.updateNodeTaints(t, node1, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node3IP, node4IP},
			"az-2": {node1IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Add back k8s2
	node2 = k.updateNodeTaints(t, node2, nil)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node1IP, node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow 2 gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow 3 gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 3)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP},
			"az-2": {node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all 4 gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 4)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node1IP, node2IP, node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerNodeRestartScenarioLocalPriority(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs for az-1 twice when an active GW restarts
	//
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2 and node3
	// Even if node1 is up again, the activeGWs, node2 and node3 stay.
	//
	// When node1 and node3 go down, select node2(local) and node5(non-local)
	// If node5 goes down, pick another non-local node4.
	// Even if node5 is up again, the activeGWs, node2 and node4 stay.
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node5Name, node5IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4,5} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalPriority,
		egressGroups: []egressGroupParams{{
			iface:           testInterface1,
			nodeLabels:      nodeGroup1Labels,
			maxGatewayNodes: 2,
		}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node5IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node4IP, node5IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP, node5IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node4IP, node5IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
	})

	k.makeNodesUnhealthy(node1Name, node3Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node4IP},
			"az-2": {node4IP, node5IP},
		},
		healthyGatewayIPs: []string{node2IP, node4IP, node5IP},
	})

	k.makeNodesUnhealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node5IP},
			"az-2": {node2IP, node5IP},
		},
		healthyGatewayIPs: []string{node2IP, node5IP},
	})

	k.makeNodesHealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node5IP},
			"az-2": {node4IP, node5IP},
		},
		healthyGatewayIPs: []string{node2IP, node4IP, node5IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updateEgressGroupMaxGatewayNodes(t, policy1, defaultEgressGroupID, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node4IP},
			"az-2": {node4IP, node5IP},
		},
		healthyGatewayIPs: []string{node2IP, node4IP, node5IP},
	})
}

func TestEgressCIDRConflictsDetection(t *testing.T) {
	testCases := []struct {
		name     string
		policies []v1.IsovalentEgressGatewayPolicy
		expected map[policyEgressCIDR]policyEgressCIDR
	}{
		{
			name: "no egress cidrs",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.CIDR{destCIDR},
						EgressCIDRs:      []v1.IPv4CIDR{},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{},
		},
		{
			name: "internal conflict for repeated egress cidr",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.48/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
		{
			name: "internal conflict",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")},
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
		{
			name: "external conflict",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "policy-1",
						UID:               policy1UID,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "policy-2",
						UID:               policy2UID,
						CreationTimestamp: metav1.NewTime(time.Now().Add(time.Second)),
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-2"}, netip.MustParsePrefix("10.100.255.49/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
		{
			name: "internal conflict overrides external",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-2",
						UID:  policy2UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")},
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := hive.New(
				cell.Provide(newOperatorTables),
				cell.Invoke(func(db *statedb.DB, pt statedb.RWTable[*PolicyConfig]) {
					manager := OperatorManager{
						logger:             hivetest.Logger(t),
						db:                 db,
						policyConfigsTable: pt,
					}

					for i, policy := range tc.policies {
						// EgressGroups cannot be empty when parsing IEGP
						policy.Spec.EgressGroups = []v1.EgressGroup{
							{
								NodeSelector: &slimv1.LabelSelector{
									MatchLabels: noNodeGroup,
								},
							},
						}

						policyCfg, err := ParseIEGP(hivetest.Logger(t), &policy)
						if err != nil {
							t.Fatalf("failed to parse policy %d: %s", i, err)
						}
						tx := manager.db.WriteTxn(manager.policyConfigsTable)
						manager.policyConfigsTable.Insert(tx, policyCfg)
						tx.Commit()
					}

					tx := manager.db.WriteTxn(manager.policyConfigsTable)
					manager.updateEgressCIDRConflicts(tx)
					tx.Commit()

					if !maps.Equal(manager.cidrConflicts, tc.expected) {
						t.Fatalf("expected conflicts:\n%v\nfound:\n%v", tc.expected, manager.cidrConflicts)
					}
				}),
			)
			tlog := hivetest.Logger(t)
			require.NoError(t, h.Start(tlog, context.TODO()))
		})
	}
}

func TestEgressCIDRAllocation(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)
	k.addNode(t, node3Name, node3IP, nodeGroup1Labels)
	k.addNode(t, node4Name, node4IP, nodeGroup1Labels)

	// Create a new HA policy that selects all four nodes and request IPs from
	// CIDR "10.100.255.48/30"
	policy := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.255.48/30"},
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP, node3IP, node4IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node2IP: "10.100.255.49",
			node3IP: "10.100.255.50",
			node4IP: "10.100.255.51",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// Adding one node should lead to only 4 IPs allocated, since the pool is a "/30" CIDR
	// Moreover, the node5 IP should not be present among the active gateways, since the egress
	// IP allocation failed for that node.
	k.addNode(t, node5Name, node5IP, nodeGroup1Labels)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP, node3IP, node4IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node2IP: "10.100.255.49",
			node3IP: "10.100.255.50",
			node4IP: "10.100.255.51",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMPoolExhausted,
			Status: metav1.ConditionUnknown,
		},
	})

	// If 3 nodes goes unhealthy, IPs will be allocated only for the 2 nodes still healthy
	k.makeNodesUnhealthy("k8s2")
	k.makeNodesUnhealthy("k8s3")
	k.makeNodesUnhealthy("k8s4")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node5IP},
		healthyGatewayIPs: []string{node1IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node5IP: "10.100.255.49",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// When 2 out of the 3 nodes become healthy again, the previous active gateways (k8s1 and k8s5)
	// retain the allocated IP
	k.makeNodesHealthy("k8s2")
	k.makeNodesHealthy("k8s3")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP, node3IP, node5IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node5IP: "10.100.255.49",
			node2IP: "10.100.255.50",
			node3IP: "10.100.255.51",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// Update the policy to allow at most 1 gateway, only a single IP will be allocated
	k.updateEgressGroupMaxGatewayNodes(t, policy, defaultEgressGroupID, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node5IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node5IP: "10.100.255.48",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// User-specified EgressIP are not supported when relying on egress-gateway IPAM
	policy.egressGroups[defaultEgressGroupID].egressIP = "10.100.255.48"
	policy.egressGroups[defaultEgressGroupID].iface = "" // clear the interface, since having both iface and egressIP is not supported
	k.addPolicy(t, policy)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:    []string{},
		healthyGatewayIPs:   []string{node1IP, node2IP, node3IP, node5IP},
		egressIPByGatewayIP: map[string]string{},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMUnsupportedEgressIP,
			Status: metav1.ConditionUnknown,
		},
	})

	// User-specified EgressInterface is not supported when using IPAM with virtualIP
	policy.egressGroups[defaultEgressGroupID].egressIP = ""
	policy.egressGroups[defaultEgressGroupID].iface = "eth0"
	policy.annotations = map[string]string{
		virtualEgressIPKey: "true",
	}
	k.addPolicy(t, policy)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:    []string{},
		healthyGatewayIPs:   []string{node1IP, node2IP, node3IP, node5IP},
		egressIPByGatewayIP: map[string]string{},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMUnsupportedEgressInterface,
			Status: metav1.ConditionUnknown,
		},
	})
}

// Test that EGW-IPAM prioritizes active nodes over quarantined ones, and if necessary moves the assigned IPs.
// This sort of "floating IP" setup is discouraged (it prevents graceful shutdown of gateway nodes).
func TestEgressCIDRAllocationFloatingIP(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)

	// Create a non-HA policy (one EgressIP, maxGatewayNodes == 1).
	// Add one gateway node for the policy.
	k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.255.48/32"},
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels, maxGatewayNodes: 1}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// Add second gateway node. Shouldn't be selected as active.
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// When Node1's health-status is agent-down, Node2 should become active and take over the egressIP.
	k.makeNodesAgentDown(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
		egressIPByGatewayIP: map[string]string{
			node2IP: "10.100.255.48",
		},
	})

	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMPoolExhausted,
			Status: metav1.ConditionUnknown,
		},
	})

	// Restore node1. Node2 should stay the active gateway node.
	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
		egressIPByGatewayIP: map[string]string{
			node2IP: "10.100.255.48",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})
}

func TestEgressCIDRAllocationWithConflicts(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)

	// Create a new HA policy that selects nodes k8s1 and k8s2 and request IPs from
	// CIDR "10.100.255.48/30"
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.255.48/30"},
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels}},
	})

	k.addNode(t, node3Name, node3IP, nodeGroup2Labels)
	k.addNode(t, node4Name, node4IP, nodeGroup2Labels)

	// Create a new HA policy that selects nodes k8s3 and k8s4 and request IPs from
	// the same CIDR "10.100.255.48/30"
	policy2 := k.addPolicy(t, &policyParams{
		name:             "policy-2",
		uid:              policy2UID,
		endpointLabels:   ep2Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.255.48/30"},
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup2Labels}},
	})

	// since policy2 is requesting allocations from a conflicting CIDR, it won't get any IP
	k.assertIegpGatewayStatusFromPolicy(t, policy1.name, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node2IP: "10.100.255.49",
		},
	})
	k.assertIegpStatusConditionsFromPolicy(t, policy1.name, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})
	k.assertIegpGatewayStatusFromPolicy(t, policy2.name, gatewayStatus{
		activeGatewayIPs:    []string{},
		healthyGatewayIPs:   []string{node3IP, node4IP},
		egressIPByGatewayIP: map[string]string{},
	})
	k.assertIegpStatusConditionsFromPolicy(t, policy2.name, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMPoolConflicting,
			Status: metav1.ConditionUnknown,
		},
	})
}

func TestEgressCIDRAllocationWithoutCIDRs(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)
	k.addNode(t, node3Name, node3IP, nodeGroup1Labels)
	k.addNode(t, node4Name, node4IP, nodeGroup1Labels)

	// Create a new HA policy that selects all four nodes and do not specify
	// any egress CIDRs (no IPAM)
	k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels}},
	})

	// no egress IPs and no Condition should be found in Status
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:    []string{node1IP, node2IP, node3IP, node4IP},
		healthyGatewayIPs:   []string{node1IP, node2IP, node3IP, node4IP},
		egressIPByGatewayIP: map[string]string{},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{})
}

func TestEgressCIDRAllocationWithAZAffinity(t *testing.T) {
	type node struct {
		name   string
		ip     string
		labels map[string]string
	}

	testCases := []struct {
		name       string
		nodes      []node
		status     gatewayStatus
		conditions []metav1.Condition
	}{
		{
			name: "two-balanced-zones",
			nodes: []node{
				{node1Name, node1IP, nodeGroup1LabelsAZ1},
				{node2Name, node2IP, nodeGroup1LabelsAZ1},
				{node3Name, node3IP, nodeGroup1LabelsAZ2},
				{node4Name, node4IP, nodeGroup1LabelsAZ2},
			},
			status: gatewayStatus{
				activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
				activeGatewayIPsByAZ: map[string][]string{
					"az-1": {node1IP, node2IP},
					"az-2": {node3IP, node4IP},
				},
				egressIPByGatewayIP: map[string]string{
					node1IP: "10.100.255.48",
					node2IP: "10.100.255.50",
					node3IP: "10.100.255.49",
					node4IP: "10.100.255.51",
				},
				healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
			},
			conditions: []metav1.Condition{
				{
					Type:   egwIPAMRequestSatisfied,
					Status: metav1.ConditionTrue,
				},
			},
		},
		{
			name: "two-unbalanced-zones",
			nodes: []node{
				{node1Name, node1IP, nodeGroup1LabelsAZ1},
				{node3Name, node3IP, nodeGroup1LabelsAZ2},
				{node4Name, node4IP, nodeGroup1LabelsAZ2},
			},
			status: gatewayStatus{
				activeGatewayIPs: []string{node1IP, node3IP, node4IP},
				activeGatewayIPsByAZ: map[string][]string{
					"az-1": {node1IP},
					"az-2": {node3IP, node4IP},
				},
				egressIPByGatewayIP: map[string]string{
					node1IP: "10.100.255.48",
					node3IP: "10.100.255.49",
					node4IP: "10.100.255.50",
				},
				healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
			},
			conditions: []metav1.Condition{
				{
					Type:   egwIPAMRequestSatisfied,
					Status: metav1.ConditionTrue,
				},
			},
		},
		{
			name: "three-unbalanced-zones",
			nodes: []node{
				{node1Name, node1IP, nodeGroup1LabelsAZ1},
				{node2Name, node2IP, nodeGroup1LabelsAZ2},
				{node3Name, node3IP, nodeGroup1LabelsAZ3},
				{node4Name, node4IP, nodeGroup1LabelsAZ3},
				{node5Name, node5IP, nodeGroup1LabelsAZ3},
			},
			status: gatewayStatus{
				activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
				activeGatewayIPsByAZ: map[string][]string{
					"az-1": {node1IP},
					"az-2": {node2IP},
					"az-3": {node3IP, node4IP, node5IP},
				},
				egressIPByGatewayIP: map[string]string{
					node1IP: "10.100.255.48",
					node2IP: "10.100.255.49",
					node3IP: "10.100.255.50",
					node4IP: "10.100.255.51",
					node5IP: "10.100.255.52",
				},
				healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
			},
			conditions: []metav1.Condition{
				{
					Type:   egwIPAMRequestSatisfied,
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := setupEgressGatewayOperatorTestSuite(t)

			for _, n := range tc.nodes {
				k.addNode(t, n.name, n.ip, n.labels)
			}

			// Create a new HA policy that selects all nodes with a /29 egress CIDR
			k.addPolicy(t, &policyParams{
				name:             "policy-1",
				uid:              policy1UID,
				endpointLabels:   ep1Labels,
				destinationCIDRs: []string{destCIDR},
				egressCIDRs:      []string{"10.100.255.48/29"},
				azAffinity:       azAffinityLocalOnly,
				egressGroups:     []egressGroupParams{{nodeLabels: nodeGroup1Labels, iface: testInterface1}},
			})

			k.assertIegpGatewayStatus(t, tc.status)
			k.assertIegpStatusConditions(t, tc.conditions)
		})
	}
}

func TestEgressCIDRAllocationWithAZAffinityPoolExhausted(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes with a /31 egress CIDR
	k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.255.48/31"},
		azAffinity:       azAffinityLocalOnly,
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels}},
	})

	// since we can allocate 2 addresses and there are 2 zones, we should
	// have one active gateway for each affinity zone.
	// Moreover, no gateway without an allocated egress IP should appear in either
	// activeGatewayIPs and activeGatewayIPsByAZ.
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node3IP: "10.100.255.49",
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMPoolExhausted,
			Status: metav1.ConditionUnknown,
		},
	})
}

func TestEgressCIDRAllocationWithAZAffinityMaxGWNodes(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes with a /30 egress CIDR
	// and max gateway nodes set to 1. Since AZ affinity is enabled, there will be one
	// active gateway for each affinity zone, for a total of 2. Consequently, IPAM should
	// allocate 2 egress IPs.
	k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.255.48/30"},
		azAffinity:       azAffinityLocalOnly,
		egressGroups:     []egressGroupParams{{iface: testInterface1, nodeLabels: nodeGroup1Labels, maxGatewayNodes: 1}},
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node4IP: "10.100.255.49",
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})
}

// TestEgressCIDRAllocationIsStable assures that in cases where a gateway IP
// spans multiple zones, that this does not cause unstable egressIP assignment
// between reconciles.
func TestEgressCIDRAllocationIsStable(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// create a node that will not match but is in az1 to ensure our
	// zones span both.
	k.addNode(t, node1Name, node1IP, nodeGroup2LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ2)
	//nodeGroup2LabelsAZ1  = map[string]string{"label2": "1", core_v1.LabelTopologyZone: "az-1"}

	k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.255.48/28"},
		azAffinity:       azAffinityLocalOnlyFirst,
		egressGroups: []egressGroupParams{{
			iface:           testInterface1,
			nodeLabels:      nodeGroup1Labels,
			maxGatewayNodes: 1,
		}},
	})

	for range 10 {
		// create node update event to force re-reconcile.
		k.addNode(t, node3Name, node3IP, nil)
		// Subsequent reconciles should result in a stable egressIP assignment.
		k.assertIegpGatewayStatus(t, gatewayStatus{
			activeGatewayIPs: []string{node2IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {node2IP},
				"az-2": {node2IP},
			},
			egressIPByGatewayIP: map[string]string{
				node2IP: "10.100.255.48",
			},
			healthyGatewayIPs: []string{node2IP},
		})
	}
}

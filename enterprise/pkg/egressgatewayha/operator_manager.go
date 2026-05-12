// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

type OperatorConfig struct {
	// Amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayHAReconciliationTriggerInterval time.Duration
}

var defaultOperatorConfig = OperatorConfig{
	2 * time.Second,
}

func (def OperatorConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-ha-reconciliation-trigger-interval", def.EgressGatewayHAReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
}

type OperatorParams struct {
	cell.In

	Logger *slog.Logger

	Config       OperatorConfig
	DaemonConfig *option.DaemonConfig
	Metrics      *Metrics

	Health        cell.Health
	Clientset     k8sClient.Clientset
	Policies      resource.Resource[*Policy]
	Nodes         resource.Resource[*slim_corev1.Node]
	CiliumNodes   resource.Resource[*cilium_api_v2.CiliumNode]
	Healthchecker healthcheck.Healthchecker

	PolicyConfigsTable statedb.RWTable[*PolicyConfig]
	DB                 *statedb.DB

	Lifecycle cell.Lifecycle
}

type OperatorManager struct {
	lock.Mutex

	logger *slog.Logger

	// manager health status reporter
	health cell.Health

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// clientset is a k8s clientset used to retrieve and update the IEGP
	// objects' status
	clientset k8sClient.Clientset

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// nodeResources allows reading Node CRD from k8s.
	nodeResources resource.Resource[*slim_corev1.Node]

	// ciliumNodes allows reading CiliumNode CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// k8sNodeDataStore stores node name to k8s node mapping
	k8sNodeDataStore map[string]k8sNode

	// nodeDataStore stores node name to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// nodesByIP stores node IP to node mapping
	nodesByIP map[string]nodeTypes.Node

	// gatewayNodeDataStore stores all nodes that are acting as a gateway
	gatewayNodeDataStore map[string]nodeTypes.Node

	// nodes stores nodes sorted by their name
	nodes []nodeTypes.Node

	// policies stores IEGPs indexed by policyID
	policyCache map[policyID]*Policy

	// policyConfigs stores policy configs indexed by policyID
	policyConfigsTable statedb.RWTable[*PolicyConfig]
	db                 *statedb.DB

	// cidrConflicts stores all egressCIDRs conflicts, that is,
	// all conflicts that originate from any couple of overlapping CIDRs
	// requested in policies spec.
	// The map key is one of the two conflicting cidrs, and the map value
	// is the other one. Each conflicting CIDR is identified by the policyID
	// where it appears and the CIDR itself.
	cidrConflicts map[policyEgressCIDR]policyEgressCIDR

	// healthchecker checks the health status of the nodes configured as
	// gateway by at least one policy
	healthchecker healthcheck.Healthchecker

	// reconciliationTrigger is the trigger used to reconcile the the egress
	// gateway policies statuses with the list of active and healthy gateway
	// IPs.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger

	// restartOnce is used to re-initialize nodes health status once at startup
	restartOnce sync.Once

	metrics *Metrics
}

func NewEgressGatewayOperatorManager(p OperatorParams) (out struct {
	cell.Out

	*OperatorManager
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableIPv4EgressGatewayHA {
		return out, nil
	}

	out.OperatorManager = newEgressGatewayOperatorManager(p)

	return out, nil
}

func newEgressGatewayOperatorManager(p OperatorParams) *OperatorManager {
	operatorManager := &OperatorManager{
		logger:               p.Logger,
		health:               p.Health,
		clientset:            p.Clientset,
		policies:             p.Policies,
		nodeResources:        p.Nodes,
		ciliumNodes:          p.CiliumNodes,
		k8sNodeDataStore:     make(map[string]k8sNode),
		nodeDataStore:        make(map[string]nodeTypes.Node),
		nodesByIP:            make(map[string]nodeTypes.Node),
		gatewayNodeDataStore: make(map[string]nodeTypes.Node),
		policyConfigsTable:   p.PolicyConfigsTable,
		policyCache:          make(map[policyID]*Policy),
		healthchecker:        p.Healthchecker,
		db:                   p.DB,
		metrics:              p.Metrics,
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			t, err := trigger.NewTrigger(trigger.Parameters{
				Name:        "egress_gateway_ha_operator_reconciliation",
				MinInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
				TriggerFunc: func(reasons []string) {
					reason := strings.Join(reasons, ", ")
					p.Logger.Debug("reconciliation triggered", logfields.Reason, reason)

					operatorManager.Lock()
					defer operatorManager.Unlock()
					tx := operatorManager.db.WriteTxn(operatorManager.policyConfigsTable)
					logger := operatorManager.logger.With(logfieldReconcileTraceID, uuid.New().String())
					operatorManager.reconcileLocked(logger, tx)
					tx.Commit()
				},
			})
			if err != nil {
				return err
			}

			operatorManager.reconciliationTrigger = t

			go operatorManager.processEvents(ctx)
			operatorManager.startHealthcheckingLoop()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			operatorManager.health.Stopped("Context done")
			return nil
		},
	})

	return operatorManager
}

func newNodeResource(lc cell.Lifecycle, cs k8sClient.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Node], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](cs.Slim().CoreV1().Nodes()),
		opts...,
	)
	return resource.New[*slim_corev1.Node](lc, lw, mp, resource.WithMetric("Node")), nil
}

func (operatorManager *OperatorManager) processEvents(ctx context.Context) {
	var policySync, nodeSync bool
	maybeTriggerReconcile := func() {
		if !policySync || !nodeSync {
			return
		}

		operatorManager.Lock()
		defer operatorManager.Unlock()

		if operatorManager.allCachesSynced {
			return
		}

		operatorManager.allCachesSynced = true
		operatorManager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	policyEvents := operatorManager.policies.Events(ctx)
	ciliumNodeEvents := operatorManager.ciliumNodes.Events(ctx)
	nodeEvents := operatorManager.nodeResources.Events(ctx)

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-policyEvents:
			if event.Kind == resource.Sync {
				policySync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				operatorManager.handlePolicyEvent(event)
			}

		case event := <-ciliumNodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				operatorManager.handleCiliumNodeEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				operatorManager.handleNodeEvent(event)
			}
		}
	}
}

// startHealthcheckingLoop spawns a goroutine that periodically checks if the
// health status of any node has changed, and when that's the case, it re runs
// the reconciliation.
func (operatorManager *OperatorManager) startHealthcheckingLoop() {
	go func() {
		for range operatorManager.healthchecker.Events() {
			operatorManager.reconciliationTrigger.TriggerWithReason("healthcheck event")
		}
	}()
}

func (operatorManager *OperatorManager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := operatorManager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		operatorManager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (operatorManager *OperatorManager) onAddEgressPolicy(policy *Policy) error {
	logger := operatorManager.logger.With(
		logfields.IsovalentEgressGatewayPolicyName, policy.ObjectMeta.Name,
		logfields.K8sUID, policy.ObjectMeta.UID,
	)

	config, err := ParseIEGP(logger, policy)
	if err != nil {
		logger.Warn("Failed to parse IsovalentEgressGatewayPolicy", logfields.Error, err)
		return err
	}

	operatorManager.Lock()
	defer operatorManager.Unlock()
	tx := operatorManager.db.WriteTxn(operatorManager.policyConfigsTable)
	defer tx.Abort()

	operatorManager.policyCache[config.id] = policy
	hadPrev, err := operatorManager.upsertPolicyConfig(tx, config)
	if err != nil {
		return err
	}

	if !hadPrev {
		logger.Debug("Added IsovalentEgressGatewayPolicy")
	} else {
		logger.Debug("Updated IsovalentEgressGatewayPolicy")
	}

	tx.Commit()

	operatorManager.reconciliationTrigger.TriggerWithReason("IsovalentEgressGatewayPolicy added")
	return nil
}

func (operatorManager *OperatorManager) upsertPolicyConfig(tx statedb.WriteTxn, pc *PolicyConfig) (bool, error) {
	_, hadPrev, err := operatorManager.policyConfigsTable.Insert(tx, pc.clone())
	return hadPrev, err
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (operatorManager *OperatorManager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseIEGPConfigID(policy)

	operatorManager.Lock()
	defer operatorManager.Unlock()
	tx := operatorManager.db.WriteTxn(operatorManager.policyConfigsTable)
	defer tx.Abort()

	logger := operatorManager.logger.With(logfields.IsovalentEgressGatewayPolicyName, configID.Name)

	delete(operatorManager.policyCache, configID)
	if prev, _, err := operatorManager.policyConfigsTable.Delete(tx, &PolicyConfig{id: configID}); err != nil {
		logger.Error("failed to upsert policyConfig",
			logfields.Error, err,
			logfields.ID, configID,
		)
		tx.Abort()
	} else if prev == nil {
		logger.Warn("Can't delete IsovalentEgressGatewayPolicy: policy not found")
		return
	}
	logger.Debug("Deleted IsovalentEgressGatewayPolicy")
	tx.Commit()

	operatorManager.deleteGatewaySelectionMetrics(policy)

	operatorManager.reconciliationTrigger.TriggerWithReason("IsovalentEgressGatewayPolicy deleted")
}

func (operatorManager *OperatorManager) deleteGatewaySelectionMetrics(policy *Policy) {
	operatorManager.metrics.ActiveGateways.DeleteLabelValues(policy.Name)
	operatorManager.metrics.HealthyGateways.DeleteLabelValues(policy.Name)
	for _, gs := range policy.Status.GroupStatuses {
		for az := range gs.ActiveGatewayIPsByAZ {
			operatorManager.metrics.ActiveGatewaysByAZ.DeleteLabelValues(policy.Name, az, labelValueScopeLocal)
			operatorManager.metrics.ActiveGatewaysByAZ.DeleteLabelValues(policy.Name, az, labelValueScopeRemote)
		}
	}
}

// handleCiliumNodeEvent takes care of node upserts and removals.
func (operatorManager *OperatorManager) handleCiliumNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := k8s.ParseCiliumNode(event.Object)

	operatorManager.Lock()
	defer operatorManager.Unlock()

	if event.Kind == resource.Upsert {
		operatorManager.nodeDataStore[node.Name] = node
		operatorManager.onChangeNodeLocked("CiliumNode updated")
	} else {
		delete(operatorManager.nodeDataStore, node.Name)
		operatorManager.onChangeNodeLocked("CiliumNode deleted")
	}
}

type k8sNode struct {
	name   string
	taints []slim_corev1.Taint
}

// handleNodeEvent takes care of node upserts and removals.
func (operatorManager *OperatorManager) handleNodeEvent(event resource.Event[*slim_corev1.Node]) {
	defer event.Done(nil)

	n := event.Object
	k8sNode := k8sNode{
		name:   n.Name,
		taints: n.Spec.Taints,
	}

	operatorManager.Lock()
	defer operatorManager.Unlock()

	if event.Kind == resource.Upsert {
		operatorManager.k8sNodeDataStore[k8sNode.name] = k8sNode
		operatorManager.onChangeNodeLocked("K8s Node updated")
	} else {
		delete(operatorManager.k8sNodeDataStore, k8sNode.name)
		operatorManager.onChangeNodeLocked("K8s Node deleted")
	}
}

func (operatorManager *OperatorManager) onChangeNodeLocked(event string) {
	operatorManager.nodes = []nodeTypes.Node{}
	for _, n := range operatorManager.nodeDataStore {
		operatorManager.nodes = append(operatorManager.nodes, n)
	}
	sort.Slice(operatorManager.nodes, func(i, j int) bool {
		return operatorManager.nodes[i].Name < operatorManager.nodes[j].Name
	})

	operatorManager.nodesByIP = make(map[string]nodeTypes.Node)
	for _, n := range operatorManager.nodeDataStore {
		for _, ipAddress := range n.IPAddresses {
			if ipAddress.AddrType() == addressing.NodeInternalIP {
				operatorManager.nodesByIP[ipAddress.ToString()] = n
			}
		}
	}

	operatorManager.reconciliationTrigger.TriggerWithReason(event)
}

func (operatorManager *OperatorManager) nodeIsReachable(nodeName string) bool {
	return operatorManager.healthchecker.NodeHealth(nodeName).Reachable
}

func (operatorManager *OperatorManager) nodeIsAvailable(node nodeTypes.Node) bool {
	return operatorManager.healthchecker.NodeHealth(node.Name).AgentUp && !operatorManager.nodeIsUnschedulable(node)
}

func (operatorManager *OperatorManager) nodeIsUnschedulable(node nodeTypes.Node) bool {
	if k8sNode, found := operatorManager.k8sNodeDataStore[node.Name]; found {
		for _, taint := range k8sNode.taints {
			if taint.Key == core_v1.TaintNodeUnschedulable && taint.Effect == slim_corev1.TaintEffectNoSchedule {
				return true
			}
		}
	}

	if val, found := node.Annotations[nodeEgressGatewayKey]; found {
		return val == nodeEgressGatewayUnschedulableValue
	}

	return false
}

func (operatorManager *OperatorManager) previousHealthyGateways(tx statedb.ReadTxn) []netip.Addr {
	var addrs []netip.Addr
	for policyConfig := range operatorManager.policyConfigsTable.All(tx) {
		for _, gs := range policyConfig.groupStatuses {
			addrs = append(addrs, gs.healthyGatewayIPs...)
		}
	}
	return ciliumslices.Unique(addrs)
}

func (operatorManager *OperatorManager) previousActiveGateways(tx statedb.ReadTxn) []netip.Addr {
	var allAddrs []netip.Addr
	for policyConfig := range operatorManager.policyConfigsTable.All(tx) {
		for _, gs := range policyConfig.groupStatuses {
			if policyConfig.azAffinity.enabled() {
				for _, addrs := range gs.activeGatewayIPsByAZ {
					allAddrs = append(allAddrs, addrs...)
				}
			} else {
				allAddrs = append(allAddrs, gs.activeGatewayIPs...)
			}
		}
	}
	return ciliumslices.Unique(allAddrs)
}

func (operatorManager *OperatorManager) regenerateGatewayNodesList(tx statedb.ReadTxn) {
	nodes := map[string]nodeTypes.Node{}

	for policyConfig := range operatorManager.policyConfigsTable.All(tx) {
		for _, gc := range policyConfig.groupConfigs {
			for _, n := range operatorManager.nodes {
				if gc.selectsNodeAsGateway(n) {
					nodes[n.Name] = n
				}
			}
		}
	}

	operatorManager.gatewayNodeDataStore = nodes
}

func (operatorManager *OperatorManager) updatePolicesGroupStatuses(logger *slog.Logger, tx statedb.WriteTxn) {
	for config := range operatorManager.policyConfigsTable.All(tx) {
		err := config.updateGroupStatuses(logger, operatorManager, tx)
		if err != nil {
			operatorManager.reconciliationTrigger.TriggerWithReason("retry after error")
		}
	}
}

// policyEgressCIDR uniquely identifies a user specified egress CIDR in a policy
type policyEgressCIDR struct {
	origin policyID
	cidr   netip.Prefix
}

func (pec policyEgressCIDR) String() string {
	return pec.origin.String() + "-" + pec.cidr.String()
}

func (operatorManager *OperatorManager) updateEgressCIDRConflicts(tx statedb.ReadTxn) {
	operatorManager.cidrConflicts = make(map[policyEgressCIDR]policyEgressCIDR)

	var egressCIDRs []policyEgressCIDR

	// internal conflicts
	for policyCfg := range operatorManager.policyConfigsTable.All(tx) {
		for _, egressCIDR := range policyCfg.egressCIDRs {
			egressCIDRs = append(egressCIDRs, policyEgressCIDR{
				origin: policyCfg.id,
				cidr:   egressCIDR,
			})
		}

		if len(policyCfg.egressCIDRs) <= 1 {
			continue
		}

		for i := 0; i < len(policyCfg.egressCIDRs)-1; i++ {
			for j := i + 1; j < len(policyCfg.egressCIDRs); j++ {
				if policyCfg.egressCIDRs[i].Overlaps(policyCfg.egressCIDRs[j]) {
					first, second := policyEgressCIDR{policyCfg.id, policyCfg.egressCIDRs[i]}, policyEgressCIDR{policyCfg.id, policyCfg.egressCIDRs[j]}
					operatorManager.cidrConflicts[first] = second
					operatorManager.cidrConflicts[second] = first
				}
			}
		}
	}

	if len(egressCIDRs) <= 1 {
		return
	}

	// external conflicts
	for i := 0; i < len(egressCIDRs)-1; i++ {
		// egressCIDR[i] is already conflicting
		if _, found := operatorManager.cidrConflicts[egressCIDRs[i]]; found {
			continue
		}

		for j := i + 1; j < len(egressCIDRs); j++ {
			// egressCIDR[j] is already conflicting
			if _, found := operatorManager.cidrConflicts[egressCIDRs[j]]; found {
				continue
			}

			if egressCIDRs[i].origin == egressCIDRs[j].origin {
				// no need to check CIDRs from the same policy, internal conflicts
				// have already been found
				continue
			}

			if egressCIDRs[i].cidr.Overlaps(egressCIDRs[j].cidr) {
				first, second := policyEgressCIDR{egressCIDRs[i].origin, egressCIDRs[i].cidr}, policyEgressCIDR{egressCIDRs[j].origin, egressCIDRs[j].cidr}

				policy1, _, _ := operatorManager.policyConfigsTable.Get(tx, OperatorIndex.Query(egressCIDRs[i].origin))
				policy2, _, _ := operatorManager.policyConfigsTable.Get(tx, OperatorIndex.Query(egressCIDRs[j].origin))

				// mark the most recent policy as conflicting
				if policy1.creationTimestamp.Before(policy2.creationTimestamp) {
					operatorManager.cidrConflicts[second] = first
				} else {
					operatorManager.cidrConflicts[first] = second
				}
			}
		}
	}
}

// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (operatorManager *OperatorManager) reconcileLocked(logger *slog.Logger, tx statedb.WriteTxn) {
	var healthyNodes, activeNodes sets.Set[string]

	if !operatorManager.allCachesSynced {
		return
	}

	operatorManager.regenerateGatewayNodesList(tx)

	// during the first reconciliation after a restart, we manually mark all
	// previous gateways as healthy.
	// This is done to avoid spurious datapath reconciliation across an operator
	// restart (e.g: spurious changes to the egw ha BPF map or IPAM addresses
	// reallocation). This might happen since at startup we don't have any node
	// health status information until the first health probe verdict is available.
	operatorManager.restartOnce.Do(func() {
		healthyNodes = sets.New[string]()
		for _, gw := range operatorManager.previousHealthyGateways(tx) {
			node, ok := operatorManager.nodesByIP[gw.String()]
			if !ok {
				// node has been cancelled during the operator restart
				continue
			}
			healthyNodes.Insert(node.Name)
		}

		activeNodes = sets.New[string]()
		for _, gw := range operatorManager.previousActiveGateways(tx) {
			node, ok := operatorManager.nodesByIP[gw.String()]
			if !ok {
				continue
			}
			activeNodes.Insert(node.Name)
		}
	})

	operatorManager.healthchecker.UpdateNodeList(operatorManager.gatewayNodeDataStore, healthyNodes, activeNodes)

	operatorManager.updateEgressCIDRConflicts(tx)
	operatorManager.updatePolicesGroupStatuses(logger, tx)
}

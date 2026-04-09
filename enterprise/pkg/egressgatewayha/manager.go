//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	enterprise_tables "github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/enterprise/pkg/datapath/sockets"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/healthconfig"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	// GatewayNotFoundIPv4 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv4 = netip.MustParseAddr("0.0.0.0")
	// ExcludedCIDRIPv4 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv4 = netip.MustParseAddr("0.0.0.1")
	// EgressIPNotFoundIPv4 is a special IP value used as egressIP in the BPF policy map
	// to indicate no egressIP was found for the given policy
	EgressIPNotFoundIPv4 = netip.IPv4Unspecified()
)

type eventType int

const (
	eventNone = eventType(1 << iota)
	eventK8sSyncDone
	eventAddPolicy
	eventDeletePolicy
	eventUpdateEndpoint
	eventDeleteEndpoint
	eventUpdateNode
	eventDeleteNode
)

const policyInitializerName = "isovalentegressgatewaypolicy-synced"

type Config struct {
	// Default amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayHAReconciliationTriggerInterval time.Duration

	// EnableEgressGatewayHASocketTermination enables socket termination feature
	// which closes client sockets for Pod connections being forwarded to a GW
	// node that is no longer healthy.
	EnableEgressGatewayHASocketTermination bool `mapstructure:"enable-egress-gateway-ha-socket-termination"`
}

var defaultConfig = Config{
	EgressGatewayHAReconciliationTriggerInterval: 1 * time.Second,
	EnableEgressGatewayHASocketTermination:       true,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-ha-reconciliation-trigger-interval", def.EgressGatewayHAReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")

	flags.Bool("enable-egress-gateway-ha-socket-termination", def.EnableEgressGatewayHASocketTermination, "Enables egress-gateway ha closing sockets for unavailable gateways")
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	logger *slog.Logger

	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// endpoints allows reading endpoint CRD from k8s.
	endpoints resource.Resource[*k8sTypes.CiliumEndpoint]

	// nodesResource allows reading node CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// nodeDataStore stores node names to node mapping
	nodeDataStore map[string]nodeTypes.Node

	// nodesByIP stores node IPs to node mapping
	nodesByIP map[string]nodeTypes.Node

	// policyConfigs stores policy configs indexed by policyID
	policyConfigsTable statedb.RWTable[AgentPolicyConfig]

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap communicates the active policies to the datapath.
	policyMapV2 egressmapha.PolicyMapV2

	// ctMap stores EGW specific conntrack entries.
	ctMap egressmapha.CtMap

	// reconciliationTriggerInterval is the amount of time between triggers
	// of reconciliations are invoked
	reconciliationTriggerInterval time.Duration

	// eventsBitmap is a bitmap that tracks which type of events has been
	// received by the manager (e.g. node added or policy removed) since the
	// last invocation of the reconciliation logic
	eventsBitmap eventType

	// reconciliationTrigger is the trigger used to reconcile the state of
	// the node with the desired egress gateway state.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger

	// reconciliationEventsCount keeps track of how many reconciliation
	// events have occoured
	reconciliationEventsCount atomic.Uint64

	localNodeStore *node.LocalNodeStore

	sysctl sysctl.Sysctl

	// bgpSignaler is used to signal reconciliation events to the BGP Control Plane
	bgpSignaler *signaler.BGPCPSignaler

	// egressConfigsByPolicy stores all the configurations (addr and iface) for IPAM
	// allocations entitled to the local node, as reported in each Egress Group Status
	// of the IEGPs.
	// The key of the map is the policy reporting the address allocation, the value is
	// the set of configuration pairs <egressIP, net_inteface> for that policy.
	egressConfigsByPolicy map[policyID]sets.Set[gwEgressIPConfig]

	egressIPTable statedb.RWTable[*enterprise_tables.EgressIPEntry]

	egressIPReconciler reconciler.Reconciler[*enterprise_tables.EgressIPEntry]

	policyInitializer func(txn statedb.WriteTxn)

	db *statedb.DB

	ctNATMapGC ctmap.GCRunner

	config Config

	health cell.Health

	socketsActions socketsActions

	ifindexResolver ifindexResolver
}

type Params struct {
	cell.In

	Logger *slog.Logger

	Config            Config
	DaemonConfig      *option.DaemonConfig
	TunnelConfig      tunnel.Config
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMapV2       egressmapha.PolicyMapV2
	Policies          resource.Resource[*Policy]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	Nodes             resource.Resource[*cilium_api_v2.CiliumNode]
	CtMap             egressmapha.CtMap
	LocalNodeStore    *node.LocalNodeStore
	Sysctl            sysctl.Sysctl
	BGPSignaler       *signaler.BGPCPSignaler

	DB                 *statedb.DB
	EgressIPTable      statedb.RWTable[*enterprise_tables.EgressIPEntry]
	EgressIPReconciler reconciler.Reconciler[*enterprise_tables.EgressIPEntry]
	PolicyConfigsTable statedb.RWTable[AgentPolicyConfig]

	CTNATMapGC ctmap.GCRunner

	Lifecycle cell.Lifecycle
	Health    cell.Health

	HealthConfig healthconfig.CiliumHealthConfig

	IfindexResolver ifindexResolver `optional:"true"`
}

type ifindexResolver func(iface netlink.Link) uint32

// EgressIPsProvider provides policy to egress IPs mappings.
type EgressIPsProvider interface {
	AdvertisedEgressIPs(policySelector *slimv1.LabelSelector) (map[types.NamespacedName][]netip.Addr, error)
}

func NewEgressGatewayManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
}, err error,
) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableIPv4EgressGatewayHA {
		return out, nil
	}

	if p.Config.EnableEgressGatewayHASocketTermination {
		if err := sockets.InetDiagDestroyEnabled(); err != nil {
			if errors.Is(err, probes.ErrNotSupported) {
				return out, fmt.Errorf("egwha socket termination feature requires CONFIG_INET_DIAG_DESTROY kernel config to be enabled: %w", err)
			}
			return out, fmt.Errorf("failed to probe for socket termination feature: %w", err)
		}
	}

	if dcfg.IdentityAllocationMode != option.IdentityAllocationModeCRD {
		return out, fmt.Errorf("egress gateway is not supported in %s identity allocation mode", dcfg.IdentityAllocationMode)
	}

	if dcfg.EnableCiliumEndpointSlice {
		return out, errors.New("egress gateway is not supported in combination with the CiliumEndpointSlice feature")
	}

	if !dcfg.EnableIPv4Masquerade || !dcfg.EnableBPFMasquerade {
		return out, fmt.Errorf("egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	}

	if p.TunnelConfig.UnderlayProtocol() != tunnel.IPv4 {
		return out, errors.New("egress gateway requires an IPv4 underlay")
	}

	if !p.HealthConfig.IsHealthCheckingEnabled() {
		return out, fmt.Errorf("egress gateway HA requires healthchecking to be enabled")
	}

	if p.IfindexResolver == nil {
		p.IfindexResolver = egressIfindexForIface
	}

	out.Manager, err = newEgressGatewayManager(p)
	if err != nil {
		return out, err
	}

	out.NodeDefines = map[string]string{
		"ENABLE_EGRESS_GATEWAY_HA": "1",
	}

	out.health = p.Health

	return out, nil
}

// tunnel.EnablerOut used to be returned from the NewEgressGatewayManager.
// However, that makes tunnel.Config depends on the Manager and that introduces
// lots of unnecessary dependencies. As a result, we hit the circular
// dependency issue, so we moved the tunnel.EnablerOut creation to a separate
// function.
func newTunnelEnabler(dcfg *option.DaemonConfig) tunnel.EnablerOut {
	return tunnel.NewEnabler(dcfg.EnableIPv4EgressGatewayHA)
}

func newEgressGatewayManager(p Params) (*Manager, error) {
	// Initializer prevents the reconciler from pruning old IPAM-related routing policy rules
	// and routes from the node network configuration until we have had a chance to recompute
	// the new state after all k8s caches are synced.
	txn := p.DB.WriteTxn(p.EgressIPTable)
	policyInitializer := p.EgressIPTable.RegisterInitializer(txn, policyInitializerName)
	txn.Commit()

	manager := &Manager{
		logger:                        p.Logger,
		nodeDataStore:                 make(map[string]nodeTypes.Node),
		policyConfigsTable:            p.PolicyConfigsTable,
		egressConfigsByPolicy:         make(map[policyID]sets.Set[gwEgressIPConfig]),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		identityAllocator:             p.IdentityAllocator,
		reconciliationTriggerInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
		policyMapV2:                   p.PolicyMapV2,
		policies:                      p.Policies,
		endpoints:                     p.Endpoints,
		ciliumNodes:                   p.Nodes,
		ctMap:                         p.CtMap,
		localNodeStore:                p.LocalNodeStore,
		sysctl:                        p.Sysctl,
		bgpSignaler:                   p.BGPSignaler,
		db:                            p.DB,
		egressIPTable:                 p.EgressIPTable,
		egressIPReconciler:            p.EgressIPReconciler,
		policyInitializer:             policyInitializer,
		ctNATMapGC:                    p.CTNATMapGC,
		config:                        p.Config,
		health:                        p.Health,
		ifindexResolver:               p.IfindexResolver,
	}

	if p.Config.EnableEgressGatewayHASocketTermination {
		manager.socketsActions = &socketsManager{
			logger: p.Logger,
			health: p.Health.NewScope("sockets-manager"),
		}
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "egress_gateway_ha_reconciliation",
		MinInterval: p.Config.EgressGatewayHAReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			reason := strings.Join(reasons, ", ")
			manager.logger.Debug("reconciliation triggered", logfields.Reason, reason)

			manager.Lock()
			defer manager.Unlock()

			manager.reconcileLocked()
		},
	})
	if err != nil {
		return nil, err
	}

	manager.reconciliationTrigger = t

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			wg.Go(func() {
				manager.processEvents(ctx)
			})

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			wg.Wait()
			return nil
		},
	})

	return manager, nil
}

func (manager *Manager) setEventBitmap(events ...eventType) {
	for _, e := range events {
		manager.eventsBitmap |= e
	}
}

func (manager *Manager) eventBitmapIsSet(events ...eventType) bool {
	for _, e := range events {
		if manager.eventsBitmap&e != 0 {
			return true
		}
	}

	return false
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (manager *Manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %w", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// processEvents spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) processEvents(ctx context.Context) {
	var policySync, endpointSync, nodeSync bool
	maybeTriggerReconcile := func() {
		if !policySync || !endpointSync || !nodeSync {
			return
		}

		manager.Lock()
		defer manager.Unlock()

		if manager.allCachesSynced {
			return
		}

		manager.allCachesSynced = true
		manager.setEventBitmap(eventK8sSyncDone)
		manager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	endpointsRateLimit := workqueue.NewTypedItemExponentialFailureRateLimiter[resource.WorkItem](time.Millisecond*20, time.Minute*20)

	policyEvents := manager.policies.Events(ctx)
	endpointEvents := manager.endpoints.Events(ctx, resource.WithRateLimiter(endpointsRateLimit))
	nodeEvents := manager.ciliumNodes.Events(ctx)

	manager.ctNATMapGC.Observe4().Observe(ctx,
		func(event ctmap.GCEvent) {
			egressmapha.PurgeEgressCTEntry(manager.ctMap, event.Key)
		},
		func(err error) {})

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
				manager.handlePolicyEvent(event)
			}

		case event := <-endpointEvents:
			if event.Kind == resource.Sync {
				endpointSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleEndpointEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleNodeEvent(event)
			}
		}
	}
}

func (manager *Manager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := manager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		manager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

// Event handlers

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddEgressPolicy(policy *Policy) error {
	logger := manager.logger.With(
		logfields.IsovalentEgressGatewayPolicyName, policy.Name,
		logfields.K8sUID, policy.UID,
	)

	if policy.Status.ObservedGeneration != policy.GetGeneration() {
		logger.Debug("Received policy whose GroupStatuses has not yet been updated by the operator, ignoring it")
		return nil
	}

	config, err := parseAgentIEGP(logger, policy)
	if err != nil {
		logger.Warn("Failed to parse IsovalentEgressGatewayPolicy", logfields.Error, err)
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	tx := manager.db.WriteTxn(manager.policyConfigsTable)
	defer tx.Abort()

	config.updateMatchedEndpointIDs(manager.epDataStore)
	hadPrev, err := manager.upsertPolicy(tx, config)
	if err != nil {
		return fmt.Errorf("update policy table: %w", err)
	}
	tx.Commit()
	if !hadPrev {
		logger.Debug("Added IsovalentEgressGatewayPolicy")
	} else {
		logger.Debug("Updated IsovalentEgressGatewayPolicy")
	}

	manager.setEventBitmap(eventAddPolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy added")
	return nil
}

func (manager *Manager) deletePolicyByID(tx statedb.WriteTxn, id types.NamespacedName) bool {
	_, deleted, err := manager.policyConfigsTable.Delete(tx, AgentPolicyConfig{
		PolicyConfig: &PolicyConfig{id: id},
	})
	if err != nil {
		manager.logger.Error("BUG: could not delete policy",
			logfields.Error, err,
			logfields.ID, id)
		return deleted
	}
	return deleted
}

func (manager *Manager) upsertPolicy(tx statedb.WriteTxn, p AgentPolicyConfig) (bool, error) {
	_, hadPrev, err := manager.policyConfigsTable.Insert(tx, p)
	if err != nil {
		return hadPrev, err
	}
	return hadPrev, err
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (manager *Manager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseIEGPConfigID(policy)

	manager.Lock()
	defer manager.Unlock()

	logger := manager.logger.With(logfields.IsovalentEgressGatewayPolicyName, configID.Name)

	logger.Debug("Deleted IsovalentEgressGatewayPolicy")

	tx := manager.db.WriteTxn(manager.policyConfigsTable)
	defer tx.Abort()
	if deleted := manager.deletePolicyByID(tx, configID); !deleted {
		logger.Warn("Can't delete IsovalentEgressGatewayPolicy: policy not found")
	}
	tx.Commit()

	manager.setEventBitmap(eventDeletePolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy deleted")
}

func (manager *Manager) addEndpoint(endpoint *k8sTypes.CiliumEndpoint) error {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	manager.Lock()
	defer manager.Unlock()

	logger := manager.logger.With(
		logfields.K8sEndpointName, endpoint.Name,
		logfields.K8sNamespace, endpoint.Namespace,
		logfields.K8sUID, endpoint.UID,
	)

	if endpoint.Identity == nil {
		logger.Warn("Endpoint is missing identity metadata, skipping update to egress policy.")
		return nil
	}

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.Warn("Failed to get identity labels for endpoint",
			logfields.Error, err,
		)
		return err
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.Warn("Failed to get valid endpoint metadata, skipping update to egress policy.",
			logfields.Error, err,
		)
		return nil
	}

	if _, ok := manager.epDataStore[epData.id]; ok {
		logger.Debug("Updated CiliumEndpoint")
	} else {
		logger.Debug("Added CiliumEndpoint")
	}

	manager.epDataStore[epData.id] = epData

	manager.setEventBitmap(eventUpdateEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint updated")

	return nil
}

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.Lock()
	defer manager.Unlock()

	logger := manager.logger.With(
		logfields.K8sEndpointName, endpoint.Name,
		logfields.K8sNamespace, endpoint.Namespace,
		logfields.K8sUID, endpoint.UID,
	)

	logger.Debug("Deleted CiliumEndpoint")
	delete(manager.epDataStore, endpoint.UID)

	manager.setEventBitmap(eventDeleteEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint deleted")
}

func (manager *Manager) handleEndpointEvent(event resource.Event[*k8sTypes.CiliumEndpoint]) {
	endpoint := event.Object

	if event.Kind == resource.Upsert {
		event.Done(manager.addEndpoint(endpoint))
	} else {
		manager.deleteEndpoint(endpoint)
		event.Done(nil)
	}
}

// handleNodeEvent takes care of node upserts and removals.
func (manager *Manager) handleNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := nodeTypes.ParseCiliumNode(event.Object)

	manager.Lock()
	defer manager.Unlock()

	if event.Kind == resource.Upsert {
		manager.nodeDataStore[node.Name] = node

		manager.setEventBitmap(eventUpdateNode)
		manager.reconciliationTrigger.TriggerWithReason("CiliumNode updated")
	} else {
		delete(manager.nodeDataStore, node.Name)

		manager.setEventBitmap(eventDeleteNode)
		manager.reconciliationTrigger.TriggerWithReason("CiliumNode deleted")
	}
}

func (manager *Manager) updatePoliciesMatchedEndpointIDs(tx statedb.WriteTxn) error {
	for policy := range manager.policyConfigsTable.All(tx) {
		if needsUpdate := policy.updateMatchedEndpointIDs(manager.epDataStore); needsUpdate {
			if _, _, err := manager.policyConfigsTable.Insert(tx, policy); err != nil {
				return fmt.Errorf("failed to update matched endpoint ID: %w", err)
			}
		}
	}
	return nil
}

func (manager *Manager) updateNodesByIP() {
	manager.nodesByIP = make(map[string]nodeTypes.Node)

	for _, node := range manager.nodeDataStore {
		for _, ipAddress := range node.IPAddresses {
			if ipAddress.AddrType() == addressing.NodeInternalIP {
				manager.nodesByIP[ipAddress.ToString()] = node
			}
		}
	}
}

func (manager *Manager) removeStaleEgressIPConfigs(tx statedb.ReadTxn) {
	for policyID := range manager.egressConfigsByPolicy {
		_, _, found := manager.policyConfigsTable.Get(tx, AgentIndex.Query(policyID))
		if found {
			continue
		}

		// policy has been removed, so remove egress IPs and routes too
		manager.removePolicyEgressIPs(manager.egressConfigsByPolicy[policyID])
		delete(manager.egressConfigsByPolicy, policyID)
	}
}

func (manager *Manager) removePolicyEgressIPs(egressIPs sets.Set[gwEgressIPConfig]) {
	txn := manager.db.WriteTxn(manager.egressIPTable)
	defer txn.Abort()

	for _, egressIP := range egressIPs.UnsortedList() {
		key := enterprise_tables.EgressIPKey{
			Addr:      egressIP.addr,
			Interface: egressIP.iface,
		}
		obj, _, found := manager.egressIPTable.Get(txn, enterprise_tables.EgressIPEntryIndex.Query(key))
		if !found {
			continue
		}
		if _, _, err := manager.egressIPTable.Delete(txn, obj); err != nil {
			manager.logger.Error(
				"Failed to delete entry from egress-ips stateDB table",
				logfields.Error, err,
				logfields.EgressIP, egressIP.addr,
				logfields.Interface, egressIP.iface,
			)
		}
	}

	txn.Commit()
}

func (manager *Manager) regenerateGatewayConfigs(tx statedb.WriteTxn) {
	for policyConfig := range manager.policyConfigsTable.All(tx) {
		policyConfig.regenerateGatewayConfig(manager, tx)
	}
}

func (manager *Manager) relaxRPFilter(tx statedb.ReadTxn) error {
	var sysSettings []tables.Sysctl
	ifSet := make(map[string]struct{})

	for pc := range manager.policyConfigsTable.All(tx) {
		if !pc.gatewayConfig.localNodeConfiguredAsGateway {
			continue
		}

		ifaceName := pc.gatewayConfig.ifaceName
		if _, ok := ifSet[ifaceName]; !ok {
			ifSet[ifaceName] = struct{}{}
			sysSettings = append(sysSettings, tables.Sysctl{
				Name:      []string{"net", "ipv4", "conf", ifaceName, "rp_filter"},
				Val:       "2",
				IgnoreErr: false,
			})
		}
	}

	if len(sysSettings) == 0 {
		return nil
	}

	return manager.sysctl.ApplySettings(sysSettings)
}

func (manager *Manager) updateEgressRulesV2(tx statedb.ReadTxn) {
	egressPolicies := map[egressmapha.EgressPolicyV2Key4]egressmapha.EgressPolicyV2Val4{}
	manager.policyMapV2.IterateWithCallback(
		func(key *egressmapha.EgressPolicyV2Key4, val *egressmapha.EgressPolicyV2Val4) {
			egressPolicies[*key] = *val
		})

	// Start with the assumption that all the entries currently present in the
	// BPF map are stale. Then as we walk the entries below and discover which
	// entries are actually still needed, shrink this set down.
	stale := sets.KeySet(egressPolicies)

	addEgressRule := func(endpoint *endpointMetadata, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) {
		activeGatewayIPs, egressIP, egressIfindex := gwc.gatewayConfigForEndpoint(manager, endpoint)
		if excludedCIDR {
			activeGatewayIPs = []netip.Addr{ExcludedCIDRIPv4}
		}

		for _, endpointIP := range endpoint.ips {
			policyKey := egressmapha.NewEgressPolicyV2Key4(endpointIP, dstCIDR)

			// This key needs to be present in the BPF map, hence remove it from
			// the list of stale ones.
			stale.Delete(policyKey)

			policyVal, policyPresent := egressPolicies[policyKey]
			if policyPresent && policyVal.Match(egressIP, activeGatewayIPs, egressIfindex) {
				return
			}

			if err := egressmapha.ApplyEgressPolicyV2(manager.policyMapV2, endpointIP, dstCIDR, egressIP, activeGatewayIPs, egressIfindex); err != nil {
				manager.logger.Error(
					"Error applying egress gateway policy",
					logfields.Error, err,
					logfields.SourceIP, endpointIP,
					logfields.DestinationCIDR, dstCIDR,
					logfields.EgressIP, egressIP,
					logfields.GatewayIPs, joinStringers(activeGatewayIPs, ","),
					logfields.LinkIndex, egressIfindex,
				)
			} else if manager.logger.Enabled(context.Background(), slog.LevelDebug) {
				manager.logger.Debug(
					"Egress gateway policy applied",
					logfields.SourceIP, endpointIP,
					logfields.DestinationCIDR, dstCIDR,
					logfields.EgressIP, egressIP,
					logfields.GatewayIPs, joinStringers(activeGatewayIPs, ","),
					logfields.LinkIndex, egressIfindex,
				)
			}
		}
	}

	for policyConfig := range manager.policyConfigsTable.All(tx) {
		policyConfig.forEachEndpointAndCIDR(addEgressRule)
	}

	// Remove all the entries still marked as stale.
	for policyKey := range stale {
		if err := egressmapha.RemoveEgressPolicyV2(manager.policyMapV2, policyKey.GetSourceIP(), policyKey.GetDestCIDR()); err != nil {
			manager.logger.Error(
				"Error removing egress gateway policy",
				logfields.Error, err,
				logfields.SourceIP, policyKey.GetSourceIP(),
				logfields.DestinationCIDR, policyKey.GetDestCIDR(),
			)
		} else if manager.logger.Enabled(context.Background(), slog.LevelDebug) {
			manager.logger.Debug(
				"Egress gateway policy removed",
				logfields.Error, err,
				logfields.SourceIP, policyKey.GetSourceIP(),
				logfields.DestinationCIDR, policyKey.GetDestCIDR(),
			)
		}
	}
}

func anonymizeCtKey(ctKey egressmapha.EgressCtKey4) tuple.TupleKey4 {
	// Note: We use ctmap tuple keys as a convenient lookup key format when
	// scanning for socket connections to be terminated.
	// We don't want to lookup against the flags value so we zero that out.
	tkey := *ctKey.ToHost().(*tuple.TupleKey4)
	return tuple.TupleKey4{
		SourceAddr: tkey.SourceAddr,
		SourcePort: tkey.SourcePort,
		DestAddr:   tkey.DestAddr,
		DestPort:   tkey.DestPort,
		NextHeader: tkey.NextHeader,
	}
}

func (manager *Manager) removeExpiredCtEntries(tx statedb.ReadTxn) error {
	ctEntries := map[egressmapha.EgressCtKey4]egressmapha.EgressCtVal4{}
	manager.ctMap.IterateWithCallback(
		func(key *egressmapha.EgressCtKey4, val *egressmapha.EgressCtVal4) {
			ctEntries[*key] = *val
		})

	policyMatchesCtEntry := func(policy AgentPolicyConfig, ctKey *egressmapha.EgressCtKey4, ctVal *egressmapha.EgressCtVal4) bool {
		gatewayIP := ctVal.Gateway.Addr()

	nextDstCIDR:
		for _, dstCIDR := range policy.dstCIDRs {
			if !dstCIDR.Contains(ctKey.DestAddr.Addr()) {
				continue
			}

			for _, excludedCIDR := range policy.excludedCIDRs {
				if excludedCIDR.Contains(ctKey.DestAddr.Addr()) {
					continue nextDstCIDR
				}
			}

			// no need to check also endpointIP.Equal(endpointIP) as we are iterating
			// over the slice of policies returned by the
			// policyConfigsBySourceIP[ipRule.Src.IP.String()] map
			if slices.Contains(policy.gatewayConfig.healthyGatewayIPs, gatewayIP) {
				return true
			}
		}

		return false
	}

	toClose := sets.New[tuple.TupleKey4]()
	toDelete := map[egressmapha.EgressCtKey4]egressmapha.EgressCtVal4{}
	for ctKey, ctVal := range ctEntries {
		var hasMatch bool
		// For policy matching the Endpoint source IP of our ctKey, iterate all of the groupStatuses
		// and see if there is any healthGatewayIPs that match the tracked GW IP.
		// If not, then this indicates that the GW IP has been removed so we can try to do socket
		// destruction (if enabled).
		// If a matching policy is not found, we do not do a CT entry delete as we want to keep those
		// around until the connection is terminated.
		//
		// If egressgateway-ha enable-egressgatewayha-socket-destroy is enabled we will try to force
		// this to happen by closing the local client socket via netlink.
	policyMatches:
		for policyConfig := range manager.policyConfigsTable.List(tx, ByEndpointSourceIP.Query(ctKey.SourceAddr.Addr().String())) {
			if hasMatch = policyMatchesCtEntry(policyConfig, &ctKey, &ctVal); hasMatch {
				break policyMatches
			}
		}

		if manager.config.EnableEgressGatewayHASocketTermination && !hasMatch {
			// We only terminate tcp or udp connections.
			if ctKey.NextHeader == u8proto.TCP || ctKey.NextHeader == u8proto.UDP {
				// If no healthy gateway addr was found in matching policies for ctKey we can attempt to
				// terminate the client connection.
				// Note: In this case foundMatchingPolicy is implied to be true.
				manager.logger.Debug(
					"tracked socket connection with unavailable gateway to be closed",
					logfields.SourceIP, ctKey.SourceAddr,
					logfields.SourcePort, ctKey.SourcePort,
					logfields.DestinationIP, ctKey.DestAddr,
					logfields.DestinationPort, ctKey.DestPort,
					logfields.GatewayIP, ctVal.Gateway,
				)
				toClose.Insert(anonymizeCtKey(ctKey))
			}
		}

		// CT tuples that do *not* match any policy + healthyGateway IP are marked for removal.
		if !hasMatch {
			toDelete[ctKey] = ctVal
		}
	}

	if manager.config.EnableEgressGatewayHASocketTermination {
		// At this point, removed health gw IPs would already be removed from policies,
		// so we can safely try terminate socket connections related to terminated GW nodes.
		stats, err := manager.socketsActions.closeSockets(toClose)

		h := manager.health.NewScope("socket-termination")
		if err != nil {
			manager.logger.Error("failed to close sockets to unavailable gateways", logfields.Error, err)
			h.Degraded("failed to close sockets to unavailable gateways", err)
		} else {
			h.OK("closed sockets to expired gateways")
		}
		if stats.deleted+stats.failed+stats.skipped > 0 {
			manager.logger.Info(
				"closed sockets to expired gateways",
				logfields.Deleted, stats.deleted,
				logfields.Failed, stats.failed,
				logfields.Skipped, stats.skipped,
			)
		}
	}

	// When a TCP socket is closed via the sock diag netlink command, a socket in most states
	// (i.e. syn/rec, etc) will send a rst packet to the upstream server.
	// In the case that the node is being drained gracefully, it is likely that the pinned
	// gateway node for which the healthGatewayIP was removed still exists and will still forward
	// traffic - so we want this rst to go out to allow for upstream server to gracefully close
	// its connection.
	// Therefore, we prefer to remove ctmap entries following socket terminations to allow for
	// this to happen.
	for ctKey, ctVal := range toDelete {
		logger := manager.logger.With(
			// TODO log the whole ctKey
			logfields.SourceIP, ctKey.SourceAddr.Addr(),
			logfields.GatewayIP, ctVal.Gateway.Addr(),
		)

		if err := manager.ctMap.Delete(&ctKey); err != nil {
			logger.Error("Error removing egress gateway CT entry", logfields.Error, err)
		} else {
			logger.Debug("Egress gateway CT entry removed")
		}
	}
	return nil
}

func (manager *Manager) finishInitializer(initializer func(txn statedb.WriteTxn)) {
	txn := manager.db.WriteTxn(manager.egressIPTable)
	initializer(txn)
	txn.Commit()
	// This works around a StateDB bug (see https://github.com/cilium/statedb/pull/47)
	// where the reconciler does not fire on an empty (but initialized) table.
	if initialized, _ := manager.egressIPTable.Initialized(manager.db.ReadTxn()); initialized {
		manager.logger.Debug("Pruning IPAM related rules and routes")
		manager.egressIPReconciler.Prune()
	}
}

// reconcileLocked is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileLocked() {
	if !manager.allCachesSynced {
		return
	}

	tx := manager.db.WriteTxn(manager.policyConfigsTable)

	// on eventK8sSyncDone we need to update all caches unconditionally as
	// we don't know which k8s events/resources were received during the
	// initial k8s sync
	if manager.eventBitmapIsSet(eventK8sSyncDone) {
		manager.updatePoliciesMatchedEndpointIDs(tx)
		manager.updateNodesByIP()
	} else {
		if manager.eventBitmapIsSet(eventUpdateEndpoint, eventDeleteEndpoint) {
			manager.updatePoliciesMatchedEndpointIDs(tx)
		}

		if manager.eventBitmapIsSet(eventUpdateNode, eventDeleteNode) {
			manager.updateNodesByIP()
		}
	}

	manager.removeStaleEgressIPConfigs(tx)

	if manager.eventBitmapIsSet(eventK8sSyncDone, eventAddPolicy, eventDeletePolicy, eventUpdateNode, eventDeleteNode) {
		manager.regenerateGatewayConfigs(tx)

		if manager.eventBitmapIsSet(eventK8sSyncDone) {
			// All caches have been synced and the first gateway configs regeneration took place.
			// Now it is safe to start pruning IPAM-related routing policy rules and routes that
			// do not appear in the egress-ips stateDB table.
			manager.finishInitializer(manager.policyInitializer)
		}

		// Sysctl updates are handled by a reconciler, with the initial update attempting to wait some time
		// for a synchronous reconciliation. Thus these updates are already resilient so in case of failure
		// our best course of action is to log the error and continue with the reconciliation.
		//
		// The rp_filter setting is only important for traffic originating from endpoints on the same host (i.e.
		// egw traffic being forwarded from a local Pod endpoint to the gateway on the same node).
		// Therefore, for the sake of resiliency, it is acceptable for EGW to continue reconciling gatewayConfigs
		// even if the rp_filter setting are failing.
		if err := manager.relaxRPFilter(tx); err != nil {
			manager.logger.Error("Error relaxing rp_filter for gateway interfaces. "+
				"Selected egress gateway interfaces require rp_filter settings to use loose mode (rp_filter=2) for gateway forwarding to work correctly. "+
				"This may cause connectivity issues for egress gateway traffic being forwarded through this node for Pods running on the same host. ",
				logfields.Error, err,
			)
		}
	}

	// Update the content of the BPF map.
	manager.updateEgressRulesV2(tx)

	// clear the events bitmap
	manager.eventsBitmap = 0

	// Remove stale CT entries. We keep entries that point at an inactive Gateway node,
	// as long as the node is healthy.
	manager.removeExpiredCtEntries(tx)

	// Signal the BGP Control Plane
	manager.bgpSignaler.Event(struct{}{})

	manager.reconciliationEventsCount.Add(1)

	tx.Commit()
}

// AdvertisedEgressIPs returns a map of policy to egress IPs, used by EGW polices selected by the provided policy selector,
// that should be advertised for this node as currently used egress IPs.
func (manager *Manager) AdvertisedEgressIPs(policySelector *slimv1.LabelSelector) (map[types.NamespacedName][]netip.Addr, error) {
	manager.Lock()
	defer manager.Unlock()

	selector, err := slimv1.LabelSelectorAsSelector(policySelector)
	if err != nil {
		return nil, err
	}

	egressIPs := make(map[types.NamespacedName][]netip.Addr)
	for policyConfig := range manager.policyConfigsTable.All(manager.db.ReadTxn()) {
		gwc := policyConfig.gatewayConfig
		if gwc == nil {
			continue
		}
		if gwc.localNodeConfiguredAsGateway && selector.Matches(k8sLabels.Set(policyConfig.labels)) {
			egressIPs[policyConfig.id] = append(egressIPs[policyConfig.id], gwc.egressIP)
		}
	}
	return egressIPs, nil
}

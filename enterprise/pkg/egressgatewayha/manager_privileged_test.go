// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	ent_tables "github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/tuple"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type EgressGatewayTestSuite struct {
	manager     *Manager
	policies    fakeResource[*Policy]
	endpoints   fakeResource[*k8sTypes.CiliumEndpoint]
	ciliumNodes fakeResource[*cilium_api_v2.CiliumNode]
	sysctl      sysctl.Sysctl

	reconciliationEventsCount uint64
}

type mockReconciler struct{}

func (m *mockReconciler) Prune() {}

func (m *mockReconciler) WaitUntilReconciled(_ context.Context, untilRevision statedb.Revision) (revision statedb.Revision, retryLowWatermark statedb.Revision, err error) {
	return untilRevision, 0, nil
}

// For testing we override the agent's ifindex resolver, so that we can validate
// the ifindex even when using dummy devices for testing.
func mockEgressIfindexForIface(ifaceIndex int, ifaceType string) uint32 {
	return uint32(ifaceIndex)
}

func setupEgressGatewayTestSuite(t *testing.T) *EgressGatewayTestSuite {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	bpf.CheckOrMountFS(log, "")
	require.NoError(t, rlimit.RemoveMemlock())

	k := &EgressGatewayTestSuite{}
	k.policies = make(fakeResource[*Policy])
	k.endpoints = make(fakeResource[*k8sTypes.CiliumEndpoint])
	k.ciliumNodes = make(fakeResource[*cilium_api_v2.CiliumNode])
	k.sysctl = sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	lc := hivetest.Lifecycle(t)
	policyMapV2 := egressmapha.CreatePrivatePolicyMapV2(lc, nil, egressmapha.DefaultPolicyConfig)
	ctMap := egressmapha.CreatePrivateCtMap(lc, log)

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{
		Node: nodeTypes.Node{
			Name:   node1Name,
			Labels: nodeGroup1LabelsAZ1,
			IPAddresses: []nodeTypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP(node1IP)},
			},
		},
	})

	var (
		db            *statedb.DB
		egressIPTable statedb.RWTable[*ent_tables.EgressIPEntry]
		r             reconciler.Reconciler[*ent_tables.EgressIPEntry]
		policyTable   statedb.RWTable[AgentPolicyConfig]
		deviceTable   statedb.Table[*tables.Device]
	)

	// create a hive to provide statedb, egress-ips table and a mock reconcile
	h := hive.New(
		cell.Provide(newAgentTables),
		cell.Provide(
			tables.NewDeviceTable,
			ent_tables.NewEgressIPTable,
			func() reconciler.Reconciler[*ent_tables.EgressIPEntry] {
				return &mockReconciler{}
			},
		),

		cell.Invoke(func(db_ *statedb.DB,
			pt statedb.RWTable[AgentPolicyConfig],
			table statedb.RWTable[*ent_tables.EgressIPEntry],
			dT statedb.RWTable[*tables.Device],
			reconciler reconciler.Reconciler[*ent_tables.EgressIPEntry]) {
			db = db_
			egressIPTable = table
			r = reconciler
			deviceTable = dT
			policyTable = pt
		}),
	)

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, context.TODO()))

	t.Cleanup(func() {
		require.NoError(t, h.Stop(tlog, context.TODO()))
	})

	health, _ := cell.NewSimpleHealth()

	manager, err := newEgressGatewayManager(Params{
		Logger:    hivetest.Logger(t),
		Lifecycle: lc,
		Config: Config{
			EgressGatewayHAReconciliationTriggerInterval: time.Millisecond,
			EnableEgressGatewayHASocketTermination:       false,
		},
		DaemonConfig:       &option.DaemonConfig{},
		IdentityAllocator:  identityAllocator,
		PolicyMapV2:        policyMapV2,
		CtMap:              ctMap,
		Policies:           k.policies,
		Endpoints:          k.endpoints,
		Nodes:              k.ciliumNodes,
		LocalNodeStore:     localNodeStore,
		BGPSignaler:        signaler.NewBGPCPSignaler(),
		Sysctl:             k.sysctl,
		DB:                 db,
		EgressIPTable:      egressIPTable,
		EgressIPReconciler: r,
		DeviceTable:        deviceTable,
		CTNATMapGC:         ctmap.NewFakeGCRunner(),
		Health:             health,
		PolicyConfigsTable: policyTable,
		IfindexResolver:    mockEgressIfindexForIface,
	})
	require.NoError(t, err)
	require.NotNil(t, manager)

	k.manager = manager

	k.reconciliationEventsCount = k.manager.reconciliationEventsCount.Load()

	createTestInterface(t, k.sysctl, testInterface1, egressCIDR1)
	createTestInterface(t, k.sysctl, testInterface2, egressCIDR2)

	k.policies.sync(t)
	k.endpoints.sync(t)
	k.ciliumNodes.sync(t)

	k.waitForReconciliationRun(t)

	return k
}

func createTestInterface(tb testing.TB, sysctl sysctl.Sysctl, iface string, addr string) {
	tb.Helper()

	la := netlink.NewLinkAttrs()
	la.Name = iface
	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		tb.Fatal(err)
	}

	link, err := safenetlink.LinkByName(iface)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		if err := netlink.LinkDel(link); err != nil {
			tb.Error(err)
		}
	})

	if err := netlink.LinkSetUp(link); err != nil {
		tb.Fatal(err)
	}

	a, _ := netlink.ParseAddr(addr)
	if err := netlink.AddrAdd(link, a); err != nil {
		tb.Fatal(err)
	}

	ensureRPFilterIsEnabled(tb, sysctl, iface)
}

func ensureRPFilterIsEnabled(tb testing.TB, sysctl sysctl.Sysctl, iface string) {
	rpFilterSetting := []string{"net", "ipv4", "conf", iface, "rp_filter"}

	for range 10 {
		if err := sysctl.Enable(rpFilterSetting); err != nil {
			tb.Fatal(err)
		}

		time.Sleep(100 * time.Millisecond)

		if val, err := sysctl.Read(rpFilterSetting); err == nil {
			if val == "1" {
				return
			}
		}
	}

	tb.Fatal("failed to enable rp_filter")
}

func (k *EgressGatewayTestSuite) waitForReconciliationRun(t *testing.T) {
	for range 200 {
		count := k.manager.reconciliationEventsCount.Load()
		if count > k.reconciliationEventsCount {
			k.reconciliationEventsCount = count
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("Reconciliation is taking too long to run")
}

func filter(slice []string, x string) []string {
	oldSlice := slice

	slice = []string{}
	for _, oldEntry := range oldSlice {
		if oldEntry != x {
			slice = append(slice, oldEntry)
		}
	}

	return slice
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func (k *EgressGatewayTestSuite) addNode(t *testing.T, name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	node := newCiliumNode(name, nodeIP, nodeLabels)
	addNode(t, nil, k.ciliumNodes, node, nil)
	k.waitForReconciliationRun(t)

	return node
}

func (k *EgressGatewayTestSuite) addPolicy(t *testing.T, policy *policyParams) *policyParams {
	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)

	return policy
}

func (k *EgressGatewayTestSuite) addHealthyGatewayToEgressGroup(t *testing.T, policy *policyParams, gwIP string, group int) {
	require.True(t, 0 <= group && group < len(policy.egressGroups))
	target := &policy.egressGroups[group]

	target.healthyGatewayIPs = unique(append(target.activeGatewayIPs, gwIP))

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) addActiveGatewayToEgressGroup(t *testing.T, policy *policyParams, gwIP, az string, group int) {
	require.True(t, 0 <= group && group < len(policy.egressGroups))
	target := &policy.egressGroups[group]

	target.activeGatewayIPs = unique(append(target.activeGatewayIPs, gwIP))
	target.healthyGatewayIPs = unique(append(target.healthyGatewayIPs, gwIP))

	if az != "" {
		target.activeGatewayIPsByAZ[az] = unique(append(target.activeGatewayIPsByAZ[az], gwIP))
	}

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) removeHealthyGatewayFromEgressGroup(t *testing.T, policy *policyParams, gwIP string, group int) {
	require.True(t, 0 <= group && group < len(policy.egressGroups))
	target := &policy.egressGroups[group]

	target.activeGatewayIPs = filter(target.activeGatewayIPs, gwIP)
	target.healthyGatewayIPs = filter(target.healthyGatewayIPs, gwIP)

	for az := range target.activeGatewayIPsByAZ {
		target.activeGatewayIPsByAZ[az] = filter(target.activeGatewayIPsByAZ[az], gwIP)
	}

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) removeActiveGatewayFromEgressGroup(t *testing.T, policy *policyParams, gwIP string, group int) {
	require.True(t, 0 <= group && group < len(policy.egressGroups))
	target := &policy.egressGroups[group]

	target.activeGatewayIPs = filter(target.activeGatewayIPs, gwIP)

	for az := range target.activeGatewayIPsByAZ {
		target.activeGatewayIPsByAZ[az] = filter(target.activeGatewayIPsByAZ[az], gwIP)
	}

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) addExcludedCIDR(t *testing.T, policy *policyParams, excludedCIDR string) {
	policy.excludedCIDRs = unique(append(policy.excludedCIDRs, excludedCIDR))

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) removeExcludedCIDR(t *testing.T, policy *policyParams, excludedCIDR string) {
	policy.excludedCIDRs = filter(policy.excludedCIDRs, excludedCIDR)

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) updatePolicyLabels(t *testing.T, policy *policyParams, labels map[string]string) {
	policy.labels = labels

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) addEndpoint(t *testing.T, name, ip string, epLabels map[string]string, nodeIP string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	ep, id := newEndpointAndIdentity(name, ip, epLabels, nodeIP)
	addEndpoint(t, k.endpoints, &ep)
	k.waitForReconciliationRun(t)

	return ep, id
}

func (k *EgressGatewayTestSuite) updateEndpointLabels(t *testing.T, ep *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabels map[string]string) *identity.Identity {
	id := updateEndpointAndIdentity(ep, oldID, newEpLabels)
	addEndpoint(t, k.endpoints, ep)
	k.waitForReconciliationRun(t)

	return id
}

type egressRule struct {
	sourceIP      string
	destCIDR      string
	egressIP      string
	gatewayIP     string
	egressIfindex uint32
}

type parsedEgressRule struct {
	sourceIP      netip.Addr
	destCIDR      netip.Prefix
	egressIP      netip.Addr
	gatewayIP     netip.Addr
	egressIfindex uint32
}

type rpFilterSetting struct {
	iFaceName       string
	rpFilterSetting string
}

func parseEgressRule(sourceIP, destCIDR, egressIP, gatewayIP string, egressIfindex uint32) parsedEgressRule {
	sip := netip.MustParseAddr(sourceIP)
	dc := netip.MustParsePrefix(destCIDR)
	eip := netip.MustParseAddr(egressIP)
	gip := netip.MustParseAddr(gatewayIP)

	return parsedEgressRule{
		sourceIP:      sip,
		destCIDR:      dc,
		egressIP:      eip,
		gatewayIP:     gip,
		egressIfindex: egressIfindex,
	}
}

func (k *EgressGatewayTestSuite) assertEgressRules(t *testing.T, rules []egressRule) {
	t.Helper()

	err := tryAssertEgressRulesV2(k.manager.policyMapV2, rules)
	require.NoError(t, err)
}

func tryAssertEgressRulesV2(policyMap egressmapha.PolicyMapV2, rules []egressRule) error {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP, r.egressIfindex))
	}

	for _, r := range parsedRules {
		policyVal, err := policyMap.Lookup(r.sourceIP, r.destCIDR)
		if err != nil {
			return fmt.Errorf("cannot lookup policy entry: %w", err)
		}

		if policyVal.GetEgressIP() != r.egressIP {
			return fmt.Errorf("policy egress IP %s doesn't match rule egress IP %s", policyVal.GetEgressIP(), r.egressIP)
		}

		if policyVal.EgressIfindex != r.egressIfindex {
			return fmt.Errorf("policy egress ifindex %d doesn't match rule egress ifindex %d", policyVal.EgressIfindex, r.egressIfindex)
		}

		if r.gatewayIP == netip.IPv4Unspecified() {
			if policyVal.Size != 0 {
				return fmt.Errorf("policy size is %d even though no gateway is set", policyVal.Size)
			}
		} else {
			gwFound := false
			for policyGatewayIP := range policyVal.GetGatewayIPs() {
				if policyGatewayIP == r.gatewayIP {
					gwFound = true
					break
				}
			}
			if !gwFound {
				return fmt.Errorf("missing gateway %s in policy", r.gatewayIP)
			}
		}
	}

	untrackedRule := false
	policyMap.IterateWithCallback(
		func(key *egressmapha.EgressPolicyV2Key4, val *egressmapha.EgressPolicyV2Val4) {
		nextPolicyGateway:
			for gatewayIP := range val.GetGatewayIPs() {
				for _, r := range parsedRules {
					if key.Match(r.sourceIP, r.destCIDR) {
						if val.GetEgressIP() == r.egressIP && gatewayIP == r.gatewayIP {
							continue nextPolicyGateway
						}
					}
				}

				untrackedRule = true
				return
			}
		},
	)

	if untrackedRule {
		return fmt.Errorf("Untracked egress policy")
	}

	return nil
}

func assertRPFilter(t *testing.T, sysctl sysctl.Sysctl, rpFilterSettings []rpFilterSetting) {
	t.Helper()

	err := tryAssertRPFilterSettings(sysctl, rpFilterSettings)
	require.NoError(t, err)
}

func tryAssertRPFilterSettings(sysctl sysctl.Sysctl, rpFilterSettings []rpFilterSetting) error {
	for _, setting := range rpFilterSettings {
		if val, err := sysctl.Read([]string{"net", "ipv4", "conf", setting.iFaceName, "rp_filter"}); err != nil {
			return fmt.Errorf("failed to read rp_filter")
		} else if val != setting.rpFilterSetting {
			return fmt.Errorf("mismatched rp_filter iface: %s rp_filter: %s", setting.iFaceName, val)
		}
	}

	return nil
}

type egressCtEntry struct {
	sourceIP             string
	destIP               string
	gatewayIP            string
	sourcePort, destPort uint16
}

type parsedEgressCtEntry struct {
	sourceIP             netip.Addr
	destIP               netip.Addr
	gatewayIP            netip.Addr
	sourcePort, destPort uint16
}

func parseEgressCtEntry(sourceIP, destIP, gatewayIP string) parsedEgressCtEntry {
	sip := netip.MustParseAddr(sourceIP)
	dip := netip.MustParseAddr(destIP)
	gip := netip.MustParseAddr(gatewayIP)

	return parsedEgressCtEntry{
		sourceIP:  sip,
		destIP:    dip,
		gatewayIP: gip,
	}
}

func (k *EgressGatewayTestSuite) insertEgressCtEntry(t *testing.T, sourceIP, destIP, gatewayIP string) {
	k.insertEgressCtEntryWithPorts(t, sourceIP, destIP, gatewayIP, 0, 0)
}

func (k *EgressGatewayTestSuite) insertEgressCtEntryWithPorts(t *testing.T, sourceIP, destIP, gatewayIP string, srcPort, dstPort uint16) {
	entry := parseEgressCtEntry(sourceIP, destIP, gatewayIP)

	key := &egressmapha.EgressCtKey4{
		TupleKey4: tuple.TupleKey4{
			DestPort:   dstPort,
			SourcePort: srcPort,
			NextHeader: u8proto.TCP,
			Flags:      0,
		},
	}

	key.DestAddr.FromAddr(entry.destIP)
	key.SourceAddr.FromAddr(entry.sourceIP)

	val := &egressmapha.EgressCtVal4{}
	val.Gateway.FromAddr(entry.gatewayIP)

	err := k.manager.ctMap.Update(key, val, 0)
	require.NoError(t, err)
}

func (k *EgressGatewayTestSuite) assertEgressCtEntries(tb testing.TB, entries []egressCtEntry) {
	tb.Helper()

	err := tryAssertEgressCtEntries(k.manager.ctMap, entries)
	require.NoError(tb, err)
}

func tryAssertEgressCtEntries(ctMap egressmapha.CtMap, entries []egressCtEntry) error {
	parsedEntries := []parsedEgressCtEntry{}
	for _, e := range entries {
		pe := parseEgressCtEntry(e.sourceIP, e.destIP, e.gatewayIP)
		pe.sourcePort = e.sourcePort
		pe.destPort = e.destPort
		parsedEntries = append(parsedEntries, pe)
	}

	for _, e := range parsedEntries {
		var val egressmapha.EgressCtVal4

		key := &egressmapha.EgressCtKey4{
			TupleKey4: tuple.TupleKey4{
				DestPort:   e.destPort,
				SourcePort: e.sourcePort,
				NextHeader: u8proto.TCP,
				Flags:      0,
			},
		}

		key.DestAddr.FromAddr(e.destIP)
		key.SourceAddr.FromAddr(e.sourceIP)

		err := ctMap.Lookup(key, &val)
		if err != nil {
			return fmt.Errorf("ctmap lookup of %s %s: %w", key, val, err)
		}

		if val.Gateway.Addr() != e.gatewayIP {
			return fmt.Errorf("%v doesn't match %v", val.Gateway.Addr(), e.gatewayIP)
		}
	}

	var err error
	ctMap.IterateWithCallback(
		func(key *egressmapha.EgressCtKey4, val *egressmapha.EgressCtVal4) {
			for _, e := range parsedEntries {
				if key.DestAddr.Addr() == e.destIP && key.SourceAddr.Addr() == e.sourceIP && val.Gateway.Addr() == e.gatewayIP {
					return
				}
			}

			err = fmt.Errorf("untracked egress CT entry: from %v to %v via %v", key.SourceAddr.Addr(), key.DestAddr.Addr(), val.Gateway.Addr())
		})

	return err
}

// assertBGPSignal asserts whether BGP CP reconciliation signal has been sent.
func (k *EgressGatewayTestSuite) assertBGPSignal(tb testing.TB, egressGatewayManager *Manager) {
	tb.Helper()

	select {
	case _, ok := <-egressGatewayManager.bgpSignaler.Sig:
		if !ok {
			tb.Fatal("BGP Signal channel closed")
		}
	default:
		tb.Fatal("BGP signal not received")
	}
}

// assertAdvertisedEgressIPs asserts whether the list of advertised gateway IPs matches the provided list.
func (k *EgressGatewayTestSuite) assertAdvertisedEgressIPs(tb testing.TB, egressGatewayManager *Manager, policySelector *slimv1.LabelSelector, expectedPolicyIPs map[types.NamespacedName][]string) {
	tb.Helper()

	egwPolicyIPs, err := egressGatewayManager.AdvertisedEgressIPs(policySelector)
	require.NoError(tb, err)

	// comparing maps, as the order of the IPs in the slice is not guaranteed
	require.Len(tb, egwPolicyIPs, len(expectedPolicyIPs))
	for policyNSName, ips := range expectedPolicyIPs {
		egwIPs := egwPolicyIPs[policyNSName]
		var egwIPsStr []string
		for _, ip := range egwIPs {
			egwIPsStr = append(egwIPsStr, ip.String())
		}
		require.ElementsMatch(tb, ips, egwIPsStr)
	}
}

func TestEgressGatewayIEGPParser(t *testing.T) {
	// must specify name
	policy := policyParams{
		name:             "",
		destinationCIDRs: []string{destCIDR},
		egressGroups:     []egressGroupParams{{iface: testInterface1}},
	}

	logger := hivetest.Logger(t)

	iegp, _ := newIEGP(&policy)
	_, err := ParseIEGP(logger, iegp)
	require.Error(t, err)

	// catch nil DestinationCIDR field
	policy = policyParams{
		name:         "policy-1",
		egressGroups: []egressGroupParams{{iface: testInterface1}},
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.DestinationCIDRs = nil
	_, err = ParseIEGP(logger, iegp)
	require.Error(t, err)
	// must specify at least one DestinationCIDR
	policy = policyParams{
		name:         "policy-1",
		egressGroups: []egressGroupParams{{iface: testInterface1}},
	}

	iegp, _ = newIEGP(&policy)
	_, err = ParseIEGP(logger, iegp)
	require.Error(t, err)

	// catch nil EgressGateway field
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
		egressGroups:     []egressGroupParams{{iface: testInterface1}},
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.EgressGroups = nil
	_, err = ParseIEGP(logger, iegp)
	require.Error(t, err)

	// must specify some sort of endpoint selector
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
		egressGroups:     []egressGroupParams{{iface: testInterface1}},
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.Selectors[0].NamespaceSelector = nil
	iegp.Spec.Selectors[0].PodSelector = nil
	_, err = ParseIEGP(logger, iegp)
	require.Error(t, err)

	// can't specify both egress iface and IP
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
		egressGroups:     []egressGroupParams{{iface: testInterface1, egressIP: egressIP1}},
	}

	iegp, _ = newIEGP(&policy)
	_, err = ParseIEGP(logger, iegp)
	require.Error(t, err)
}

type fakeSockets struct {
	toClose sets.Set[tuple.TupleKey4]
}

func (s *fakeSockets) closeSockets(toClose sets.Set[tuple.TupleKey4]) (socketCloseStats, error) {
	s.toClose = toClose
	return socketCloseStats{deleted: len(toClose)}, nil
}

// TestPrivilegedRemoveExpiredCTOnNoMatchingPolicies tests egwha-ct expired entry
// removal.
func TestPrivilegedRemoveExpiredCTOnNoMatchingPolicies(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)
	k.manager.config.EnableEgressGatewayHASocketTermination = true
	sm := &fakeSockets{}
	k.manager.socketsActions = sm

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	// 1. Add egress ct entry that is not matched or keyed on any policy.
	k.insertEgressCtEntryWithPorts(t, ep2IP, "1.1.4.127", node2IP, 0xdead, 0xbeef)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	// Note: k.addPolicy kicks off a reconciliation so we expect to see
	// 	a ct entry purge.
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	// 2. Our initial ct-entry was keyed on no policies, so there should have
	// 	been no policy matching check. Regardless, we assert that ct entries
	// 	that do not match *any* policy on sourceIP (i.e. in this case ep2IP)
	// 	are still removed.
	//	This is to prevent regression on the subtleties between:
	//	a) policy-by-source-ip matches source IP and there are *some*
	//		policies to evaluate further.
	//	b) policy-by-source-ip matches *no* source IP (i.e. empty list) and
	//		there are no policies to evaluate further.
	//	Both should have the same outcome of ctentry removal.
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Create a new HA policy that selects k8s1 and k8s2 nodes.
	// This will overlap on source IP on policy1.
	k.addPolicy(t, &policyParams{
		name:             "policy-2",
		uid:              policy2UID,
		endpointLabels:   ep1Labels, // same a p1.
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	assertRPFilter(t, k.sysctl, []rpFilterSetting{
		{iFaceName: testInterface1, rpFilterSetting: "2"},
		{iFaceName: testInterface2, rpFilterSetting: "1"},
	})

	k.assertEgressRules(t, []egressRule{})
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add a new endpoint which matches policy-1
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Note: Port values will come out as swapped byte order (0xadde and 0xefbe).
	// This is matched by a policy, and node1IP
	k.insertEgressCtEntryWithPorts(t, ep1IP, "1.1.1.127", node2IP, 0xdead, 0xbeef)

	k.assertEgressCtEntries(t, []egressCtEntry{
		{sourceIP: ep1IP, destIP: "1.1.1.127", gatewayIP: node2IP, sourcePort: 0xdead, destPort: 0xbeef},
	})

	// Here we test the scenario where egress ct entry is matched by two policies
	// We want to ensure that it is only removed if it is matched by *no* policies.
	// 3. By adding a exclude cidr for 1.1.1.127 on p1, we should see p1 no longer match.
	//	However, most importantly, policy 1 is still keyed by ep1IP as the source IP
	//	in lookup-by-source-up, thus there are two policies evaluated as matches.
	//	We ensure that it is only necessary for one to match, not both.
	k.addExcludedCIDR(t, policy1, "1.1.1.127/32")
	k.assertEgressCtEntries(t, []egressCtEntry{
		{sourceIP: ep1IP, destIP: "1.1.1.127", gatewayIP: node2IP, sourcePort: 0xdead, destPort: 0xbeef},
	})
}

// TestPrivilegedEgressGatewayManagerHASocketTermination tests the socket termination feature
// of the agent control plane manager.
// Specifically, this ensures that the socket manager is handed the correct set of
// connection tuples to possibly evict via client sockets.
func TestPrivilegedEgressGatewayManagerHASocketTermination(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)
	k.manager.config.EnableEgressGatewayHASocketTermination = true
	sm := &fakeSockets{}
	k.manager.socketsActions = sm

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	assertRPFilter(t, k.sysctl, []rpFilterSetting{
		{iFaceName: testInterface1, rpFilterSetting: "2"},
		{iFaceName: testInterface2, rpFilterSetting: "1"},
	})

	k.assertEgressRules(t, []egressRule{})
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add a new endpoint which matches policy-1
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Note: Port values will come out as swapped byte order (0xadde and 0xefbe).
	// This is matched by a policy, and node1IP
	k.insertEgressCtEntryWithPorts(t, ep1IP, "1.1.1.128", node1IP, 0xdead, 0xbeef)
	// Different pinned gateway IP.
	k.insertEgressCtEntryWithPorts(t, ep1IP, "1.1.1.127", node2IP, 0xdead, 0xbeef)

	k.assertEgressCtEntries(t, []egressCtEntry{
		{sourceIP: ep1IP, destIP: "1.1.1.128", gatewayIP: node1IP, sourcePort: 0xdead, destPort: 0xbeef},
		{sourceIP: ep1IP, destIP: "1.1.1.127", gatewayIP: node2IP, sourcePort: 0xdead, destPort: 0xbeef},
	})

	// Remove k8s1
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, node2IP, 0},
	})

	// First tuple will be removed because GW IP no longer exists
	k.assertEgressCtEntries(t, []egressCtEntry{
		{sourceIP: ep1IP, destIP: "1.1.1.127", gatewayIP: node2IP, sourcePort: 0xdead, destPort: 0xbeef},
	})

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.Contains(t, sm.toClose, tuple.TupleKey4{
			DestAddr:   ciliumTypes.IPv4{1, 1, 1, 128},
			SourceAddr: ciliumTypes.IPv4{10, 0, 0, 1},
			NextHeader: u8proto.TCP,
			SourcePort: 0xadde,
			DestPort:   0xefbe,
		})
		assert.Len(t, sm.toClose, 1)
	}, time.Second*5, time.Millisecond*500)

	// Re-add now gc'd ct entry
	k.insertEgressCtEntryWithPorts(t, ep1IP, "1.1.1.128", node1IP, 0xdead, 0xbeef)

	// GW Node is added back
	k.addHealthyGatewayToEgressGroup(t, policy1, node1IP, defaultEgressGroupID)

	// Newly added GW IP means that the connection tuple in the ct map is not
	// subject to client socket termination.
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.Empty(t, sm.toClose)
	}, time.Second*5, time.Millisecond*500)

	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.Contains(t, sm.toClose, tuple.TupleKey4{
			DestAddr:   ciliumTypes.IPv4{1, 1, 1, 127},
			SourceAddr: ciliumTypes.IPv4{10, 0, 0, 1},
			NextHeader: u8proto.TCP,
			SourcePort: 0xadde,
			DestPort:   0xefbe,
		})
		assert.Len(t, sm.toClose, 1)
	}, time.Second*5, time.Millisecond*500)

	k.removeHealthyGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.Contains(t, sm.toClose, tuple.TupleKey4{
			DestAddr:   ciliumTypes.IPv4{1, 1, 1, 128},
			SourceAddr: ciliumTypes.IPv4{10, 0, 0, 1},
			NextHeader: u8proto.TCP,
			SourcePort: 0xadde,
			DestPort:   0xefbe,
		})
		assert.Len(t, sm.toClose, 1)
	}, time.Second*5, time.Millisecond*500)
}

func TestPrivilegedEgressGatewayManagerAlternateIfaceName(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	if err := netlink.LinkAddAltName(link, testInterfaceAlternate1); err != nil {
		t.Fatal(err)
	}

	// Create a new HA policy that uses the alternate interface name
	_ = k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterfaceAlternate1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP},
			healthyGatewayIPs: []string{node1IP},
		}},
	})

	assertRPFilter(t, k.sysctl, []rpFilterSetting{
		{iFaceName: testInterface1, rpFilterSetting: "2"},
		{iFaceName: testInterface2, rpFilterSetting: "1"},
	})
	k.assertEgressRules(t, []egressRule{})

	// Add a new endpoint which matches policy-1
	_, _ = k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})
}

func TestPrivilegedEgressGatewayManagerHAGroup(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	link, err = safenetlink.LinkByName(testInterface2)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex2 := uint32(link.Attrs().Index)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	assertRPFilter(t, k.sysctl, []rpFilterSetting{
		{iFaceName: testInterface1, rpFilterSetting: "2"},
		{iFaceName: testInterface2, rpFilterSetting: "1"},
	})
	k.assertEgressRules(t, []egressRule{})

	// Add a new endpoint which matches policy-1
	ep1, id1 := k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Remove k8s1
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, node2IP, 0},
	})

	// Remove k8s2
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, zeroIP4, 0},
	})

	// Add back k8s1
	k.addActiveGatewayToEgressGroup(t, policy1, node1IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// Add back k8s2
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Remove k8s1 from the active GW list
	k.removeActiveGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	// It should retain egressIP1 as long as the k8s1(local node) is healthy
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Remove k8s2 from the healthy GW list
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)
	// It should retain egressIP1 even though no gateway is available
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, zeroIP4, ifIndex1},
	})

	// Remove k8s1 from healthy GW list
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, zeroIP4, 0},
	})

	// Add back k8s1
	k.addActiveGatewayToEgressGroup(t, policy1, node1IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// Add back k8s2
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Remove k8s2
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// Add back k8s2
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Update the EP labels in order for it to not be a match
	id1 = k.updateEndpointLabels(t, &ep1, id1, map[string]string{})
	k.assertEgressRules(t, []egressRule{})

	// Add back the endpoint
	id1 = k.updateEndpointLabels(t, &ep1, id1, ep1Labels)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Create a new HA policy that matches no nodes
	policy2 := k.addPolicy(t, &policyParams{
		name:             "policy-2",
		uid:              policy2UID,
		endpointLabels:   ep2Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups:     []egressGroupParams{{iface: testInterface2, nodeLabels: nodeGroup2Labels}},
	})

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Add k8s1 node to policy-2
	k.addActiveGatewayToEgressGroup(t, policy2, node1IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Add a new endpoint that matches policy-2
	ep2, id2 := k.addEndpoint(t, "ep-2", ep2IP, ep2Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
	})

	// Add also k8s2 to policy-2
	k.addActiveGatewayToEgressGroup(t, policy2, node2IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
		{ep2IP, destCIDR, egressIP2, node2IP, ifIndex2},
	})

	// Test excluded CIDRs by adding one to policy-1
	k.addExcludedCIDR(t, policy1, excludedCIDR1)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
		{ep2IP, destCIDR, egressIP2, node2IP, ifIndex2},
	})

	// Add a second excluded CIDR to policy-1
	k.addExcludedCIDR(t, policy1, excludedCIDR2)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue, ifIndex1},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
		{ep2IP, destCIDR, egressIP2, node2IP, ifIndex2},
	})

	// Remove the first excluded CIDR from policy-1
	k.removeExcludedCIDR(t, policy1, excludedCIDR1)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
		{ep2IP, destCIDR, egressIP2, node2IP, ifIndex2},
	})

	// Remove the second excluded CIDR
	k.removeExcludedCIDR(t, policy1, excludedCIDR2)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
		{ep2IP, destCIDR, egressIP2, node2IP, ifIndex2},
	})

	// Test a policy without valid egressIP
	k.addPolicy(t, &policyParams{
		name:             "policy-3",
		uid:              policy3UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR3},
		egressGroups: []egressGroupParams{{
			iface:             "no_interface",
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep1IP, destCIDR3, egressIPNotFoundValue, node1IP, 0},
		{ep1IP, destCIDR3, egressIPNotFoundValue, node2IP, 0},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
		{ep2IP, destCIDR, egressIP2, node2IP, ifIndex2},
	})

	// Update the EP 1 labels in order for it to not be a match
	k.updateEndpointLabels(t, &ep1, id1, map[string]string{})
	k.assertEgressRules(t, []egressRule{
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
		{ep2IP, destCIDR, egressIP2, node2IP, ifIndex2},
	})

	// Update the EP 2 labels in order for it to not be a match
	k.updateEndpointLabels(t, &ep2, id2, map[string]string{})
	k.assertEgressRules(t, []egressRule{})
}

func TestPrivilegedEgressGatewayManagerHAGroupAZAffinity(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ2)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		azAffinity:       azAffinityLocalOnly,
		egressGroups: []egressGroupParams{{
			iface:            testInterface1,
			nodeLabels:       nodeGroup1Labels,
			activeGatewayIPs: []string{node1IP, node2IP},
			activeGatewayIPsByAZ: map[string][]string{
				"az-1": {node1IP},
				"az-2": {node2IP},
			},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	k.assertEgressRules(t, []egressRule{})

	// Add a new endpoint on node-1 which matches policy-1
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// Add a new endpoint on node-2 which matches policy-1
	k.addEndpoint(t, "ep-2", ep2IP, ep1Labels, node2IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep2IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Remove k8s1
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, zeroIP4, 0},
		{ep2IP, destCIDR, zeroIP4, node2IP, 0},
	})

	// Add back node1
	k.addActiveGatewayToEgressGroup(t, policy1, node1IP, "az-1", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep2IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Remove k8s1 from the active GW list
	k.removeActiveGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	// It should retain egressIP1 as long as the k8s1(local node) is healthy
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, zeroIP4, ifIndex1},
		{ep2IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Remove k8s2 from the active GW list
	k.removeActiveGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, zeroIP4, ifIndex1},
		{ep2IP, destCIDR, egressIP1, zeroIP4, ifIndex1},
	})

	// Remove k8s2 from the healthy GW list
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, zeroIP4, ifIndex1},
		{ep2IP, destCIDR, egressIP1, zeroIP4, ifIndex1},
	})

	// Remove k8s1 from the healthy GW list
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, zeroIP4, 0},
		{ep2IP, destCIDR, zeroIP4, zeroIP4, 0},
	})

	// Add back node1
	k.addActiveGatewayToEgressGroup(t, policy1, node1IP, "az-1", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep2IP, destCIDR, egressIP1, zeroIP4, ifIndex1},
	})

	// Add back node2
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "az-2", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep2IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})
}

func TestPrivilegedEgressGatewayManagerCtEntries(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	// Create a new HA policy based on a group config
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	k.assertEgressRules(t, []egressRule{})
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add a new endpoint which matches 1
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)

	/* Scenario:
	 * 1. A gateway becomes unhealthy. Its CT entries should expire.
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP, 0, 0},
	})

	// Remove k8s2 from 1
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// CT entry is gone:
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add back k8s2 to policy-1
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "", defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. A gateway is no longer selected by the policy's labels.
	 *    Its CT entries should expire.
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP, 0, 0},
	})

	// Remove k8s2 from node-group-1
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// CT entry should now also be gone
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add back k8s2
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "", defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. De-activate a gateway that is used by an CT entry.
	 *    (the CT entry should not expire, as the gateway is healthy and still selected by labels)
	 * 2. Make the gateway unhealthy.
	 *    (the CT entry should now expire)
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP, 0, 0},
	})

	// Update the policy group config to allow at most 1 gateway at a time (k8s1)
	k.removeActiveGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// CT entry should still exist, as k8s2 is healthy
	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP, 0, 0},
	})

	// Make k8s2 unhealthy
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// CT entry should now also be gone
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Make k8s2 healthy again
	k.addHealthyGatewayToEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Update the policy group config to allow all gateways again
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "", defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. De-activate a gateway that is used by an CT entry.
	 *    (the CT entry should not expire, as the gateway is healthy and still selected by labels)
	 * 2. De-select the gateway from the policy
	 *    (the CT entry should now expire)
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP, 0, 0},
	})

	// Update the policy group config to allow at most 1 gateway at a time (k8s1)
	k.removeActiveGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// CT entry should still exist, as k8s2 is healthy
	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP, 0, 0},
	})

	// Remove k8s2 from node-group-1
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	// CT entry should now also be gone
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add back k8s2
	k.addHealthyGatewayToEgressGroup(t, policy1, node2IP, defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Update the policy group config to allow all gateways again
	k.addActiveGatewayToEgressGroup(t, policy1, node2IP, "", defaultEgressGroupID)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. A policy changes and a CT entry is now matched by an excluded CIDR
	 *    (the CT entry should now expire)
	 */
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP, 0, 0},
	})

	// Add the destination IP to the policy excluded CIDRs list
	k.addExcludedCIDR(t, policy1, excludedCIDR3)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep1IP, excludedCIDR3, egressIP1, gatewayExcludedCIDRValue, ifIndex1},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})
}

func TestPrivilegedEndpointDataStore(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	// Create a new policy
	k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	k.assertEgressRules(t, []egressRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, _ := k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Simulate statefulset pod migrations to a different node.

	// Produce a new endpoint ep2 similar to ep1 - with the same name & labels, but with a different IP address.
	// The ep1 will be deleted.
	ep2, _ := newEndpointAndIdentity(ep1.Name, ep2IP, ep1Labels, node1IP)

	// Test event order: add new -> delete old
	addEndpoint(t, k.endpoints, &ep2)
	k.waitForReconciliationRun(t)
	deleteEndpoint(t, k.endpoints, &ep1)
	k.waitForReconciliationRun(t)

	k.assertEgressRules(t, []egressRule{
		{ep2IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep2IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})

	// Produce a new endpoint ep3 similar to ep2 (and ep1) - with the same name & labels, but with a different IP address.
	ep3, _ := newEndpointAndIdentity(ep1.Name, ep3IP, ep1Labels, node1IP)

	// Test event order: delete old -> update new
	deleteEndpoint(t, k.endpoints, &ep2)
	k.waitForReconciliationRun(t)
	addEndpoint(t, k.endpoints, &ep3)
	k.waitForReconciliationRun(t)

	k.assertEgressRules(t, []egressRule{
		{ep3IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep3IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})
}

func TestPrivilegedAdvertisedEgressIPs(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	link, err = safenetlink.LinkByName(testInterface2)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex2 := uint32(link.Attrs().Index)

	// Create a new HA policy (policy-1) using testInterface1,
	// with labels used in advertisePolicySelector - egressIP1 should be advertised
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		labels:           advertisePolicyLabels,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			activeGatewayIPs:  []string{node1IP, node2IP},
			healthyGatewayIPs: []string{node1IP, node2IP},
		}},
	})

	k.assertEgressRules(t, []egressRule{})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})

	// Add a new endpoint which matches policy-1 - no change
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})

	// Remove node1 - no advertisement
	k.removeHealthyGatewayFromEgressGroup(t, policy1, node1IP, defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, node2IP, 0},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{})

	// Add back node1 - advertise again
	k.addActiveGatewayToEgressGroup(t, policy1, node1IP, "", defaultEgressGroupID)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})

	// Create a new HA policy (policy-2) using testInterface2,
	// without labels used in advertisePolicySelector - only egressIP1 should be advertised
	policy2 := k.addPolicy(t, &policyParams{
		name:             "policy-2",
		uid:              policy2UID,
		endpointLabels:   ep2Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface2,
			nodeLabels:        nodeGroup2Labels,
			activeGatewayIPs:  []string{node1IP},
			healthyGatewayIPs: []string{node1IP},
		}},
	})

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})

	// Update labels on policy-2 to be selected by advertisePolicySelector
	// - both egressIP1 and egressIP2 should be advertised
	k.updatePolicyLabels(t, policy2, advertisePolicyLabels)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
		{Name: policy2.name}: {egressIP2},
	})

	// Add a new endpoint that matches policy-2 - no change
	k.addEndpoint(t, "ep-2", ep2IP, ep2Labels, node1IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
		{Name: policy2.name}: {egressIP2},
	})

	// Create a new HA policy (policy-3) using testInterface2,
	// with labels used in advertisePolicySelector - egressIP1 and egressIP2 should be advertised
	policy3 := k.addPolicy(t, &policyParams{
		name:             "policy-3",
		uid:              policy3UID,
		labels:           advertisePolicyLabels,
		endpointLabels:   ep2Labels,
		destinationCIDRs: []string{destCIDR},
		egressGroups: []egressGroupParams{{
			iface:             testInterface2,
			nodeLabels:        nodeGroup2Labels,
			activeGatewayIPs:  []string{node1IP},
			healthyGatewayIPs: []string{node1IP},
		}},
	})

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
		{Name: policy2.name}: {egressIP2},
		{Name: policy3.name}: {egressIP2},
	})

	// Update labels on policy-2 to NOT be selected by advertisePolicySelector
	// - both egressIP1 and egressIP2 still should be advertised
	k.updatePolicyLabels(t, policy2, nil)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
		{Name: policy3.name}: {egressIP2},
	})

	// Update labels on policy-3 to NOT be selected by advertisePolicySelector - only egressIP1 should be advertised
	k.updatePolicyLabels(t, policy3, nil)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})

	// Update labels on policy-1 to NOT be selected by advertisePolicySelector - no egress IPs should be advertised
	k.updatePolicyLabels(t, policy1, nil)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR, egressIP1, node2IP, ifIndex1},
		{ep2IP, destCIDR, egressIP2, node1IP, ifIndex2},
	})
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{})
}

func TestPrivilegedSameGatewayInMultipleEgressGroups(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	// Create a new HA policy (policy-1) using the same nodeGroup in two egress groups,
	// with testInterface1 and testInterface2 and with labels used in advertisePolicySelector.
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		labels:           advertisePolicyLabels,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDR3},
		egressGroups: []egressGroupParams{
			{
				iface:      testInterface1,
				nodeLabels: nodeGroup1Labels,
			},
			{
				iface:      testInterface2,
				nodeLabels: nodeGroup1Labels,
			},
		},
	})

	// Expect no rules and no EgressIP advertised.
	k.assertEgressRules(t, []egressRule{})
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{})

	// Add active gateway node1 to egress group1 - advertise egressIP1.
	k.addActiveGatewayToEgressGroup(t, policy1, node1IP, "", egressGroupID1)
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})

	// Add active gateway node1 to egress group2 - advertise egressIP1 only.
	// We log the "Local node selected by multiple egress gateway groups from the same policy"
	// in the agent, and interrupt the regeneration of the gateway config.
	k.addActiveGatewayToEgressGroup(t, policy1, node1IP, "", egressGroupID2)
	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})

	// Add a new endpoint that matches policy-1 - assert that only egressIP1 is in the map.
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR3, egressIP1, node1IP, ifIndex1},
	})

	// Change interface of active gateway in egress group 2 to testInterface1 -
	// advertise and use only egressIP1 as also specified in group 1. The previous
	// error is also logged here, no regeneration happens.
	policy1.egressGroups[egressGroupID2].iface = testInterface1
	k.addPolicy(t, policy1)

	k.assertBGPSignal(t, k.manager)
	k.assertAdvertisedEgressIPs(t, k.manager, advertisePolicySelector, map[types.NamespacedName][]string{
		{Name: policy1.name}: {egressIP1},
	})
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, ifIndex1},
		{ep1IP, destCIDR3, egressIP1, node1IP, ifIndex1},
	})
}

// TestPrivilegedEgressGatewayManagerIPAMWithEgressCIDRs verifies that when
// egressCIDRs is set, the agent skips gateway configuration until the
// operator assigns an egress IP from the pool.
func TestPrivilegedEgressGatewayManagerIPAMWithEgressCIDRs(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	link, err := safenetlink.LinkByName(testInterface1)
	if err != nil {
		t.Fatal(err)
	}
	ifIndex1 := uint32(link.Attrs().Index)

	// Add an endpoint that matches the policy.
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)

	// Create a policy with egressCIDRs set. The local node (node1) is healthy
	// but the operator has not yet assigned an egress IP from the pool
	// (egressIPByGatewayIP is empty).
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.0.0/24"},
		egressGroups: []egressGroupParams{{
			iface:             testInterface1,
			nodeLabels:        nodeGroup1Labels,
			healthyGatewayIPs: []string{node1IP},
		}},
	})

	// The local node must NOT be configured as a gateway: egressCIDRs is set
	// but no egress IP has been assigned from the pool yet.
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, zeroIP4, 0},
	})

	// Simulate the operator assigning an egress IP from the pool to node1.
	policy1.egressGroups[0].activeGatewayIPs = []string{node1IP}
	policy1.egressGroups[0].egressIPByGatewayIP = map[string]string{
		node1IP: "10.100.0.1",
	}
	k.addPolicy(t, policy1)

	// Now the local node should be configured as a gateway using the
	// IPAM-assigned IP (10.100.0.1), not the interface IP (egressIP1).
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, "10.100.0.1", node1IP, ifIndex1},
	})
}

// TestPrivilegedEgressGatewayManagerIPAMWithVirtualIP verifies that an IPAM
// policy without interface selector creates Virtual IPs (with no interface
// binding in the datapath).
func TestPrivilegedEgressGatewayManagerIPAMWithVirtualIP(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	// Add an endpoint that matches the policy.
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)

	// Create an IPAM policy with virtual EgressIPs.
	k.addPolicy(t, &policyParams{
		name: "policy-1",
		uid:  policy1UID,
		annotations: map[string]string{
			virtualEgressIPKey: "true",
		},
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		egressCIDRs:      []string{"10.100.0.0/24"},
		egressGroups: []egressGroupParams{{
			nodeLabels:        nodeGroup1Labels,
			healthyGatewayIPs: []string{node1IP},
			activeGatewayIPs:  []string{node1IP},
			egressIPByGatewayIP: map[string]string{
				node1IP: "10.100.0.1",
			},
		}},
	})

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, "10.100.0.1", node1IP, 0},
	})
}

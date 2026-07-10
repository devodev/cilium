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
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	ent_tables "github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/linux/netdevice"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// AgentPolicyConfig is composed of a PolicyConfig but also contains
// fields specific to the agent control-plane manager.
type AgentPolicyConfig struct {
	*PolicyConfig

	gatewayConfig    *gatewayConfig
	matchedEndpoints map[endpointID]*endpointMetadata
}

// parseAgentIEGP parses IEGP from k8s resource and initializes agent specific
// policy config fields for us in agent manager.
func parseAgentIEGP(logger *slog.Logger, iegp *v1.IsovalentEgressGatewayPolicy) (AgentPolicyConfig, error) {
	config, err := ParseIEGP(logger, iegp)
	if err != nil {
		return AgentPolicyConfig{}, err
	}
	return AgentPolicyConfig{
		PolicyConfig: config,
	}, nil
}

// azActiveGatewayIPs is a list of active gateway IPs for a particular AZ.
// In addition to the list of IPs
type azActiveGatewayIPs struct {
	// list of active gateway IPs for a given AZ
	gatewayIPs []netip.Addr
}

// gatewayConfig is the gateway configuration derived at runtime from a policy.
//
// Some of these fields are derived from the running system as the policy may
// specify only the egress IP (and so we need to figure out which interface has
// that IP assigned to) or the interface (and in this case we need to find the
// first IPv4 assigned to that).
type gatewayConfig struct {
	// ifaceName is the name of the interface used to SNAT traffic
	ifaceName string

	// egressIfindex is the ifindex of the interface used to SNAT traffic
	egressIfindex uint32

	// egressIP4 is the IP used to SNAT traffic with IPv4 policies
	egressIP4 netip.Addr
	// egressIP6 is the IP used to SNAT traffic with IPv6 policies
	egressIP6 netip.Addr

	// activeGatewayIPs is a slice of node IPs that are actively working as
	// egress gateways
	activeGatewayIPs []netip.Addr

	// activeGatewayIPsByAZ maps AZs to a slice of node IPs that are
	// actively working as egress gateway for that AZ
	activeGatewayIPsByAZ map[string]azActiveGatewayIPs

	// healthyGatewayIPs is the entire pool of healthy nodes that can act as
	// egress gateway for the given policy.
	// Not all of them may be actively acting as gateway since with the
	// maxGatewayNodes policy directive we can select a subset of them
	healthyGatewayIPs []netip.Addr

	// azAffinity configures the AZ affinity mode for the policy
	azAffinity azAffinityMode

	// localNodeConfiguredAsGateway tells if the local node belongs to the
	// pool of egress gateway node for this config.
	// This information is used to make sure the node does not get selected
	// multiple times by different egress groups
	localNodeConfiguredAsGateway bool
}

// matchesEndpointLabels determines if the given endpoint is a match for the
// policy config based on matching labels.
func (config *PolicyConfig) matchesEndpointLabels(endpointInfo *endpointMetadata) bool {
	labelsToMatch := labels.K8sSet(endpointInfo.labels)

	for i := range config.endpointSelectors {
		if policyTypes.Matches(config.endpointSelectors[i], labelsToMatch) {
			return true
		}
	}
	return false
}

func keys[Map ~map[K]V, K comparable, V any](m Map) sets.Set[K] {
	return sets.New(slices.Collect(maps.Keys(m))...)
}

// updateMatchedEndpointIDs update the policy's cache of matched endpoint IDs
func (config *AgentPolicyConfig) updateMatchedEndpointIDs(epDataStore map[endpointID]*endpointMetadata) bool {
	// save old matched endpoints
	prevMatchedEndpoints := config.matchedEndpoints

	// update matched endpoints
	config.matchedEndpoints = make(map[endpointID]*endpointMetadata)
	for _, endpoint := range epDataStore {
		if config.matchesEndpointLabels(endpoint) {
			config.matchedEndpoints[endpoint.id] = endpoint
		}
	}

	// if a new endpoint is matched or a previously matched endpoint is not anymore
	// an update is needed
	cur, prev := keys(config.matchedEndpoints), keys(prevMatchedEndpoints)
	if !cur.Equal(prev) {
		return true
	}

	// if an endpoint is matched and already was, but its metadata changed,
	// an update is needed
	for endpointID := range config.matchedEndpoints {
		if !config.matchedEndpoints[endpointID].equals(prevMatchedEndpoints[endpointID]) {
			return true
		}
	}

	// no update needed
	return false
}

func (config *AgentPolicyConfig) regenerateGatewayConfig(manager *Manager, tx statedb.WriteTxn) {
	config.gatewayConfig = &gatewayConfig{
		egressIP4:            EgressIPNotFoundIPv4,
		egressIP6:            EgressIPNotFoundIPv6,
		activeGatewayIPs:     []netip.Addr{},
		activeGatewayIPsByAZ: map[string]azActiveGatewayIPs{},
		healthyGatewayIPs:    []netip.Addr{},
		azAffinity:           config.azAffinity,
	}

	upsertPolicy := func() {
		// Still upsert, as we want to overwrite the gatewayConfig.
		if _, err := manager.upsertPolicy(tx, *config); err != nil {
			manager.logger.Error("BUG: could not upsert policy with empty gw config",
				logfields.Error, err)
		}
	}
	if len(config.groupStatuses) == 0 {
		upsertPolicy()
		return
	}

	localNode, err := manager.localNodeStore.Get(context.TODO())
	if err != nil {
		manager.logger.Error("Failed to get local node store",
			logfields.Error, err)
		upsertPolicy()
		return
	}

	nip := localNode.GetCiliumTunnelIP()
	if nip == nil {
		nip = localNode.GetK8sNodeIP()
	}
	localNodeK8sAddr, ok := netipx.FromStdIP(nip)
	if !ok {
		manager.logger.Error("Failed to parse local node IP",
			logfields.IPAddr, nip)
		upsertPolicy()
		return
	}

	var egressIPs []gwEgressIPConfig

	gwc := config.gatewayConfig
	for groupIndex, gc := range config.groupConfigs {
		groupStatus := &config.groupStatuses[groupIndex]
		// We use the local node IP to determine if the current node
		// matches the list of healthy gateway IPs
		localNodeMatchesGatewayIP := false

		if !gwc.azAffinity.enabled() {
			gwc.activeGatewayIPs = append(gwc.activeGatewayIPs, groupStatus.activeGatewayIPs...)
		} else {
			for az, gwIPs := range groupStatus.activeGatewayIPsByAZ {
				azGwIPs, ok := gwc.activeGatewayIPsByAZ[az]
				if !ok {
					azGwIPs = azActiveGatewayIPs{
						gatewayIPs: []netip.Addr{},
					}
				}
				azGwIPs.gatewayIPs = append(azGwIPs.gatewayIPs, gwIPs...)
				gwc.activeGatewayIPsByAZ[az] = azGwIPs
			}
		}
		// retain gateway configuration while the local node is healthy regardless of the az so that it can handle
		// the existing connection seamlessly. Depending on the AZ mode, the gateway node may receive traffic from
		// endpoints in different AZs, and since the information about which AZ it belonged to when it was active is lost.
		// So the AZ is not considered here.
		if slices.Contains(groupStatus.healthyGatewayIPs, localNodeK8sAddr) {
			localNodeMatchesGatewayIP = true
		}
		gwc.healthyGatewayIPs = append(gwc.healthyGatewayIPs, groupStatus.healthyGatewayIPs...)

		logger := manager.logger.With(
			logfields.IsovalentEgressGatewayPolicyName, config.id,
			logfields.Interface, gc.iface,
			logfields.EgressIP, gc.egressIP,
		)

		if localNodeMatchesGatewayIP {
			// If localNodeConfiguredAsGateway is already set it means that another
			// egress group for the same policy has already selected it as gateway. In
			// this case don't regenerate a new gatewayConfig and return an error
			if gwc.localNodeConfiguredAsGateway {
				logger.Error("Local node selected by multiple egress gateway groups from the same policy",
					logfields.Error, err,
				)
				continue
			}

			if len(config.egressCIDRs) > 0 {
				if egressIP, found := groupStatus.egressIPByGatewayIP[localNodeK8sAddr]; found {
					var (
						iface      netlink.Link
						ifaceIndex int
						ifaceName  string
						ifaceType  string
						err        error
					)

					if gc.iface != "" {
						ifaceName, ifaceIndex, ifaceType, err = fetchLinkInfo(manager, gc.iface)
					} else if !config.virtualIP {
						iface, err = route.NodeDeviceWithDefaultRoute(logger, true, false)
						if err == nil {
							ifaceIndex = iface.Attrs().Index
							ifaceName = iface.Attrs().Name
							ifaceType = iface.Type()
						}
					}
					if err != nil {
						logger.Error("Failed to find interface while updating node egress IP config",
							logfields.Error, err,
						)
						continue
					}

					egressIPs = append(egressIPs, gwEgressIPConfig{egressIP, ifaceName})
					gwc.egressIP4 = egressIP

					if ifaceName != "" {
						gwc.egressIfindex = manager.ifindexResolver(ifaceIndex, ifaceType)
						gwc.ifaceName = ifaceName
					}
				} else {
					// egressCIDRs is set, meaning the operator is responsible for IPAM-assigning
					// egress IPs from those CIDRs. If the local node has no assigned egress IP,
					// do not fall back to deriveFromGroupConfig which could pick an IP outside
					// the user-specified egressCIDRs.
					logger.Info("Local node is a gateway but has no egress IP assigned from egressCIDRs pool yet")
					continue
				}
			} else if err := gwc.deriveFromGroupConfig(manager, logger, &gc, config.v4Needed, config.v6Needed); err != nil {
				logger.Error("Failed to derive policy gateway configuration",
					logfields.Error, err,
				)
				continue
			}

			gwc.localNodeConfiguredAsGateway = true
		}
	}

	// upsert all the egress configs <egress IP, egress interface>
	// from the current status of the policy and remove the configs from the previous policy status
	nextEgressIPs := sets.New(egressIPs...)
	curEgressIPs := manager.egressConfigsByPolicy[config.id]
	toDel := curEgressIPs.Difference(nextEgressIPs)
	updateEgressIPsConfig(manager.logger, manager.db, manager.egressIPTable, nextEgressIPs, toDel)
	if _, err := manager.upsertPolicy(tx, *config); err != nil {
		manager.logger.Error("BUG: could not upsert policy with new gw config",
			logfields.Error, err)
	}
	manager.egressConfigsByPolicy[config.id] = nextEgressIPs
}

func updateEgressIPsConfig(
	logger *slog.Logger,
	db *statedb.DB,
	table statedb.RWTable[*ent_tables.EgressIPEntry],
	toUpsert, toDel sets.Set[gwEgressIPConfig],
) {
	txn := db.WriteTxn(table)
	defer txn.Abort()

	for _, config := range toDel.UnsortedList() {
		table.Delete(txn, &ent_tables.EgressIPEntry{
			Addr:      config.addr,
			Interface: config.iface,
		})
	}

	for _, config := range toUpsert.UnsortedList() {
		entry := ent_tables.EgressIPEntry{
			Addr:      config.addr,
			Interface: config.iface,
			Status:    reconciler.StatusPending(),
		}
		table.Insert(txn, &entry)
	}

	txn.Commit()
}

// egressIfindexForIface returns the interface index to use for BPF egress
// forwarding. If the device is a dummy interface, ifindex-based BPF forwarding
// can't be used. In such cases, it returns 0 to fallback to fib_lookup based selection.
func egressIfindexForIface(ifaceIndex int, ifaceType string) uint32 {
	if ifaceType == "dummy" {
		return 0
	}

	return uint32(ifaceIndex)
}

func fetchLinkInfo(manager *Manager, name string) (ifaceName string, ifaceIndex int, ifaceType string, err error) {
	dev, _, found := manager.deviceTable.Get(manager.db.ReadTxn(), tables.DeviceByName(name))
	if found {
		return dev.Name, dev.Index, dev.Type, nil
	}

	// Fall back to netlink, for (1) alternate interface name and (2) ignored devices.
	iface, err := safenetlink.LinkByName(name)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to retrieve egress interface %s: %w", name, err)
	}

	return iface.Attrs().Name, iface.Attrs().Index, iface.Type(), nil
}

func deviceGetPrimaryAddresses(manager *Manager, iface string) (netip.Addr, netip.Addr) {
	var primaryIP4, primaryIP6 netip.Addr

	addrs := manager.nodeAddrTable.List(manager.db.ReadTxn(), tables.NodeAddressDeviceNameIndex.Query(iface))
	for addr := range addrs {
		if !addr.Primary {
			continue
		}

		if addr.Addr.Is4() {
			primaryIP4 = addr.Addr
		} else if addr.Addr.Is6() {
			primaryIP6 = addr.Addr
		}
	}

	return primaryIP4, primaryIP6
}

func getDeviceWithAddress(manager *Manager, addr netip.Addr) *tables.Device {
	for dev := range manager.deviceTable.All(manager.db.ReadTxn()) {
		if dev.HasIP(addr) {
			return dev
		}
	}

	return nil
}

// deriveFromGroupConfig retrieves all the missing gateway configuration data
// (such as egress IP or interface) given a policy group config
func (gwc *gatewayConfig) deriveFromGroupConfig(manager *Manager, logger *slog.Logger, gc *groupConfig, v4Needed bool, v6Needed bool) error {
	var err error
	var egressIP4, egressIP6 netip.Addr

	gwc.egressIP4 = EgressIPNotFoundIPv4
	gwc.egressIP6 = EgressIPNotFoundIPv6

	switch {
	case gc.iface != "":
		// If the group config specifies an interface, use the first IPv4 assigned to that
		// interface as egress IP

		dev, _, found := manager.deviceTable.Get(manager.db.ReadTxn(), tables.DeviceByName(gc.iface))
		if found {
			gwc.egressIfindex = manager.ifindexResolver(dev.Index, dev.Type)
			gwc.ifaceName = dev.Name

			egressIP4, egressIP6 = deviceGetPrimaryAddresses(manager, dev.Name)
			if v4Needed && !egressIP4.IsValid() {
				return fmt.Errorf("failed to retrieve IPv4 address for egress interface")
			}

			if v6Needed && !egressIP6.IsValid() {
				return fmt.Errorf("failed to retrieve IPv6 address for egress interface")
			}
		} else {
			iface, err := safenetlink.LinkByName(gc.iface)
			if err != nil {
				return fmt.Errorf("failed to retrieve egress interface %s: %w", gc.iface, err)
			}

			gwc.egressIfindex = manager.ifindexResolver(iface.Attrs().Index, iface.Type())
			gwc.ifaceName = iface.Attrs().Name

			if v4Needed {
				egressIP4, err = netdevice.GetIfaceFirstIPv4Address(gc.iface)
				if err != nil {
					return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
				}
			}

			if v6Needed {
				egressIP6, err = netdevice.GetIfaceFirstIPv6Address(gc.iface)
				if err != nil {
					return fmt.Errorf("failed to retrieve IPv6 address for egress interface: %w", err)
				}
			}
		}
	case gc.egressIP.IsValid():
		// If the group config specifies an egress IP, use the interface with that IP as egress
		// interface

		if !gc.egressIP.Is4() && !gc.egressIP.Is6() {
			return fmt.Errorf("EgressIP %s is not a supported type", gc.egressIP)
		}

		dev := getDeviceWithAddress(manager, gc.egressIP)
		if dev != nil {
			gwc.ifaceName = dev.Name

			if gc.egressIP.Is4() {
				egressIP4 = gc.egressIP

				if v6Needed {
					_, egressIP6 = deviceGetPrimaryAddresses(manager, dev.Name)
					if !egressIP6.IsValid() {
						return fmt.Errorf("failed to retrieve IPv6 address for egress interface")
					}
				}
			} else if gc.egressIP.Is6() {
				egressIP6 = gc.egressIP

				if v4Needed {
					egressIP4, _ = deviceGetPrimaryAddresses(manager, dev.Name)
					if !egressIP4.IsValid() {
						return fmt.Errorf("failed to retrieve IPv4 address for egress interface")
					}
				}
			}
		} else {
			if gc.egressIP.Is4() {
				egressIP4 = gc.egressIP

				gwc.ifaceName, err = netdevice.GetIfaceWithIPv4Address(gc.egressIP)
				if err != nil {
					return fmt.Errorf("failed to retrieve interface with egress IP: %w", err)
				}

				if v6Needed {
					egressIP6, err = netdevice.GetIfaceFirstIPv6Address(gwc.ifaceName)
					if err != nil {
						return fmt.Errorf("failed to retrieve IPv6 address for egress interface: %w", err)
					}
				}
			} else if gc.egressIP.Is6() {
				egressIP6 = gc.egressIP

				gwc.ifaceName, err = netdevice.GetIfaceWithIPv6Address(gc.egressIP)
				if err != nil {
					return fmt.Errorf("failed to retrieve interface with IPv6 egress IP: %w", err)
				}

				if v4Needed {
					egressIP4, err = netdevice.GetIfaceFirstIPv4Address(gwc.ifaceName)
					if err != nil {
						return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
					}
				}
			}
		}

		// Don't apply ifindex-based BPF forwarding, and instead defer to IP routing:
		gwc.egressIfindex = 0
	default:
		// If the group config doesn't specify any egress IP or interface, use
		// the interface with the IPv4 default route

		if v4Needed {
			iface, err := route.NodeDeviceWithDefaultRoute(logger, true, false)
			if err != nil {
				return fmt.Errorf("failed to find interface with IPv4 default route: %w", err)
			}

			gwc.ifaceName = iface.Attrs().Name
			gwc.egressIfindex = uint32(iface.Attrs().Index)

			egressIP4, err = netdevice.GetIfaceFirstIPv4Address(gwc.ifaceName)
			if err != nil {
				return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
			}
		}

		if v6Needed {
			iface, err := route.NodeDeviceWithDefaultRoute(logger, false, true)
			if err != nil {
				return fmt.Errorf("failed to find interface with IPv6 default route: %w", err)
			}

			// Check that the two default routes point to the same interface
			if gwc.ifaceName != "" && iface.Attrs().Name != gwc.ifaceName {
				return fmt.Errorf("IPv6 default route interface doesn't match IPv4 default route interface")
			}

			gwc.ifaceName = iface.Attrs().Name
			gwc.egressIfindex = uint32(iface.Attrs().Index)

			egressIP6, err = netdevice.GetIfaceFirstIPv6Address(gwc.ifaceName)
			if err != nil {
				return fmt.Errorf("failed to retrieve IPv6 address for egress interface: %w", err)
			}
		}
	}

	if v4Needed {
		gwc.egressIP4 = egressIP4
	}
	if v6Needed {
		gwc.egressIP6 = egressIP6
	}

	return nil
}

// gatewayConfigForEndpoint returns the configuration of active gateway IPs
// and egress IP for a given endpoint
//
// If the AZ resolution fails, this method will fallback to the non AZ-aware list of active gateway IPs
func (gwc *gatewayConfig) gatewayConfigForEndpoint(manager *Manager, endpoint *endpointMetadata) ([]netip.Addr, netip.Addr, uint32) {
	egressIP := EgressIPNotFoundIPv4
	egressIfindex := uint32(0)

	if gwc.localNodeConfiguredAsGateway {
		egressIP = gwc.egressIP4
		egressIfindex = gwc.egressIfindex
	}

	if !gwc.azAffinity.enabled() {
		return gwc.activeGatewayIPs, egressIP, egressIfindex
	}

	endpointNode, ok := manager.nodesByIP[endpoint.nodeIP.String()]
	if !ok {
		manager.logger.Error(
			"cannot find endpoint's node",
			logfields.EndpointID, endpoint.id,
			logfields.K8sNodeIP, endpoint.nodeIP,
		)

		// fallback to the non AZ-aware list of gateway IPs
		return gwc.activeGatewayIPs, egressIP, egressIfindex
	}

	az, ok := endpointNode.Labels[core_v1.LabelTopologyZone]
	if !ok {
		manager.logger.Error(
			"missing node's AZ label",
			logfields.EndpointID, endpoint.id,
			logfields.K8sNodeIP, endpoint.nodeIP,
		)

		// fallback to the non AZ-aware list of gateway IPs
		return gwc.activeGatewayIPs, egressIP, egressIfindex
	}

	return gwc.activeGatewayIPsByAZ[az].gatewayIPs, egressIP, egressIfindex
}

// forEachEndpointAndCIDR iterates through each combination of endpoints and
// destination/excluded CIDRs of the receiver policy, and for each of them it
// calls the f callback function passing the given endpoint and CIDR, together
// with a boolean value indicating if the CIDR belongs to the excluded ones and
// the gatewayConfig of the receiver policy
func (config *AgentPolicyConfig) forEachEndpointAndCIDR(f func(*endpointMetadata, netip.Prefix, bool, *gatewayConfig)) {
	for _, endpoint := range config.matchedEndpoints {
		isExcludedCIDR := false
		for _, dstCIDR := range config.dstCIDRs {
			f(endpoint, dstCIDR, isExcludedCIDR, config.gatewayConfig)
		}

		isExcludedCIDR = true
		for _, excludedCIDR := range config.excludedCIDRs {
			f(endpoint, excludedCIDR, isExcludedCIDR, config.gatewayConfig)
		}
	}
}

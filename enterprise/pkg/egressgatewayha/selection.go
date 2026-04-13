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
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"go4.org/netipx"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// gatewayNodeIP is used to carry potential gateway node IPs for a
// policy.
// This is to be able to pre-compute viable gateways in a single pass
// such that each groupStatus has consistent inputs. The "per-group"
// policies are subsequently computed from a set of gatewayNodeIP's.
type gatewayNodeIP struct {
	*nodeTypes.Node

	// ip is the potential IP addr of the egress gateway that may
	// be used in a IEGP policy.
	ip netip.Addr
	// selectingGroupIndices contains a set of indices indicating
	// which groupConfigs matched this gateway in the pre-selection
	// stage (i.e. via the nodeSelector).
	// We use this later to compute per-groupConfig sets that only
	// match a particular group.
	selectingGroupIndices []int
	// zone indicates that this gatewayIP had a valid topology zone
	// set and can be used for "AZ-aware" policy computation.
	// We make this distinction as we also may need to perform "AZ-unaware"
	// computation for the fallback set.
	zone string
	// available indicates whether this gateway is available for active
	// gateway selection.
	available bool
}

func (gni *gatewayNodeIP) toStringCompact() string {
	selecting := strings.ReplaceAll(fmt.Sprintf("%v", gni.selectingGroupIndices), " ", ",")
	return fmt.Sprintf("{%s,%v,%q,%v}",
		gni.ip, selecting, gni.zone, gni.available)
}

func (gni *gatewayNodeIP) selectsGroupIndex(index int) bool {
	return slices.Contains(gni.selectingGroupIndices, index)
}

func (gni *gatewayNodeIP) zoneOK() bool {
	return gni.zone != ""
}

func (gni *gatewayNodeIP) isSelected() bool {
	return len(gni.selectingGroupIndices) > 0
}

func parseNodeIP(n nodeTypes.Node) netip.Addr {
	nodeIP, ok := netipx.FromStdIP(n.GetK8sNodeIP())
	if !ok {
		return netip.Addr{} // note: netip.Addr{}.IsValid() == false.
	}
	return nodeIP
}

func (config *PolicyConfig) preComputePolicyHealthyGateways(logger *slog.Logger, operatorManager *OperatorManager) (
	allAZs sets.Set[string], policyHealthyGatewayIPs []gatewayNodeIP) {
	allAZs = sets.New[string]()

	recordZone := func(gn gatewayNodeIP) {
		if gn.zoneOK() {
			// as the availableHealthyGatewayIPsByAZ map is used also to keep track of all the available AZs,
			// always create an empty entry if it doesn't exist yet.
			// In this way we can ensure all AZs will have a key in the map
			allAZs.Insert(gn.zone)
		}
	}

	logInvalidNodes := func(gn gatewayNodeIP) {
		if config.azAffinity.enabled() && !gn.zoneOK() {
			logger.Warn(
				fmt.Sprintf("AZ affinity is enabled but node is missing %s label. Node will be ignored", core_v1.LabelTopologyZone),
				logfields.NodeName, gn.Node.Name,
			)
		}
	}

	var unreachable []netip.Addr

	var policyHealthyGateways []gatewayNodeIP
	for _, n := range operatorManager.nodes {
		gn := gatewayNodeIP{
			ip:   parseNodeIP(n),
			Node: &n,
			zone: n.Labels[core_v1.LabelTopologyZone],

			selectingGroupIndices: config.selectingGroupConfigIndices(n),
			available:             operatorManager.nodeIsAvailable(n),
		}

		recordZone(gn)

		if !gn.ip.IsValid() || !gn.isSelected() {
			continue
		}

		if !operatorManager.nodeIsReachable(gn.Node.Name) {
			unreachable = append(unreachable, gn.ip)
			continue
		}

		logInvalidNodes(gn)

		policyHealthyGateways = append(policyHealthyGateways, gn)
	}

	logger.Info("skipped unreachable nodes", logfieldPolicyUnreachableGatewayIPs, unreachable)
	logPolicyHealthyGatewayIPs(logger, policyHealthyGateways)

	return allAZs, policyHealthyGateways
}

func gatewayNodesToAddrs(gns []gatewayNodeIP) []netip.Addr {
	var out []netip.Addr
	for _, gn := range gns {
		out = append(out, gn.ip)
	}
	return out
}

// computeHealthyGateways takes in a list of policy-wide gatewayNodeIPs and translates it to
// a per groupConfig list used for the final healthyGatewayIPs groupStatus field.
func computeHealthyGateways(policyHealthyGatewayIPs []gatewayNodeIP, groupIndex int) []gatewayNodeIP {
	var out []gatewayNodeIP
	for _, gn := range policyHealthyGatewayIPs {
		if !gn.selectsGroupIndex(groupIndex) {
			continue
		}
		out = append(out, gn)
	}
	return out
}

func computeAvailableHealthyGatewayIPs(healthyGatewayIPs []gatewayNodeIP) []netip.Addr {
	var out []netip.Addr
	for _, gn := range healthyGatewayIPs {
		if !gn.available {
			continue
		}
		out = append(out, gn.ip)
	}
	return out
}

type zoneToAvailable map[string]int

// hasAvailableGateways returns whether there exists at least one available
// gateway for all policy selected nodes, inside the zone.
func (za zoneToAvailable) hasAvailableGateways(zone string) bool {
	return za[zone] > 0
}

// computeAvailableHealthyGatewaysByAZ takes the policy healthy and available gateways and filters/partitions
// it down to the per-group availableHealthyGatewayIPsByAZ used by selectActiveGatewaysByAZ to perform
// az-aware gateway selection.
func computeAvailableHealthyGatewaysByAZ(allAZs sets.Set[string], policyHealthyGatewayIPs []gatewayNodeIP, groupIndex int) (map[string][]netip.Addr, zoneToAvailable) {
	availGWs := map[string][]netip.Addr{}
	policyAvailByZone := map[string]int{}
	for az := range allAZs {
		availGWs[az] = []netip.Addr{}
		policyAvailByZone[az] = 0
	}

	for _, gn := range policyHealthyGatewayIPs {
		if !gn.available || !gn.zoneOK() {
			continue
		}
		policyAvailByZone[gn.zone]++
		if !gn.selectsGroupIndex(groupIndex) {
			continue
		}
		availGWs[gn.zone] = append(availGWs[gn.zone], gn.ip)
	}
	return availGWs, policyAvailByZone
}

// doSelection performs an active gateway selection, given a status active (i.e. currently active) and available set.
// Priority is given to current status active to ensure stability across selections and selectionKey.
func doSelection(logger *slog.Logger, statusActiveGateways, availableHealthyGatewayIPs []netip.Addr, selectionKey string, neededGatewayNodes int) []netip.Addr {
	var currentLocalActiveGWs []netip.Addr
	// statusNotAvailable is nodes that were previously in the statuses active set but
	// are no longer available for stable selection due zone change or not being available.
	var statusNotAvailable []netip.Addr
	if len(statusActiveGateways) != 0 {
		// we have to reverify they're still local and active.
		availableForReselection := sets.New(availableHealthyGatewayIPs...).Has
		for _, activeGW := range statusActiveGateways {
			if !availableForReselection(activeGW) {
				// track just for tracing.
				statusNotAvailable = append(statusNotAvailable, activeGW)
				continue
			}
			currentLocalActiveGWs = append(currentLocalActiveGWs, activeGW)
		}
	}

	logger.Info("selecting active gateways",
		logfieldStatusActiveGatewayIPs, statusActiveGateways,
		logfieldStatusNotAvailable, statusNotAvailable,
		logfieldGatewaySelectionKey, selectionKey,
		logfieldsNeededGateways, neededGatewayNodes)

	// seed with zone
	return selectActiveGWs(selectionKey, neededGatewayNodes, currentLocalActiveGWs, availableHealthyGatewayIPs)
}

// selectCurrentNonLocalActiveByAZ re-selects from a set of currently active gateways.
// Because the zone and health status of the gateway may have changed since the last
// reconciliation we have to revalidate that these are still valid.
func selectCurrentNonLocalActiveByAZ(
	availableHealthyGatewaysByAZ map[string][]netip.Addr,
	az string,
	currentActiveGWs []netip.Addr,
) []netip.Addr {
	var out []netip.Addr
	nonLocal := sets.New[netip.Addr]()
	for k := range availableHealthyGatewaysByAZ {
		if k != az {
			nonLocal.Insert(availableHealthyGatewaysByAZ[k]...)
		}
	}

	for _, activeGW := range currentActiveGWs {
		if !nonLocal.Has(activeGW) {
			continue
		}
		out = append(out, activeGW)
	}
	return out
}

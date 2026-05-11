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
	"strconv"

	"k8s.io/apimachinery/pkg/types"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	egressGatewayPrefix = "egw.isovalent.com"
	virtualEgressIPKey  = egressGatewayPrefix + "/virtual-ip"
)

// groupConfig is the internal representation of an egress group, describing
// which nodes should act as egress gateway for a given policy
type groupConfig struct {
	nodeSelector    *policyTypes.LabelSelector
	iface           string
	egressIP        netip.Addr
	maxGatewayNodes int
}

func (g *groupConfig) String() string {
	out := ""
	if g.iface != "" {
		out += g.iface
	}
	if g.egressIP.String() != "" {
		out += g.egressIP.String()
	}
	out += strconv.Itoa(g.maxGatewayNodes)
	return out
}

type groupStatus struct {
	activeGatewayIPs     []netip.Addr
	activeGatewayIPsByAZ map[string][]netip.Addr
	healthyGatewayIPs    []netip.Addr
	egressIPByGatewayIP  map[netip.Addr]netip.Addr
}

type azAffinityMode int

const (
	azAffinityDisabled azAffinityMode = iota
	azAffinityLocalOnly
	azAffinityLocalOnlyFirst
	azAffinityLocalPriority
)

func azAffinityModeFromString(azAffinity string) (azAffinityMode, error) {
	switch azAffinity {
	case "disabled", "":
		return azAffinityDisabled, nil
	case "localOnly":
		return azAffinityLocalOnly, nil
	case "localOnlyFirst":
		return azAffinityLocalOnlyFirst, nil
	case "localPriority":
		return azAffinityLocalPriority, nil
	default:
		return 0, fmt.Errorf("invalid azAffinity value \"%s\"", azAffinity)
	}
}

func (m azAffinityMode) toString() string {
	switch m {
	case azAffinityDisabled:
		return "disabled"
	case azAffinityLocalOnly:
		return "localOnly"
	case azAffinityLocalOnlyFirst:
		return "localOnlyFirst"
	case azAffinityLocalPriority:
		return "localPriority"
	default:
		return ""
	}
}

func (m azAffinityMode) enabled() bool {
	return m != azAffinityDisabled
}

// PolicyConfig is the internal representation of IsovalentEgressGatewayPolicy.
// These are only shallow copied when upserting into the database to avoid excess
// memory copying.
// Most fields are either considered immutable (i.e. "spec" type fields - derived
// directly from IEGP resources), or are always regenerated and never mutated
// such as with the groupConfigs and groupStatuses.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id                types.NamespacedName
	uid               types.UID
	creationTimestamp time.Time

	apiVersion string
	generation int64
	labels     map[string]string
	// ingested from annotations:
	virtualIP bool

	endpointSelectors []*policyTypes.LabelSelector
	dstCIDRs          []netip.Prefix
	excludedCIDRs     []netip.Prefix
	egressCIDRs       []netip.Prefix

	azAffinity azAffinityMode

	groupStatusesGeneration int64
	groupStatuses           []groupStatus

	// These fields should always be re-created when regenerating
	groupConfigs []groupConfig
}

func (pc *PolicyConfig) clone() *PolicyConfig {
	out := *pc
	return &out
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

type gwEgressIPConfig struct {
	addr  netip.Addr
	iface string
}

// ParseIEGP takes a IsovalentEgressGatewayPolicy CR and converts to PolicyConfig,
// the internal representation of the egress gateway policy
func ParseIEGP(logger *slog.Logger, iegp *v1.IsovalentEgressGatewayPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []*policyTypes.LabelSelector
	var dstCidrList []netip.Prefix
	var excludedCIDRs []netip.Prefix
	var egressCIDRs []netip.Prefix
	var virtualIP bool

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := iegp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("must have a name")
	}

	uid := iegp.UID
	if uid == "" {
		return nil, fmt.Errorf("must have a uid")
	}

	if val, found := iegp.Annotations[virtualEgressIPKey]; found {
		virtualIP = val == "true"
	}

	destinationCIDRs := iegp.Spec.DestinationCIDRs
	if destinationCIDRs == nil {
		return nil, fmt.Errorf("destinationCIDRs can't be empty")
	}

	egressGroups := iegp.Spec.EgressGroups
	if egressGroups == nil {
		return nil, fmt.Errorf("egressGroups can't be empty")
	}

	gcs := []groupConfig{}
	for _, gcSpec := range egressGroups {
		if gcSpec.Interface != "" && gcSpec.EgressIP != "" {
			return nil, fmt.Errorf("group configuration can't specify both an interface and an egress IP")
		}

		gc := groupConfig{
			nodeSelector:    policyTypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, gcSpec.NodeSelector)),
			iface:           gcSpec.Interface,
			maxGatewayNodes: gcSpec.MaxGatewayNodes,
		}

		// EgressIP is not a required field, validate and parse it only if non-empty
		if gcSpec.EgressIP != "" {
			egressIP, err := netip.ParseAddr(gcSpec.EgressIP)
			if err != nil {
				return nil, fmt.Errorf("failed to parse egress IP %s: %w", gcSpec.EgressIP, err)
			}
			gc.egressIP = egressIP
		}

		gcs = append(gcs, gc)
	}

	for _, cidrString := range destinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse destination CIDR %s: %w", cidrString, err)
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, cidrString := range iegp.Spec.ExcludedCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse excluded CIDR %s: %w", cidr, err)
		}
		excludedCIDRs = append(excludedCIDRs, cidr)
	}

	for _, cidrString := range iegp.Spec.EgressCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse egress CIDR %s: %w", cidr, err)
		}
		egressCIDRs = append(egressCIDRs, cidr)
	}

	for _, egressRule := range iegp.Spec.Selectors {
		if egressRule.NamespaceSelector != nil {
			prefixedNsSelector := egressRule.NamespaceSelector.DeepCopy()
			matchLabels := map[string]string{}
			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for k, v := range egressRule.NamespaceSelector.MatchLabels {
				matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
			}

			prefixedNsSelector.MatchLabels = matchLabels

			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for i, lsr := range egressRule.NamespaceSelector.MatchExpressions {
				lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
				prefixedNsSelector.MatchExpressions[i] = lsr
			}

			// Empty namespace selector selects all namespaces (i.e., a namespace
			// label exists).
			if len(egressRule.NamespaceSelector.MatchLabels) == 0 && len(egressRule.NamespaceSelector.MatchExpressions) == 0 {
				prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
			}

			endpointSelectorList = append(
				endpointSelectorList,
				policyTypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, prefixedNsSelector, egressRule.PodSelector)))
		} else if egressRule.PodSelector != nil {
			endpointSelectorList = append(
				endpointSelectorList,
				policyTypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, egressRule.PodSelector)))
		} else {
			return nil, fmt.Errorf("cannot have both nil namespace selector and nil pod selector")
		}
	}

	azAffinity, err := azAffinityModeFromString(iegp.Spec.AZAffinity)
	if err != nil {
		return nil, err
	}

	if azAffinity == azAffinityLocalPriority {
		for _, gc := range gcs {
			if gc.maxGatewayNodes == 0 {
				return nil, fmt.Errorf("cannot have localPriority AZ affinity mode without maxGatewayNodes set")
			}
		}
	}

	gs := []groupStatus{}

	for _, policyGroupStatus := range iegp.Status.GroupStatuses {
		activeGatewayIPs := []netip.Addr{}
		activeGatewayIPsByAZ := map[string][]netip.Addr{}
		healthyGatewayIPs := []netip.Addr{}
		egressIPByGatewayIP := make(map[netip.Addr]netip.Addr)

		for _, gwIP := range policyGroupStatus.ActiveGatewayIPs {
			activeGatewayIP, err := netip.ParseAddr(gwIP)
			if err != nil {
				logger.Error(
					"Cannot parse active gateway IP",
					logfields.Error, err,
				)
				continue
			}

			activeGatewayIPs = append(activeGatewayIPs, activeGatewayIP)
		}

		for az, gwIPs := range policyGroupStatus.ActiveGatewayIPsByAZ {
			for _, gwIP := range gwIPs {
				ip, err := netip.ParseAddr(gwIP)
				if err != nil {
					logger.Error(
						"Cannot parse AZ active gateway IP",
						logfields.Error, err,
					)
					continue
				}

				activeGatewayIPsByAZ[az] = append(activeGatewayIPsByAZ[az], ip)
			}
		}

		for _, gwIP := range policyGroupStatus.HealthyGatewayIPs {
			healthyGatewayIP, err := netip.ParseAddr(gwIP)
			if err != nil {
				logger.Error(
					"Cannot parse healthy gateway IP",
					logfields.Error, err,
				)
				continue
			}

			healthyGatewayIPs = append(healthyGatewayIPs, healthyGatewayIP)
		}

		for gwIP, egressIP := range policyGroupStatus.EgressIPByGatewayIP {
			gwAddr, err := netip.ParseAddr(gwIP)
			if err != nil {
				logger.Error(
					"Cannot parse gateway IP",
					logfields.Error, err,
				)
				continue
			}

			egressAddr, err := netip.ParseAddr(egressIP)
			if err != nil {
				logger.Error(
					"Cannot parse allocated egress IP",
					logfields.Error, err,
				)
				continue
			}

			egressIPByGatewayIP[gwAddr] = egressAddr
		}

		gs = append(gs, groupStatus{
			activeGatewayIPs,
			activeGatewayIPsByAZ,
			healthyGatewayIPs,
			egressIPByGatewayIP,
		})
	}

	return &PolicyConfig{
		labels:                  iegp.Labels,
		endpointSelectors:       endpointSelectorList,
		dstCIDRs:                dstCidrList,
		excludedCIDRs:           excludedCIDRs,
		egressCIDRs:             egressCIDRs,
		azAffinity:              azAffinity,
		groupConfigs:            gcs,
		groupStatusesGeneration: iegp.Status.ObservedGeneration,
		groupStatuses:           gs,
		id: types.NamespacedName{
			Name: name,
		},
		uid:               uid,
		creationTimestamp: iegp.CreationTimestamp.Time,
		apiVersion:        "isovalent.com/v1",
		generation:        iegp.GetGeneration(),
		virtualIP:         virtualIP,
	}, nil
}

// ParseIEGPConfigID takes a IsovalentEgressGatewayPolicy CR and returns only the config id
func ParseIEGPConfigID(iegp *v1.IsovalentEgressGatewayPolicy) types.NamespacedName {
	return policyID{
		Name: iegp.Name,
	}
}

func toSortedStringSlice(s []netip.Addr) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, v.String())
	}
	slices.Sort(out)
	return out
}

func toStringMap(m map[netip.Addr]netip.Addr) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k.String()] = v.String()
	}
	return out
}

func toStringMapStringSlice(m map[string][]netip.Addr) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = toSortedStringSlice(v)
	}
	return out
}

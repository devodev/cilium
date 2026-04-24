// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package evpn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
	ceebgptypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
)

const (
	agentShellExecTimeout = 5 * time.Second
)

// bgpNodeInfo contains per-node information retrieved from the agent's BGP Control Plane.
type bgpNodeInfo struct {
	NodeName          string
	AgentPodName      string
	AgentPodNamespace string
	LearnedRT5        map[uint32][]rt5Route
}

type rt5Route struct {
	Prefix          netip.Prefix
	SecurityGroupID *uint16
}

// bgpRoutesPayload is the payload of the "cilium-dbg shell -- bgp/routes" (extended) command used for JSON unmarshalling.
// Only contains parts that are important for the tests.
// Note that we are not using the InstanceRoutesExtended type here for two reasons:
//  1. GoBGP's AddrPrefixInterface / PathAttributeInterface do not provide JSON unmarshalling API.
//  2. If this payload format changes across various Cilium versions, we are able to support multiple versions here.
type bgpRoutesPayload struct {
	Instances []struct {
		Routes []struct {
			Paths []struct {
				NLRI struct {
					Type  int `json:"type"`
					Value struct {
						Prefix string `json:"prefix"`
						Label  uint32 `json:"label"`
					} `json:"value"`
				} `json:"NLRI"`
				PathAttributes []bgpPathAttributePayload `json:"PathAttributes"`
			} `json:"Paths"`
		} `json:"Routes"`
	} `json:"Instances"`
}

type bgpPathAttributePayload struct {
	Type     int             `json:"type"`
	RawValue json.RawMessage `json:"value"`
}

type bgpExtendedCommunityPayload struct {
	Type     uint8           `json:"type"`
	Subtype  uint8           `json:"subtype"`
	RawValue json.RawMessage `json:"value"`
}

func (r *TestRun) retrieveBGPNodeInfo(ctx context.Context) (map[string]bgpNodeInfo, error) {
	pods, err := r.client.ListPods(ctx, r.params.CiliumNamespace, metav1.ListOptions{
		LabelSelector: r.params.AgentPodSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("error listing cilium-agent pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no cilium-agent pod found in namespace %s matching selector %q", r.params.CiliumNamespace, r.params.AgentPodSelector)
	}

	res := make(map[string]bgpNodeInfo, len(pods.Items))
	for _, pod := range pods.Items {
		nodeName := pod.Spec.NodeName

		routesOut, err := r.execAgentShellCommand(ctx, pod.Namespace, pod.Name, []string{"bgp/routes", "in", "l2vpn", "evpn", "-f", "json"})
		if err != nil {
			return nil, fmt.Errorf("error retrieving learned EVPN routes from pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		routes, err := unmarshalBGPRoutes(routesOut)
		if err != nil {
			return nil, err
		}
		rt5Routes, err := getRT5Routes(routes)
		if err != nil {
			return nil, fmt.Errorf("error parsing learned EVPN routes from pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		res[nodeName] = bgpNodeInfo{
			NodeName:          nodeName,
			AgentPodName:      pod.Name,
			AgentPodNamespace: pod.Namespace,
			LearnedRT5:        rt5Routes,
		}
		fmt.Fprintf(r.out, "Node %s: learned RT-5 routes for %d VNIs\n", nodeName, len(rt5Routes))
	}
	return res, nil
}

func unmarshalBGPRoutes(raw string) (bgpRoutesPayload, error) {
	var payload bgpRoutesPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return bgpRoutesPayload{}, fmt.Errorf("error unmarshaling bgp/routes command JSON: %w", err)
	}
	return payload, nil
}

func getRT5Routes(allRoutes bgpRoutesPayload) (map[uint32][]rt5Route, error) {
	routesByVNI := make(map[uint32][]rt5Route)
	for _, instance := range allRoutes.Instances {
		for _, route := range instance.Routes {
			for _, path := range route.Paths {
				if path.NLRI.Type != 5 {
					continue
				}
				vni := path.NLRI.Value.Label
				prefix, err := netip.ParsePrefix(path.NLRI.Value.Prefix)
				if err != nil {
					return nil, fmt.Errorf("error parsing learned RT-5 prefix %q: %w", path.NLRI.Value.Prefix, err)
				}
				routesByVNI[vni] = append(routesByVNI[vni], rt5Route{Prefix: prefix})
			}
		}
	}
	return routesByVNI, nil
}

// getPingTargetsForVNI returns test ping targets from the learned RT-5 routes per node and VNI.
// Prefers /32 or /128 prefixes if available for the VNI, otherwise uses first non-network IP of larger prefixes.
func getPingTargetsForVNI(bgpNodeInfo map[string]bgpNodeInfo, nodeName string, vni uint32) ([]netip.Addr, error) {
	var (
		hostTargets    []netip.Addr
		networkTargets []netip.Addr
	)
	nodeInfo, ok := bgpNodeInfo[nodeName]
	if !ok {
		return hostTargets, fmt.Errorf("BGP info for node %s not found", nodeName)
	}
	for _, rt5 := range nodeInfo.LearnedRT5[vni] {
		if rt5.Prefix.IsSingleIP() {
			hostTargets = append(hostTargets, rt5.Prefix.Addr())
			continue
		}
		networkTargets = append(networkTargets, rt5.Prefix.Addr().Next())
	}
	if len(hostTargets) > 0 {
		return hostTargets, nil
	} else if len(networkTargets) > 0 {
		return networkTargets, nil
	}
	return nil, fmt.Errorf("no ping targets found for VNI %d", vni)
}

func (r *TestRun) retrieveAdvertisedRT5Routes(ctx context.Context, nodeInfo bgpNodeInfo) (map[netip.Prefix]rt5Route, error) {
	if nodeInfo.AgentPodName == "" {
		return nil, fmt.Errorf("agent pod for node %s not known", nodeInfo.NodeName)
	}

	out, err := r.execAgentShellCommand(ctx, nodeInfo.AgentPodNamespace, nodeInfo.AgentPodName, []string{"bgp/routes", "out", "l2vpn", "evpn", "-f", "json"})
	if err != nil {
		return nil, fmt.Errorf("error retrieving advertised EVPN routes from pod %s/%s: %w", nodeInfo.AgentPodNamespace, nodeInfo.AgentPodName, err)
	}

	routes, err := parseAdvertisedRT5Routes(out)
	if err != nil {
		return nil, fmt.Errorf("error parsing advertised EVPN routes from pod %s/%s: %w", nodeInfo.AgentPodNamespace, nodeInfo.AgentPodName, err)
	}
	return routes, nil
}

func parseAdvertisedRT5Routes(rawJSON string) (map[netip.Prefix]rt5Route, error) {
	payload, err := unmarshalBGPRoutes(rawJSON)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling bgp/routes command JSON: %w", err)
	}
	routes := make(map[netip.Prefix]rt5Route)
	for _, instance := range payload.Instances {
		for _, route := range instance.Routes {
			for _, path := range route.Paths {
				if path.NLRI.Type != 5 {
					continue
				}
				prefix, err := netip.ParsePrefix(path.NLRI.Value.Prefix)
				if err != nil {
					return nil, fmt.Errorf("error parsing advertised RT-5 prefix %q: %w", path.NLRI.Value.Prefix, err)
				}
				sgID, err := parseSecurityGroupIDFromPathAttributes(path.PathAttributes)
				if err != nil {
					return nil, fmt.Errorf("error parsing RT-5 path attributes for prefix %s: %w", prefix, err)
				}
				if existing, found := routes[prefix]; found {
					if existing.SecurityGroupID != nil && sgID != nil && *existing.SecurityGroupID != *sgID {
						return nil, fmt.Errorf("conflicting GroupPolicyID values for prefix %s", prefix)
					}
				}
				routes[prefix] = rt5Route{
					Prefix:          prefix,
					SecurityGroupID: sgID,
				}
			}
		}
	}
	return routes, nil
}

func parseSecurityGroupIDFromPathAttributes(pathAttrs []bgpPathAttributePayload) (*uint16, error) {
	for _, pathAttr := range pathAttrs {
		if pathAttr.Type != int(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES) {
			continue
		}
		var extComms []bgpExtendedCommunityPayload
		if err := json.Unmarshal(pathAttr.RawValue, &extComms); err != nil {
			return nil, fmt.Errorf("error unmarshaling extended communities: %w", err)
		}
		for _, extComm := range extComms {
			if extComm.Type != uint8(bgp.EC_TYPE_TRANSITIVE_OPAQUE) && extComm.Type != uint8(bgp.EC_TYPE_NON_TRANSITIVE_OPAQUE) {
				continue
			}
			if extComm.Subtype != ceebgptypes.GroupPolicyIDExtCommSubType {
				continue
			}
			var value []byte
			if err := json.Unmarshal(extComm.RawValue, &value); err != nil {
				return nil, fmt.Errorf("error unmarshaling opaque extended community value: %w", err)
			}
			opaque := &bgp.OpaqueExtended{
				IsTransitive: extComm.Type == uint8(bgp.EC_TYPE_TRANSITIVE_OPAQUE),
				Value:        value,
			}
			if !ceebgptypes.IsGroupPolicyIDExtendedCommunity(opaque) {
				continue
			}
			groupID := ceebgptypes.GetGroupPolicyIDFromExtendedCommunity(opaque)
			return &groupID, nil
		}
	}
	return nil, nil
}

func (r *TestRun) execAgentShellCommand(ctx context.Context, namespace, pod string, shellCommand []string) (string, error) {
	command := append([]string{"cilium-dbg", "shell", "--"}, shellCommand...)
	execCtx, cancel := context.WithTimeout(ctx, agentShellExecTimeout)
	defer cancel()

	out, err := r.client.ExecInPod(execCtx, namespace, pod, defaults.AgentContainerName, command)
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

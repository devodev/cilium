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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

// bgpNodeInfo contains per-node information retrieved from the agent's BGP Control Plane.
type bgpNodeInfo struct {
	NodeName   string
	LearnedRT5 map[uint32][]netip.Prefix
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
			} `json:"Paths"`
		} `json:"Routes"`
	} `json:"Instances"`
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

		routesOut, err := r.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName,
			[]string{"cilium-dbg", "shell", "--", "bgp/routes", "in", "l2vpn", "evpn", "-f", "json"})
		if err != nil {
			return nil, fmt.Errorf("error retrieving learned EVPN routes from pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		routes, err := unmarshalBGPRoutes(routesOut.String())
		if err != nil {
			return nil, err
		}
		rt5Routes, err := getRT5Routes(routes)
		if err != nil {
			return nil, fmt.Errorf("error parsing learned EVPN routes from pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		res[nodeName] = bgpNodeInfo{
			NodeName:   nodeName,
			LearnedRT5: rt5Routes,
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

func getRT5Routes(allRoutes bgpRoutesPayload) (map[uint32][]netip.Prefix, error) {
	routesByVNI := make(map[uint32][]netip.Prefix)
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
				routesByVNI[vni] = append(routesByVNI[vni], prefix)
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
	for _, prefix := range nodeInfo.LearnedRT5[vni] {
		if prefix.IsSingleIP() {
			hostTargets = append(hostTargets, prefix.Addr())
			continue
		}
		networkTargets = append(networkTargets, prefix.Addr().Next())
	}
	if len(hostTargets) > 0 {
		return hostTargets, nil
	} else if len(networkTargets) > 0 {
		return networkTargets, nil
	}
	return nil, fmt.Errorf("no ping targets found for VNI %d", vni)
}

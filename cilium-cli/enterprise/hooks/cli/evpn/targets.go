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
	"os/exec"
	"strings"
	"time"
)

// getRemoteTargetsForPod returns remote EVPN target IPs to use in connectivity tests for the given privnet pod.
// When an external Docker container is mapped to the privnet's VNI, its IPs are used as remote targets.
// Otherwise, learned RT-5 routes are used to derive remote targets.
func getRemoteTargetsForPod(ctx context.Context, run *TestRun, env *testEnv, podConfig *privnetPodConfig, nodeName string) ([]netip.Addr, error) {
	if containerName, ok := env.vniContainers[podConfig.privnet.VNI]; ok {
		return discoverContainerSourceIPs(ctx, containerName, podConfig)
	}
	return deriveTargetsFromRT5(env.bgpNodeInfo, nodeName, podConfig.privnet.VNI)
}

// deriveTargetsFromRT5 derives remote EVPN target IPs from the learned RT-5 routes per node and VNI.
// Prefers /32 or /128 prefixes if available for the VNI, otherwise uses first non-network IP of larger prefixes.
func deriveTargetsFromRT5(bgpNodeInfo map[string]bgpNodeInfo, nodeName string, vni uint32) ([]netip.Addr, error) {
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
	return nil, fmt.Errorf("no target IPs found for VNI %d", vni)
}

// discoverContainerSourceIPs discovers external container's local IPs (IPv4 and IPv6) used as the source IPs
// when communicating with the given privnet pod.
func discoverContainerSourceIPs(ctx context.Context, containerName string, podConfig *privnetPodConfig) ([]netip.Addr, error) {
	var targets []netip.Addr
	for _, podAddr := range []netip.Addr{podConfig.ipv4, podConfig.ipv6} {
		if !podAddr.IsValid() {
			continue
		}
		sourceAddr, err := getContainerSourceAddr(ctx, containerName, podAddr)
		if err != nil {
			return nil, fmt.Errorf("could not discover source IP for Docker container %s and pod %s address %s: %w", containerName, podConfig.name, podAddr, err)
		}
		targets = append(targets, sourceAddr)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("could not discover source IPs for Docker container %s and pod %s", containerName, podConfig.name)
	}
	return targets, nil
}

func getContainerSourceAddr(ctx context.Context, containerName string, target netip.Addr) (netip.Addr, error) {
	routeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	stdout, err := execInDockerContainer(routeCtx, containerName, "ip", "-j", "route", "get", target.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("route lookup failed: %w: %s", err, strings.TrimSpace(stdout))
	}

	source, err := parseRouteGetSourceAddr(stdout)
	if err != nil {
		return netip.Addr{}, err
	}
	return source, nil
}

func parseRouteGetSourceAddr(raw string) (netip.Addr, error) {
	type ipRouteGetEntry struct {
		PrefSrc string `json:"prefsrc"`
		Src     string `json:"src"`
	}
	var entries []ipRouteGetEntry

	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		var single ipRouteGetEntry
		if errSingle := json.Unmarshal([]byte(raw), &single); errSingle != nil {
			return netip.Addr{}, fmt.Errorf("failed parsing ip route get JSON: %w", err)
		}
		entries = []ipRouteGetEntry{single}
	}
	if len(entries) == 0 {
		return netip.Addr{}, fmt.Errorf("ip route get returned no entries")
	}

	rawSource := strings.TrimSpace(entries[0].PrefSrc)
	if rawSource == "" {
		rawSource = strings.TrimSpace(entries[0].Src)
	}
	if rawSource == "" {
		return netip.Addr{}, fmt.Errorf("ip route get output did not contain a source address")
	}

	source, err := netip.ParseAddr(rawSource)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed parsing route source address %q: %w", rawSource, err)
	}
	return source, nil
}

func execInDockerContainer(ctx context.Context, containerName string, args ...string) (string, error) {
	commandArgs := append([]string{"exec", containerName}, args...)
	cmd := exec.CommandContext(ctx, "docker", commandArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

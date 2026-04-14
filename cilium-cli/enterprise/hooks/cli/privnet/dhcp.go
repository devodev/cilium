// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type dhcpScenario struct {
	scenario

	vm VM
}

func NewDHCP(t *TestRun, vm VM) Scenario {
	name := fmt.Sprintf("dhcp-%s", vm.Name)
	return &dhcpScenario{
		scenario: scenario{t: t, name: name},
		vm:       vm,
	}
}

func (s *dhcpScenario) Run(ctx context.Context, _ Expectation, _ ...features.IPFamily) {
	s.t.log.Info(fmt.Sprintf("🧐 Running DHCP validation for %s", s.vm.DescName()))

	ip4, err := s.waitForAssignedIPv4(ctx)
	if err != nil {
		s.fail(features.IPFamilyAny, "%v", err)
		return
	}

	prefix, ok := ipv4PrefixForNetworkSubnet(s.vm.NetName, s.vm.NetSubnet)
	if !ok {
		s.fail(features.IPFamilyAny, "missing IPv4 prefix for network %s", s.vm.NetName)
		return
	}
	if !prefix.Contains(ip4) {
		s.fail(features.IPFamilyAny, "IPv4 address %s not in expected prefix %s", ip4, prefix)
		return
	}

	launcherPod := s.t.VirtLauncherPodForVM(s.vm)
	if launcherPod == nil {
		s.fail(features.IPFamilyAny, "no launcher pod found for VM %s", s.vm.Name)
		return
	}
	nodeName := NodeName(launcherPod.Spec.NodeName)
	agentPod, ok := s.t.ciliumPodsCluster[nodeName]
	if !ok {
		s.fail(features.IPFamilyAny, "no Cilium agent pod found on node %s", nodeName)
		return
	}

	err = s.validateLeaseOnNode(ctx, agentPod, ip4)
	if err != nil {
		s.fail(features.IPFamilyAny, "validating DHCP lease on node %s: %v", nodeName, err)
		return
	}

	if err := s.validateConnectivity(ctx); err != nil {
		s.fail(features.IPFamilyAny, "validating DHCP connectivity: %v", err)
		return
	}
}

func (s *dhcpScenario) waitForAssignedIPv4(ctx context.Context) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, check.ShortTimeout)
	defer cancel()

	var lastErr error
	for {
		stdout, stderr, err := s.t.vmExec(ctx, s.vm,
			[]string{"ip", "-j", "-4", "addr", "show", "dev", s.vm.Interface})

		exitCode, ok := extractExitCode(err)
		switch {
		case err == nil:
			ip4, hasIPv4 := parseIPv4FromIPOutput(stdout)
			if hasIPv4 && !ip4.IsUnspecified() {
				return ip4, nil
			}
			if !hasIPv4 {
				lastErr = fmt.Errorf("no IPv4 address found on %s", s.vm.Interface)
			} else {
				lastErr = fmt.Errorf("IPv4 address still 0.0.0.0 (DHCP lease not acquired)")
			}
			s.t.log.Debug("DHCP IPv4 check failed, retrying",
				logfields.Error, lastErr,
				logfields.Stdout, stdout,
				logfields.Interval, check.PollInterval,
			)
		case !ok:
			return netip.Addr{}, fmt.Errorf("failed with unexpected exec error: %w", err)
		default:
			lastErr = fmt.Errorf("ip command failed with exit code %d", exitCode)
			s.t.log.Debug("DHCP IP command failed, retrying",
				logfields.Error, lastErr,
				logfields.Stdout, stdout,
				logfields.Stderr, stderr,
				logfields.Interval, check.PollInterval,
			)
		}

		select {
		case <-time.After(check.PollInterval):
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return netip.Addr{}, fmt.Errorf("timed out waiting for IPv4 address on %s: %w", s.vm.Interface, lastErr)
		}
	}
}

func parseIPv4FromIPOutput(output string) (netip.Addr, bool) {
	type addrInfo struct {
		Family string `json:"family"`
		Local  string `json:"local"`
	}
	type iface struct {
		AddrInfo []addrInfo `json:"addr_info"`
	}

	var ifaces []iface
	if err := json.Unmarshal([]byte(output), &ifaces); err == nil {
		for _, iface := range ifaces {
			for _, ai := range iface.AddrInfo {
				if ai.Family != "inet" {
					continue
				}
				ip, err := netip.ParseAddr(ai.Local)
				if err != nil || !ip.Is4() {
					continue
				}
				return ip, true
			}
		}
	}

	return netip.Addr{}, false
}

func ipv4PrefixForNetworkSubnet(network NetworkName, subnet SubnetName) (netip.Prefix, bool) {
	ndata, ok := networkTopology.Networks[network]
	if !ok {
		return netip.Prefix{}, false
	}
	for _, p := range ndata.Prefixes {
		if p.Name != subnet {
			continue
		}

		pfx, err := netip.ParsePrefix(p.CIDRv4)
		if err != nil {
			continue
		}
		if pfx.Addr().Is4() {
			return pfx, true
		}
	}
	return netip.Prefix{}, false
}

func (s *dhcpScenario) validateLeaseOnNode(ctx context.Context, agent check.Pod, ip4 netip.Addr) error {
	stdout, err := agent.K8sClient.ExecInPod(ctx, agent.Pod.Namespace, agent.Pod.Name,
		defaults.AgentContainerName,
		[]string{"cilium-dbg", "shell", "--", "db/show", "privnet-dhcp-leases", "--format=yaml"},
	)
	if err != nil {
		return fmt.Errorf("retrieving DHCP leases: %w", err)
	}

	for item := range bytes.SplitSeq(stdout.Bytes(), []byte("\n---")) {
		var lease tables.DHCPLease
		if err := yaml.Unmarshal(item, &lease); err != nil {
			return fmt.Errorf("failed to unmarshal lease information: %w", err)
		}
		if lease.Network != tables.NetworkName(s.vm.NetName) {
			continue
		}
		if lease.MAC.String() != s.vm.NetMAC {
			continue
		}
		if lease.IPv4 != ip4 {
			return fmt.Errorf("lease IPv4 mismatch: got %s want %s", lease.IPv4, ip4)
		}
		return nil
	}
	return fmt.Errorf("lease not found for network %s mac %s", s.vm.NetName, s.vm.NetMAC)
}

func (s *dhcpScenario) validateConnectivity(ctx context.Context) error {
	dst := s.t.VM(s.vm.NetName, EchoOtherVM(s.vm.NetName))
	dstIP := dst.IP(features.IPFamilyV4)

	_, _, err := s.t.vmExec(ctx, s.vm,
		curlCmd(netip.AddrPortFrom(dstIP, EchoServerPort).String(), s.vm.Interface))
	if err != nil {
		exitCode, ok := extractExitCode(err)
		if !ok {
			return fmt.Errorf("unexpected exec error: %w", err)
		}
		return fmt.Errorf("curl failed with exit code %d", exitCode)
	}
	return nil
}

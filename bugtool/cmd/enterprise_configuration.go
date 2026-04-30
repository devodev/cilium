//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	bgpTypes "github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/defaults"
)

func init() {
	ExtraCommands = append(ExtraCommands, enterpriseCommands)
}

func enterpriseCommands(confDir string, _ string) []string {
	var commands []string

	bpfMapsPath := []string{
		"tc/globals/cilium_egress_gw_ha_policy_v4",
		"tc/globals/cilium_egress_gw_ha_policy_v4_v2",
		"tc/globals/cilium_egress_gw_ha_ct_v4",
		"tc/globals/cilium_egress_gw_standalone_v4",
		"tc/globals/cilium_encryption_policy_map",
	}

	infoCommands := []string{
		"cilium-dbg bpf egress-ha list",
		"cilium-dbg bpf egress-ha ct list",
		"cilium-dbg bpf egress-ha standalone list",
		"cilium-dbg bpf privnet fib list",
		"cilium-dbg bpf privnet pip list",
		"cilium-dbg bpf privnet devices list",
		"cilium-dbg bpf privnet subnets list",
		"cilium-dbg bpf privnet arp-sender list",
		"cilium-dbg shell -- privnet/status --color=false",
		"cilium-dbg shell -- privnet/status -o=json",
		"cilium-dbg bfd peers",
	}

	commands = append(commands, bpfMapDumpCommands(bpfMapsPath)...)
	commands = append(commands, infoCommands...)
	commands = append(commands, fqdnProxyCommands()...)
	commands = append(commands, bgpRIBDumpCommands()...)
	commands = append(commands, ribDumpCommand())

	return commands
}

func bgpRIBDumpCommands() []string {
	var cmds []string
	for _, family := range []bgpTypes.Family{
		{Afi: bgpTypes.AfiIPv4, Safi: bgpTypes.SafiUnicast},
		{Afi: bgpTypes.AfiIPv6, Safi: bgpTypes.SafiUnicast},
		{Afi: bgpTypes.AfiL2VPN, Safi: bgpTypes.SafiEvpn},
		{Afi: bgpTypes.AfiIPv4, Safi: bgpTypes.SafiMplsVpn},
	} {

		afi := family.Afi.String()
		safi := family.Safi.String()
		cmds = append(cmds, bgpRIBDumpCommand("in", afi, safi))
		cmds = append(cmds, bgpRIBDumpCommand("loc", afi, safi))
		cmds = append(cmds, bgpRIBDumpCommand("out", afi, safi))
	}
	return cmds
}

func bgpRIBDumpCommand(ribType, afi, safi string) string {
	return fmt.Sprintf("cilium-dbg shell -- bgp/routes -a %s %s %s", ribType, afi, safi)
}

func ribDumpCommand() string {
	return "cilium-dbg shell -- rib/list"
}

func fqdnProxyCommands() []string {
	shellSockPath := filepath.Join(defaults.RuntimePath, "dnsproxy-shell.sock")
	shellCmd := fmt.Sprintf("cilium-dbg shell --shell-sock-path %s -- ", shellSockPath)

	// Ensure that the fqdn proxy shell server is listening.
	if _, err := os.Stat(shellSockPath); os.IsNotExist(err) {
		return nil
	}

	return []string{
		shellCmd + "dnsproxy/config -o=json",
		shellCmd + "dnsproxy/rules -o=json",
		shellCmd + "dnsproxy/bpfipcache",
		shellCmd + "dnsproxy/selectors",
		shellCmd + "dnsproxy/identities",
		shellCmd + "dnsproxy/endpoints",
		shellCmd + "dnsproxy/iplist",
	}
}

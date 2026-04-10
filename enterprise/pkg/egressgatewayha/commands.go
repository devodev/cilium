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
	"os"
	"slices"
	"sort"
	"text/tabwriter"

	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
)

// Contains test commands used for hive-script-testing egwha.
// These should *not* be included in the general egwha hive cells.
//
// In general, it should be preferred to have output come from statedb
// tables as that provides a consistent interface for table writing
// and queries etc.
//
// This also attempts to maintain a separation between script testing
// code and egwha internals.
var testCommandsCell = cell.Module("test-commands", "Test Commands",
	cell.Provide(scriptCommands),
)

type params struct {
	cell.In

	PolicyMap egressmapha.PolicyMapV2
	CtMap     egressmapha.CtMap
}

func scriptCommands(p params) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"egressha/policy-maps-dump": mapsDump(p),
	})
}

func mapsDump(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump the egwha BPF maps",
			Args:    "(output file)",
			Detail: []string{
				"This dumps the egwha BPF maps either to stdout or to a file.",
				"Output is written in the format: key=value with spaces used to separate",
				"For example: source_ip=10.0.0.1 dest_cidr=99.0.0.0/24 egress_ip=100.0.0.1 gateway_ips=[]",
				"Format is not guaranteed to be stable as this command is only",
				"for testing and debugging purposes.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				out := s.LogWriter()
				if len(args) > 0 {
					var err error
					out, err = os.Create(s.Path(args[0]))
					if err != nil {
						return "", "", err
					}
				}
				w := tabwriter.NewWriter(out, 5, 0, 3, ' ', 0)
				lines := []string{}
				p.PolicyMap.IterateWithCallback(func(k *egressmapha.EgressPolicyV2Key4, v *egressmapha.EgressPolicyV2Val4) {
					lines = append(lines,
						fmt.Sprintf("source_ip=%s dest_cidr=%s egress_ip=%s egress_ifindex=%d gateway_ips=%v", k.SourceIP, k.DestCIDR, v.EgressIP, v.EgressIfindex, slices.Collect(v.GetGatewayIPs())))
				})
				sort.Strings(lines)
				for _, l := range lines {
					fmt.Fprintln(w, l)
				}
				w.Flush()

				return
			}, nil
		},
	)
}

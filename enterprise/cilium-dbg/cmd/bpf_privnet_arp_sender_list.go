// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cmd

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
)

func init() {
	bpfPrivNetARPSenderCmd.AddCommand(bpfPrivNetARPSenderListCmd)
}

type arpSenderEntry struct {
	NetID    uint16
	SubnetID uint16
	IPv4     string
}

var bpfPrivNetARPSenderListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List private network ARP sender map entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf private-network arp-sender list")

		m, err := privnet.OpenPinnedARPSenderMap(log)
		if err != nil {
			Fatalf("Failed to open privnet arp_sender map: %s", err)
		}

		var entries []arpSenderEntry
		parseARPSenders := func(k bpf.MapKey, v bpf.MapValue) {
			key := k.(*privnet.ARPSenderKey)
			val := v.(*privnet.ARPSenderVal)

			entries = append(entries, arpSenderEntry{
				NetID:    uint16(key.NetworkID),
				SubnetID: uint16(key.SubnetID),
				IPv4:     val.IPv4.String(),
			})
		}

		if err := m.Map.DumpWithCallback(parseARPSenders); err != nil {
			Fatalf("Error dumping content of privnet arp_sender map: %v", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("Error getting output of privnet arp_sender map in JSON: %v", err)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NetID\tSubnetID\tIPv4")

		for _, e := range slices.SortedFunc(
			slices.Values(entries),
			func(a, b arpSenderEntry) int {
				return cmp.Or(
					cmp.Compare(a.NetID, b.NetID),
					cmp.Compare(a.SubnetID, b.SubnetID),
				)
			}) {
			fmt.Fprintf(w, "%#x\t%#x\t%s\n", e.NetID, e.SubnetID, e.IPv4)
		}
		w.Flush()
	},
}

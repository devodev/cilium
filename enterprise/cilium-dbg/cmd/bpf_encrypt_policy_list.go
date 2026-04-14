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
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/enterprise/pkg/maps/encryptionpolicymap"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
)

type encryptionPolicyEntry struct {
	Key encryptionpolicymap.EncryptionPolicyKey
	Val encryptionpolicymap.EncryptionPolicyVal
}

var bpfEncryptPolicyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List encryption policy entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf encrypt policy list")

		policyMap, err := encryptionpolicymap.OpenPinnedPolicyMap(log)
		if err != nil {
			Fatalf("Cannot open encryption policy bpf map: %s", err)
		}
		defer policyMap.Close()

		entries := []encryptionPolicyEntry{}
		callback := func(key bpf.MapKey, value bpf.MapValue) {
			record := encryptionPolicyEntry{Key: *key.(*encryptionpolicymap.EncryptionPolicyKey), Val: *value.(*encryptionpolicymap.EncryptionPolicyVal)}
			entries = append(entries, record)
		}
		if err = policyMap.DumpWithCallback(callback); err != nil {
			Fatalf("Error while collecting BPF map entries: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("Error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printEncryptionPolicyList(entries)
		}
	},
}

func printEncryptionPolicyList(entries []encryptionPolicyEntry) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "PrefixLen\tSubjectIdentity\tPeerIdentity\tNexthdr\tPeerPortNetwork\tEncrypt")
	for _, ep := range entries {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%d\t%t\n", ep.Key.Prefixlen, ep.Key.SubjectIdentity, ep.Key.PeerIdentity, ep.Key.Nexthdr, ep.Key.PeerPortNetwork, ep.Val.IsEncrypt())
	}

	w.Flush()
}

func init() {
	bpfEncryptPolicyCmd.AddCommand(bpfEncryptPolicyListCmd)
	command.AddOutputOption(bpfEncryptPolicyListCmd)
}

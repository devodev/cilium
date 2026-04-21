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

	"github.com/cilium/hive/shell"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-dbg/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

var (
	bgpInstanceFlag string
	bgpFormatFlag   string
)

// bgpRoutePoliciesCmd is CEE-specific BGP route-policies command to dump extended BGP route policies.
var bgpRoutePoliciesCmd = &cobra.Command{
	Use:   "route-policies",
	Short: "List configured route policies",
	Long:  "List route policies configured in the underlying routing daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := hive.DefaultShellConfig
		if err := cfg.Parse(cmd.Flags()); err != nil {
			return err
		}
		shellCmd := "bgp/route-policies"
		if bgpInstanceFlag != "" {
			shellCmd = fmt.Sprintf("%s --instance=%s", shellCmd, bgpInstanceFlag)
		}
		if bgpFormatFlag != "" {
			shellCmd = fmt.Sprintf("%s --format=%s", shellCmd, bgpFormatFlag)
		}
		return shell.ShellExchange(cfg, os.Stdout, shellCmd)
	},
}

func init() {
	bgpRoutePoliciesCmd.Flags().StringVarP(&bgpInstanceFlag, "instance", "i", "", "Name of a Cilium router instance. Lists policies of all instances if omitted.")
	bgpRoutePoliciesCmd.Flags().StringVarP(&bgpFormatFlag, "format", "f", "table", "Format to write in (table, yaml or json)")

	// override the OSS "bgp route-policies" command with the CEE "bgp/route-policies" shell command
	cmd.BgpCmd.RemoveCommand(cmd.BgpRoutePoliciesCmd)
	cmd.BgpCmd.AddCommand(bgpRoutePoliciesCmd)
	hive.DefaultShellConfig.Flags(bgpRoutePoliciesCmd.Flags())
}

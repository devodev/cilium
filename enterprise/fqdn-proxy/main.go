//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

func main() {
	binaryName := filepath.Base(os.Args[0])

	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			// slogloggercheck: it has been initialized in the PreRun function.
			return Hive.Run(logging.DefaultSlogLogger)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// slogloggercheck: it was initialized in SetupLogging
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, binaryName)

			option.Config.SetupLogging(Hive.Viper(), "external-dns-proxy")
			// dnsproxy does not manage identity allocation; set the
			// mode explicitly to suppress the spurious warning from
			// option.Config.Populate() when kvstore is empty.
			Hive.Viper().Set(option.IdentityAllocationMode, option.IdentityAllocationModeCRD)
			option.Config.Populate(logger, Hive.Viper())
			option.LogRegisteredSlogOptions(Hive.Viper(), logger)

			logging.AddHandlers(metrics.NewLoggingHook())
		},
	}

	Hive.RegisterFlags(cmd.Flags())
	cmd.AddCommand(
		cmdref.NewCmd(cmd),
		shell.ShellCmd(shellSockPath, shellPrompt(), shellGreeting),
		Hive.Command(),
	)

	cmd.Execute()
}

func shellPrompt() string {
	if name, err := os.Hostname(); err == nil {
		return name + "> "
	}
	return "dnsproxy> "
}

func shellGreeting(w io.Writer) {
	const (
		Red     = "\033[31m"
		Yellow  = "\033[33m"
		Blue    = "\033[34m"
		Green   = "\033[32m"
		Magenta = "\033[35m"
		Cyan    = "\033[36m"
		Reset   = "\033[0m"
	)
	fmt.Fprint(w, Yellow+"    /¯¯\\\n")
	fmt.Fprint(w, Cyan+" /¯¯"+Yellow+"\\__/"+Green+"¯¯\\"+Reset+"\n")
	fmt.Fprintf(w, Cyan+" \\__"+Red+"/¯¯\\"+Green+"__/"+Reset+"  Cilium DNSProxy %s\n", version.GetCiliumVersion().Version)
	fmt.Fprint(w, Green+" /¯¯"+Red+"\\__/"+Magenta+"¯¯\\"+Reset+"  Welcome to the Cilium DNSProxy Shell! Type 'help' for list of commands.\n")
	fmt.Fprint(w, Green+" \\__"+Blue+"/¯¯\\"+Magenta+"__/"+Reset+"\n")
	fmt.Fprint(w, Blue+Blue+Blue+"    \\__/"+Reset+"\n")
	fmt.Fprint(w, "\n")
}

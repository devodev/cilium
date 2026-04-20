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
	"os"
	"path/filepath"

	"github.com/cilium/hive/shell"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/version"
)

func Execute() {
	binaryName := filepath.Base(os.Args[0])

	rootCmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		RunE: func(_ *cobra.Command, _ []string) error {
			// slogloggercheck: this binary configures the shared Cilium logger in PreRunE before starting Hive.
			return Hive.Run(logging.DefaultSlogLogger)
		},
		PreRunE: func(_ *cobra.Command, _ []string) error {
			level, err := logging.ParseLevel(Hive.Viper().GetString("log-level"))
			if err != nil {
				return fmt.Errorf("invalid log level: %w", err)
			}
			logging.SetLogLevel(level)

			// slogloggercheck: startup logging should use the same configured logger instance that Hive receives below.
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, binaryName)
			logger.Info("Gateway API controlplane", logfields.Version, version.Version)

			return nil
		},
	}

	Hive.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(
		cmdref.NewCmd(rootCmd),
		shell.ShellCmd(shellSockPath, "gateway-api-controlplane> ", nil),
		Hive.Command(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

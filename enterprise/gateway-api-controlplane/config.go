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
	"path/filepath"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/pprof"
)

var shellSockPath = filepath.Join(defaults.RuntimePath, "gateway-api-controlplane-shell.sock")

const defaultGopsPort = 8912

var pprofConfig = pprof.Config{
	Pprof:                     false,
	PprofAddress:              "localhost",
	PprofPort:                 8922,
	PprofMutexProfileFraction: 0,
	PprofBlockProfileRate:     0,
}

type Config struct {
	LogLevel          string
	HealthBindAddress string
}

var defaultConfig = Config{
	LogLevel:          "info",
	HealthBindAddress: ":18001",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("log-level", def.LogLevel, "Log level for the Gateway API controlplane.")
	flags.String("health-bind-address", def.HealthBindAddress, "Address for the Gateway API controlplane health endpoint to listen on.")
}

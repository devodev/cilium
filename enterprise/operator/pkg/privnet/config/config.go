// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
)

var (
	// Cell registers the private networks configuration.
	Cell = cell.Group(
		cell.Config(defaultConfig),
		cell.Invoke(Config.validate),
	)

	defaultConfig = Config{
		Common: config.DefaultCommon,

		NADIntegration: NADIntegrationConfig{
			Enabled:      false,
			CNILogFile:   filepath.Join(defaults.RuntimePath, "cilium-cni.log"),
			CNILogFormat: string(logging.DefaultLogFormatTimestamp),
		},

		AutoExternalEndpoints: AutoExternalEndpointsConfig{
			Enabled:          false,
			ConfigDir:        filepath.Join(defaults.LibraryPath, "privnet", "auto-external-endpoints-config"),
			SecretsNamespace: "cilium-secrets",
		},
	}
)

type Config struct {
	config.Common `mapstructure:",squash"`

	NADIntegration        NADIntegrationConfig        `mapstructure:",squash"`
	AutoExternalEndpoints AutoExternalEndpointsConfig `mapstructure:",squash"`
}

func (cfg Config) validate() error {
	return cfg.NADIntegration.validate()
}

func (def Config) Flags(flags *pflag.FlagSet) {
	def.Common.Flags(flags)
	def.NADIntegration.Flags(flags)
	def.AutoExternalEndpoints.Flags(flags)
}

// EnabledWithNADIntegration returns whether private networking is enabled, with
// support for Multus network attachment definitions.
func (cfg Config) EnabledWithNADIntegration() bool {
	return cfg.Enabled && cfg.NADIntegration.Enabled
}

type NADIntegrationConfig struct {
	Enabled      bool   `mapstructure:"private-networks-nad-integration-enabled"`
	CNILogFile   string `mapstructure:"private-networks-nad-cni-log-file"`
	CNILogFormat string `mapstructure:"private-networks-nad-cni-log-format"`
}

func (def NADIntegrationConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("private-networks-nad-integration-enabled", def.Enabled,
		"Enable the private networks integration with Multus network attachment definitions")
	flags.String("private-networks-nad-cni-log-file", def.CNILogFile,
		"CNI logs path configured for managed Multus network attachment definitions")
	flags.String("private-networks-nad-cni-log-format", def.CNILogFormat,
		"CNI logs format configured for managed Multus network attachment definitions")
}

func (cfg NADIntegrationConfig) validate() error {
	switch logging.LogFormat(cfg.CNILogFormat) {
	case logging.LogFormatJSON, logging.LogFormatJSONTimestamp,
		logging.LogFormatText, logging.LogFormatTextTimestamp:
	default:
		return fmt.Errorf("invalid NAD CNI logs format %q, should be one of %q, %q, %q, %q",
			cfg.CNILogFormat, logging.LogFormatJSON, logging.LogFormatJSONTimestamp,
			logging.LogFormatText, logging.LogFormatTextTimestamp)
	}

	return nil
}

// EnabledWithAutoExternalEndpoints returns whether private networking is enabled, with
// support for automatic creation of PrivateNetworkExternalEndpoints.
func (cfg Config) EnabledWithAutoExternalEndpoints() bool {
	return cfg.Enabled && cfg.AutoExternalEndpoints.Enabled
}

type AutoExternalEndpointsConfig struct {
	Enabled          bool   `mapstructure:"private-networks-auto-external-endpoints-enabled"`
	ConfigDir        string `mapstructure:"private-networks-auto-external-endpoints-config-dir"`
	SecretsNamespace string `mapstructure:"private-networks-auto-external-endpoints-secrets-namespace"`
}

func (cfg AutoExternalEndpointsConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("private-networks-auto-external-endpoints-enabled", cfg.Enabled,
		"Automatically create PrivateNetworkExternalEndpoints")
	flags.String("private-networks-auto-external-endpoints-config-dir", cfg.ConfigDir,
		"Configuration for the creation of PrivateNetworkExternalEndpoints")
	flags.String("private-networks-auto-external-endpoints-secrets-namespace", cfg.SecretsNamespace,
		"Kubernetes namespace from which provider secrets are read")
}

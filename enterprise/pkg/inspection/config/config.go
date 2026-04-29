//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import "github.com/spf13/pflag"

const (
	// FlagEnable is the flag to enable passive inspection for pod traffic.
	FlagEnable = "enable-passive-inspection"

	// InterfaceName is the well-known name of the dummy network interface
	// created by the agent to receive mirrored pod traffic for passive
	// inspection. It follows the cilium_* naming convention used by all
	// other agent-managed interfaces and is not user-configurable.
	InterfaceName = "cilium_inspect"

	// PropertyEndpointEnabled stores whether passive inspection remains enabled
	// for a specific endpoint after applying the singleton inspection config.
	PropertyEndpointEnabled = "inspection.isovalent.com/effective-enabled"
)

// Config groups the passive inspection configuration.
type Config struct {
	// Enabled enables passive inspection for pod traffic. When enabled, a clone of packets
	// leaving and entering pods is redirected to a dedicated dummy inspection interface.
	Enabled bool `mapstructure:"enable-passive-inspection"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(FlagEnable, def.Enabled, "Enable passive inspection for pod traffic (mirror packets to a dedicated dummy interface)")
}

var defaultConfig = Config{
	Enabled: false,
}

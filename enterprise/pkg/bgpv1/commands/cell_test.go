// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package commands

import (
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	ossCommands "github.com/cilium/cilium/pkg/bgp/commands"
	ciliumHive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
)

func TestBGPCommandOverride(t *testing.T) {
	tests := []struct {
		name              string
		ossEnabled        bool
		enterpriseEnabled bool
		check             func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd)
	}{
		{
			name:              "OSS enabled Enterprise enabled",
			ossEnabled:        true,
			enterpriseEnabled: true,
			check: func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd) {
				// Override should occur
				require.NotNil(t, bgpCommands["bgp/routes"])
				require.NotNil(t, bgpCommands["bgp/route-policies"])
				// Global command should not be provided.
				require.NotContains(t, commands, "bgp/routes")
				require.NotContains(t, commands, "bgp/route-policies")
			},
		},
		{
			name:              "OSS enabled Enterprise disabled",
			ossEnabled:        true,
			enterpriseEnabled: false,
			check: func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd) {
				// No override should occur
				require.Nil(t, bgpCommands["bgp/routes"])
				require.Nil(t, bgpCommands["bgp/route-policies"])
				// Global command should not be provided.
				require.NotContains(t, commands, "bgp/routes")
				require.NotContains(t, commands, "bgp/route-policies")
			},
		},
		{
			name:              "OSS disabled Enterprise enabled",
			ossEnabled:        false,
			enterpriseEnabled: true,
			check: func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd) {
				// No override should occur
				require.Nil(t, bgpCommands["bgp/routes"])
				require.Nil(t, bgpCommands["bgp/route-policies"])
				// Global command should be provided
				require.Contains(t, commands, "bgp/routes")
				require.Contains(t, commands, "bgp/route-policies")
			},
		},
		{
			name:              "OSS disabled Enterprise disabled",
			ossEnabled:        false,
			enterpriseEnabled: false,
			check: func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd) {
				// No override should occur
				require.Nil(t, bgpCommands["bgp/routes"])
				require.Nil(t, bgpCommands["bgp/route-policies"])
				// Global command should not be provided
				require.NotContains(t, commands, "bgp/routes")
				require.NotContains(t, commands, "bgp/route-policies")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				bgpCommands ossCommands.BGPCommands
				commands    map[string]script.Cmd
			)

			h := ciliumHive.New(
				Cell,
				cell.Provide(
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableBGPControlPlane: tt.ossEnabled,
						}
					},
					func() config.Config {
						return config.Config{
							Enabled: tt.enterpriseEnabled,
						}
					},
					func() agent.EnterpriseBGPRouterManager {
						return nil
					},
					func() *reconcilerv2.ErrorPathStore {
						return nil
					},
					func() ossCommands.BGPCommands {
						// Provide nil OSS BGP
						// commands so that we can
						// verify the override by
						// checking for the presence of
						// the enterprise-extended
						// commands.
						return ossCommands.BGPCommands{
							"bgp/routes":         nil,
							"bgp/route-policies": nil,
						}
					},
				),
				cell.Invoke(func(bgpCmds ossCommands.BGPCommands, cmds hive.ScriptCmds) {
					bgpCommands = bgpCmds
					commands = cmds.Map()
				}),
			)
			require.NoError(t, h.Populate(hivetest.Logger(t)))

			// The commands should always be present.
			require.Contains(t, bgpCommands, "bgp/routes")
			require.Contains(t, bgpCommands, "bgp/route-policies")

			tt.check(t, bgpCommands, commands)
		})
	}
}

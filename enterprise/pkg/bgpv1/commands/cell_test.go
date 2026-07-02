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
)

func TestBGPCommandOverride(t *testing.T) {
	tests := []struct {
		name              string
		enterpriseEnabled bool
		check             func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd)
	}{
		{
			name:              "Enterprise enabled",
			enterpriseEnabled: true,
			check: func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd) {
				// Override should occur
				require.NotNil(t, bgpCommands["bgp/globals"])
				require.NotNil(t, bgpCommands["bgp/routes"])
				require.NotNil(t, bgpCommands["bgp/route-policies"])
			},
		},
		{
			name:              "Enterprise disabled",
			enterpriseEnabled: false,
			check: func(t *testing.T, bgpCommands ossCommands.BGPCommands, commands map[string]script.Cmd) {
				// No override should occur
				require.Nil(t, bgpCommands["bgp/globals"])
				require.Nil(t, bgpCommands["bgp/routes"])
				require.Nil(t, bgpCommands["bgp/route-policies"])
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
							"bgp/globals":        nil,
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
			require.Contains(t, bgpCommands, "bgp/globals")
			require.Contains(t, bgpCommands, "bgp/routes")
			require.Contains(t, bgpCommands, "bgp/route-policies")

			tt.check(t, bgpCommands, commands)
		})
	}
}

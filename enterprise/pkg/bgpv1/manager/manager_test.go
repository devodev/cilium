// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	ossAgent "github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/manager"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
)

func TestNewBGPRouterManager(t *testing.T) {
	ossRouterManager := &manager.BGPRouterManager{}

	tests := []struct {
		name              string
		ossEnabled        bool
		enterpriseEnabled bool
		check             func(t *testing.T, m agent.EnterpriseBGPRouterManager)
	}{
		{
			name:              "OSS enabled Enterprise enabled",
			ossEnabled:        true,
			enterpriseEnabled: true,
			check: func(t *testing.T, m agent.EnterpriseBGPRouterManager) {
				require.NotNil(t, m)
				require.IsType(t, ossRouterManager, m)
			},
		},
		{
			name:              "OSS enabled Enterprise disabled",
			ossEnabled:        true,
			enterpriseEnabled: false,
			check: func(t *testing.T, m agent.EnterpriseBGPRouterManager) {
				require.NotNil(t, m)
				require.IsType(t, ossRouterManager, m)
			},
		},
		{
			name:              "OSS disabled Enterprise enabled",
			ossEnabled:        false,
			enterpriseEnabled: true,
			check: func(t *testing.T, m agent.EnterpriseBGPRouterManager) {
				require.NotNil(t, m)
				require.IsType(t, &BGPRouterManager{}, m)
			},
		},
		{
			name:              "OSS disabled Enterprise disabled",
			ossEnabled:        false,
			enterpriseEnabled: false,
			check: func(t *testing.T, m agent.EnterpriseBGPRouterManager) {
				require.Nil(t, m)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var enterpriseRouterManager agent.EnterpriseBGPRouterManager

			h := hive.New(
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
					func() ossAgent.BGPRouterManager {
						return ossRouterManager
					},
					NewBGPRouterManager,
				),
				cell.Invoke(func(m agent.EnterpriseBGPRouterManager) {
					enterpriseRouterManager = m
				}),
			)
			require.NoError(t, h.Populate(hivetest.Logger(t)))

			tt.check(t, enterpriseRouterManager)
		})
	}
}

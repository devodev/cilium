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
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/enterprise/pkg/vrf"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	ossManager "github.com/cilium/cilium/pkg/bgp/manager"
	"github.com/cilium/cilium/pkg/bgp/manager/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
)

func TestNewBGPRouterManager(t *testing.T) {
	tests := []struct {
		name              string
		enterpriseEnabled bool
		check             func(t *testing.T, m agent.EnterpriseBGPRouterManager, notifier reconcilerv2.StateChangeNotifier)
	}{
		{
			name:              "Enterprise enabled",
			enterpriseEnabled: true,
			check: func(t *testing.T, m agent.EnterpriseBGPRouterManager, notifier reconcilerv2.StateChangeNotifier) {
				require.NotNil(t, m)
				require.NotNil(t, notifier)
				require.IsType(t, &BGPRouterManager{}, m)
				require.Same(t, m, notifier)
			},
		},
		{
			name:              "Enterprise disabled",
			enterpriseEnabled: false,
			check: func(t *testing.T, m agent.EnterpriseBGPRouterManager, notifier reconcilerv2.StateChangeNotifier) {
				require.Nil(t, m)
				require.Nil(t, notifier)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				enterpriseRouterManager agent.EnterpriseBGPRouterManager
				notifier                reconcilerv2.StateChangeNotifier
			)

			h := hive.New(
				metrics.Metric(ossManager.NewBGPManagerMetrics),
				cell.Config(cmtypes.DefaultClusterInfo),
				node.LocalNodeStoreTestCell,
				cell.Provide(
					gobgp.NewEnterpriseRouterProvider,
					tables.NewBGPReconcileErrorTable,
					func(db *statedb.DB) (statedb.Table[vrf.VRF], error) {
						return vrf.NewVRFTable(db)
					},
					func() config.Config {
						return config.Config{
							Enabled: tt.enterpriseEnabled,
						}
					},
					NewBGPRouterManager,
				),
				cell.Invoke(func(m agent.EnterpriseBGPRouterManager, n reconcilerv2.StateChangeNotifier) {
					enterpriseRouterManager = m
					notifier = n
				}),
			)
			require.NoError(t, h.Populate(hivetest.Logger(t)))

			tt.check(t, enterpriseRouterManager, notifier)
		})
	}
}

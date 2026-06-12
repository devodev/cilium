//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lbipam

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	bgpConfig "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	agentK8s "github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/option"
)

func TestEnterpriseLoadBalancerClass(t *testing.T) {
	tests := []struct {
		name              string
		ossBGPEnabled     bool
		ceeBGPEnabled     bool
		expectedLBClasses []string
	}{
		{
			name:              "All disabled",
			ossBGPEnabled:     false,
			ceeBGPEnabled:     false,
			expectedLBClasses: []string{},
		},
		{
			name:          "OSS BGP enabled",
			ossBGPEnabled: true,
			ceeBGPEnabled: false,
			expectedLBClasses: []string{
				v2alpha1.BGPLoadBalancerClass,
			},
		},
		{
			name:          "OSS and CEE BGP enabled",
			ossBGPEnabled: true,
			ceeBGPEnabled: true,
			expectedLBClasses: []string{
				v2alpha1.BGPLoadBalancerClass,
			},
		},
		{
			name:          "Only CEE BGP enabled",
			ossBGPEnabled: false,
			ceeBGPEnabled: true,
			expectedLBClasses: []string{
				v2alpha1.BGPLoadBalancerClass,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ipam *LBIPAM

			h := hive.New(
				Cell,
				EnterpriseCell,
				k8s.ResourcesCell,
				testutils.FakeClientCell(),

				cell.Provide(
					agentK8s.ServiceResource,
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableBGPControlPlane: tt.ossBGPEnabled,
						}
					},
				),

				cell.Config(bgpConfig.DefaultConfig),

				cell.Invoke(func(_ipam *LBIPAM) {
					ipam = _ipam
				}),
			)
			hive.AddConfigOverride(h, func(cfg *bgpConfig.Config) {
				cfg.Enabled = tt.ceeBGPEnabled
			})

			err := h.Populate(hivetest.Logger(t))
			require.NoError(t, err)

			require.ElementsMatch(t, tt.expectedLBClasses, ipam.lbClasses, "LB classes didn't match to the expected values")
		})
	}
}

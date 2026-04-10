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

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
)

type fakeWgConfig struct {
	EnableWireguard bool
}

func (fwc fakeWgConfig) Enabled() bool {
	return fwc.EnableWireguard
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		dcfg      *option.DaemonConfig
		kprCfg    kpr.KPRConfig
		wgCfg     fakeWgConfig
		ipsecCfg  ipsecTypes.Config
		assertion func(t assert.TestingT, err error, msgAndArgs ...any) bool
	}{
		{
			name: "ClusterAwareAddressing disabled",
			cfg: Config{
				EnableClusterAwareAddressing: false,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg: &option.DaemonConfig{
				RoutingMode: option.RoutingModeNative,
			},
			kprCfg: kpr.KPRConfig{
				KubeProxyReplacement: false,
			},
			assertion: assert.NoError,
		},
		{
			name: "ClusterAwareAddressing disabled but InterClusterSNAT enabled",
			cfg: Config{
				EnableInterClusterSNAT:       true,
				EnableClusterAwareAddressing: false,
				EnablePhantomServices:        true,
			},
			dcfg:      &option.DaemonConfig{},
			kprCfg:    kpr.KPRConfig{},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and native routing mode",
			cfg: Config{
				EnableClusterAwareAddressing: true,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg:      &option.DaemonConfig{RoutingMode: option.RoutingModeNative},
			kprCfg:    kpr.KPRConfig{},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and KPR true",
			cfg: Config{
				EnableClusterAwareAddressing: true,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg: &option.DaemonConfig{},
			kprCfg: kpr.KPRConfig{
				KubeProxyReplacement: true,
			},
			assertion: assert.NoError,
		},
		{
			name: "ClusterAwareAddressing enabled and KPR false",
			cfg: Config{
				EnableClusterAwareAddressing: true,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg: &option.DaemonConfig{},
			kprCfg: kpr.KPRConfig{
				KubeProxyReplacement: false,
			},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and EndpointRoutes enabled",
			cfg: Config{
				EnableClusterAwareAddressing: true,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg:      &option.DaemonConfig{EnableEndpointRoutes: true},
			kprCfg:    kpr.KPRConfig{},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and EndpointHealthChecking enabled",
			cfg: Config{
				EnableClusterAwareAddressing: true,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg:      &option.DaemonConfig{EnableEndpointHealthChecking: true},
			kprCfg:    kpr.KPRConfig{},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and IPSec encryption enabled",
			cfg: Config{
				EnableClusterAwareAddressing: true,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg:      &option.DaemonConfig{},
			kprCfg:    kpr.KPRConfig{},
			ipsecCfg:  ipsecTypes.Config{EnableIPsec: true},
			assertion: assert.Error,
		},
		{
			name: "ClusterAwareAddressing enabled and Wireguard encryption enabled",
			cfg: Config{
				EnableClusterAwareAddressing: true,
				EnableInterClusterSNAT:       false,
				EnablePhantomServices:        true,
			},
			dcfg:      &option.DaemonConfig{},
			kprCfg:    kpr.KPRConfig{},
			wgCfg:     fakeWgConfig{EnableWireguard: true},
			assertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.cfg.Validate(tt.dcfg, tt.kprCfg, tt.wgCfg, tt.ipsecCfg))
		})
	}
}

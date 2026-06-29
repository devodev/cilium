//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/option"
	daemonOption "github.com/cilium/cilium/pkg/option"
)

type mockEnterpriseFeatures struct {
	EnterpriseBGPEnabled bool
	BFDEnabled           bool
}

func (p mockEnterpriseFeatures) IsEnterpriseBGPEnabled() bool {
	return p.EnterpriseBGPEnabled
}

func (p mockEnterpriseFeatures) IsBFDEnabled() bool {
	return p.BFDEnabled
}

func TestUpdateEnterpriseBGPEnabled(t *testing.T) {
	tests := []struct {
		name                string
		enableEnterpriseBGP bool
		expected            float64
	}{
		{
			name:                "Enterprise BGP enabled",
			enableEnterpriseBGP: true,
			expected:            1,
		},
		{
			name:                "Enterprise BGP disabled",
			enableEnterpriseBGP: false,
			expected:            0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.OperatorConfig{}
			daemonConfig := &daemonOption.DaemonConfig{}

			params := mockEnterpriseFeatures{
				EnterpriseBGPEnabled: tt.enableEnterpriseBGP,
			}

			metrics.update(params, config, daemonConfig)

			counterValue := metrics.ACLBEnterpriseBGPEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEnterpriseBGP, counterValue)
		})
	}
}

func TestUpdateBFDEnabled(t *testing.T) {
	tests := []struct {
		name      string
		enableBFD bool
		expected  float64
	}{
		{
			name:      "BFD enabled",
			enableBFD: true,
			expected:  1,
		},
		{
			name:      "BFD disabled",
			enableBFD: false,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.OperatorConfig{}
			daemonConfig := &daemonOption.DaemonConfig{}

			params := mockEnterpriseFeatures{
				BFDEnabled: tt.enableBFD,
			}

			metrics.update(params, config, daemonConfig)

			counterValue := metrics.ACLBBFDEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableBFD, counterValue)
		})
	}
}

func TestUpdateEgressGatewayHAEnabled(t *testing.T) {
	tests := []struct {
		name                  string
		enableEgressGatewayHA bool
		expected              float64
	}{
		{
			name:                  "Egress Gateway HA enabled",
			enableEgressGatewayHA: true,
			expected:              1,
		},
		{
			name:                  "Egress Gateway HA disabled",
			enableEgressGatewayHA: false,
			expected:              0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.OperatorConfig{}
			daemonConfig := &daemonOption.DaemonConfig{
				EnterpriseDaemonConfig: daemonOption.EnterpriseDaemonConfig{
					EnableIPv4EgressGatewayHA: tt.enableEgressGatewayHA,
				},
			}

			params := mockEnterpriseFeatures{}

			metrics.update(params, config, daemonConfig)

			counterValue := metrics.ACLBEgressGatewayHAEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEgressGatewayHA, counterValue)
		})
	}
}

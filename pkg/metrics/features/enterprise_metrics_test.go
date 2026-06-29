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

	"github.com/cilium/cilium/pkg/option"

	"github.com/stretchr/testify/assert"
)

type mockEnterpriseFeatures struct {
	EnterpriseBGPEnabled           bool
	BFDEnabled                     bool
	EgressGatewayStandaloneEnabled bool
	MixedRoutingModeEnabled        bool
	EncryptionPolicyEnabled        bool
	PhantomServicesEnabled         bool
	OverlappingPodCIDREnabled      bool
	FQDNHAEnabled                  bool
	FQDNOfflineModeEnabled         bool
	MulticastEnabled               bool
}

func (m mockEnterpriseFeatures) IsEnterpriseBGPEnabled() bool {
	return m.EnterpriseBGPEnabled
}

func (m mockEnterpriseFeatures) IsBFDEnabled() bool {
	return m.BFDEnabled
}

func (m mockEnterpriseFeatures) IsEgressGatewayStandaloneEnabled() bool {
	return m.EgressGatewayStandaloneEnabled
}

func (m mockEnterpriseFeatures) IsMixedRoutingEnabled() bool {
	return m.MixedRoutingModeEnabled
}

func (m mockEnterpriseFeatures) IsEncryptionPolicyEnabled() bool {
	return m.EncryptionPolicyEnabled
}

func (m mockEnterpriseFeatures) IsFQDNHAEnabled() bool {
	return m.FQDNHAEnabled
}

func (m mockEnterpriseFeatures) IsFQDNOfflineModeEnabled() bool {
	return m.FQDNOfflineModeEnabled
}

func (m mockEnterpriseFeatures) IsPhantomServicesEnabled() bool {
	return m.PhantomServicesEnabled
}

func (m mockEnterpriseFeatures) IsOverlappingPodCIDREnabled() bool {
	return m.OverlappingPodCIDREnabled
}

func (m mockEnterpriseFeatures) IsMulticastEnabled() bool {
	return m.MulticastEnabled
}

func TestUpdateSRv6(t *testing.T) {
	tests := []struct {
		name       string
		enableSRv6 bool
		expected   float64
	}{
		{
			name:       "SRv6 enabled",
			enableSRv6: true,
			expected:   1,
		},
		{
			name:       "SRv6 disabled",
			enableSRv6: false,
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{
				EnableSRv6: tt.enableSRv6,
			}

			params := mockEnterpriseFeatures{}

			metrics.update(params, config)

			counterValue := metrics.ACLBSRv6.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableSRv6, counterValue)
		})
	}
}

func TestUpdateEnterpriseBGP(t *testing.T) {
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
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				EnterpriseBGPEnabled: tt.enableEnterpriseBGP,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBEnterpriseBGPEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEnterpriseBGP, counterValue)
		})
	}
}

func TestUpdateBFD(t *testing.T) {
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
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				BFDEnabled: tt.enableBFD,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBBFDEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableBFD, counterValue)
		})
	}
}

func TestUpdateEgressGatewayHA(t *testing.T) {
	tests := []struct {
		name                      string
		enableIPv4EgressGatewayHA bool
		expected                  float64
	}{
		{
			name:                      "Egress Gateway HA enabled",
			enableIPv4EgressGatewayHA: true,
			expected:                  1,
		},
		{
			name:                      "Egress Gateway HA disabled",
			enableIPv4EgressGatewayHA: false,
			expected:                  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{
				EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
					EnableIPv4EgressGatewayHA: tt.enableIPv4EgressGatewayHA,
				},
			}

			params := mockEnterpriseFeatures{}

			metrics.update(params, config)

			counterValue := metrics.ACLBEgressGatewayHAEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableIPv4EgressGatewayHA, counterValue)
		})
	}
}

func TestUpdateEgressGatewayStandalone(t *testing.T) {
	tests := []struct {
		name                          string
		enableEgressGatewayStandalone bool
		expected                      float64
	}{
		{
			name:                          "Egress Gateway Standalone enabled",
			enableEgressGatewayStandalone: true,
			expected:                      1,
		},
		{
			name:                          "Egress Gateway Standalone disabled",
			enableEgressGatewayStandalone: false,
			expected:                      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				EgressGatewayStandaloneEnabled: tt.enableEgressGatewayStandalone,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBEgressGatewayStandaloneEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEgressGatewayStandalone, counterValue)
		})
	}
}

func TestUpdateMixedRoutingMode(t *testing.T) {
	tests := []struct {
		name                   string
		enableMixedRoutingMode bool
		expected               float64
	}{
		{
			name:                   "Mixed Routing Mode enabled",
			enableMixedRoutingMode: true,
			expected:               1,
		},
		{
			name:                   "Mixed Routing Mode disabled",
			enableMixedRoutingMode: false,
			expected:               0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				MixedRoutingModeEnabled: tt.enableMixedRoutingMode,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBMixedRoutingModeEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableMixedRoutingMode, counterValue)
		})
	}
}

func TestUpdateEncryptionPolicy(t *testing.T) {
	tests := []struct {
		name                   string
		enableEncryptionPolicy bool
		expected               float64
	}{
		{
			name:                   "Encryption Policy enabled",
			enableEncryptionPolicy: true,
			expected:               1,
		},
		{
			name:                   "Encryption Policy disabled",
			enableEncryptionPolicy: false,
			expected:               0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				EncryptionPolicyEnabled: tt.enableEncryptionPolicy,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBEncryptionPolicyEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEncryptionPolicy, counterValue)
		})
	}
}

func TestUpdatePhantomServices(t *testing.T) {
	tests := []struct {
		name                  string
		enablePhantomServices bool
		expected              float64
	}{
		{
			name:                  "Phantom Services enabled",
			enablePhantomServices: true,
			expected:              1,
		},
		{
			name:                  "Phantom Services disabled",
			enablePhantomServices: false,
			expected:              0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				PhantomServicesEnabled: tt.enablePhantomServices,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBPhantomServicesEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enablePhantomServices, counterValue)
		})
	}
}

func TestUpdateOverlappingPodCIDR(t *testing.T) {
	tests := []struct {
		name                     string
		enableOverlappingPodCIDR bool
		expected                 float64
	}{
		{
			name:                     "Overlapping Pod CIDR enabled",
			enableOverlappingPodCIDR: true,
			expected:                 1,
		},
		{
			name:                     "Overlapping Pod CIDR disabled",
			enableOverlappingPodCIDR: false,
			expected:                 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				OverlappingPodCIDREnabled: tt.enableOverlappingPodCIDR,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBOverlappingPodCIDREnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableOverlappingPodCIDR, counterValue)
		})
	}
}

func TestUpdateFQDNHA(t *testing.T) {
	tests := []struct {
		name         string
		enableFQDNHA bool
		expected     float64
	}{
		{
			name:         "FQDN HA enabled",
			enableFQDNHA: true,
			expected:     1,
		},
		{
			name:         "FQDN HA disabled",
			enableFQDNHA: false,
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				FQDNHAEnabled: tt.enableFQDNHA,
			}

			metrics.update(params, config)

			counterValue := metrics.CPFQDNHAEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableFQDNHA, counterValue)
		})
	}
}

func TestUpdateFQDNOfflineMode(t *testing.T) {
	tests := []struct {
		name                  string
		enableFQDNOfflineMode bool
		expected              float64
	}{
		{
			name:                  "FQDN Offline Mode enabled",
			enableFQDNOfflineMode: true,
			expected:              1,
		},
		{
			name:                  "FQDN Offline Mode disabled",
			enableFQDNOfflineMode: false,
			expected:              0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				FQDNOfflineModeEnabled: tt.enableFQDNOfflineMode,
			}

			metrics.update(params, config)

			counterValue := metrics.CPFQDNOfflineModeEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableFQDNOfflineMode, counterValue)
		})
	}
}

func TestUpdateMulticast(t *testing.T) {
	tests := []struct {
		name            string
		enableMulticast bool
		expected        float64
	}{
		{
			name:            "Multicast enabled",
			enableMulticast: true,
			expected:        1,
		},
		{
			name:            "Multicast disabled",
			enableMulticast: false,
			expected:        0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				MulticastEnabled: tt.enableMulticast,
			}

			metrics.update(params, config)

			counterValue := metrics.DPMulticastEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableMulticast, counterValue)
		})
	}
}

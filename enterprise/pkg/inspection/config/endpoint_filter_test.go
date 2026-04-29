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

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func TestEndpointFilter_EnabledForEndpoint(t *testing.T) {
	selector := policyTypes.NewLabelSelectorFromLabels(
		labels.NewLabel(ciliumio.PodNamespaceMetaNameLabel, "payments", labels.LabelSourceK8s),
	)

	matchedIdentity := identity.NumericIdentity(1001)
	unmatchedIdentity := identity.NumericIdentity(1002)

	store := newTestSelectorStore(t, identity.IdentityMap{
		matchedIdentity: labels.Map2Labels(map[string]string{
			ciliumio.PodNamespaceMetaNameLabel: "payments",
			"app":                              "checkout",
		}, labels.LabelSourceK8s).LabelArray(),
		unmatchedIdentity: labels.Map2Labels(map[string]string{
			ciliumio.PodNamespaceMetaNameLabel: "default",
			"app":                              "client",
		}, labels.LabelSourceK8s).LabelArray(),
	})
	store.SetSelector(selector)
	filter := NewEndpointFilter(Config{Enabled: true}, store)

	require.True(t, filter.EnabledForEndpoint(fakeSelectorEndpoint{id: newFakeIdentity(map[string]string{
		ciliumio.PodNamespaceMetaNameLabel: "payments",
		"app":                              "checkout",
	})}))
	require.True(t, filter.EnabledForEndpoint(fakeConfigEndpoint{id: matchedIdentity}))
	require.False(t, filter.EnabledForEndpoint(fakeConfigEndpoint{id: unmatchedIdentity, properties: map[string]any{PropertyEndpointEnabled: true}}))

	require.False(t, NewEndpointFilter(Config{}, store).EnabledForEndpoint(fakeConfigEndpoint{
		id:         matchedIdentity,
		properties: map[string]any{PropertyEndpointEnabled: true},
	}))
}

func TestEndpointFilter_EnabledForEndpoint_IgnoresHostIdentity(t *testing.T) {
	store := newTestSelectorStore(t, identity.IdentityMap{
		identity.ReservedIdentityHost: labels.LabelHost.LabelArray(),
	})
	store.SetSelector(policyTypes.HostSelector)
	filter := NewEndpointFilter(Config{Enabled: true}, store)

	require.False(t, filter.EnabledForEndpoint(fakeConfigEndpoint{
		id:         identity.ReservedIdentityHost,
		properties: map[string]any{PropertyEndpointEnabled: true},
	}))
}

func TestEndpointFilter_EnabledForEndpoint_IgnoresSelectorEndpointHostIdentity(t *testing.T) {
	store := NewSelectorStore()
	store.SetSelector(nil)
	filter := NewEndpointFilter(Config{Enabled: true}, store)

	require.False(t, filter.EnabledForEndpoint(fakeSelectorEndpoint{
		id: &identity.Identity{
			ID:     identity.ReservedIdentityHost,
			Labels: labels.LabelHost,
		},
		properties: map[string]any{PropertyEndpointEnabled: true},
	}))
}

func TestEndpointFilter_EnabledForEndpoint_FallsBackToPropertyWhenSelectorUnavailable(t *testing.T) {
	filter := NewEndpointFilter(Config{Enabled: true}, NewSelectorStore())

	require.True(t, filter.EnabledForEndpoint(fakeConfigEndpoint{
		properties: map[string]any{PropertyEndpointEnabled: true},
	}))
	require.False(t, (*EndpointFilter)(nil).EnabledForEndpoint(fakeConfigEndpoint{
		properties: map[string]any{PropertyEndpointEnabled: true},
	}))
}

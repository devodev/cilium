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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func TestSelectorStore_DesiredEnabledForEndpoint(t *testing.T) {
	store := NewSelectorStore()
	// Selector matches the "payments" namespace.
	selector := policyTypes.NewLabelSelectorFromLabels(
		labels.NewLabel(ciliumio.PodNamespaceMetaNameLabel, "payments", labels.LabelSourceK8s),
	)
	store.SetSelector(selector)

	tests := []struct {
		name string
		ep   fakeSelectorEndpoint
		want bool
	}{
		{
			name: "matched endpoint is enabled",
			ep: fakeSelectorEndpoint{
				id: newFakeIdentity(map[string]string{
					ciliumio.PodNamespaceMetaNameLabel: "payments",
					"app":                              "checkout",
				}),
			},
			want: true,
		},
		{
			name: "non matched endpoint is disabled",
			ep: fakeSelectorEndpoint{
				id: newFakeIdentity(map[string]string{
					ciliumio.PodNamespaceMetaNameLabel: "default",
					"app":                              "client",
				}),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := store.DesiredEnabledForEndpoint(tt.ep)
			require.True(t, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSelectorStore_DesiredEnabledForEndpoint_AuthorityAndWildcard(t *testing.T) {
	matchedEndpoint := fakeSelectorEndpoint{
		id: newFakeIdentity(map[string]string{
			ciliumio.PodNamespaceMetaNameLabel: "payments",
			"app":                              "checkout",
		}),
	}

	enabled, ok := (*SelectorStore)(nil).DesiredEnabledForEndpoint(matchedEndpoint)
	require.False(t, ok)
	require.False(t, enabled)

	store := NewSelectorStore()
	require.False(t, store.HasSelector())
	enabled, ok = store.DesiredEnabledForEndpoint(matchedEndpoint)
	require.False(t, ok)
	require.False(t, enabled)

	store.SetSelector(nil)
	require.True(t, store.HasSelector())
	enabled, ok = store.DesiredEnabledForEndpoint(matchedEndpoint)
	require.True(t, ok)
	require.True(t, enabled)
	enabled, ok = store.DesiredEnabledForEndpoint(fakeSelectorEndpoint{})
	require.True(t, ok)
	require.False(t, enabled)

	store.SetSelectNone()
	enabled, ok = store.DesiredEnabledForEndpoint(matchedEndpoint)
	require.True(t, ok)
	require.False(t, enabled)
}

func TestSelectorStore_DesiredEnabledForEndpoint_UnmatchableEndpoint(t *testing.T) {
	store := NewSelectorStore()
	store.SetSelector(policyTypes.NewLabelSelectorFromLabels(
		labels.NewLabel(ciliumio.PodNamespaceMetaNameLabel, "payments", labels.LabelSourceK8s),
	))

	tests := []struct {
		name   string
		ep     fakeSelectorEndpoint
		wantOK bool
	}{
		{
			name:   "non kubernetes endpoint is authoritatively disabled",
			ep:     fakeSelectorEndpoint{},
			wantOK: true,
		},
		{
			name: "missing identity is not authoritative",
			ep: fakeSelectorEndpoint{
				k8sMetadataSet: true,
			},
		},
		{
			name: "identity error is not authoritative",
			ep: fakeSelectorEndpoint{
				k8sMetadataSet: true,
				identityErr:    errors.New("identity unavailable"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, ok := store.DesiredEnabledForEndpoint(tt.ep)
			require.Equal(t, tt.wantOK, ok)
			require.False(t, enabled)
		})
	}
}

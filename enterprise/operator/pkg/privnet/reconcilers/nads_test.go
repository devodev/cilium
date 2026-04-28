// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
)

func TestDesiredNADName(t *testing.T) {
	type NN = tables.NamespacedName

	var (
		db      = statedb.New()
		nads, _ = tables.NewNetworkAttachmentDefinitionsTable(db)
		tbl, _  = tables.NewDesiredNetworkAttachmentDefinitionsTable(db)

		reconciler = NetworkAttachmentDefinitions{
			db: db, nads: nads, tbl: tbl,
		}

		cfg = func(network tables.NetworkName, subnet tables.SubnetName) tables.NADCNIConfig {
			return tables.NADCNIConfig{PrivateNetworks: tables.NADCNIConfigPrivateNetworks{
				Network: string(network), Subnet: string(subnet)}}
		}
	)

	wtx := db.WriteTxn(nads, tbl)

	for _, nad := range []tables.NetworkAttachmentDefinition{
		{NamespacedName: NN{Namespace: "default", Name: "baz"}, CNIConfig: cfg("cod", "sunfish"), Managed: true},
		{NamespacedName: NN{Namespace: "default", Name: "bar"}, CNIConfig: cfg("cod", "javelin")},
		{NamespacedName: NN{Namespace: "default", Name: "qux"}, CNIConfig: cfg("012345.shy.cod", "raccoon"), Managed: true},
	} {
		nads.Insert(wtx, nad)
	}

	for _, nad := range []tables.DesiredNetworkAttachmentDefinition{
		{NamespacedName: NN{Namespace: "other", Name: "cod-javelin"}, Network: "cod", Subnet: "other"},
		{NamespacedName: NN{Namespace: "other", Name: "cod-javelin-kfo"}, Network: "cod", Subnet: "other"},
		{NamespacedName: NN{Namespace: "other", Name: "cod-raccoon"}, Network: "cod", Subnet: "other"},
		{NamespacedName: NN{Namespace: "other", Name: "cod-raccoon-k6t"}, Network: "cod", Subnet: "other"},
		{NamespacedName: NN{Namespace: "other", Name: "cod-raccoon-ap5"}, Network: "cod", Subnet: "other"},
		{NamespacedName: NN{Namespace: "other", Name: "cod-raccoon-klt"}, Network: "cod", Subnet: "other"},
		{NamespacedName: NN{Namespace: "other", Name: "cod-raccoon-bil"}, Network: "cod", Subnet: "other"},
		{NamespacedName: NN{Namespace: "other", Name: "nad-012345-shy-cod-raccoon"}, Network: "012345.shy.cod", Subnet: "other"},
		{NamespacedName: NN{
			Namespace: "other",
			Name:      fmt.Sprintf("%s-6a2p-%s", strings.Repeat("a", 180), strings.Repeat("b", 63)),
		}, Network: "cod", Subnet: "other"},
	} {
		tbl.Insert(wtx, nad)
	}

	wtx.Commit()

	tests := []struct {
		name      string
		network   tables.NetworkName
		subnet    tables.SubnetName
		namespace string

		expected    string
		expectedErr string
	}{
		{
			name:    "match, managed",
			network: "cod", subnet: "sunfish", namespace: "default",
			expected: "baz",
		},
		{
			name:    "match, not managed",
			network: "cod", subnet: "javelin", namespace: "default",
			expected: "cod-javelin",
		},
		{
			name:    "no match, no conflict",
			network: "cod", subnet: "sunfish", namespace: "other",
			expected: "cod-sunfish",
		},
		{
			name:    "no match, conflict",
			network: "cod", subnet: "javelin", namespace: "other",
			expected: "cod-javelin-nek",
		},
		{
			name:    "no match, repeated conflict",
			network: "cod", subnet: "raccoon", namespace: "other",
			expectedErr: "conflict, despite retries",
		},
		{
			name:      "no match, no conflict, long names",
			network:   tables.NetworkName(strings.Repeat("a", 253)),
			subnet:    tables.SubnetName(strings.Repeat("b", 63)),
			namespace: "default",
			expected:  fmt.Sprintf("%s-6a2p-%s", strings.Repeat("a", 180), strings.Repeat("b", 63)),
		},
		{
			name:      "no match, conflict, long names",
			network:   tables.NetworkName(strings.Repeat("a", 253)),
			subnet:    tables.SubnetName(strings.Repeat("b", 63)),
			namespace: "other",
			expected:  fmt.Sprintf("%s-6a2p-%s-sm6", strings.Repeat("a", 180), strings.Repeat("b", 63)),
		},
		{
			name:    "match, no conflict, name with dots and leading 0",
			network: "012345.shy.cod", subnet: "raccoon", namespace: "default",
			expected: "qux",
		},
		{
			name:    "no match, no conflict, name with dots",
			network: "shy.cod", subnet: "raccoon", namespace: "other",
			expected: "shy-cod-raccoon",
		},
		{
			name:    "no match, no conflict, leading 0",
			network: "012345-foo", subnet: "raccoon", namespace: "other",
			expected: "nad-012345-foo-raccoon",
		},
		{
			name:      "no match, no conflict, long name with dots and leading 0",
			network:   tables.NetworkName("00." + strings.Repeat("a", 250)),
			subnet:    tables.SubnetName(strings.Repeat("b", 63)),
			namespace: "other",
			expected:  fmt.Sprintf("nad-00-%s-4tp1-%s", strings.Repeat("a", 173), strings.Repeat("b", 63)),
		},
		{
			name:    "no match, conflict, name with dots and leading 0",
			network: "012345.shy.cod", subnet: "raccoon", namespace: "other",
			expected: "nad-012345-shy-cod-raccoon-r2b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := reconciler.desiredNADName(db.ReadTxn(), tt.network, tt.subnet, tt.namespace)
			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Empty(t, got)
				return
			}

			require.NoError(t, err, "reconciler.desiredNADName")
			require.Equal(t, tt.expected, got)
			require.LessOrEqual(t, len(got), 253)
			require.Regexp(t, `^[a-z-1-9]([-a-z0-9]*[a-z0-9])?$`, got)
		})
	}
}

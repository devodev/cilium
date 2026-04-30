//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package wafpolicy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReconcileInlineBundleData(t *testing.T) {
	expectedInline, err := BuildInlineRules(`SecAction "id:1000,phase:1,pass,nolog"`)
	require.NoError(t, err)

	otherInline, err := BuildInlineRules(`SecAction "id:1001,phase:1,pass,nolog"`)
	require.NoError(t, err)

	testCases := []struct {
		name                  string
		existing              map[string]string
		policyRef             string
		desiredHashKey        string
		desiredInline         string
		expectedInlineRules   map[string]string
		expectedInlineMetdata map[string]inlineMetadata
	}{
		{
			name: "reassigns policy and prunes stale bundle",
			existing: combineInlineBundleData(
				map[string]string{
					"stale":                `{"policies":["team-a/policy-a"]}`,
					otherInline.HashKey:    `{"policies":["team-b/policy-b"]}`,
					expectedInline.HashKey: `{"policies":["team-c/policy-c"]}`,
				},
				map[string]string{
					"stale":                "stale-inline",
					otherInline.HashKey:    otherInline.Inline,
					expectedInline.HashKey: expectedInline.Inline,
				},
			),
			policyRef:      "team-a/policy-a",
			desiredHashKey: expectedInline.HashKey,
			desiredInline:  expectedInline.Inline,
			expectedInlineRules: map[string]string{
				otherInline.HashKey:    otherInline.Inline,
				expectedInline.HashKey: expectedInline.Inline,
			},
			expectedInlineMetdata: map[string]inlineMetadata{
				otherInline.HashKey:    {Policies: []string{"team-b/policy-b"}},
				expectedInline.HashKey: {Policies: []string{"team-a/policy-a", "team-c/policy-c"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := reconcileInlineBundleState(tc.existing, tc.policyRef, tc.desiredHashKey, tc.desiredInline)
			require.NoError(t, err)
			require.Equal(t, tc.expectedInlineRules, extractInlineRules(actual))
			requireInlineBundleMetadataData(t, actual, tc.expectedInlineMetdata)
		})
	}
}

func TestRemovePolicyInlineRulesData(t *testing.T) {
	expectedInline, err := BuildInlineRules(`SecAction "id:1000,phase:1,pass,nolog"`)
	require.NoError(t, err)

	otherInline, err := BuildInlineRules(`SecAction "id:1001,phase:1,pass,nolog"`)
	require.NoError(t, err)

	testCases := []struct {
		name                   string
		existing               map[string]string
		policyRef              string
		expectedHashesToDelete map[string]struct{}
		expectedInlineRules    map[string]string
		expectedInlineMetdata  map[string]inlineMetadata
	}{
		{
			name: "removes only unreferenced hashes",
			existing: combineInlineBundleData(
				map[string]string{
					expectedInline.HashKey: `{"policies":["team-a/policy-a"]}`,
					otherInline.HashKey:    `{"policies":["team-a/policy-a","team-b/policy-b"]}`,
				},
				map[string]string{
					expectedInline.HashKey: expectedInline.Inline,
					otherInline.HashKey:    otherInline.Inline,
				},
			),
			policyRef: "team-a/policy-a",
			expectedHashesToDelete: map[string]struct{}{
				expectedInline.HashKey: {},
			},
			expectedInlineRules: map[string]string{
				otherInline.HashKey: otherInline.Inline,
			},
			expectedInlineMetdata: map[string]inlineMetadata{
				otherInline.HashKey: {Policies: []string{"team-b/policy-b"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, hashesToDelete, err := removePolicyInlineRulesFromState(tc.existing, tc.policyRef)
			require.NoError(t, err)
			require.Equal(t, tc.expectedHashesToDelete, hashesToDelete)
			require.Equal(t, tc.expectedInlineRules, extractInlineRules(actual))
			requireInlineBundleMetadataData(t, actual, tc.expectedInlineMetdata)
		})
	}
}

func TestInlineBundleDataExtractionAndLayout(t *testing.T) {
	testCases := []struct {
		name              string
		data              map[string]string
		metadata          map[string]string
		inlineRules       map[string]string
		expectedExtracted map[string]string
		expectedMetadata  map[string]string
		expectedCombined  map[string]string
	}{
		{
			name: "extracts only prefixed metadata and inline rules",
			data: map[string]string{
				inlineMetadataPrefix + "hash-a": `{"policies":["team-a/policy-a"]}`,
				inlineMetadataPrefix + "hash-b": `{"policies":["team-b/policy-b"]}`,
				inlineRulePrefix + "hash-a":     "inline-a",
				"other-key":                     "ignored",
			},
			expectedExtracted: map[string]string{
				"hash-a": "inline-a",
			},
			expectedMetadata: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a"]}`,
				"hash-b": `{"policies":["team-b/policy-b"]}`,
			},
		},
		{
			name: "combines metadata and inline rules with prefixes",
			metadata: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a"]}`,
			},
			inlineRules: map[string]string{
				"hash-a": "inline-a",
			},
			expectedCombined: map[string]string{
				inlineMetadataPrefix + "hash-a": `{"policies":["team-a/policy-a"]}`,
				inlineRulePrefix + "hash-a":     "inline-a",
			},
		},
		{
			name:             "empty inputs combine to nil",
			expectedCombined: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.data != nil || tc.expectedExtracted != nil || tc.expectedMetadata != nil {
				require.Equal(t, tc.expectedExtracted, extractInlineRules(tc.data))
				require.Equal(t, tc.expectedMetadata, extractInlineMetadata(tc.data))
			}
			if tc.expectedCombined != nil || (tc.metadata == nil && tc.inlineRules == nil) {
				require.Equal(t, tc.expectedCombined, combineInlineBundleData(tc.metadata, tc.inlineRules))
			}
		})
	}
}

func requireInlineBundleMetadataData(t *testing.T, data map[string]string, expected map[string]inlineMetadata) {
	t.Helper()

	actualMetadataData := extractInlineMetadata(data)
	require.Len(t, actualMetadataData, len(expected))
	for hashKey, expectedMetadata := range expected {
		var actualMetadata inlineMetadata
		err := json.Unmarshal([]byte(actualMetadataData[hashKey]), &actualMetadata)
		require.NoError(t, err)
		require.Equal(t, expectedMetadata, actualMetadata)
	}
}

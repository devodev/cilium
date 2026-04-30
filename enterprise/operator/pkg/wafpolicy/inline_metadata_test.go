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
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseInlineMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		raw      string
		expected inlineMetadata
		wantErr  bool
	}{
		{
			name: "parses valid metadata",
			raw:  `{"policies":["team-a/policy-a","team-b/policy-b"]}`,
			expected: inlineMetadata{
				Policies: []string{"team-a/policy-a", "team-b/policy-b"},
			},
		},
		{
			name:    "rejects invalid json",
			raw:     `not-json`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := parseInlineMetadata(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestMarshalInlineMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		metadata inlineMetadata
		expected string
	}{
		{
			name: "sorts and deduplicates policy refs",
			metadata: inlineMetadata{
				Policies: []string{"team-b/policy-b", "team-a/policy-a", "team-a/policy-a"},
			},
			expected: `{"policies":["team-a/policy-a","team-b/policy-b"]}`,
		},
		{
			name:     "marshals empty metadata",
			metadata: inlineMetadata{},
			expected: `{"policies":null}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := marshalInlineMetadata(tc.metadata)
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestUpsertInlineMetadata(t *testing.T) {
	testCases := []struct {
		name        string
		data        map[string]string
		hashKey     string
		policyRef   string
		expected    map[string]string
		expectedErr string
	}{
		{
			name:      "creates new metadata entry",
			data:      nil,
			hashKey:   "hash-a",
			policyRef: "team-a/policy-a",
			expected: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a"]}`,
			},
		},
		{
			name: "adds policy to existing metadata entry",
			data: map[string]string{
				"hash-a": `{"policies":["team-b/policy-b"]}`,
			},
			hashKey:   "hash-a",
			policyRef: "team-a/policy-a",
			expected: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a","team-b/policy-b"]}`,
			},
		},
		{
			name: "deduplicates existing policy refs on write",
			data: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a","team-a/policy-a"]}`,
			},
			hashKey:   "hash-a",
			policyRef: "team-a/policy-a",
			expected: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a"]}`,
			},
		},
		{
			name: "returns error for invalid metadata",
			data: map[string]string{
				"hash-a": `not-json`,
			},
			hashKey:     "hash-a",
			policyRef:   "team-a/policy-a",
			expectedErr: `failed to parse inline metadata for "hash-a"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]string(nil)
			if tc.data != nil {
				input = make(map[string]string, len(tc.data))
				maps.Copy(input, tc.data)
			}

			actual, err := upsertInlineMetadata(input, tc.hashKey, tc.policyRef)
			if tc.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestRemovePolicyFromMetadata(t *testing.T) {
	testCases := []struct {
		name            string
		data            map[string]string
		hashKey         string
		policyRef       string
		expectedData    map[string]string
		expectedDeleted bool
		expectedErr     string
	}{
		{
			name:            "empty data is a no-op",
			data:            nil,
			hashKey:         "hash-a",
			policyRef:       "team-a/policy-a",
			expectedData:    nil,
			expectedDeleted: false,
		},
		{
			name: "missing hash key is a no-op",
			data: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a"]}`,
			},
			hashKey:   "hash-b",
			policyRef: "team-a/policy-a",
			expectedData: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a"]}`,
			},
			expectedDeleted: false,
		},
		{
			name: "removes single remaining policy and deletes entry",
			data: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a"]}`,
			},
			hashKey:         "hash-a",
			policyRef:       "team-a/policy-a",
			expectedData:    map[string]string{},
			expectedDeleted: true,
		},
		{
			name: "removes matching policy and keeps other refs",
			data: map[string]string{
				"hash-a": `{"policies":["team-a/policy-a","team-b/policy-b"]}`,
			},
			hashKey:   "hash-a",
			policyRef: "team-a/policy-a",
			expectedData: map[string]string{
				"hash-a": `{"policies":["team-b/policy-b"]}`,
			},
			expectedDeleted: false,
		},
		{
			name: "invalid metadata returns error",
			data: map[string]string{
				"hash-a": `not-json`,
			},
			hashKey:     "hash-a",
			policyRef:   "team-a/policy-a",
			expectedErr: `failed to parse inline metadata for "hash-a"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]string(nil)
			if tc.data != nil {
				input = make(map[string]string, len(tc.data))
				maps.Copy(input, tc.data)
			}

			actualData, actualDeleted, err := removePolicyFromMetadata(input, tc.hashKey, tc.policyRef)
			if tc.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedDeleted, actualDeleted)
			require.Equal(t, tc.expectedData, actualData)
		})
	}
}

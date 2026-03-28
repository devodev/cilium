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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	testCases := []struct {
		name     string
		inline   string
		expected string
	}{
		{
			name:     "empty",
			inline:   "",
			expected: "",
		},
		{
			name:     "normalizes line endings and trailing newlines",
			inline:   "SecRuleRemoveById 949110\r\nSecRuleEngine On\r\n\r\n",
			expected: "SecRuleRemoveById 949110\nSecRuleEngine On",
		},
		{
			name:     "trims leading and trailing blank symbols",
			inline:   "\n \tSecAction \"id:1000,phase:1,pass,nolog\"\r\n\r\n\t ",
			expected: "SecAction \"id:1000,phase:1,pass,nolog\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, normalize(tc.inline))
		})
	}
}

func TestHashKey(t *testing.T) {
	testCases := []struct {
		name        string
		inline      string
		expected    string
		expectError bool
	}{
		{
			name:     "empty",
			inline:   "",
			expected: "",
		},
		{
			name:     "hashes normalized inline rules",
			inline:   "SecRuleRemoveById 949110\nSecRuleEngine On\n",
			expected: "crs_inline_sha256_v1_24b978d9ec57e1c0bcb4c5bf615a2faccda8fdf23426f25ff1b85cb37bab8603",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := hashKey(tc.inline)
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestValidateInlineRules(t *testing.T) {
	testCases := []struct {
		name        string
		inline      string
		expectError string
	}{
		{
			name:   "accepts valid inline rules",
			inline: `SecAction "id:1000,phase:1,pass,nolog"` + "\r\n",
		},
		{
			name:        "rejects inline rules that declare SecRuleEngine",
			inline:      "SecRuleEngine DetectionOnly\r\n",
			expectError: "inline rules must not declare SecRuleEngine",
		},
		{
			name:        "rejects inline rules that declare Include",
			inline:      "Include @crs-setup.conf.example\r\n",
			expectError: "inline rules must not declare Include",
		},
		{
			name:        "rejects syntactically invalid inline rules",
			inline:      `SecRule REQUEST_URI "@rx (" "id:1000,phase:1,deny"`,
			expectError: "effective WAF rule validation failed",
		},
		{
			name:        "rejects empty inline rules",
			inline:      "",
			expectError: "spec.rules.custom.inline must not be empty",
		},
		{
			name:        "rejects whitespace only inline rules",
			inline:      "\r\n\t  \r\n",
			expectError: "spec.rules.custom.inline must not be empty",
		},
		{
			name:        "rejects comment only inline rules",
			inline:      "# comment only",
			expectError: "spec.rules.custom.inline must not be empty",
		},
		{
			name:        "rejects blank and comment only inline rules",
			inline:      "\n\t# comment only\r\n\n# another comment",
			expectError: "spec.rules.custom.inline must not be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateInlineRules(tc.inline)
			if tc.expectError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectError)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestBuildInlineRules(t *testing.T) {
	validInline := `SecAction "id:1000,phase:1,pass,nolog"` + "\r\n"
	validHashKey, err := hashKey(normalize(validInline))
	require.NoError(t, err)

	testCases := []struct {
		name        string
		config      string
		expected    InlineRules
		expectError string
	}{
		{
			name:   "compiles full custom inline rules",
			config: validInline,
			expected: InlineRules{
				Inline:  `SecAction "id:1000,phase:1,pass,nolog"`,
				HashKey: validHashKey,
			},
		},
		{
			name:        "rejects empty inline rules",
			config:      "",
			expectError: "spec.rules.custom.inline must not be empty",
		},
		{
			name:        "rejects whitespace only inline rules",
			config:      "\r\n\t  \r\n",
			expectError: "spec.rules.custom.inline must not be empty",
		},
		{
			name:        "rejects comment only inline rules",
			config:      "# comment only",
			expectError: "spec.rules.custom.inline must not be empty",
		},
		{
			name:        "rejects blank and comment only inline rules",
			config:      "\n\t# comment only\r\n\n# another comment",
			expectError: "spec.rules.custom.inline must not be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := BuildInlineRules(tc.config)
			if tc.expectError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

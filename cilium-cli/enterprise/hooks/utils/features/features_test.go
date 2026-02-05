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

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
)

func TestPhantomServicesEnabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      map[string]string
		vsn      semver.Version
		expected assert.BoolAssertionFunc
	}{
		{
			name:     "Cilium v1.16.0, no feature flag",
			cfg:      map[string]string{},
			vsn:      semver.MustParse("1.16.0"),
			expected: assert.False,
		},
		{
			name:     "Cilium v1.16.0, feature flag disabled",
			cfg:      map[string]string{"enable-phantom-services": "false"},
			vsn:      semver.MustParse("1.16.0"),
			expected: assert.False,
		},
		{
			name:     "Cilium v1.16.0, feature flag enabled",
			cfg:      map[string]string{"enable-phantom-services": "true"},
			vsn:      semver.MustParse("1.16.0"),
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.expected(t, phantomServicesEnabled(tt.cfg, tt.vsn))
		})
	}
}

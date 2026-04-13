//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/enterprise/features"
)

func TestFeatureGates_MinimumMaturity(t *testing.T) {
	log := hivetest.Logger(t)

	// Check through each maturity level and validate that
	// features with higher maturity levels are rejected.
	for _, minimum := range features.FeaturesYaml.Levels {
		gc, err := features.NewGateChecker(log, features.FeatureGatesConfig{
			ApprovedFeatures:   []string{},
			MinimumMaturity:    minimum.Name,
			StrictFeatureGates: true,
		})
		if !assert.NoError(t, err, "newGateChecker") {
			continue
		}

		for id, feat := range features.FeaturesYaml.Features {
			err := gc.CheckFeatureGates(id, feat)
			level := features.FeaturesYaml.LevelByName[feat.Maturity]

			if feat.Maturity == features.UnsupportedMaturity {
				assert.Error(t, err, "expected Unsupported feature %q to always fail", id)
			} else if level.Order <= minimum.Order {
				assert.NoError(t, err, "expected feature %q to pass (maturity %s/%d) with minimum %s/%d", id, level.Name, level.Order, minimum.Name, minimum.Order)
			} else {
				assert.Error(t, err, "expected feature %q to fail (maturity %s/%d) with minimum %s/%d", id, level.Name, level.Order, minimum.Name, minimum.Order)
			}
		}
	}
}

func TestFeatureGates_FeatureGate(t *testing.T) {
	log := hivetest.Logger(t)

	// Check that each feature can be approved with a feature gate,
	// except Unsupported features which must always be rejected.
	for id, feat := range features.FeaturesYaml.Features {
		gc, err := features.NewGateChecker(log, features.FeatureGatesConfig{
			ApprovedFeatures:   []string{id},
			MinimumMaturity:    features.FeaturesYaml.Levels[0].Name,
			StrictFeatureGates: true,
		})
		if assert.NoError(t, err, "newGateChecker") {
			err = gc.CheckFeatureGates(id, feat)
			if feat.Maturity == features.UnsupportedMaturity {
				assert.Error(t, err, "expected Unsupported feature %q to fail even when approved", id)
			} else {
				assert.NoError(t, err, "expected feature %q to pass when added to gates", id)
			}
		}
	}
}

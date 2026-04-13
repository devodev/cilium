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

package features

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/cast"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	logfieldID      = "id"
	logfieldFlags   = "flags"
	logfieldValues  = "values"
	logfieldFeature = "feature"
)

const UnsupportedMaturity = "Unsupported"

var ErrUnsupportedFeatures = errors.New("Unsupported feature(s) enabled")

func featureCheckError(id ID, feat YAMLFeature) error {
	return fmt.Errorf("%s (%s)", id, feat.Maturity)
}

var pleaseContactSupport = "Please contact Isovalent Support for more information on how to grant an exception."

// Validate the feature gates against given settings. This is for building
// CLI tools to validate an existing config map.
func Validate(log *slog.Logger, settings map[string]string) error {
	gates := strings.FieldsFunc(settings[FeatureGatesApprovedFlag], func(r rune) bool { return r == ',' })
	minimum := FeaturesYaml.Levels[0].Name
	if m, ok := settings[FeatureGatesMinimumMaturityFlag]; ok {
		minimum = m
	}
	cfg := FeatureGatesConfig{
		ApprovedFeatures:   gates,
		MinimumMaturity:    minimum,
		StrictFeatureGates: true,
	}
	all2 := make(map[string]any)
	for k, v := range settings {
		all2[k] = v
	}
	return validateFeatureGates(
		log,
		cfg,
		cell.AllSettings(all2),
	)
}

func validateFeatureGates(log *slog.Logger, cfg FeatureGatesConfig, settings cell.AllSettings) error {
	gc, err := NewGateChecker(log, cfg)
	if err != nil {
		return err
	}

	gateErrors := []string{}

	featureIDs := make([]string, 0, len(FeaturesYaml.Features))
	for id := range FeaturesYaml.Features {
		featureIDs = append(featureIDs, id)
	}
	sort.Strings(featureIDs)

	// Check features in sorted order for reproducible error.
	for _, id := range featureIDs {
		feat := FeaturesYaml.Features[id]
		enableCount := 0
		featValues := map[string]string{}
		for flag, value := range feat.Flags {
			v, found := settings[flag]
			if !found {
				// A flag might not be found from settings if it is an operator flag.
				// Since "features/validate" checks that all the features have a flag either
				// in the agent or the operator we assume here that the user has not
				// set the option and that the default for the option is always fine.
				break
			}

			// Convert lower-case for case-insensitive comparisons.
			value = strings.ToLower(value)

			cmpEq := true
			switch {
			case value == "":
				// Unspecified values default to true.
				value = "true"
			case strings.HasPrefix(value, "!"):
				// Values prefixed with '!' negate the check
				cmpEq = false
				value = value[1:]
			}

			// Convert into a string using the 'cast' library, e.g. the same
			// way as Viper.GetString() does it.
			vStr := cast.ToString(v)

			featValues[flag] = vStr

			if cmpEq {
				if vStr == value {
					enableCount++
				}
			} else {
				if vStr != value {
					enableCount++
				}
			}
		}
		if len(feat.Flags) > 0 && enableCount == len(feat.Flags) {
			gc.log.Debug("Feature enabled, checking feature gates",
				logfieldID, id,
				logfieldFlags, feat.Flags,
				logfieldValues, featValues)
			if err := gc.CheckFeatureGates(id, feat); err != nil {
				// We swallow the error type here and produce a string in order to produce
				// a nicer concatenated error below.
				gateErrors = append(gateErrors, err.Error())
			}
		}
	}

	if len(gateErrors) > 0 {
		err = fmt.Errorf("%w: %s. %s",
			ErrUnsupportedFeatures, strings.Join(gateErrors, ", "), pleaseContactSupport)
		gc.log.Warn(err.Error())
	}

	if cfg.StrictFeatureGates {
		return err
	} else {
		return nil
	}
}

type gateChecker struct {
	log              *slog.Logger
	cfg              FeatureGatesConfig
	approvedFeatures sets.Set[string]
	minimumLevel     LevelInfo
}

func NewGateChecker(log *slog.Logger, fcfg FeatureGatesConfig) (*gateChecker, error) {
	gc := &gateChecker{
		cfg:              fcfg,
		log:              log,
		approvedFeatures: sets.Set[string](sets.NewString(fcfg.ApprovedFeatures...)),
	}
	if level, found := FeaturesYaml.LevelByName[fcfg.MinimumMaturity]; !found {
		return nil, fmt.Errorf("unknown maturity %s", fcfg.MinimumMaturity)
	} else {
		gc.minimumLevel = level
	}
	for _, feature := range fcfg.ApprovedFeatures {
		if _, found := FeaturesYaml.Features[feature]; found {
			gc.approvedFeatures.Insert(feature)
		} else {
			// Only log a warning since we might be upgrading and some agents might
			// be running an older version that doesn't yet know about this feature.
			log.Warn("unknown feature in feature gates",
				logfieldFeature, feature)
		}
	}
	return gc, nil
}

func (c *gateChecker) CheckFeatureGates(id ID, feat YAMLFeature) error {
	level := FeaturesYaml.LevelByName[feat.Maturity]
	switch {
	case feat.Maturity == UnsupportedMaturity:
		return featureCheckError(id, feat)
	case level.Order <= c.minimumLevel.Order:
		return nil
	case c.approvedFeatures.Has(id):
		return nil
	default:
		return featureCheckError(id, feat)
	}
}

const (
	ciliumConfigMapName   = "cilium-config"
	featureGateAnnotation = "feature-gate-error"
)

func registerFeatureGatesOperatorValidation(log *slog.Logger, cs client.Clientset, cfg FeatureGatesConfig, settings cell.AllSettings, jg job.Group) {
	if !cs.IsEnabled() {
		return
	}

	// Start a background job to update the config map annotations with the result from
	// the feature gates.
	jg.Add(
		job.OneShot(
			"update-annotation",
			func(ctx context.Context, health cell.Health) error {
				cfg.StrictFeatureGates = true
				var errorValue string
				if err := validateFeatureGates(log, cfg, settings); err != nil {
					errorValue = err.Error()
				}

				path := fmt.Sprintf("/metadata/annotations/%s~1%s", annotation.ConfigPrefix, featureGateAnnotation)
				patches := []k8s.JSONPatch{
					{OP: "add", Path: path, Value: errorValue},
				}
				if errorValue == "" {
					// No error, we can remove the annotation. Note that we do the
					// "add" on purpose even when removing as otherwise "remove" would
					// fail.
					patches = append(patches, k8s.JSONPatch{OP: "remove", Path: path})
				}
				patchBytes, err := json.Marshal(patches)
				if err != nil {
					return fmt.Errorf("failed to marshal patch: %w", err)
				}
				namespace, ok := settings[option.K8sNamespaceName].(string)
				if !ok {
					namespace = metav1.NamespaceSystem
				}
				maps := cs.CoreV1().ConfigMaps(namespace)
				_, err = maps.Patch(
					ctx,
					ciliumConfigMapName,
					types.JSONPatchType,
					patchBytes,
					metav1.PatchOptions{},
				)
				if err != nil {
					return fmt.Errorf("failed to patch configmaps/%s: %w", ciliumConfigMapName, err)
				}
				return nil
			},
			job.WithRetry(10, &job.ExponentialBackoff{
				Min: time.Second,
				Max: time.Minute,
			}),
		),
	)

}

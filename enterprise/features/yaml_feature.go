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
	_ "embed"
	"fmt"
	"regexp"

	"github.com/blang/semver/v4"
	"go.yaml.in/yaml/v3"
)

type ID = string

type LevelInfo struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Order       int    `yaml:"-"`
}

type YAMLFeatures struct {
	Levels      []LevelInfo          `yaml:"maturity"`
	Features    map[ID]YAMLFeature   `yaml:"features"`
	LevelByName map[string]LevelInfo `yaml:"-"`
}

// YAMLFeature is a feature specified in the "features.yaml" file.
type YAMLFeature struct {
	// Description is a short description of the feature. This will be used to generate documentation
	// regarding the feature (with respect to the stage of the feature).
	Description string `yaml:"description,omitempty"`

	// Maturity is the maturity level of the feature, this must be one of Alpha, Beta, or Stable.
	// If Default is false, then stage is used to determine if the feature requires a feature gate
	// to be enabled.
	Maturity string `yaml:"maturity"`

	// Flags are the configuration flags for determining if a feature is enabled or not.
	// This corresponds to a key in the Cilium configmap and can be deduced either
	// through "cilium-agent --help" or via the "install/kubernetes/templates/cilium-configmap.yaml"
	// that generates the configmap.
	//
	// Value is the expected value for the flag that marks it enabled. For
	// boolean this can be omitted (defaulting to "true").
	//
	// NOTE: The value is only partially validated, e.g. if registered flag is bool or int
	// the value is checked to be parseable as such, but enumerations are not validated!
	Flags map[string]string `yaml:"flags"`

	// SkipFlagCheck causes 'tests/validate_test.go' to skip checking this flag.
	SkipFlagCheck bool `yaml:"skip-flag-check"`

	// Helm is the helm options to enable the feature.
	Helm map[string]string `yaml:"helm"`

	// Helm is an optional helm template snippet to check if the feature is enabled.
	// Overrides the generated checks from [Helm]
	HelmCheck string `yaml:"helm-check"`

	// Extra helm options that shall be set when the target feature is enabled,
	// e.g, to fulfill possible validation steps. They are used only by the
	// self-tests, when verifying that the feature flag works correctly.
	HelmTestDeps map[string]string `yaml:"helm-test-deps"`
}

type Version semver.Version

func (v Version) MarshalYAML() (any, error) {
	return semver.Version(v).String(), nil
}

func (v *Version) UnmarshalYAML(value *yaml.Node) error {
	sv, err := semver.Parse(value.Value)
	if err != nil {
		return err
	}
	*v = Version(sv)
	return nil
}

var (
	//go:embed features.yaml
	FeaturesYamlContents []byte
	FeaturesYaml         YAMLFeatures = unmarshalFeatures()
)

func unmarshalFeatures() YAMLFeatures {
	var feats YAMLFeatures
	err := yaml.Unmarshal(FeaturesYamlContents, &feats)
	if err != nil {
		panic(err)
	}
	delete(feats.Features, "Example")

	feats.LevelByName = map[string]LevelInfo{}
	for i := range feats.Levels {
		level := &feats.Levels[i]
		level.Order = i
		feats.LevelByName[level.Name] = *level
	}

	// Validate that the features are well-formed
	if err := validateYAMLFeatures(feats); err != nil {
		panic(err)
	}

	return feats
}

var featureIDValidRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{1,50}$`)

func validateYAMLFeatures(feats YAMLFeatures) error {
	for id, feat := range feats.Features {
		_, found := feats.LevelByName[feat.Maturity]
		switch {
		case !found:
			return fmt.Errorf("feature %s refers to unknown maturity level %s", id, feat.Maturity)
		case !featureIDValidRe.MatchString(id):
			return fmt.Errorf("feature ID %q is invalid, must match %q", id, featureIDValidRe.String())
		case feat.Description == "":
			return fmt.Errorf("feature %s has no description", id)
		}
	}
	return nil

}

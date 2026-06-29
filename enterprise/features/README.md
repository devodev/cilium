# Enterprise feature gates

This package defines features and feature gates for Cilium Enterprise.

## Adding a new feature

1. Edit features.yaml to add in the new feature.

2. Test that the flags refer to real flags: `go test ./enterprise/features/...`
   NOTE: Currently validating only against the flags in OSS agent&operator,
   set 'skip-flag-check' when adding enterprise-only flag.

3. Update the generated helm validation:
   `make -C install/kubernetes cilium/templates/enterprise_features_validate.yaml`.
   This also tests that the helm references are correct.

## Implementation structure

The implementation consists of the following major parts:

### features.yaml

Defines maturity levels and features. A feature defines which configuration flags and helm
options enable the feature.

The `features.yaml` file is embedded into the cilium-agent binary and at agent start-up the
configuration options are validated to pass the feature gates.

### config.go & enterprise.featureGate

Defines the agent configuration flags for feature gates:
* --feature-gates-approved: A list of feature IDs that are approved regardless of maturity
* --feature-gates-minimum-maturity: Minimum maturity for a feature to be automatically approved (Stable, Limited, Beta, Alpha)
* --feature-gates-strict: If set then feature gate error is fatal instead of log message

The corresponding helm options are defined in 
`install/kubernetes/cilium/zz_enterprise_values.yaml.tmpl` and the flags are generated
in `install/kubernetes/cilium/templates/_enterprise.tpl`.

### featuregates.go

Implements the feature gate validation. Provides `Validate` and `validateFeatureGates` functions.

`validateFeatureGates` is `cell.Invoke`d to validate the feature gates in the cilium-agent. You
can test this in action with the `hive` command (for flags coming from cell.Config):

  $ go run ./enterprise/daemon hive --private-networks-enabled --feature-gates-strict=true
  ...
	feature not approved: Beta feature: DatapathIPModeDualStack was enabled, but it is not a supported feature.
  Please contact Isovalent Support for more information on how to grant an exception.
  
  $ go run ./enterprise/daemon hive --private-networks-enabled --feature-gates-strict=true \
    --feature-gates-approved=PrivateNetworks,DatapathIPModeDualStack
  ...

### helm-gen

`helm-gen/main.go` generates a helm template from `features.yaml`. This is invoked
from `install/kubernetes/Makefile` to generate the helm validation template
`install/kubernetes/cilium/templates/enterprise_features_validate.yaml`.

To generate to stdout:

  cilium$ go run ./enterprise/features/helm-gen generate

To regenerate the template file run:

  cilium$ make -C install/kubernetes cilium/templates/enterprise_features_validate.yaml
 
## Tests

There are three tests for checking that `features.yaml` is well formed:

tests/featuregatest_test.go:
Tests the mechanics of feature gates for each defined feature, e.g.
that each feature is only approved if it passes maturity or is explicitly
approved.

tests/flags_test.go:
Tests that all flags defined in features.yaml are registered to either agent or operator.
This way you cannot add a flag that doesn't actually exist.

helm-gen: 
When run with "validate" command it executes "helm template" with different options. 
This test makes sure each helm option mentioned actually exists and that every non-stable feature 
fails when enabled without allowing it and succeeds when approved.

It is invoked in "install/kubernetes" as part of the make target "cilium/templates/enterprise_features_validate.yaml".
See "helm-gen" section above on how to generate and validate the helm template.


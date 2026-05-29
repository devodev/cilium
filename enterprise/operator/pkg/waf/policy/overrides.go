//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"fmt"
	"strings"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func validateRuleOverrides(rules *isovalentv1alpha1.IsovalentWAFPolicyRules) error {
	if rules == nil || len(rules.Overrides) == 0 {
		return nil
	}

	if rules.Profile == nil && rules.Inline != "" {
		return fmt.Errorf("spec.rules.overrides are not supported with standalone inline rules")
	}

	for i, override := range rules.Overrides {
		if err := validateOverride(i, override); err != nil {
			return err
		}
	}

	return nil
}

func validateOverride(idx int, override isovalentv1alpha1.IsovalentWAFRuleOverride) error {
	if override.RuleID < 1 {
		return fmt.Errorf("spec.rules.overrides[%d].ruleID must be greater than 0", idx)
	}

	switch override.Action {
	case isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable:
		if override.Target != "" {
			return fmt.Errorf("spec.rules.overrides[%d].target must be omitted for action %q", idx, override.Action)
		}
	case isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget:
		if override.Target == "" {
			return fmt.Errorf("spec.rules.overrides[%d].target must be specified for action %q", idx, override.Action)
		}
		if err := validateOverrideTarget(idx, override.Target); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported spec.rules.overrides[%d].action %q", idx, override.Action)
	}

	return nil
}

func validateOverrideTarget(idx int, target string) error {
	if strings.TrimSpace(target) != target || target == "" {
		return fmt.Errorf("spec.rules.overrides[%d].target must be a non-empty target in COLLECTION:name form", idx)
	}
	if strings.ContainsAny(target, "| \t\r\n") {
		return fmt.Errorf("spec.rules.overrides[%d].target must not contain whitespace or target separators", idx)
	}

	collection, name, ok := strings.Cut(target, ":")
	if !ok || collection == "" || name == "" {
		return fmt.Errorf("spec.rules.overrides[%d].target must be in COLLECTION:name form", idx)
	}
	if strings.HasPrefix(collection, "!") {
		return fmt.Errorf("spec.rules.overrides[%d].target must not include exclusion prefixes", idx)
	}

	return nil
}

func copyRuleOverrides(in []isovalentv1alpha1.IsovalentWAFRuleOverride) []isovalentv1alpha1.IsovalentWAFRuleOverride {
	if len(in) == 0 {
		return nil
	}
	out := make([]isovalentv1alpha1.IsovalentWAFRuleOverride, len(in))
	copy(out, in)
	return out
}

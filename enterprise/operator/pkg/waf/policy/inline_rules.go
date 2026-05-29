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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3"
	apivalidation "k8s.io/apimachinery/pkg/util/validation"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const inlineHashKeyPrefix = "crs_inline_sha256_v1_"

type InlineRules struct {
	Inline  string
	HashKey string
}

func ValidateCustomRules(rules *isovalentv1alpha1.IsovalentWAFPolicyRules) error {
	if rules == nil || rules.Inline == "" {
		return nil
	}

	directives, err := parseDirectives(rules.Inline)
	if err != nil {
		return err
	}

	if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives)); err != nil {
		return fmt.Errorf("effective WAF rule validation failed: %w", err)
	}
	return nil
}

func BuildInlineRules(inline string) (InlineRules, error) {
	directives, err := parseDirectives(inline)
	if err != nil {
		return InlineRules{}, err
	}
	key, err := hashKey(directives)
	if err != nil {
		return InlineRules{}, err
	}
	return InlineRules{
		Inline:  directives,
		HashKey: key,
	}, nil
}

func parseDirectives(inline string) (string, error) {
	directives := normalize(inline)
	if directives == "" {
		return "", fmt.Errorf("spec.rules.inline must not be empty")
	}
	hasDirective, err := inspectDirective(directives)
	if err != nil {
		return "", err
	}
	if !hasDirective {
		return "", fmt.Errorf("spec.rules.inline must not be empty")
	}
	return directives, nil
}

func normalize(inline string) string {
	normalized := strings.ReplaceAll(inline, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	return strings.TrimSpace(normalized)
}

func hashKey(normalizedInline string) (string, error) {
	if normalizedInline == "" {
		return "", nil
	}

	sum := sha256.Sum256([]byte(normalizedInline))
	key := inlineHashKeyPrefix + hex.EncodeToString(sum[:])
	if errs := apivalidation.IsConfigMapKey(key); len(errs) > 0 {
		return "", fmt.Errorf("generated inline hash key %q is not a valid ConfigMap key: %s", key, strings.Join(errs, ", "))
	}

	return key, nil
}

// Inline rules must not declare SecRuleEngine because spec.mode is the
// authoritative source for monitor/enforce behavior. They also must not
// declare Include, because custom rulesets must be self-contained rather than
// depend on external files.
func inspectDirective(directives string) (bool, error) {
	hasDirective := false
	for line := range strings.SplitSeq(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		hasDirective = true

		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "SecRuleEngine") {
			return false, fmt.Errorf("inline rules must not declare SecRuleEngine; use spec.mode instead")
		}
		if strings.EqualFold(fields[0], "Include") {
			return false, fmt.Errorf("inline rules must not declare Include; custom rulesets must be self-contained")
		}
	}
	return hasDirective, nil
}

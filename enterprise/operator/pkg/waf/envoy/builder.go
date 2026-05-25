//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package envoy

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const (
	wafBlockPath           = "/__waf_block__"
	wafResponseBlockStatus = 403
	wafResponseBlockBody   = "blocked by waf"
	wafBodyLimitBytes      = 1024 * 1024
	wafRulesPath           = "/etc/coraza/rules"
	wafProfilesPath        = "/etc/coraza/rules/profiles"
	wafMainConfigPath      = wafRulesPath + "/main.conf"
	// Coraza requires an ID for the generated SecAction that applies custom CRS tuning.
	wafCustomProfileRuleID = 1000000
)

var (
	directiveBuilders = map[policy.EffectiveRuleSource]func(policy.EffectiveRules) (string, error){
		policy.EffectiveRuleSourceManaged: directivesForManagedProfile,
		policy.EffectiveRuleSourceProfile: directivesForCustomProfile,
		policy.EffectiveRuleSourceInline: func(rules policy.EffectiveRules) (string, error) {
			return rules.Inline.Inline, nil
		},
	}

	overrideBuilders = map[isovalentv1alpha1.IsovalentWAFRuleOverrideActionType]func(isovalentv1alpha1.IsovalentWAFRuleOverride) (string, error){
		isovalentv1alpha1.IsovalentWAFRuleOverrideActionDisable: func(o isovalentv1alpha1.IsovalentWAFRuleOverride) (string, error) {
			return fmt.Sprintf("SecRuleRemoveById %d", o.RuleID), nil
		},
		isovalentv1alpha1.IsovalentWAFRuleOverrideActionExcludeTarget: func(o isovalentv1alpha1.IsovalentWAFRuleOverride) (string, error) {
			if o.Target == "" {
				return "", fmt.Errorf("target must be specified for override action %q", o.Action)
			}
			return fmt.Sprintf("SecRuleUpdateTargetById %d !%s", o.RuleID, o.Target), nil
		},
	}
)

type ProxyConfig struct {
	DefaultMode         string `json:"default_mode"`
	BodyLimitBytes      int64  `json:"body_limit_bytes"`
	FailPolicy          string `json:"fail_policy"`
	RouteModeHeader     string `json:"route_mode_header"`
	BlockPath           string `json:"block_path"`
	ResponseBlockStatus int    `json:"response_block_status"`
	ResponseBlockBody   string `json:"response_block_body"`
	Directives          string `json:"directives"`
}

type ProxyConfigBuilder struct{}

func NewProxyConfigBuilder() ProxyConfigBuilder {
	return ProxyConfigBuilder{}
}

func (ProxyConfigBuilder) Build(cfg policy.EffectiveConfig) (*ProxyConfig, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	directivesFn, ok := directiveBuilders[cfg.Rules.Source]
	if !ok {
		return nil, fmt.Errorf("unsupported WAF rules source %q", cfg.Rules.Source)
	}

	directives, err := directivesFn(cfg.Rules)
	if err != nil {
		return nil, err
	}

	return &ProxyConfig{
		DefaultMode:         toWAFDefaultMode(cfg.Mode),
		BodyLimitBytes:      policy.ValueOrDefault(cfg.HandlingOverrides.BodyLimitBytes, int64(wafBodyLimitBytes)),
		FailPolicy:          toWAFFailPolicy(cfg.FailureMode),
		RouteModeHeader:     "",
		BlockPath:           wafBlockPath,
		ResponseBlockStatus: int(policy.ValueOrDefault(cfg.HandlingOverrides.BlockResponseStatusCode, int32(wafResponseBlockStatus))),
		ResponseBlockBody:   policy.ValueOrDefault(cfg.HandlingOverrides.BlockResponseBody, wafResponseBlockBody),
		Directives:          directives,
	}, nil
}

func toWAFDefaultMode(mode isovalentv1alpha1.IsovalentWAFPolicyModeType) string {
	if mode == isovalentv1alpha1.IsovalentWAFPolicyModeMonitor {
		return "detection"
	}

	return "block"
}

func toWAFFailPolicy(mode isovalentv1alpha1.WAFFailureModeType) string {
	if mode == isovalentv1alpha1.WAFFailureModeClose {
		return "closed"
	}

	return "open"
}

func directivesForManagedProfile(rules policy.EffectiveRules) (string, error) {
	overrides, err := directivesOverrides(rules.Overrides)
	if err != nil {
		return "", err
	}

	directives := []string{fmt.Sprintf("Include %s/%s.conf", wafProfilesPath, rules.PolicyProfile)}
	if overrides != "" {
		directives = append(directives, overrides)
	}
	return strings.Join(directives, "\n"), nil
}

func directivesForCustomProfile(rules policy.EffectiveRules) (string, error) {
	overrides, err := directivesOverrides(rules.Overrides)
	if err != nil {
		return "", err
	}

	directives := []string{
		fmt.Sprintf(
			`SecAction "id:%d,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`,
			wafCustomProfileRuleID,
			rules.CustomProfile.BlockingParanoiaLevel,
			rules.CustomProfile.DetectionParanoiaLevel,
			rules.CustomProfile.InboundAnomalyScoreThreshold,
			rules.CustomProfile.OutboundAnomalyScoreThreshold,
		),
		fmt.Sprintf("Include %s", wafMainConfigPath),
	}
	if overrides != "" {
		directives = append(directives, overrides)
	}
	if rules.Inline.Inline != "" {
		directives = append(directives, rules.Inline.Inline)
	}
	return strings.Join(directives, "\n"), nil
}

func directivesOverrides(overrides []isovalentv1alpha1.IsovalentWAFRuleOverride) (string, error) {
	if len(overrides) == 0 {
		return "", nil
	}

	directives := make([]string, 0, len(overrides))
	for _, override := range overrides {
		directiveFn, ok := overrideBuilders[override.Action]
		if !ok {
			return "", fmt.Errorf("unsupported WAF override action %q", override.Action)
		}

		directive, err := directiveFn(override)
		if err != nil {
			return "", err
		}

		directives = append(directives, directive)
	}
	return strings.Join(directives, "\n"), nil
}

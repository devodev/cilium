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
	wafCRSPath             = "/etc/coraza/crs"
	wafCRSSetupPath        = wafCRSPath + "/crs-setup.conf"
	wafCRSRulesPath        = wafCRSPath + "/rules/*.conf"
	// Coraza requires an ID for the generated SecAction that applies custom CRS tuning.
	wafCustomProfileRuleID = 1000000
)

var (
	directiveBuilders = map[policy.EffectiveRuleSource]func(policy.EffectiveRules) (string, error){
		policy.EffectiveRuleSourceManaged: managedProfileDirectives,
		policy.EffectiveRuleSourceProfile: customProfileDirectives,
		policy.EffectiveRuleSourceInline: func(rules policy.EffectiveRules) (string, error) {
			return rules.Inline.Inline, nil
		},
	}

	managedProfileTunings = map[isovalentv1alpha1.IsovalentWAFPolicyProfileType]crsTuning{
		isovalentv1alpha1.IsovalentWAFPolicyProfileMaxSecurity: {
			RuleID:                        1100001,
			BlockingParanoiaLevel:         3,
			DetectionParanoiaLevel:        3,
			InboundAnomalyScoreThreshold:  5,
			OutboundAnomalyScoreThreshold: 4,
		},
		isovalentv1alpha1.IsovalentWAFPolicyProfileHighSecurity: {
			RuleID:                        1100002,
			BlockingParanoiaLevel:         2,
			DetectionParanoiaLevel:        2,
			InboundAnomalyScoreThreshold:  7,
			OutboundAnomalyScoreThreshold: 6,
		},
		isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced: {
			RuleID:                        1100003,
			BlockingParanoiaLevel:         1,
			DetectionParanoiaLevel:        1,
			InboundAnomalyScoreThreshold:  10,
			OutboundAnomalyScoreThreshold: 8,
		},
		isovalentv1alpha1.IsovalentWAFPolicyProfileLowFriction: {
			RuleID:                        1100004,
			BlockingParanoiaLevel:         1,
			DetectionParanoiaLevel:        1,
			InboundAnomalyScoreThreshold:  15,
			OutboundAnomalyScoreThreshold: 12,
		},
		isovalentv1alpha1.IsovalentWAFPolicyProfileMinFriction: {
			RuleID:                        1100005,
			BlockingParanoiaLevel:         1,
			DetectionParanoiaLevel:        1,
			InboundAnomalyScoreThreshold:  20,
			OutboundAnomalyScoreThreshold: 16,
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

type crsTuning struct {
	RuleID                        int
	BlockingParanoiaLevel         int32
	DetectionParanoiaLevel        int32
	InboundAnomalyScoreThreshold  int32
	OutboundAnomalyScoreThreshold int32
}

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

func managedProfileDirectives(rules policy.EffectiveRules) (string, error) {
	tuning, ok := managedProfileTunings[rules.PolicyProfile]
	if !ok {
		return "", fmt.Errorf("unsupported WAF managed profile %q", rules.PolicyProfile)
	}

	return profileDirectives(tuning, rules)
}

func customProfileDirectives(rules policy.EffectiveRules) (string, error) {
	return profileDirectives(crsTuning{
		RuleID:                        wafCustomProfileRuleID,
		BlockingParanoiaLevel:         rules.CustomProfile.BlockingParanoiaLevel,
		DetectionParanoiaLevel:        rules.CustomProfile.DetectionParanoiaLevel,
		InboundAnomalyScoreThreshold:  rules.CustomProfile.InboundAnomalyScoreThreshold,
		OutboundAnomalyScoreThreshold: rules.CustomProfile.OutboundAnomalyScoreThreshold,
	}, rules)
}

func profileDirectives(tuning crsTuning, rules policy.EffectiveRules) (string, error) {
	overrides, err := directivesOverrides(rules.Overrides)
	if err != nil {
		return "", err
	}

	directives := []string{
		fmt.Sprintf(
			`SecAction "id:%d,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`,
			tuning.RuleID,
			tuning.BlockingParanoiaLevel,
			tuning.DetectionParanoiaLevel,
			tuning.InboundAnomalyScoreThreshold,
			tuning.OutboundAnomalyScoreThreshold,
		),
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecResponseBodyAccess On",
		fmt.Sprintf("Include %s", wafCRSSetupPath),
		fmt.Sprintf("Include %s", wafCRSRulesPath),
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

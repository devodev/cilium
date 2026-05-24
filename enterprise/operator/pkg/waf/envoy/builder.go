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

	directives, err := directivesForWAFConfig(cfg)
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

func directivesForWAFConfig(config policy.EffectiveConfig) (string, error) {
	switch config.Rules.Source {
	case policy.EffectiveRuleSourceManaged:
		return fmt.Sprintf("Include %s/%s.conf", wafProfilesPath, config.Rules.PolicyProfile), nil
	case policy.EffectiveRuleSourceProfile:
		return directivesForCustomProfile(config.Rules.CustomProfile, config.Rules.Inline), nil
	case policy.EffectiveRuleSourceInline:
		return config.Rules.Inline.Inline, nil
	default:
		return "", fmt.Errorf("unsupported WAF rules source %q", config.Rules.Source)
	}
}

func directivesForCustomProfile(profile isovalentv1alpha1.IsovalentWAFCustomProfile, inline policy.InlineRules) string {
	parts := []string{
		fmt.Sprintf(
			`SecAction "id:%d,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`,
			wafCustomProfileRuleID,
			profile.BlockingParanoiaLevel,
			profile.DetectionParanoiaLevel,
			profile.InboundAnomalyScoreThreshold,
			profile.OutboundAnomalyScoreThreshold,
		),
		fmt.Sprintf("Include %s", wafMainConfigPath),
	}
	if inline.Inline != "" {
		parts = append(parts, inline.Inline)
	}
	return strings.Join(parts, "\n")
}

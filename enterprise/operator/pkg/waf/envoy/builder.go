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

	"github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const (
	wafBlockPath           = "/__coraza_block__"
	wafResponseBlockStatus = 403
	wafResponseBlockBody   = "blocked by waf"
	wafBodyLimitBytes      = 1024 * 1024
	wafProfilesPath        = "/etc/coraza/rules/profiles"
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

	switch cfg.Rules.Source {
	case policy.EffectiveRuleSourceDefault, policy.EffectiveRuleSourceManaged:
	case policy.EffectiveRuleSourceInline:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported WAF rules source %q", cfg.Rules.Source)
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
	case policy.EffectiveRuleSourceDefault, policy.EffectiveRuleSourceManaged:
		return fmt.Sprintf("Include %s/%s.conf", wafProfilesPath, config.Rules.PolicyProfile), nil
	default:
		return "", fmt.Errorf("unsupported WAF rules source %q", config.Rules.Source)
	}
}

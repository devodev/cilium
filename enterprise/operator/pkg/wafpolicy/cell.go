//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package wafpolicy

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"wafpolicy",
	"Manages IsovalentWAFPolicy validation and shared defaults",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Provide(newGlobalDefaults),
	cell.Invoke(registerReconcilers),
)

type Config struct {
	WAFEnabled              bool
	WAFMode                 string
	WAFPolicyProfile        string
	WAFFailureMode          string
	WAFInlineRulesConfigMap string
}

const DefaultInlineRulesCM = "waf-inline-rules"

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("waf-enabled", cfg.WAFEnabled, "Enable WAF by default for operator-managed resources.")
	flags.String("waf-mode", string(isovalentv1alpha1.IsovalentWAFPolicyModeEnforce), "Default WAF mode for operator-managed resources. Applicable values: Monitor, Enforce")
	flags.String("waf-policy-profile", string(isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced), "Default WAF policy profile for operator-managed resources. Applicable values: max_security, high_security, balanced, low_friction, min_friction")
	flags.String("waf-failure-mode", string(isovalentv1alpha1.WAFFailureModeOpen), "Default WAF failure mode for operator-managed resources. Applicable values: Open, Close")
	flags.String("waf-inline-rules-config-map", DefaultInlineRulesCM, "Name of the ConfigMap used to publish shared WAF inline rule bundles.")
}

type GlobalDefaults struct {
	Enabled       bool
	Mode          isovalentv1alpha1.IsovalentWAFPolicyModeType
	PolicyProfile isovalentv1alpha1.IsovalentWAFPolicyProfileType
	FailureMode   isovalentv1alpha1.WAFFailureModeType
}

func newGlobalDefaults(config Config) (GlobalDefaults, error) {
	defaults := GlobalDefaults{
		Enabled:       config.WAFEnabled,
		Mode:          isovalentv1alpha1.IsovalentWAFPolicyModeType(config.WAFMode),
		PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileType(config.WAFPolicyProfile),
		FailureMode:   isovalentv1alpha1.WAFFailureModeType(config.WAFFailureMode),
	}

	switch defaults.Mode {
	case isovalentv1alpha1.IsovalentWAFPolicyModeMonitor, isovalentv1alpha1.IsovalentWAFPolicyModeEnforce:
	default:
		return GlobalDefaults{}, fmt.Errorf("unsupported waf-mode %q", config.WAFMode)
	}

	switch defaults.PolicyProfile {
	case isovalentv1alpha1.IsovalentWAFPolicyProfileMaxSecurity,
		isovalentv1alpha1.IsovalentWAFPolicyProfileHighSecurity,
		isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
		isovalentv1alpha1.IsovalentWAFPolicyProfileLowFriction,
		isovalentv1alpha1.IsovalentWAFPolicyProfileMinFriction:
	default:
		return GlobalDefaults{}, fmt.Errorf(
			"unsupported waf-policy-profile %q",
			config.WAFPolicyProfile,
		)
	}

	switch defaults.FailureMode {
	case isovalentv1alpha1.WAFFailureModeOpen, isovalentv1alpha1.WAFFailureModeClose:
	default:
		return GlobalDefaults{}, fmt.Errorf(
			"unsupported waf-failure-mode %q",
			config.WAFFailureMode,
		)
	}

	return defaults, nil
}

type reconcilerParams struct {
	cell.In

	Logger             *slog.Logger
	Config             Config
	AgentConfig        *option.DaemonConfig
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme
}

func registerReconcilers(params reconcilerParams) error {
	if params.CtrlRuntimeManager == nil || params.Scheme == nil {
		return nil
	}
	if !params.Config.WAFEnabled {
		return nil
	}

	if err := isovalentv1alpha1.AddToScheme(params.Scheme); err != nil {
		return fmt.Errorf("failed to add Isovalent scheme: %w", err)
	}

	namespace := ""
	if params.AgentConfig != nil {
		namespace = params.AgentConfig.CiliumNamespaceName()
	}

	return newReconciler(
		params.Logger,
		params.CtrlRuntimeManager.GetClient(),
		// Use an uncached reader for the operator-managed ConfigMap to avoid
		// starting a cluster-scoped ConfigMap informer.
		params.CtrlRuntimeManager.GetAPIReader(),
		namespace,
		params.Config.WAFInlineRulesConfigMap,
	).SetupWithManager(params.CtrlRuntimeManager)
}

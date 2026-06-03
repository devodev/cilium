//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package waf

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/enterprise/operator/pkg/waf/envoy"
	"github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"waf",
	"Manages IsovalentWAFPolicy validation and shared defaults",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Provide(newGlobalDefaults),
	cell.Provide(newResolver),
	cell.Provide(envoy.NewProxyConfigBuilder),
	cell.Provide(envoy.NewTranslator),
	cell.Provide(newLBExtension),
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

func newGlobalDefaults(config Config) (policy.GlobalDefaults, error) {
	return policy.NewGlobalDefaults(
		config.WAFEnabled,
		config.WAFMode,
		config.WAFPolicyProfile,
		config.WAFFailureMode,
	)
}

type resolverParams struct {
	cell.In

	CtrlRuntimeManager ctrlRuntime.Manager
	Logger             *slog.Logger
	Defaults           policy.GlobalDefaults
}

func newResolver(params resolverParams) (*policy.Resolver, error) {
	if params.Defaults.Enabled && params.CtrlRuntimeManager == nil {
		return nil, errors.New("waf requires Kubernetes support to be enabled")
	}

	if params.CtrlRuntimeManager != nil {
		return policy.NewResolver(params.CtrlRuntimeManager.GetClient(), params.Logger, params.Defaults), nil
	}

	// Hive inspection can populate this cell without a controller-runtime
	// manager, so tolerate the nil manager on non-runtime paths.
	return policy.NewResolver(nil, params.Logger, params.Defaults), nil
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

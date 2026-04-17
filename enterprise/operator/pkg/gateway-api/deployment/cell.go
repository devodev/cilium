//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package deployment

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell registers the controller that creates the control- and dataplane
// K8s workloads for the per-Gateway Envoy Deployment Gateway API implementation.
var Cell = cell.Module(
	"gateway-api-deployment",
	"Per-Gateway Envoy Deployment Gateway API implementation",

	cell.Config(Config{
		GatewayAPIDeploymentControllerEnabled:              false,
		GatewayAPIDeploymentControlplaneDefaultImage:       "",
		GatewayAPIDeploymentControlplaneDefaultLogLevel:    "info",
		GatewayAPIDeploymentControlplaneDefaultReplicas:    2,
		GatewayAPIDeploymentDataplaneDefaultEnvoyImage:     "",
		GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel:  "error",
		GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort: 9901,
		GatewayAPIDeploymentDataplaneDefaultReplicas:       2,
	}),

	cell.Invoke(registerReconcilers),
)

var requiredResources = []string{
	"gatewayclasses",
	"gateways",
}

type Config struct {
	GatewayAPIDeploymentControllerEnabled              bool
	GatewayAPIDeploymentControlplaneDefaultImage       string
	GatewayAPIDeploymentControlplaneDefaultLogLevel    string
	GatewayAPIDeploymentControlplaneDefaultReplicas    int
	GatewayAPIDeploymentDataplaneDefaultEnvoyImage     string
	GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel  string
	GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort int
	GatewayAPIDeploymentDataplaneDefaultReplicas       int
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("gateway-api-deployment-controller-enabled", cfg.GatewayAPIDeploymentControllerEnabled, "Enable the enterprise Gateway API deployment-based controller.")
	flags.String("gateway-api-deployment-controlplane-default-image", cfg.GatewayAPIDeploymentControlplaneDefaultImage, "Default controlplane image for the deployment-based Gateway API implementation.")
	flags.String("gateway-api-deployment-controlplane-default-log-level", cfg.GatewayAPIDeploymentControlplaneDefaultLogLevel, "Default log level for the deployment-based Gateway API controlplane implementation.")
	flags.Int("gateway-api-deployment-controlplane-default-replicas", cfg.GatewayAPIDeploymentControlplaneDefaultReplicas, "Default number of replicas for the deployment-based Gateway API controlplane implementation.")
	flags.String("gateway-api-deployment-dataplane-default-envoy-image", cfg.GatewayAPIDeploymentDataplaneDefaultEnvoyImage, "Default Envoy image for the deployment-based Gateway API dataplane implementation.")
	flags.String("gateway-api-deployment-dataplane-default-envoy-log-level", cfg.GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel, "Default Envoy log level for the deployment-based Gateway API dataplane implementation.")
	flags.Int("gateway-api-deployment-dataplane-default-envoy-admin-port", cfg.GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort, "Default Envoy admin port for the deployment-based Gateway API dataplane implementation.")
	flags.Int("gateway-api-deployment-dataplane-default-replicas", cfg.GatewayAPIDeploymentDataplaneDefaultReplicas, "Default number of Envoy replicas for the deployment-based Gateway API dataplane implementation.")
}

type reconcilerParams struct {
	cell.In

	Logger             *slog.Logger
	Config             Config
	DaemonConfig       *option.DaemonConfig
	K8sClient          k8sClient.Clientset
	Health             cell.Health
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme
	Lifecycle          cell.Lifecycle
}

func registerReconcilers(params reconcilerParams) error {
	if !params.Config.GatewayAPIDeploymentControllerEnabled {
		return nil
	}
	if !params.K8sClient.IsEnabled() {
		return nil
	}
	if err := validateGatewayAPIResources(params); err != nil {
		return nil
	}

	params.Logger.Info("Registering Gateway API deployment reconcilers")

	for gv, addToScheme := range map[string]func(*runtime.Scheme) error{
		gatewayv1.GroupVersion.String():    gatewayv1.Install,
		appsv1.SchemeGroupVersion.String(): appsv1.AddToScheme,
		corev1.SchemeGroupVersion.String(): corev1.AddToScheme,
	} {
		if err := addToScheme(params.Scheme); err != nil {
			return fmt.Errorf("failed to add %s types to scheme: %w", gv, err)
		}
	}

	gwClassReconciler := NewGatewayClassReconciler(params.CtrlRuntimeManager, params.Logger)
	gwReconciler := NewGatewayReconciler(
		params.CtrlRuntimeManager.GetClient(),
		params.CtrlRuntimeManager.GetScheme(),
		params.Logger,
		params.Config,
		params.DaemonConfig,
	)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			params.Logger.Info("Setting up GatewayClass reconciler")
			if err := gwClassReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup GatewayClass reconciler: %w", err)
			}

			params.Logger.Info("Setting up Gateway reconciler")
			if err := gwReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup Gateway reconciler: %w", err)
			}

			return nil
		},
	})

	return nil
}

func validateGatewayAPIResources(params reconcilerParams) error {
	resourceList, err := params.K8sClient.Discovery().ServerResourcesForGroupVersion(gatewayv1.GroupVersion.String())
	if err != nil {
		params.Health.Degraded("Gateway API deployment controller CRD discovery failed", err)
		params.Logger.Warn("Skipping Gateway API deployment controller registration because Gateway API discovery failed", logfields.Error, err)
		return err
	}

	var available []string
	for _, resource := range resourceList.APIResources {
		available = append(available, resource.Name)
	}

	for _, requiredResource := range requiredResources {
		if !slices.Contains(available, requiredResource) {
			err := fmt.Errorf("missing required Gateway API resource %q in %s", requiredResource, gatewayv1.GroupVersion.String())
			params.Health.Degraded("Gateway API deployment controller CRDs not installed", err)
			params.Logger.Warn("Skipping Gateway API deployment controller registration because required resources are missing", logfields.Error, err)
			return err
		}
	}

	params.Health.OK("Gateway API deployment controller CRDs discovered")
	return nil
}

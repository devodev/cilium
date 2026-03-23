//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"cmp"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/enterprise/operator/pkg/lb/accesslog"
	"github.com/cilium/cilium/enterprise/operator/pkg/lb/extlb"
	"github.com/cilium/cilium/enterprise/operator/pkg/lb/metrics"
	"github.com/cilium/cilium/enterprise/operator/pkg/wafpolicy"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"loadbalancer-controlplane",
	"LoadBalancer control plane",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Invoke(registerLBReconcilers),
	cell.Provide(registerSecretSync),
	cell.ProvidePrivate(newNodeSource),
	cell.ProvidePrivate(newT1Translator),
	cell.ProvidePrivate(newT2Translator),

	metrics.Cell,
	extlb.Cell,
)

type Config struct {
	LoadBalancerCPEnabled                                 bool
	LoadBalancerCPSecretsNamespace                        string
	LoadBalancerCPAccessLogEnableStdOut                   bool
	LoadBalancerCPAccessLogEnableGRPC                     bool
	LoadBalancerCPAccessLogFilePath                       string
	LoadBalancerCPAccessLogEnableHC                       bool
	LoadBalancerCPAccessLogEnableTCP                      bool
	LoadBalancerCPAccessLogEnableUDP                      bool
	LoadBalancerCPAccessLogFormatHC                       string
	LoadBalancerCPAccessLogJSONFormatHC                   string
	LoadBalancerCPAccessLogFormatTCP                      string
	LoadBalancerCPAccessLogJSONFormatTCP                  string
	LoadBalancerCPAccessLogFormatUDP                      string
	LoadBalancerCPAccessLogJSONFormatUDP                  string
	LoadBalancerCPAccessLogFormatTLSPassthrough           string
	LoadBalancerCPAccessLogJSONFormatTLSPassthrough       string
	LoadBalancerCPAccessLogFormatTLS                      string
	LoadBalancerCPAccessLogJSONFormatTLS                  string
	LoadBalancerCPAccessLogFormatHTTPS                    string
	LoadBalancerCPAccessLogJSONFormatHTTPS                string
	LoadBalancerCPAccessLogFormatHTTP                     string
	LoadBalancerCPAccessLogJSONFormatHTTP                 string
	LoadBalancerCPMetricsClusterTimeoutBudget             bool
	LoadBalancerCPMetricsClusterAdditionalRequestResponse bool
	LoadBalancerCPMetricsClusterPerEndpoint               bool
	LoadBalancerCPRequestIDGenerate                       bool
	LoadBalancerCPRequestIDPreserve                       bool
	LoadBalancerCPRequestIDResponse                       bool
	LoadBalancerCPHTTPServerName                          string
	LoadBalancerCPT2HCPushEnabled                         bool
	LoadBalancerCPT1HCProbeTimeoutSeconds                 uint
	LoadBalancerCPT2HCProbeMinHealthyBackends             uint
	LoadbalancerCPT2HCEventLoggingEnabled                 bool
	LoadbalancerCPT2HCEventLoggingStateDir                string
	LoadBalancerCPT2UseRemoteAddress                      bool
	LoadBalancerCPT2XffNumTrustedHops                     uint
	LoadBalancerCPDefaultT1LabelSelector                  string
	LoadBalancerCPDefaultT2LabelSelector                  string
	LoadBalancerCPPolicyEnableCiliumPolicyFilters         bool
	LoadBalancerGatewayAPIEnabled                         bool
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-cp-enabled", false, "Whether or not the LoadBalancer control plane is enabled.")
	flags.String("loadbalancer-cp-secrets-namespace", "cilium-secrets", "Namespace that should be used when syncing TLS secrets used by the LoadBalancer control plane.")
	flags.Bool("loadbalancer-cp-accesslog-enable-stdout", true, "Whether Envoy Access Log should be sent to stdout on the T2 Envoy by the LoadBalancer control plane.")
	flags.Bool("loadbalancer-cp-accesslog-enable-grpc", false, "Whether Envoy Access Log should be sent to a GRPC logger.")
	flags.String("loadbalancer-cp-accesslog-file-path", "", "Path where the Envoy Access Log should be sent to on the T2 Envoy by the LoadBalancer control plane.")
	flags.Bool("loadbalancer-cp-accesslog-enable-hc", false, "Whether Envoy Access Log should be enabled for T1 -> T2 Health Check requests on the T2 Envoy by the LoadBalancer control plane.")
	flags.Bool("loadbalancer-cp-accesslog-enable-tcp", false, "Whether Envoy Access Log should be enabled for the TCP listener on the T2 Envoy by the LoadBalancer control plane")
	flags.Bool("loadbalancer-cp-accesslog-enable-udp", true, "Whether Envoy Access Log should be enabled for the UDP proxy on the T2 Envoy by the LoadBalancer control plane")
	flags.String("loadbalancer-cp-accesslog-format-hc", "", "Envoy Access Log format for T1 -> T2 Health Check HTTP requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-json-format-hc", "", "Envoy Access Log JSON format for T1 -> T2 Health Check HTTP requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-tcp", "", "Envoy Access Log format for the TCP listener that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-json-format-tcp", "", "Envoy Access Log JSON format for the TCP listener that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-udp", "", "Envoy Access Log format for the UDP proxy that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-json-format-udp", "", "Envoy Access Log JSON format for the UDP proxy that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-tls-passthrough", "", "Envoy Access Log format for TLS passthrough requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-json-format-tls-passthrough", "", "Envoy Access Log JSON format for TLS passthrough requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-tls", "", "Envoy Access Log format for TLS requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-json-format-tls", "", "Envoy Access Log JSON format for TLS requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-https", "", "Envoy Access Log format for HTTPS requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-json-format-https", "", "Envoy Access Log JSON format for HTTPS requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-format-http", "", "Envoy Access Log format for HTTP requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.String("loadbalancer-cp-accesslog-json-format-http", "", "Envoy Access Log JSON format for HTTP requests that should be configured on T2 Envoy by the LoadBalancer control plane (without the trailing newline)")
	flags.Bool("loadbalancer-cp-metrics-cluster-timeout-budget", true, "Enable Envoy timeout budget metrics on the cluster")
	flags.Bool("loadbalancer-cp-metrics-cluster-additional-request-response", true, "Enable additional Envoy request & response metrics on the cluster (Body size, header size & count)")
	flags.Bool("loadbalancer-cp-metrics-cluster-per-endpoint", true, "Enable per-endpoint Envoy metrics on the cluster")
	flags.Bool("loadbalancer-cp-requestid-generate", false, "Whether or not the LoadBalancer control plane should configure T2 Envoy to generate the X-Request-ID HTTP header")
	flags.Bool("loadbalancer-cp-requestid-preserve", false, "Whether or not the LoadBalancer control plane should configure T2 Envoy to preserve any existing X-Request-ID HTTP header")
	flags.Bool("loadbalancer-cp-requestid-response", false, "Whether or not the LoadBalancer control plane should configure T2 Envoy to add the X-Request-ID HTTP header to the response")
	flags.String("loadbalancer-cp-http-server-name", "ilb", "Server name that is used when writing the server header in T2 HTTP responses")
	flags.Bool("loadbalancer-cp-t2-hc-push-enabled", false, "Whether or not the LoadBalancer control plane should configure T1 services to consume remote T2 health instead of actively probing T2 nodes")
	flags.Uint("loadbalancer-cp-t1-hc-probe-timeout-seconds", 5, "Probe timeout in seconds for T1 -> T2 health checks")
	flags.Uint("loadbalancer-cp-t2-hc-probe-min-healthy-backends", 20, "The minimum percentage of backend that must be healthy from T2 point of view in order to send traffic from T1 to it")
	flags.Bool("loadbalancer-cp-t2-hc-event-logging-enabled", false, "Enables LB health check event logging between Envoy proxy and the node-local Agent")
	flags.String("loadbalancer-cp-t2-hc-event-logging-state-dir", "", "State directory for the Envoy health check logging socket")
	flags.Bool("loadbalancer-cp-t2-use-remote-address", true, "Whether or not the LoadBalancer control plane should configure T2 Envoy to use the real remote address of the client connection when determining internal versus external origin.\n"+
		"More information can be found at https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for")
	flags.Uint("loadbalancer-cp-t2-xff-num-trusted-hops", 0, "The number of additional ingress proxy hops from the right side of the HTTP header to trust when determining the origin client's IP address.\n"+
		"More information can be found at https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for")
	flags.String("loadbalancer-cp-default-t1-label-selector", fmt.Sprintf("%s in ( %s, %s )", ossannotation.ServiceNodeExposure, lbNodeTypeT1, lbNodeTypeT1AndT2), "Default K8s node label selectors that is used to define the T1 nodes")
	flags.String("loadbalancer-cp-default-t2-label-selector", fmt.Sprintf("%s in ( %s, %s )", ossannotation.ServiceNodeExposure, lbNodeTypeT2, lbNodeTypeT1AndT2), "Default K8s node label selectors that is used to define the T2 nodes")
	flags.Bool("loadbalancer-cp-policy-enable-cilium-policy-filters", true, "Whether or not the LoadBalancer control plane should configure the Cilium Policy filters on the T2 Envoy listeners")
	flags.Bool("loadbalancer-gateway-api-enabled", false, "Enable experimental Gateway API support for Isovalent Loadbalancer")
}

type reconcilerParams struct {
	cell.In

	Logger      *slog.Logger
	Lifecycle   cell.Lifecycle
	JobGroup    job.Group
	Config      Config
	AgentConfig *option.DaemonConfig

	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	T1Translator *lbServiceT1Translator
	T2Translator *lbServiceT2Translator

	NodeSource *ciliumNodeSource

	WAFDefaults wafpolicy.GlobalDefaults
}

type translatorParams struct {
	cell.In

	Logger      *slog.Logger
	Config      Config
	AgentConfig *option.DaemonConfig
}

func newT1Translator(params translatorParams) *lbServiceT1Translator {
	if !params.Config.LoadBalancerCPEnabled {
		return nil
	}

	reconcilerConfig := mapReconcilerConfig(params.Config, params.AgentConfig)

	return &lbServiceT1Translator{logger: params.Logger, config: reconcilerConfig}
}

func newT2Translator(params translatorParams) *lbServiceT2Translator {
	if !params.Config.LoadBalancerCPEnabled {
		return nil
	}

	reconcilerConfig := mapReconcilerConfig(params.Config, params.AgentConfig)

	return &lbServiceT2Translator{logger: params.Logger, config: reconcilerConfig}
}

func registerLBReconcilers(params reconcilerParams) error {
	if !params.Config.LoadBalancerCPEnabled {
		return nil
	}

	if err := isovalentv1alpha1.AddToScheme(params.Scheme); err != nil {
		return fmt.Errorf("failed to add scheme: %w", err)
	}

	if err := gatewayv1.AddToScheme(params.Scheme); err != nil {
		return fmt.Errorf("failed to add scheme: %w", err)
	}

	if err := gatewayv1beta1.AddToScheme(params.Scheme); err != nil {
		return fmt.Errorf("failed to add scheme: %w", err)
	}

	t1ls, t2ls, err := parseDefaultTierLabelSelectors(params.Config.LoadBalancerCPDefaultT1LabelSelector, params.Config.LoadBalancerCPDefaultT2LabelSelector)
	if err != nil {
		return err
	}

	lbServiceReconciler := newLbServiceReconciler(
		params.Logger,
		params.CtrlRuntimeManager.GetClient(),
		params.Scheme,
		params.NodeSource,
		newIngestor(params.Logger, *t1ls, *t2ls),
		params.T1Translator,
		params.T2Translator,
		params.WAFDefaults,
	)

	lbVIPReconciler := newLBVIPReconciler(
		params.Logger,
		params.CtrlRuntimeManager.GetClient(),
		params.Scheme,
		lbVIPReconcilerConfig{
			ipFamilies: reconcilerIPFamilyConfig{
				EnableIPv4: params.AgentConfig.EnableIPv4,
				EnableIPv6: params.AgentConfig.EnableIPv6,
			},
		},
	)

	lbBackendPoolReconciler := newLbBackendPoolReconciler(
		params.Logger,
		params.CtrlRuntimeManager.GetClient(),
	)

	lbDeploymentReconciler := newLBDeploymentReconciler(
		params.Logger,
		params.CtrlRuntimeManager.GetClient(),
	)

	gwClassReconciler := &gatewayClassReconciler{}
	gwReconciler := &gatewayReconciler{}
	// if Load balancer gateway api is enabled
	if params.Config.LoadBalancerGatewayAPIEnabled {
		gwClassReconciler = newGatewayClassReconciler(params.CtrlRuntimeManager, params.Logger)

		gwReconciler = newGatewayReconciler(
			params.CtrlRuntimeManager.GetClient(),
			params.T1Translator,
			params.T2Translator,
			params.Logger,
			newGWIngestor(params.Logger, *t1ls, *t2ls),
			params.NodeSource,
		)
	}
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			// Register reconcilers to manager in lifecycle to ensure that CRDs are installed on the cluster
			if err := lbServiceReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup LBService reconciler: %w", err)
			}

			if err := lbVIPReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup LBVIP reconciler: %w", err)
			}

			if err := lbBackendPoolReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup LBBackendPool reconciler: %w", err)
			}

			if err := lbDeploymentReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup LBDeployment reconciler: %w", err)
			}
			if params.Config.LoadBalancerGatewayAPIEnabled {
				if err := gwClassReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
					return fmt.Errorf("failed to setup GatewayClass reconciler: %w", err)
				}
				if err := gwReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
					return fmt.Errorf("failed to setup GatewayAPI reconciler: %w", err)
				}
			}

			return nil
		},
	})

	return nil
}

func mapReconcilerConfig(config Config, agentConfig *option.DaemonConfig) reconcilerConfig {
	return reconcilerConfig{
		SecretsNamespace: config.LoadBalancerCPSecretsNamespace,
		ServerName:       config.LoadBalancerCPHTTPServerName,
		AccessLog: reconcilerAccesslogConfig{
			EnableStdOut:             config.LoadBalancerCPAccessLogEnableStdOut,
			EnableGRPC:               config.LoadBalancerCPAccessLogEnableGRPC,
			FilePath:                 config.LoadBalancerCPAccessLogFilePath,
			EnableHC:                 config.LoadBalancerCPAccessLogEnableHC,
			EnableTCP:                config.LoadBalancerCPAccessLogEnableTCP,
			EnableUDP:                config.LoadBalancerCPAccessLogEnableUDP,
			FormatHC:                 cmp.Or(config.LoadBalancerCPAccessLogFormatHC, accesslog.GetFormatText(accesslog.AccessLogTypeHealthCheck)),
			JSONFormatHC:             cmp.Or(config.LoadBalancerCPAccessLogJSONFormatHC, accesslog.GetFormatJSON(accesslog.AccessLogTypeHealthCheck)),
			FormatTCP:                cmp.Or(config.LoadBalancerCPAccessLogFormatTCP, accesslog.GetFormatText(accesslog.AccessLogTypeTCP)),
			JSONFormatTCP:            cmp.Or(config.LoadBalancerCPAccessLogJSONFormatTCP, accesslog.GetFormatJSON(accesslog.AccessLogTypeTCP)),
			FormatUDP:                cmp.Or(config.LoadBalancerCPAccessLogFormatUDP, accesslog.GetFormatText(accesslog.AccessLogTypeUDP)),
			JSONFormatUDP:            cmp.Or(config.LoadBalancerCPAccessLogJSONFormatUDP, accesslog.GetFormatJSON(accesslog.AccessLogTypeUDP)),
			FormatTLSPassthrough:     cmp.Or(config.LoadBalancerCPAccessLogFormatTLSPassthrough, accesslog.GetFormatText(accesslog.AccessLogTypeTLSPassthrough)),
			JSONFormatTLSPassthrough: cmp.Or(config.LoadBalancerCPAccessLogJSONFormatTLSPassthrough, accesslog.GetFormatJSON(accesslog.AccessLogTypeTLSPassthrough)),
			FormatTLS:                cmp.Or(config.LoadBalancerCPAccessLogFormatTLS, accesslog.GetFormatText(accesslog.AccessLogTypeTLS)),
			JSONFormatTLS:            cmp.Or(config.LoadBalancerCPAccessLogJSONFormatTLS, accesslog.GetFormatJSON(accesslog.AccessLogTypeTLS)),
			FormatHTTPS:              cmp.Or(config.LoadBalancerCPAccessLogFormatHTTPS, accesslog.GetFormatText(accesslog.AccessLogTypeHTTPS)),
			JSONFormatHTTPS:          cmp.Or(config.LoadBalancerCPAccessLogJSONFormatHTTPS, accesslog.GetFormatJSON(accesslog.AccessLogTypeHTTPS)),
			FormatHTTP:               cmp.Or(config.LoadBalancerCPAccessLogFormatHTTP, accesslog.GetFormatText(accesslog.AccessLogTypeHTTP)),
			JSONFormatHTTP:           cmp.Or(config.LoadBalancerCPAccessLogJSONFormatHTTP, accesslog.GetFormatJSON(accesslog.AccessLogTypeHTTP)),
		},
		Metrics: reconcilerMetricsConfig{
			ClusterTimeoutBudget:             config.LoadBalancerCPMetricsClusterTimeoutBudget,
			ClusterAdditionalRequestResponse: config.LoadBalancerCPMetricsClusterAdditionalRequestResponse,
			ClusterPerEndpoint:               config.LoadBalancerCPMetricsClusterPerEndpoint,
		},
		RequestID: reconcilerRequestIDConfig{
			Generate: config.LoadBalancerCPRequestIDGenerate,
			Preserve: config.LoadBalancerCPRequestIDPreserve,
			Response: config.LoadBalancerCPRequestIDResponse,
		},
		T1T2HealthCheck: reconcilerT1T2HealthCheckConfig{
			T2HCPushEnabled:                    config.LoadBalancerCPT2HCPushEnabled,
			T1ProbeTimeoutSeconds:              config.LoadBalancerCPT1HCProbeTimeoutSeconds,
			T1ProbeHttpPath:                    "/health",
			T1ProbeHttpMethod:                  "GET",
			T1ProbeHttpUserAgentPrefix:         "cilium-probe/",
			T2ProbeMinHealthyBackendPercentage: config.LoadBalancerCPT2HCProbeMinHealthyBackends,
			T2EnvoyHCEventLoggingEnabled:       config.LoadbalancerCPT2HCEventLoggingEnabled,
			T2EnvoyHCEventLoggingStateDir:      config.LoadbalancerCPT2HCEventLoggingStateDir,
		},
		OriginalIPDetection: reconcilerOriginalIPDetectionConfig{
			UseRemoteAddress:  config.LoadBalancerCPT2UseRemoteAddress,
			XffNumTrustedHops: config.LoadBalancerCPT2XffNumTrustedHops,
		},
		Policy: reconcilerPolicyConfig{
			EnableCiliumPolicyFilters: config.LoadBalancerCPPolicyEnableCiliumPolicyFilters,
		},
		IPFamilies: reconcilerIPFamilyConfig{
			EnableIPv4: agentConfig.EnableIPv4,
			EnableIPv6: agentConfig.EnableIPv6,
		},
	}
}

// registerSecretSync registers the LoadBalancer controlplane for secret synchronization based on TLS secrets referenced
// by the LBServices.
func registerSecretSync(params reconcilerParams) secretsync.SecretSyncRegistrationOut {
	if !params.Config.LoadBalancerCPEnabled {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &isovalentv1alpha1.LBService{},
			RefObjectEnqueueFunc: enqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   isReferencedByLBService,
			SecretsNamespace:     params.Config.LoadBalancerCPSecretsNamespace,
		},
	}
}

func parseDefaultTierLabelSelectors(t1 string, t2 string) (*slim_metav1.LabelSelector, *slim_metav1.LabelSelector, error) {
	t1LS, err := slim_metav1.ParseToLabelSelector(t1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse T1 label selector: %w", err)
	}

	t2LS, err := slim_metav1.ParseToLabelSelector(t2)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse T2 label selector: %w", err)
	}

	return t1LS, t2LS, nil
}

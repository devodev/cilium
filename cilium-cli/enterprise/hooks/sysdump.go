//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package hooks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli"
	enterpriseCli "github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli"
	enterpriseSysdump "github.com/cilium/cilium/cilium-cli/enterprise/hooks/sysdump"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/sysdump"
	loadbalancerStatus "github.com/cilium/cilium/enterprise/pkg/lb/status"
)

const (
	enterpriseLabelSelector      = "app.kubernetes.io/name=hubble-enterprise"
	enterpriseAgentContainerName = "enterprise"
	enterpriseBugtoolPrefix      = "hubble-enterprise-bugtool"
	enterpriseCLICommand         = "hubble-enterprise"

	dnsProxyContainerName   = "cilium-dnsproxy"
	dnsProxyMetricsPortName = "metrics"

	privateNetworksCertgenCronJob           = "cilium-private-networks-generate-certs"
	privateNetworksCertgenCronJobFileName   = privateNetworksCertgenCronJob + ".yaml"
	privateNetworksCertgenLabelSelector     = "k8s-app=cilium-private-networks-generate-certs"
	privateNetworksCertManagerCertsFileName = "cilium-private-networks-certmanager-certs.yaml"
)

var (
	fluentdAWSKeyIDRegexp     *regexp.Regexp
	fluentdAWSSecretKeyRegexp *regexp.Regexp
)

func init() {
	fluentdAWSKeyIDRegexp = regexp.MustCompile(`(aws_key_id).*`)
	fluentdAWSSecretKeyRegexp = regexp.MustCompile(`(aws_sec_key).*`)
}

func addSysdumpTasks(collector *sysdump.Collector, opts *EnterpriseOptions) error {
	collector.AddTasks([]sysdump.Task{
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-enterprise' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: enterpriseLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'hubble-enterprise' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-enterprise' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting bugtool output from 'hubble-enterprise' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: enterpriseLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get 'hubble-enterprise' pods")
				}
				if err = collector.SubmitTetragonBugtoolTasks(sysdump.FilterPods(p, collector.NodeList),
					enterpriseAgentContainerName, enterpriseBugtoolPrefix, enterpriseCLICommand); err != nil {
					return fmt.Errorf("failed to collect bugtool output from 'hubble-enterprise' pods: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collect hubble-relay rbac policies",
			Quick:           true,
			Task: func(ctx context.Context) error {
				cm := "hubble-rbac-policy"
				configMap, err := collector.Client.GetConfigMap(ctx, collector.Options.CiliumNamespace, cm, metav1.GetOptions{})
				if kerrors.IsNotFound(err) {
					// Ignore not found. Might not be enabled or we're looking at the wrong namespace
					return nil
				}
				if err != nil {
					return fmt.Errorf("failed to get Hubble Relay RBAC policy configmap: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("%s-<ts>.yaml", cm), configMap); err != nil {
					return fmt.Errorf("failed to collect Hubble Relay RBAC policy configmap: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Timescape Helm values",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}

				var taskErr error
				for _, ns := range namespaces {
					val, err := collector.Client.GetHelmValues(ctx, opts.HubbleTimescapeReleaseName, ns)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-timescape helm values from namespace %q: %w", ns, err))
						continue
					}
					if err := collector.WriteString("hubble-timescape-helm-values-<ts>.yaml", val); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-timescape helm values from namespace %q: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful values
					return nil
				}
				return taskErr
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Timescape configmaps",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}
				// TODO: List all the configmaps by label selector instead of hardcoding the names.
				configMaps := []string{
					"hubble-timescape-clickhouse-client-config",
					"hubble-timescape-ingester-config",
					"hubble-timescape-migrate-config",
					"hubble-timescape-rbac-policy",
					"hubble-timescape-server-config",
					"hubble-timescape-config",
					"hubble-timescape-clickhouse-settings",
					"hubble-timescape-ui-config",
				}

				for _, ns := range namespaces {
					for _, cm := range configMaps {
						configMap, err := collector.Client.GetConfigMap(ctx, ns, cm, metav1.GetOptions{})
						if kerrors.IsNotFound(err) {
							// Ignore not found. Might not be enabled or we're looking at the wrong namespace
							continue
						}
						if err != nil {
							return fmt.Errorf("failed to get Hubble Timescape configmaps: %w", err)
						}
						if err := collector.WriteYAML(fmt.Sprintf("%s-<ts>.yaml", cm), configMap); err != nil {
							return fmt.Errorf("failed to collect Hubble Timescape configmaps: %w", err)
						}
					}
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-timescape' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				pods := &corev1.PodList{}
				var err error

				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}

				for _, ns := range namespaces {
					p, err := collector.Client.ListPods(ctx, ns, metav1.ListOptions{
						LabelSelector: opts.HubbleTimescapeSelector,
					})
					if err != nil {
						return fmt.Errorf("failed to get logs from 'hubble-timescape' pods")
					}
					pods.Items = append(pods.Items, p.Items...)
				}
				// Collect integrated Timescape logs in cilium namespace
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: opts.HubbleIntegratedTimescapeSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'integrated-hubble-timescape' pods")
				}
				pods.Items = append(pods.Items, p.Items...)
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(pods, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-timescape' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting bugtool output from 'hubble-timescape' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				pods := &corev1.PodList{}
				var err error

				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}

				for _, ns := range namespaces {
					p, err := collector.Client.ListPods(ctx, ns, metav1.ListOptions{
						LabelSelector: opts.HubbleTimescapeSelector,
					})
					if err != nil {
						return fmt.Errorf("failed to get bugtool info from 'hubble-timescape' pods")
					}
					pods.Items = append(pods.Items, p.Items...)
				}
				if err = enterpriseSysdump.SubmitTimescapeBugtoolTasks(
					collector,
					sysdump.FilterPods(pods, collector.NodeList),
					"hubble-timescape-bugtool",
					opts.HubbleTimescapeBugtoolFlags,
				); err != nil {
					return fmt.Errorf("error collecting bugtool output from 'hubble-timescape' pods: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting bugtool output from 'integrated-hubble-timescape' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				pods, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: opts.HubbleIntegratedTimescapeSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get bugtool info from 'integrated-hubble-timescape' pods")
				}
				if err = enterpriseSysdump.SubmitTimescapeBugtoolTasks(
					collector,
					sysdump.FilterPods(pods, collector.NodeList),
					"hubble-integrated-timescape-bugtool",
					opts.HubbleIntegratedTimescapeBugtoolFlags,
				); err != nil {
					return fmt.Errorf("error collecting bugtool output from 'integrated-hubble-timescape' pods: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-ui' enterprise pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleUINamespace, collector.Options.CiliumNamespace}

				var taskErr error
				for _, ns := range namespaces {
					p, err := collector.Client.ListPods(ctx, ns, metav1.ListOptions{
						LabelSelector: collector.Options.HubbleUILabelSelector,
					})
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to get logs from '%s/hubble-ui' pods: %w", ns, err))
						continue
					}
					if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
						collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect logs from '%s/hubble-ui' pods: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful logs
					return nil
				}
				return taskErr
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting 'hubble-ui' Helm values",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{collector.Options.CiliumNamespace, opts.HubbleUINamespace}
				var taskErr error
				for _, ns := range namespaces {
					val, err := collector.Client.GetHelmValues(ctx, opts.HubbleUIReleaseName, ns)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-ui helm values from namespace %q: %w", ns, err))
						continue
					}
					if err := collector.WriteString("hubble-ui-helm-values-<ts>.yaml", val); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to write hubble-ui helm values: %w", err))
						continue
					}
					// we didn't hit any errors, return early with the successful values
					return nil
				}
				return taskErr
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs, metrics and gops stats from 'cilium-dnsproxy' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "k8s-app=cilium-dnsproxy",
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'cilium-dnsproxy' pods: %w", err)
				}

				pods := sysdump.FilterPods(p, collector.NodeList)
				if err = collector.SubmitLogsTasks(pods,
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'cilium-dnsproxy' pods: %w", err)
				}
				if err = collector.SubmitMetricsSubtask(pods,
					dnsProxyContainerName, dnsProxyMetricsPortName); err != nil {
					return fmt.Errorf("failed to collect metrics from 'cilium-dnsproxy' pods: %w", err)
				}

				if err = collector.SubmitGopsSubtasks(pods, dnsProxyContainerName); err != nil {
					return fmt.Errorf("failed to collect gops stats from 'cilium-dnsproxy' pods: %w", err)
				}

				if collector.Options.Profiling {
					if err = collector.SubmitProfilingGopsSubtasks(pods, dnsProxyContainerName); err != nil {
						return fmt.Errorf("failed to collect profiles from 'cilium-dnsproxy' pods: %w", err)
					}
				}

				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting DNS Proxy Daemonset",
			Quick:           true,
			Task: func(ctx context.Context) error {
				daemonSets, err := collector.Client.ListDaemonSet(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "k8s-app=cilium-dnsproxy",
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium DNS Daemonset")
				}
				if err := collector.WriteYAML("cilium-enterprise-dns-proxy-daemonset-<ts>.yaml", daemonSets); err != nil {
					return fmt.Errorf("failed to collect DNS Proxy Daemonset: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Cilium DNS Proxy Helm values",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{collector.Options.CiliumNamespace}
				var taskErr error
				for _, ns := range namespaces {
					val, err := collector.Client.GetHelmValues(ctx, opts.CiliumDnsProxyReleaseName, ns)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect Cilium DNS Proxy helm values from namespace %q: %w", ns, err))
						continue
					}
					if err := collector.WriteString("cilium-dnsproxy-helm-values-<ts>.yaml", val); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to write cilium-dnsproxy helm values: %w", err))
						continue
					}
					// we didn't hit any errors, return early with the successful values
					return nil
				}
				return taskErr
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble UI Enterprise oauth2-proxy Configmap",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleUINamespace, collector.Options.CiliumNamespace}
				var taskErr error
				for _, ns := range namespaces {
					configMap, err := collector.Client.GetConfigMap(ctx, ns, "oauth2-proxy", metav1.GetOptions{})
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to get Hubble UI Enterprise '%s/oauth2-proxy' Configmap: %w", ns, err))
						continue
					}
					if err := collector.WriteYAML("hubble-enterprise-oauth2-proxy-configmap-<ts>.yaml", configMap); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to get Hubble UI Enterprise '%s/oauth2-proxy' Configmap: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful config
					return nil
				}
				return taskErr
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Enterprise Configmap",
			Quick:           true,
			Task: func(ctx context.Context) error {
				configMap, err := collector.Client.GetConfigMap(ctx, collector.Options.CiliumNamespace, "hubble-enterprise-config", metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get Hubble Enterprise configmap")
				}
				if err := collector.WriteYAML("hubble-enterprise-configmap-<ts>.yaml", configMap); err != nil {
					return fmt.Errorf("failed to collect Hubble Enterprise configmap: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collect hubble-enterprise fluentd-export configmap",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleEnterpriseNamespace}

				var taskErr error
				for _, ns := range namespaces {
					cm := "hubble-enterprise-export-fluentd"
					configMap, err := collector.Client.GetConfigMap(ctx, ns, cm, metav1.GetOptions{})
					if kerrors.IsNotFound(err) {
						// Ignore not found. Might not be enabled or we're looking at the wrong namespace
						return nil
					}
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect %s configmap from namespace %q: %w", cm, ns, err))
						continue
					}

					// DeepCopy before mutating
					configMap = configMap.DeepCopy()
					// Sanitize any potentially hardcoded AWS creds in the Config
					for k, v := range configMap.Data {
						configMap.Data[k] = sanitizeHardcodedFluentdS3Creds(v)
					}
					if err := collector.WriteYAML(fmt.Sprintf("%s-configmap-<ts>.yaml", cm), configMap); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect %s configmap from namespace %q: %w", cm, ns, err))
						continue
					}
					return nil
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Enterprise Helm values",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleEnterpriseNamespace}

				var taskErr error
				for _, ns := range namespaces {
					val, err := collector.Client.GetHelmValues(ctx, opts.HubbleEnterpriseReleaseName, ns)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}

					var data map[string]any
					if err := yamlutil.Unmarshal([]byte(val), &data); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}

					// sanitize tls related options. Private keys in are especially
					// important to avoid collecting, but we skip other fields in case
					// the user made a mistake configuring.
					sanitizeRBACTLSOptions(data)
					// sanitize fluentd AWS output in-case the user hard-coded creds in there
					sanitizeFluentdAWSCreds(data)

					b, err := yaml.Marshal(data)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}
					val = string(b)

					if err := collector.WriteString("hubble-enterprise-helm-values-<ts>.yaml", val); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful values
					return nil
				}
				return taskErr
			},
		},
		{
			Description: "Collecting IsovalentFQDNGroup",
			Quick:       true,
			Task: func(ctx context.Context) error {
				fqdnGroups := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentfqdngroups",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, fqdnGroups, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent FQDN groups: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentfqdngroups-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent FQDN groups: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentPodNetworks",
			Quick:       true,
			Task: func(ctx context.Context) error {
				podNetworks := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentpodnetworks",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, podNetworks, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent pod networks: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentpodnetworks-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent pod networks: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentEgressGatewayPolicy",
			Quick:       true,
			Task: func(ctx context.Context) error {
				gatewayPolicies := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentegressgatewaypolicies",
					Version:  "v1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, gatewayPolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent Egress Gateway policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentegressgatewaypolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent Egress Gateway policies: %w", err)
				}
				return nil
			},
		},
		{
			// collect raw output to pick up HA-style format
			Description: "Collecting CiliumEgressGatewayPolicy",
			Quick:       true,
			Task: func(ctx context.Context) error {
				gatewayPolicies := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "ciliumegressgatewaypolicies",
					Version:  "v2",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, gatewayPolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium Egress Gateway policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-ciliumegressgatewaypolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Cilium Egress Gateway policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentMulticastGroup",
			Quick:       true,
			Task: func(ctx context.Context) error {
				multicastGroups := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentmulticastgroups",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, multicastGroups, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Groups: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentmulticastgroups-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Groups: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentMulticastNodes",
			Quick:       true,
			Task: func(ctx context.Context) error {
				multicastNodes := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentmulticastnodes",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, multicastNodes, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Nodes: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentmulticastnodes-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Nodes: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting LBVIPs",
			Quick:       true,
			Task: func(ctx context.Context) error {
				fqdnGroups := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "lbvips",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, fqdnGroups, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect LBVIPs: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-lbvips-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect LBVIPs: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting LBDeployments",
			Quick:       true,
			Task: func(ctx context.Context) error {
				fqdnGroups := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "lbdeployments",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, fqdnGroups, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect LBDeployments: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-lbdeployments-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect LBDeployments: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting LBServices",
			Quick:       true,
			Task: func(ctx context.Context) error {
				lbServices := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "lbservices",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, lbServices, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect LBServices: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-lbservices-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect LBServices: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting LBBackendPools",
			Quick:       true,
			Task: func(ctx context.Context) error {
				fqdnGroups := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "lbbackendpools",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, fqdnGroups, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect LBBackendPools: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-lbbackendpools-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect LBBackendPools: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Tetragon SandboxPolicies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				sandboxpolicies := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "sandboxpolicies",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, sandboxpolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Tetragon SandboxPolicies: %w", err)
				}
				if err := collector.WriteYAML("tetragon-enterprise-sandboxpolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to write Tetragon SandboxPolicies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Tetragon SandboxPoliciesNamespaced",
			Quick:       true,
			Task: func(ctx context.Context) error {
				sandboxpolicies := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "sandboxpoliciesnamespaced",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, sandboxpolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Tetragon SandboxPoliciesNamespaced: %w", err)
				}
				if err := collector.WriteYAML("tetragon-enterprise-sandboxpoliciesnamespaced-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to write Tetragon SandboxPoliciesNamespaced: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Tetragon NetworkPolicies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				gvr := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "tetragonnetworkpolicies",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Tetragon NetworkPolicies: %w", err)
				}
				if err := collector.WriteYAML("tetragon-enterprise-networkpolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to write Tetragon NetworkPolicies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Tetragon NetworkPoliciesNamespaced",
			Quick:       true,
			Task: func(ctx context.Context) error {
				gvr := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "tetragonnetworkpoliciesnamespaced",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Tetragon NetworkPoliciesNamespaced: %w", err)
				}
				if err := collector.WriteYAML("tetragon-enterprise-networkpoliciesnamespaced-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to write Tetragon NetworkPoliciesNamespaced: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Tetragon AlertRules",
			Quick:       true,
			Task: func(ctx context.Context) error {
				gvr := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "alertrules",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Tetragon AlertRules: %w", err)
				}
				if err := collector.WriteYAML("tetragon-enterprise-alertrules-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to write Tetragon AlertRules: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting all Custom Resource Definitions (CRDs)",
			Quick:           true,
			Task: func(ctx context.Context) error {
				crdGVR := schema.GroupVersionResource{
					Group:    "apiextensions.k8s.io",
					Version:  "v1",
					Resource: "customresourcedefinitions",
				}
				n := corev1.NamespaceAll
				crdList, err := collector.Client.ListUnstructured(ctx, crdGVR, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to list CRDs: %w", err)
				}
				if err := collector.WriteYAML("k8s-crds-<ts>.yaml", crdList); err != nil {
					return fmt.Errorf("failed to write CRD list to YAML file: %w", err)
				}

				return nil
			},
		},
		{
			Description: "Collecting LB Status",
			Quick:       false,
			Task: func(ctx context.Context) error {
				if !collector.FeatureSet[enterpriseFeatures.LoadBalancer].Enabled {
					return nil
				}

				k8sClient := collector.Client.(*k8s.Client)
				lsm, err := enterpriseCli.GetLoadbalancerStatus(ctx, k8sClient, loadbalancerStatus.Parameters{})
				if err != nil {
					return err
				}

				out := []struct {
					name   string
					format string
				}{
					{
						name:   "cilium-lb-status.txt",
						format: "summary",
					},
					{
						name:   "cilium-lb-status.json",
						format: "json",
					},
				}

				var errs error
				for _, o := range out {
					f, err := os.Create(collector.AbsoluteTempPath(o.name))
					if errs != nil {
						errs = errors.Join(errs, fmt.Errorf("failed to create %q: %w", o.name, err))
						continue
					}
					defer f.Close()

					errs = errors.Join(errs, lsm.Output(f,
						loadbalancerStatus.Parameters{Output: o.format, Colors: false, Verbose: o.format == "json"}))
				}

				return errs
			},
		},
		{
			Description: "Collecting Isovalent network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "isovalentnetworkpolicies"
				inps := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: resource,
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, inps, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent network policies: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), v); err != nil {
					return fmt.Errorf("failed to collect Isovalent network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Isovalent cluster-wide network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "isovalentclusterwidenetworkpolicies"
				icnps := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: resource,
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, icnps, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent cluster-wide network policies: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), v); err != nil {
					return fmt.Errorf("failed to collect Isovalent cluster-wide network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting ClusterwidePrivateNetworks",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "clusterwideprivatenetworks"
				v, err := collector.Client.ListUnstructured(ctx, schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: resource,
					Version:  "v1alpha1",
				}, ptr.To(corev1.NamespaceAll), metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cluster-wide Private Networks: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), v); err != nil {
					return fmt.Errorf("failed to collect Cluster-wide Private Networks: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting PrivateNetworkEndpointSlices",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "privatenetworkendpointslices"
				v, err := collector.Client.ListUnstructured(ctx, schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: resource,
					Version:  "v1alpha1",
				}, ptr.To(corev1.NamespaceAll), metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Private Network Endpoint Slices: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), v); err != nil {
					return fmt.Errorf("failed to collect Private Network Endpoint Slices: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting PrivateNetworkExternalEndpoints",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "privatenetworkexternalendpoints"
				v, err := collector.Client.ListUnstructured(ctx, schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: resource,
					Version:  "v1alpha1",
				}, ptr.To(corev1.NamespaceAll), metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Private Network External Endpoints: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), v); err != nil {
					return fmt.Errorf("failed to collect Private Network External Endpoints: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting PrivateNetworkNodeAttachments",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "privatenetworknodeattachments"
				v, err := collector.Client.ListUnstructured(ctx, schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: resource,
					Version:  "v1alpha1",
				}, ptr.To(corev1.NamespaceAll), metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Private Network Node Attachments: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), v); err != nil {
					return fmt.Errorf("failed to collect Private Network Node Attachments: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Private Networks certgen cronjob",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := collector.Client.GetCronJob(ctx, collector.Options.CiliumNamespace, privateNetworksCertgenCronJob, metav1.GetOptions{})
				if err == nil {
					err = collector.WriteYAML(privateNetworksCertgenCronJobFileName, v)
				}
				if err != nil {
					return fmt.Errorf("failed to collect the Private Networks certgen cronjob: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Private Networks certgen logs",
			Quick:       false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: privateNetworksCertgenLabelSelector,
				})
				if err == nil {
					err = collector.SubmitLogsTasks(
						sysdump.AllPods(p),
						collector.Options.LogsSinceTime,
						collector.Options.LogsLimitBytes)
				}
				if err != nil {
					return fmt.Errorf("failed to collect logs from Private Networks certgen pods")
				}
				return nil
			},
		},
		{
			Description: "Collecting the Private Networks cert-manager certificates",
			Quick:       true,
			Task: func(ctx context.Context) error {
				return collector.GatherResourceUnstructured(
					ctx,
					schema.GroupVersionResource{
						Group:    "cert-manager.io",
						Resource: "certificates",
						Version:  "v1",
					},
					privateNetworksCertManagerCertsFileName,
					"cilium-private-networks-webhook",
					"cilium-private-networks-api-client",
					"cilium-private-networks-api-server",
				)
			},
		},
		{
			Description: "Collecting NetworkAttachmentDefinitions",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "network-attachment-definitions"
				objs, err := collector.Client.ListUnstructured(ctx, schema.GroupVersionResource{
					Group:    "k8s.cni.cncf.io",
					Resource: resource,
					Version:  "v1",
				}, ptr.To(corev1.NamespaceAll), metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect NetworkAttachmentDefinitions: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), objs); err != nil {
					return fmt.Errorf("failed to collect NetworkAttachmentDefinitions: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting InspectionConfigs",
			Quick:       true,
			Task: func(ctx context.Context) error {
				resource := "isovalentinspectionconfigs"
				inspectionCfgs := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: resource,
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, inspectionCfgs, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect InspectionConfigs: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", resource), v); err != nil {
					return fmt.Errorf("failed to collect InspectionConfigs: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting diagnostics",
			Task: func(ctx context.Context) error {
				return collector.WithFileSink("diagnostics.txt", func(w io.Writer) error {
					_, err := cli.CollectAndPrintDiagnostics(ctx, slices.Values(collector.CiliumPods), collector.Client, false, w)
					return err
				})
			},
		},
	})

	if collector.FeatureSet[enterpriseFeatures.SRv6].Enabled {
		addSRv6SysdumpTasks(collector)
	}

	if collector.FeatureSet[enterpriseFeatures.SRv6LocatorPool].Enabled {
		addSRv6LocatorPoolSysdumpTasks(collector)
	}

	if collector.FeatureSet[enterpriseFeatures.EnterpriseBGPControlPlane].Enabled {
		addEnterpriseBGPSysdumpTasks(collector)
	}

	if collector.FeatureSet[enterpriseFeatures.BFD].Enabled {
		addEnterpriseBFDSysdumpTasks(collector)
	}

	if collector.FeatureSet[enterpriseFeatures.EVPN].Enabled {
		addEnterpriseEVPNSysdumpTasks(collector)
	}

	if collector.FeatureSet[enterpriseFeatures.EncryptionPolicy].Enabled {
		addEnterpriseEncryptionPolicySysdumpTasks(collector)
	}

	kind := collector.Client.AutodetectFlavor(context.Background()).Kind
	if kind == k8s.KindOpenShift {
		collector.AddTasks([]sysdump.Task{collectOpenShiftMustGather(collector)})
		collector.AddTasks([]sysdump.Task{collectOpenShiftCiliumConfig(collector, "CiliumConfig", "ciliumconfigs")})
	}

	return nil
}

func addSRv6SysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "IsovalentVRF", "isovalentvrfs"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentSRv6EgressPolicy", "isovalentsrv6egresspolicies"),
	})
}

func addSRv6LocatorPoolSysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "IsovalentSRv6SIDManager", "isovalentsrv6sidmanagers"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentSRv6LocatorPool", "isovalentsrv6locatorpools"),
	})
}

func addEnterpriseBGPSysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1OrV1Alpha1Resource(collector, "IsovalentBGPClusterConfig", "isovalentbgpclusterconfigs"),
		collectIsovalentV1OrV1Alpha1Resource(collector, "IsovalentBGPPeerConfig", "isovalentbgppeerconfigs"),
		collectIsovalentV1OrV1Alpha1Resource(collector, "IsovalentBGPAdvertisement", "isovalentbgpadvertisements"),
		collectIsovalentV1OrV1Alpha1Resource(collector, "IsovalentBGPNodeConfig", "isovalentbgpnodeconfigs"),
		collectIsovalentV1OrV1Alpha1Resource(collector, "IsovalentBGPNodeConfigOverride", "isovalentbgpnodeconfigoverrides"),
		collectIsovalentV1OrV1Alpha1Resource(collector, "IsovalentBGPPolicy", "isovalentbgppolicies"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBGPVRFConfig", "isovalentbgpvrfconfigs"),
	})
}

func addEnterpriseBFDSysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBFDProfile", "isovalentbfdprofiles"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBFDNodeConfig", "isovalentbfdnodeconfigs"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBFDNodeConfigOverride", "isovalentbfdnodeconfigoverrides"),
	})
}

func addEnterpriseEVPNSysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "FabricSecurityGroup", "fabricsecuritygroups"),
	})
}

func addEnterpriseEncryptionPolicySysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "IsovalentClusterwideEncryptionPolicy", "isovalentclusterwideencryptionpolicies"),
	})
}

func collectIsovalentV1Alpha1Resource(collector *sysdump.Collector, kind, name string) sysdump.Task {
	return sysdump.Task{
		Description: fmt.Sprintf("Collecting %s", kind),
		Quick:       true,
		Task: func(ctx context.Context) error {
			gvr := schema.GroupVersionResource{
				Group:    "isovalent.com",
				Resource: name,
				Version:  "v1alpha1",
			}
			n := corev1.NamespaceAll
			v, err := collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", name), v); err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			return nil
		},
	}
}

// collects objects of v1 (primarily) or v1alpha1 (fallback) version of an isovalent.com resource
func collectIsovalentV1OrV1Alpha1Resource(collector *sysdump.Collector, kind, name string) sysdump.Task {
	return sysdump.Task{
		Description: fmt.Sprintf("Collecting %s", kind),
		Quick:       true,
		Task: func(ctx context.Context) error {
			gvr := schema.GroupVersionResource{
				Group:    "isovalent.com",
				Resource: name,
				Version:  "v1",
			}
			n := corev1.NamespaceAll
			// try to collect the v1 version first
			v, err := collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
			if err != nil && kerrors.IsNotFound(err) {
				// if the v1 version does not exist, try to collect the v1alpha1 version
				gvr.Version = "v1alpha1"
				v, err = collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
			}
			if err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", name), v); err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			return nil
		},
	}
}

// collects 'oc adm must-gather' output
func collectOpenShiftMustGather(collector *sysdump.Collector) sysdump.Task {
	command := "bash"
	args := []string{"-c", "oc adm must-gather --dest-dir='oc-adm-mustgather' && zip -r oc-adm-mustgather.zip oc-adm-mustgather"}
	outputFile := "oc-adm-must-gather"
	extraFile := "oc-adm-must-gather.zip"

	return sysdump.Task{
		Description: "Collecting 'oc adm must-gather' data (OpenShift only)",
		Quick:       false,
		Task: func(ctx context.Context) error {
			cmd := exec.CommandContext(ctx, command, args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to execute '%s': %w, check if `oc` and `zip` binaries are installed", command+" "+strings.Join(args, " "), err)
			}
			if err := collector.WriteString(outputFile, string(output)); err != nil {
				return fmt.Errorf("failed to write shell command output to sysdump: %w", err)
			}

			if extraFile != "" {
				extra, err := os.ReadFile(extraFile)
				if err != nil {
					return fmt.Errorf("failed to read extra file %s: %w", extraFile, err)
				}
				if err := collector.WriteString(extraFile, string(extra)); err != nil {
					return fmt.Errorf("failed to write extra file %s to sysdump: %w", extraFile, err)
				}
			}
			return nil
		},
	}
}

func collectOpenShiftCiliumConfig(collector *sysdump.Collector, kind, name string) sysdump.Task {
	return sysdump.Task{
		Description: fmt.Sprintf("Collecting %s", kind),
		Quick:       true,
		Task: func(ctx context.Context) error {
			gvr := schema.GroupVersionResource{
				Group:    "cilium.io",
				Resource: name,
				Version:  "v1alpha1",
			}
			n := corev1.NamespaceAll
			v, err := collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", name), v); err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			return nil
		},
	}
}

func setMapValueIfExists(m map[string]any, path string, val any) {
	keys := strings.Split(path, ".")
	for i, key := range keys {
		if i == len(keys)-1 {
			if _, exists := m[key]; exists {
				m[key] = val
			}
			return
		}
		m2, ok := m[key]
		if !ok {
			return
		}
		m3, ok := m2.(map[string]any)
		if !ok {
			return
		}
		m = m3
	}
}

func getMapValueIfExists(m map[string]any, path string) (any, bool) {
	keys := strings.Split(path, ".")
	for i, key := range keys {
		if i == len(keys)-1 {
			val, ok := m[key]
			return val, ok
		}
		m2, ok := m[key]
		if !ok {
			return nil, false
		}
		m3, ok := m2.(map[string]any)
		if !ok {
			return nil, false
		}
		m = m3
	}
	return nil, false
}

func sanitizeRBACTLSOptions(data map[string]any) {
	setMapValueIfExists(data, "rbac.metricsProxy.oidcCert", "xxx")
	setMapValueIfExists(data, "rbac.metricsProxy.tlsKey", "xxx")
	setMapValueIfExists(data, "rbac.metricsProxy.cert", "xxx")
	setMapValueIfExists(data, "rbac.metricsProxy.clientCA", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.oidcCert", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.tlsKey", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.cert", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.clientCA", "xxx")
}

func sanitizeFluentdAWSCreds(data map[string]any) {
	var fluentdOutput string
	if output, ok := getMapValueIfExists(data, "export.fluentd.output"); ok {
		outputStr, ok := output.(string)
		if !ok {
			return
		}
		fluentdOutput = outputStr
	}

	fluentdOutput = sanitizeHardcodedFluentdS3Creds(fluentdOutput)

	setMapValueIfExists(data, "export.fluentd.output", fluentdOutput)
}

func sanitizeHardcodedFluentdS3Creds(s string) string {
	for _, re := range []*regexp.Regexp{fluentdAWSKeyIDRegexp, fluentdAWSSecretKeyRegexp} {
		s = re.ReplaceAllString(s, "$1 xxx")
	}
	return s
}

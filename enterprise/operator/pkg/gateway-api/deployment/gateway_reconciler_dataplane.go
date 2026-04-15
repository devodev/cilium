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
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstrutil "k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/shortener"
)

//go:embed envoy-bootstrap-config.json
var envoyBootstrapConfig string

func (r *GatewayReconciler) reconcileDataplaneResources(ctx context.Context, gw *gatewayv1.Gateway) error {
	if err := r.reconcileDataplaneConfigMap(ctx, gw); err != nil {
		return err
	}

	if err := r.reconcileDataplaneServiceAccount(ctx, gw); err != nil {
		return err
	}

	if err := r.reconcileDataplaneService(ctx, gw); err != nil {
		return err
	}

	if err := r.reconcileDataplaneDeployment(ctx, gw); err != nil {
		return err
	}

	return nil
}

func (r *GatewayReconciler) reconcileDataplaneDeployment(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredDataplaneDeployment(gw)
	deployment := &appsv1.Deployment{}
	exists := true
	if err := r.client.Get(ctx, client.ObjectKeyFromObject(desired), deployment); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to get dataplane Deployment: %w", err)
		}
		exists = false
		deployment = &appsv1.Deployment{ObjectMeta: desired.ObjectMeta}
	}

	// Recreate the Deployment when immutable fields change during migrations.
	// Today this covers the selector, but other immutable parts may need similar
	// handling in the future.
	if exists && !apiequality.Semantic.DeepEqual(deployment.Spec.Selector, desired.Spec.Selector) {
		if err := r.client.Delete(ctx, deployment); err != nil {
			return fmt.Errorf("failed to recreate dataplane Deployment after selector change: %w", err)
		}
		deployment = &appsv1.Deployment{ObjectMeta: desired.ObjectMeta}
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, deployment, func() error {
		deployment.Labels = desired.Labels
		deployment.Spec = desired.Spec

		return controllerutil.SetControllerReference(gw, deployment, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update dataplane Deployment: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) reconcileDataplaneConfigMap(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredDataplaneConfigMap(gw)
	configMap := &corev1.ConfigMap{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, configMap, func() error {
		configMap.Labels = desired.Labels
		configMap.Data = desired.Data

		return controllerutil.SetControllerReference(gw, configMap, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update dataplane ConfigMap: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) reconcileDataplaneServiceAccount(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredDataplaneServiceAccount(gw)
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, serviceAccount, func() error {
		serviceAccount.Labels = desired.Labels

		return controllerutil.SetControllerReference(gw, serviceAccount, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update dataplane ServiceAccount: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) reconcileDataplaneService(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredDataplaneService(gw)
	service := &corev1.Service{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, service, func() error {
		// Preserve API-assigned and externally managed fields across updates.
		clusterIP := service.Spec.ClusterIP
		clusterIPs := service.Spec.ClusterIPs
		ipFamilies := service.Spec.IPFamilies
		ipFamilyPolicy := service.Spec.IPFamilyPolicy
		healthCheckNodePort := service.Spec.HealthCheckNodePort
		loadBalancerClass := service.Spec.LoadBalancerClass

		service.Labels = desired.Labels
		service.Spec = desired.Spec
		service.Spec.ClusterIP = clusterIP
		service.Spec.ClusterIPs = clusterIPs
		service.Spec.IPFamilies = ipFamilies
		service.Spec.IPFamilyPolicy = ipFamilyPolicy
		service.Spec.HealthCheckNodePort = healthCheckNodePort
		service.Spec.LoadBalancerClass = loadBalancerClass

		return controllerutil.SetControllerReference(gw, service, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update dataplane Service: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) desiredDataplaneConfigMap(gw *gatewayv1.Gateway) *corev1.ConfigMap {
	labels := r.dataplaneComponentLabels(gw)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.dataplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"envoy-bootstrap-config.json": r.bootstrapConfigForGateway(gw),
		},
	}
}

func (r *GatewayReconciler) desiredDataplaneDeployment(gw *gatewayv1.Gateway) *appsv1.Deployment {
	labels := r.dataplaneComponentLabels(gw)
	renderedBootstrapConfig := r.bootstrapConfigForGateway(gw)
	adminLoopback := r.adminLoopbackAddress()
	adminPort := int32(r.config.GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.dataplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Replicas: ptr.To(int32(r.config.GatewayAPIDeploymentDataplaneDefaultReplicas)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						bootstrapChecksumAnnotation: bootstrapConfigMapChecksum(renderedBootstrapConfig),
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: r.dataplaneResourceName(gw),
					Containers: []corev1.Container{{
						Name:    "envoy",
						Image:   r.config.GatewayAPIDeploymentDataplaneDefaultEnvoyImage,
						Command: []string{"/usr/bin/cilium-envoy"},
						Args: []string{
							"--log-level " + r.config.GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel,
							"--config-path /var/run/cilium/envoy/envoy-bootstrap-config.json",
							"--base-id " + gatewayAsEnvoyBaseID(gw),
							"--service-cluster " + gatewayAsEnvoyClusterName(gw),
							"--service-node " + gatewayAsEnvoyNodeID(gw),
						},
						Env: []corev1.EnvVar{
							{
								Name: "POD_NAME",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										APIVersion: "v1",
										FieldPath:  "metadata.name",
									},
								},
							},
						},
						StartupProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Host: adminLoopback,
									Path: "/ready",
									Port: intstrutil.FromInt32(adminPort),
								},
							},
							FailureThreshold: 105,
							PeriodSeconds:    2,
							TimeoutSeconds:   1,
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Host: adminLoopback,
									Path: "/ready",
									Port: intstrutil.FromInt32(adminPort),
								},
							},
							FailureThreshold: 10,
							PeriodSeconds:    30,
							TimeoutSeconds:   5,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Host: adminLoopback,
									Path: "/ready",
									Port: intstrutil.FromInt32(adminPort),
								},
							},
							FailureThreshold: 3,
							PeriodSeconds:    5,
							TimeoutSeconds:   3,
						},
						Ports: r.desiredDataplaneContainerPorts(gw),
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "envoy-config",
								MountPath: "/var/run/cilium/envoy/",
								ReadOnly:  true,
							},
						},
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					}},
					Volumes: []corev1.Volume{
						{
							Name: "envoy-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.dataplaneResourceName(gw),
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "envoy-bootstrap-config.json",
											Path: "envoy-bootstrap-config.json",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *GatewayReconciler) desiredDataplaneServiceAccount(gw *gatewayv1.Gateway) *corev1.ServiceAccount {
	labels := r.dataplaneComponentLabels(gw)

	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.dataplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
	}
}

func (r *GatewayReconciler) desiredDataplaneService(gw *gatewayv1.Gateway) *corev1.Service {
	labels := r.dataplaneComponentLabels(gw)

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.dataplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: labels,
			Ports:    r.desiredDataplaneServicePorts(gw),
		},
	}
}

func (r *GatewayReconciler) desiredDataplaneServicePorts(gw *gatewayv1.Gateway) []corev1.ServicePort {
	ports := make([]corev1.ServicePort, 0, len(gw.Spec.Listeners))
	for _, listener := range gw.Spec.Listeners {
		ports = append(ports, corev1.ServicePort{
			Name:       string(listener.Name),
			Port:       int32(listener.Port),
			Protocol:   r.listenerProtocol(listener.Protocol),
			TargetPort: intstrutil.FromInt32(int32(listener.Port)),
		})
	}

	return ports
}

func (r *GatewayReconciler) desiredDataplaneContainerPorts(gw *gatewayv1.Gateway) []corev1.ContainerPort {
	ports := make([]corev1.ContainerPort, 0, len(gw.Spec.Listeners))
	for _, listener := range gw.Spec.Listeners {
		ports = append(ports, corev1.ContainerPort{
			Name:          string(listener.Name),
			ContainerPort: int32(listener.Port),
			Protocol:      r.listenerProtocol(listener.Protocol),
		})
	}

	return ports
}

func (r *GatewayReconciler) cleanupDataplaneResources(ctx context.Context, gw *gatewayv1.Gateway) error {
	for _, obj := range []client.Object{
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.dataplaneResourceName(gw),
				Namespace: gw.Namespace,
			},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.dataplaneResourceName(gw),
				Namespace: gw.Namespace,
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.dataplaneResourceName(gw),
				Namespace: gw.Namespace,
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.dataplaneResourceName(gw),
				Namespace: gw.Namespace,
			},
		},
	} {
		if err := r.client.Delete(ctx, obj); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete %T %s/%s: %w", obj, gw.Namespace, r.dataplaneResourceName(gw), err)
		}
	}

	return nil
}

func (r *GatewayReconciler) dataplaneComponentLabels(gw *gatewayv1.Gateway) map[string]string {
	return map[string]string{
		appKubernetesNameLabel:          gatewayDataplaneAppName,
		appKubernetesComponentLabel:     gatewayDataplaneComponent,
		appKubernetesPartOfLabel:        gatewayDeploymentPartOf,
		appKubernetesManagedByLabel:     gatewayDeploymentManagedBy,
		appKubernetesInstanceLabel:      shortener.ShortenK8sResourceName(gw.Namespace + "." + gw.Name),
		gatewayNameAttachmentLabel:      shortener.ShortenK8sResourceName(gw.Name),
		gatewayClassNameAttachmentLabel: shortener.ShortenK8sResourceName(string(gw.Spec.GatewayClassName)),
	}
}

func (r *GatewayReconciler) dataplaneResourceName(gw *gatewayv1.Gateway) string {
	return shortener.ShortenK8sResourceName(dataplaneResourcePrefix + gw.Name)
}

func gatewayAsEnvoyBaseID(gw *gatewayv1.Gateway) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(gw.Namespace))
	_, _ = h.Write([]byte("/"))
	_, _ = h.Write([]byte(gw.Name))

	return strconv.FormatUint(uint64(h.Sum32()), 10)
}

func gatewayAsEnvoyClusterName(gw *gatewayv1.Gateway) string {
	return gw.Namespace + "/" + gw.Name
}

func gatewayAsEnvoyNodeID(gw *gatewayv1.Gateway) string {
	return gatewayAsEnvoyClusterName(gw) + "/$(POD_NAME)"
}

func bootstrapConfigMapChecksum(config string) string {
	sum := sha256.Sum256([]byte(config))
	return fmt.Sprintf("%x", sum)
}

func (r *GatewayReconciler) bootstrapConfigForGateway(gw *gatewayv1.Gateway) string {
	config := strings.Replace(envoyBootstrapConfig, "\"__ADMIN_LOOPBACK__\"", strconv.Quote(r.adminLoopbackAddress()), 1)
	return strings.Replace(config, "__ADMIN_PORT__", strconv.Itoa(r.config.GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort), 1)
}

func (r *GatewayReconciler) adminLoopbackAddress() string {
	if !r.daemonConfig.EnableIPv4 && r.daemonConfig.EnableIPv6 {
		return "::1"
	}

	return "127.0.0.1"
}

func (r *GatewayReconciler) listenerProtocol(protocol gatewayv1.ProtocolType) corev1.Protocol {
	if protocol == gatewayv1.UDPProtocolType {
		return corev1.ProtocolUDP
	}

	return corev1.ProtocolTCP
}

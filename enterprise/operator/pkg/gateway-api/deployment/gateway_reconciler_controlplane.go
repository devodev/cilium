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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstrutil "k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
)

const (
	controlplaneXDSPort     = int32(18000)
	controlplaneHealthPort  = int32(18001)
	controlplaneMetricsPort = int32(9966)
)

func (r *GatewayReconciler) reconcileControlplaneResources(ctx context.Context, gw *gatewayv1.Gateway) error {
	r.logger.DebugContext(ctx, "Reconciling Gateway controlplane resources", logfields.Resource, client.ObjectKeyFromObject(gw))

	if err := r.reconcileControlplaneServiceAccount(ctx, gw); err != nil {
		return err
	}
	if err := r.reconcileControlplaneRole(ctx, gw); err != nil {
		return err
	}
	if err := r.reconcileControlplaneRoleBinding(ctx, gw); err != nil {
		return err
	}
	if err := r.reconcileControlplaneService(ctx, gw); err != nil {
		return err
	}
	if err := r.reconcileControlplaneDeployment(ctx, gw); err != nil {
		return err
	}

	return nil
}

func (r *GatewayReconciler) reconcileControlplaneDeployment(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredControlplaneDeployment(gw)
	deployment := &appsv1.Deployment{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, deployment, func() error {
		deployment.Labels = desired.Labels
		deployment.Spec = desired.Spec
		return controllerutil.SetControllerReference(gw, deployment, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update controlplane Deployment: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) reconcileControlplaneServiceAccount(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredControlplaneServiceAccount(gw)
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, serviceAccount, func() error {
		serviceAccount.Labels = desired.Labels
		return controllerutil.SetControllerReference(gw, serviceAccount, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update controlplane ServiceAccount: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) reconcileControlplaneRole(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredControlplaneRole(gw)
	role := &rbacv1.Role{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, role, func() error {
		role.Labels = desired.Labels
		role.Rules = desired.Rules
		return controllerutil.SetControllerReference(gw, role, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update controlplane Role: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) reconcileControlplaneRoleBinding(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredControlplaneRoleBinding(gw)
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, roleBinding, func() error {
		roleBinding.Labels = desired.Labels
		roleBinding.RoleRef = desired.RoleRef
		roleBinding.Subjects = desired.Subjects
		return controllerutil.SetControllerReference(gw, roleBinding, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update controlplane RoleBinding: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) reconcileControlplaneService(ctx context.Context, gw *gatewayv1.Gateway) error {
	desired := r.desiredControlplaneService(gw)
	service := &corev1.Service{ObjectMeta: desired.ObjectMeta}

	_, err := controllerutil.CreateOrUpdate(ctx, r.client, service, func() error {
		clusterIP := service.Spec.ClusterIP
		clusterIPs := service.Spec.ClusterIPs
		ipFamilies := service.Spec.IPFamilies
		ipFamilyPolicy := service.Spec.IPFamilyPolicy

		service.Labels = desired.Labels
		service.Spec = desired.Spec
		service.Spec.ClusterIP = clusterIP
		service.Spec.ClusterIPs = clusterIPs
		service.Spec.IPFamilies = ipFamilies
		service.Spec.IPFamilyPolicy = ipFamilyPolicy

		return controllerutil.SetControllerReference(gw, service, r.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update controlplane Service: %w", err)
	}

	return nil
}

func (r *GatewayReconciler) desiredControlplaneDeployment(gw *gatewayv1.Gateway) *appsv1.Deployment {
	labels := r.controlplaneComponentLabels(gw)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.controlplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Replicas: ptr.To(int32(r.config.GatewayAPIDeploymentControlplaneDefaultReplicas)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: r.controlplaneResourceName(gw),
					Containers: []corev1.Container{
						{
							Name:  "controlplane",
							Image: r.config.GatewayAPIDeploymentControlplaneDefaultImage,
							Args: []string{
								"--gateway-namespace", gw.Namespace,
								"--gateway-name", gw.Name,
								"--log-level", r.config.GatewayAPIDeploymentControlplaneDefaultLogLevel,
							},
							Ports: []corev1.ContainerPort{
								{Name: "xds", ContainerPort: controlplaneXDSPort, Protocol: corev1.ProtocolTCP},
								{Name: "health", ContainerPort: controlplaneHealthPort, Protocol: corev1.ProtocolTCP},
								{Name: "metrics", ContainerPort: controlplaneMetricsPort, Protocol: corev1.ProtocolTCP},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "cilium-run",
									MountPath: "/var/run/cilium",
								},
							},
							StartupProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz",
										Port: intstrutil.FromInt32(controlplaneHealthPort),
									},
								},
								FailureThreshold: 60,
								PeriodSeconds:    2,
								TimeoutSeconds:   1,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstrutil.FromInt32(controlplaneHealthPort),
									},
								},
								FailureThreshold: 10,
								PeriodSeconds:    30,
								TimeoutSeconds:   5,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz",
										Port: intstrutil.FromInt32(controlplaneHealthPort),
									},
								},
								FailureThreshold: 3,
								PeriodSeconds:    5,
								TimeoutSeconds:   3,
							},
							TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "cilium-run",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}
}

func (r *GatewayReconciler) desiredControlplaneServiceAccount(gw *gatewayv1.Gateway) *corev1.ServiceAccount {
	labels := r.controlplaneComponentLabels(gw)
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.controlplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
	}
}

func (r *GatewayReconciler) desiredControlplaneRole(gw *gatewayv1.Gateway) *rbacv1.Role {
	labels := r.controlplaneComponentLabels(gw)
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.controlplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// controller-runtime uses informer list/watch for the namespaced cache,
				// so this cannot be restricted to a single Gateway via ResourceNames.
				APIGroups: []string{gatewayv1.GroupVersion.Group},
				Resources: []string{"gateways"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{gatewayv1.GroupVersion.Group},
				Resources: []string{"gateways/status"},
				Verbs:     []string{"update", "patch"},
			},
		},
	}
}

func (r *GatewayReconciler) desiredControlplaneRoleBinding(gw *gatewayv1.Gateway) *rbacv1.RoleBinding {
	labels := r.controlplaneComponentLabels(gw)
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.controlplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     r.controlplaneResourceName(gw),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      r.controlplaneResourceName(gw),
				Namespace: gw.Namespace,
			},
		},
	}
}

func (r *GatewayReconciler) desiredControlplaneService(gw *gatewayv1.Gateway) *corev1.Service {
	labels := r.controlplaneComponentLabels(gw)
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.controlplaneResourceName(gw),
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "xds",
					Port:       controlplaneXDSPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstrutil.FromInt32(controlplaneXDSPort),
				},
			},
		},
	}
}

func (r *GatewayReconciler) controlplaneComponentLabels(gw *gatewayv1.Gateway) map[string]string {
	return map[string]string{
		appKubernetesNameLabel:          gatewayControlplaneAppName,
		appKubernetesComponentLabel:     gatewayControlplaneComponent,
		appKubernetesPartOfLabel:        gatewayDeploymentPartOf,
		appKubernetesManagedByLabel:     gatewayDeploymentManagedBy,
		appKubernetesInstanceLabel:      shortener.ShortenK8sResourceName(gw.Namespace + "." + gw.Name),
		gatewayNameAttachmentLabel:      shortener.ShortenK8sResourceName(gw.Name),
		gatewayClassNameAttachmentLabel: shortener.ShortenK8sResourceName(string(gw.Spec.GatewayClassName)),
	}
}

func (r *GatewayReconciler) controlplaneResourceName(gw *gatewayv1.Gateway) string {
	return shortener.ShortenK8sResourceName(controlplaneResourcePrefix + gw.Name)
}

func (r *GatewayReconciler) cleanupControlplaneResources(ctx context.Context, gw *gatewayv1.Gateway) error {
	for _, obj := range []client.Object{
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace},
		},
	} {
		if err := client.IgnoreNotFound(r.client.Delete(ctx, obj)); err != nil {
			return fmt.Errorf("failed to delete %T %s/%s: %w", obj, obj.GetNamespace(), obj.GetName(), err)
		}
	}

	return nil
}

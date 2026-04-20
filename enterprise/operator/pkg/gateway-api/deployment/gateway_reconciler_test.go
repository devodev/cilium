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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func TestGatewayReconcilerCreatesDeploymentAndService(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("cilium-deployment"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}).
		WithObjects(gwc, namespace, gw).
		Build()

	r := NewGatewayReconciler(c, scheme, slog.Default(), Config{
		GatewayAPIDeploymentControlplaneDefaultImage:       "quay.io/cilium/gateway-api-controlplane:test",
		GatewayAPIDeploymentControlplaneDefaultLogLevel:    "info",
		GatewayAPIDeploymentControlplaneDefaultReplicas:    2,
		GatewayAPIDeploymentDataplaneDefaultEnvoyImage:     "quay.io/cilium/cilium-envoy:v1.36.5-1775137579-2b3493aca96923190423ccec7e4dbc5f074ccad4@sha256:df144744740f91dc55ca39367f61c9a214a989d543c6f91319ccd686ddd7477f",
		GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel:  "trace",
		GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort: 19001,
		GatewayAPIDeploymentDataplaneDefaultReplicas:       2,
	}, &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: false,
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	deployment := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, deployment))
	require.Equal(t, "quay.io/cilium/cilium-envoy:v1.36.5-1775137579-2b3493aca96923190423ccec7e4dbc5f074ccad4@sha256:df144744740f91dc55ca39367f61c9a214a989d543c6f91319ccd686ddd7477f", deployment.Spec.Template.Spec.Containers[0].Image)
	require.Equal(t, int32(2), *deployment.Spec.Replicas)
	require.Equal(t, r.dataplaneResourceName(gw), deployment.Spec.Template.Spec.ServiceAccountName)
	require.Equal(t, "cilium-deployment", deployment.Labels["gateway.networking.k8s.io/gateway-class-name"])
	require.Equal(t, []string{"/usr/bin/cilium-envoy"}, deployment.Spec.Template.Spec.Containers[0].Command)
	require.Equal(t, []string{
		"--log-level trace",
		"--config-path /var/run/cilium/envoy/envoy-bootstrap-config.json",
		"--base-id " + gatewayAsEnvoyBaseID(gw),
		"--service-cluster " + gatewayAsEnvoyClusterName(gw),
		"--service-node " + gatewayAsEnvoyNodeID(gw),
	}, deployment.Spec.Template.Spec.Containers[0].Args)
	require.Equal(t, bootstrapConfigMapChecksum(r.bootstrapConfigForGateway(gw)), deployment.Spec.Template.Annotations[bootstrapChecksumAnnotation])
	require.Len(t, deployment.Spec.Template.Spec.Containers[0].Env, 1)
	require.Equal(t, "POD_NAME", deployment.Spec.Template.Spec.Containers[0].Env[0].Name)
	require.Equal(t, "metadata.name", deployment.Spec.Template.Spec.Containers[0].Env[0].ValueFrom.FieldRef.FieldPath)
	require.NotNil(t, deployment.Spec.Template.Spec.Containers[0].StartupProbe)
	require.Equal(t, "/ready", deployment.Spec.Template.Spec.Containers[0].StartupProbe.HTTPGet.Path)
	require.Equal(t, int32(19001), deployment.Spec.Template.Spec.Containers[0].StartupProbe.HTTPGet.Port.IntVal)
	require.NotNil(t, deployment.Spec.Template.Spec.Containers[0].LivenessProbe)
	require.NotNil(t, deployment.Spec.Template.Spec.Containers[0].ReadinessProbe)
	require.Equal(t, int32(80), deployment.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort)

	configMap := &corev1.ConfigMap{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, configMap))
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"admin\"")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"address\": \"127.0.0.1\"")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"port_value\": 19001")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"dynamic_resources\"")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"ads_config\"")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"ads\": {}")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"cluster_name\": \"gateway-controlplane-xds\"")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"address\": \""+r.controlplaneServiceDNSName(gw)+"\"")
	require.Contains(t, configMap.Data["envoy-bootstrap-config.json"], "\"port_value\": 18000")
	require.NotContains(t, configMap.Data["envoy-bootstrap-config.json"], "gateway: default/example")

	serviceAccount := &corev1.ServiceAccount{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, serviceAccount))
	require.Equal(t, "cilium-deployment", serviceAccount.Labels["gateway.networking.k8s.io/gateway-class-name"])

	controlplaneDeployment := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, controlplaneDeployment))
	require.Equal(t, "quay.io/cilium/gateway-api-controlplane:test", controlplaneDeployment.Spec.Template.Spec.Containers[0].Image)
	require.Equal(t, []string{
		"--gateway-namespace", gw.Namespace,
		"--gateway-name", gw.Name,
		"--log-level", "info",
	}, controlplaneDeployment.Spec.Template.Spec.Containers[0].Args)
	require.Len(t, controlplaneDeployment.Spec.Template.Spec.Containers[0].VolumeMounts, 1)
	require.Equal(t, "cilium-run", controlplaneDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name)
	require.Equal(t, "/var/run/cilium", controlplaneDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath)
	require.Len(t, controlplaneDeployment.Spec.Template.Spec.Volumes, 1)
	require.Equal(t, "cilium-run", controlplaneDeployment.Spec.Template.Spec.Volumes[0].Name)
	require.NotNil(t, controlplaneDeployment.Spec.Template.Spec.Volumes[0].EmptyDir)
	require.Empty(t, controlplaneDeployment.Spec.Template.Spec.Containers[0].StartupProbe.HTTPGet.Host)
	require.Equal(t, int32(2), *controlplaneDeployment.Spec.Replicas)
	require.Equal(t, r.controlplaneResourceName(gw), controlplaneDeployment.Spec.Template.Spec.ServiceAccountName)

	controlplaneServiceAccount := &corev1.ServiceAccount{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, controlplaneServiceAccount))

	controlplaneService := &corev1.Service{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, controlplaneService))
	require.Equal(t, int32(18000), controlplaneService.Spec.Ports[0].Port)

	controlplaneRole := &rbacv1.Role{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, controlplaneRole))
	require.Len(t, controlplaneRole.Rules, 2)
	require.Equal(t, []string{"gateways/status"}, controlplaneRole.Rules[1].Resources)
	require.Equal(t, []string{"update", "patch"}, controlplaneRole.Rules[1].Verbs)

	controlplaneRoleBinding := &rbacv1.RoleBinding{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, controlplaneRoleBinding))

	service := &corev1.Service{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, service))
	require.Equal(t, corev1.ServiceTypeLoadBalancer, service.Spec.Type)
	require.Equal(t, int32(80), service.Spec.Ports[0].Port)
	require.Equal(t, "cilium-deployment", service.Labels["gateway.networking.k8s.io/gateway-class-name"])

	updatedGateway := &gatewayv1.Gateway{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(gw), updatedGateway))
	require.Condition(t, func() bool {
		for _, condition := range updatedGateway.Status.Conditions {
			if condition.Type == gatewayConditionDataplaneReady {
				return condition.Status == metav1.ConditionTrue &&
					condition.Message == "Gateway dataplane resources are reconciled"
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, condition := range updatedGateway.Status.Conditions {
			if condition.Type == gatewayConditionControlplaneReady {
				return condition.Status == metav1.ConditionTrue &&
					condition.Message == "Gateway controlplane resources are reconciled"
			}
		}
		return false
	})
	require.Empty(t, updatedGateway.Status.Addresses)
}

func TestGatewayReconcilerPreservesAssignedServiceFields(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("cilium-deployment"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}).
		WithObjects(gwc, namespace, gw).
		Build()

	r := NewGatewayReconciler(c, scheme, slog.Default(), Config{
		GatewayAPIDeploymentControlplaneDefaultImage:       "quay.io/cilium/gateway-api-controlplane:test",
		GatewayAPIDeploymentControlplaneDefaultLogLevel:    "info",
		GatewayAPIDeploymentControlplaneDefaultReplicas:    2,
		GatewayAPIDeploymentDataplaneDefaultEnvoyImage:     "quay.io/cilium/cilium-envoy:test",
		GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel:  "trace",
		GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort: 19001,
		GatewayAPIDeploymentDataplaneDefaultReplicas:       2,
	}, &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: false,
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	service := &corev1.Service{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, service))

	service.Spec.ClusterIP = "10.96.0.10"
	service.Spec.ClusterIPs = []string{"10.96.0.10"}
	service.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
	service.Spec.IPFamilyPolicy = ptr.To(corev1.IPFamilyPolicySingleStack)
	service.Spec.HealthCheckNodePort = 32080
	service.Spec.LoadBalancerClass = ptr.To("example.com/custom")
	require.NoError(t, c.Update(context.Background(), service))

	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	service = &corev1.Service{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, service))
	require.Equal(t, "10.96.0.10", service.Spec.ClusterIP)
	require.Equal(t, []string{"10.96.0.10"}, service.Spec.ClusterIPs)
	require.Equal(t, []corev1.IPFamily{corev1.IPv4Protocol}, service.Spec.IPFamilies)
	require.NotNil(t, service.Spec.IPFamilyPolicy)
	require.Equal(t, corev1.IPFamilyPolicySingleStack, *service.Spec.IPFamilyPolicy)
	require.Equal(t, int32(32080), service.Spec.HealthCheckNodePort)
	require.NotNil(t, service.Spec.LoadBalancerClass)
	require.Equal(t, "example.com/custom", *service.Spec.LoadBalancerClass)
}

func TestGatewayReconcilerSetsGatewayStatusAddressesFromDataplaneService(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("cilium-deployment"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}, &corev1.Service{}).
		WithObjects(gwc, namespace, gw).
		Build()

	r := NewGatewayReconciler(c, scheme, slog.Default(), Config{
		GatewayAPIDeploymentControlplaneDefaultImage:       "quay.io/cilium/gateway-api-controlplane:test",
		GatewayAPIDeploymentControlplaneDefaultLogLevel:    "info",
		GatewayAPIDeploymentControlplaneDefaultReplicas:    2,
		GatewayAPIDeploymentDataplaneDefaultEnvoyImage:     "quay.io/cilium/cilium-envoy:test",
		GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel:  "trace",
		GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort: 19001,
		GatewayAPIDeploymentDataplaneDefaultReplicas:       2,
	}, &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: false,
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	service := &corev1.Service{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, service))
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: "192.0.2.10"},
		{Hostname: "gw.example.com"},
	}
	require.NoError(t, c.Status().Update(context.Background(), service))

	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	updatedGateway := &gatewayv1.Gateway{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(gw), updatedGateway))
	require.Equal(t, []gatewayv1.GatewayStatusAddress{
		{
			Type:  ptr.To(gatewayv1.IPAddressType),
			Value: "192.0.2.10",
		},
		{
			Type:  ptr.To(gatewayv1.HostnameAddressType),
			Value: "gw.example.com",
		},
	}, updatedGateway.Status.Addresses)
}

func TestGatewayReconcilerIgnoresGatewayWithDifferentController(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "other"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController("example.com/other"),
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("other"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		WithObjects(gwc, namespace, gw).
		Build()

	r := NewGatewayReconciler(c, scheme, slog.Default(), Config{}, &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: false,
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	err = c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, &appsv1.Deployment{})
	require.Error(t, err)
}

func TestGatewayReconcilerSkipsGatewayInTerminatingNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "default",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers:        []string{"kubernetes"},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("cilium-deployment"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}).
		WithObjects(gwc, namespace, gw).
		Build()

	r := NewGatewayReconciler(c, scheme, slog.Default(), Config{}, &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: false,
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	err = c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, &appsv1.Deployment{})
	require.True(t, k8serrors.IsNotFound(err))
}

func TestGatewayReconcilerRecreatesDeploymentWhenSelectorChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("cilium-deployment"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	oldLabels := map[string]string{
		"app.kubernetes.io/name":                       "cilium-gateway-datapath",
		"app.kubernetes.io/component":                  "datapath",
		"app.kubernetes.io/part-of":                    "cilium-gateway-api",
		"app.kubernetes.io/managed-by":                 "cilium-operator",
		"app.kubernetes.io/instance":                   "default.example",
		"gateway.networking.k8s.io/gateway-name":       "example",
		"gateway.networking.k8s.io/gateway-class-name": "cilium-deployment",
	}

	oldDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-gwd-example",
			Namespace: "default",
			Labels:    oldLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: oldLabels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: oldLabels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "old"}}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}).
		WithObjects(gwc, namespace, gw, oldDeployment).
		Build()

	r := NewGatewayReconciler(c, scheme, slog.Default(), Config{
		GatewayAPIDeploymentControlplaneDefaultImage:       "quay.io/cilium/gateway-api-controlplane:test",
		GatewayAPIDeploymentControlplaneDefaultLogLevel:    "info",
		GatewayAPIDeploymentControlplaneDefaultReplicas:    2,
		GatewayAPIDeploymentDataplaneDefaultEnvoyImage:     "quay.io/cilium/cilium-envoy:test",
		GatewayAPIDeploymentDataplaneDefaultEnvoyLogLevel:  "trace",
		GatewayAPIDeploymentDataplaneDefaultEnvoyAdminPort: 19001,
		GatewayAPIDeploymentDataplaneDefaultReplicas:       2,
	}, &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: false,
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	deployment := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, deployment))
	require.Equal(t, "dataplane", deployment.Spec.Selector.MatchLabels["app.kubernetes.io/component"])
	require.Equal(t, "cilium-gateway-dataplane", deployment.Spec.Selector.MatchLabels["app.kubernetes.io/name"])
}

func TestGatewayReconcilerCleansUpResourcesWhenGatewayClassChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("cilium-deployment"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}).
		WithObjects(gwc, namespace, gw).
		Build()

	updatedGateway := &gatewayv1.Gateway{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(gw), updatedGateway))
	// Preserve status conditions set by the controlplane / xDS server controller
	// while this reconciler updates only its own custom dataplane condition.
	updatedGateway.Status.Conditions = []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.GatewayReasonAccepted),
			Message:            "Accepted by xDS controller",
			ObservedGeneration: 1,
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
		{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.GatewayReasonProgrammed),
			Message:            "Programmed by xDS controller",
			ObservedGeneration: 1,
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	}
	updatedGateway.Status.Addresses = []gatewayv1.GatewayStatusAddress{
		{
			Type:  ptr.To(gatewayv1.IPAddressType),
			Value: "192.0.2.10",
		},
	}
	require.NoError(t, c.Status().Update(context.Background(), updatedGateway))

	r := NewGatewayReconciler(c, scheme, slog.Default(), Config{}, &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: false,
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	updatedClass := gwc.DeepCopy()
	updatedClass.Spec.ControllerName = gatewayv1.GatewayController("example.com/other")
	require.NoError(t, c.Update(context.Background(), updatedClass))

	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	err = c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, &appsv1.Deployment{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, &corev1.ConfigMap{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, &corev1.ServiceAccount{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.dataplaneResourceName(gw), Namespace: gw.Namespace}, &corev1.Service{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, &appsv1.Deployment{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, &corev1.ServiceAccount{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, &corev1.Service{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, &rbacv1.Role{})
	require.True(t, k8serrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKey{Name: r.controlplaneResourceName(gw), Namespace: gw.Namespace}, &rbacv1.RoleBinding{})
	require.True(t, k8serrors.IsNotFound(err))

	updatedGateway = &gatewayv1.Gateway{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(gw), updatedGateway))
	require.Condition(t, func() bool {
		for _, condition := range updatedGateway.Status.Conditions {
			if condition.Type == gatewayConditionDataplaneReady {
				return false
			}
		}
		return true
	})
	require.Condition(t, func() bool {
		for _, condition := range updatedGateway.Status.Conditions {
			if condition.Type == gatewayConditionControlplaneReady {
				return false
			}
		}
		return true
	})
	require.Condition(t, func() bool {
		for _, condition := range updatedGateway.Status.Conditions {
			if condition.Type == string(gatewayv1.GatewayConditionAccepted) {
				return condition.Status == metav1.ConditionTrue &&
					condition.Message == "Accepted by xDS controller"
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, condition := range updatedGateway.Status.Conditions {
			if condition.Type == string(gatewayv1.GatewayConditionProgrammed) {
				return condition.Status == metav1.ConditionTrue &&
					condition.Message == "Programmed by xDS controller"
			}
		}
		return false
	})
	require.Empty(t, updatedGateway.Status.Addresses)
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package check

import (
	"context"
	"fmt"
	"maps"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

const (
	kindMulticastName = "multicast"
)

type deploymentParameters struct {
	Name                          string
	Kind                          string
	Image                         string
	Replicas                      int
	NamedPort                     string
	Port                          int
	HostPort                      int
	Command                       []string
	Affinity                      *corev1.Affinity
	NodeSelector                  map[string]string
	ReadinessProbe                *corev1.Probe
	Labels                        map[string]string
	Annotations                   map[string]string
	HostNetwork                   bool
	Tolerations                   []corev1.Toleration
	TerminationGracePeriodSeconds *int64
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
	}
	if len(p.NamedPort) == 0 {
		p.NamedPort = fmt.Sprintf("port-%d", p.Port)
	}
	replicas32 := int32(p.Replicas)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name,
			Labels: map[string]string{
				"name": p.Name,
				"kind": p.Kind,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: p.Name,
					Labels: map[string]string{
						"name": p.Name,
						"kind": p.Kind,
					},
					Annotations: p.Annotations,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: p.Name,
							Env: []corev1.EnvVar{
								{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
								{Name: "NAMED_PORT", Value: p.NamedPort},
							},
							Ports: []corev1.ContainerPort{
								{Name: p.NamedPort, ContainerPort: int32(p.Port), HostPort: int32(p.HostPort)},
							},
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
							ReadinessProbe:  p.ReadinessProbe,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_RAW"},
								},
							},
						},
					},
					Affinity:                      p.Affinity,
					NodeSelector:                  p.NodeSelector,
					HostNetwork:                   p.HostNetwork,
					Tolerations:                   p.Tolerations,
					ServiceAccountName:            p.Name,
					TerminationGracePeriodSeconds: p.TerminationGracePeriodSeconds,
				},
			},
			Replicas: &replicas32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": p.Name,
					"kind": p.Kind,
				},
			},
		},
	}

	maps.Copy(dep.Spec.Template.ObjectMeta.Labels, p.Labels)

	return dep
}

func newMulticastDeployment(p deploymentParameters, igmpVersion int) *appsv1.Deployment {
	dep := newDeployment(p)

	// set sysctl for IGMP version
	for i := range dep.Spec.Template.Spec.Containers {
		dep.Spec.Template.Spec.Containers[i].SecurityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		}
	}

	// IGMP version 2 and version 3 are only applicable.
	if igmpVersion == 2 || igmpVersion == 3 {
		dep.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{
			Sysctls: []corev1.Sysctl{
				{
					Name:  "net.ipv4.conf.eth0.force_igmp_version",
					Value: fmt.Sprintf("%d", igmpVersion),
				},
			},
		}
	}

	return dep
}

func (t *EnterpriseTest) addMulticastDeployment(deps ...*appsv1.Deployment) error {
	for _, d := range deps {
		if d == nil {
			return fmt.Errorf("nil deployment")
		}

		if d.Name == "" {
			return fmt.Errorf("deployment name is empty")
		}

		if _, exist := t.mcastDeploys[d.Name]; exist {
			return fmt.Errorf("deployment %s already exist in test scope", d.Name)
		}

		t.mcastDeploys[d.Name] = d
	}

	return nil
}

func (t *EnterpriseTest) applyDeployments(ctx context.Context) error {
	if len(t.mcastDeploys) == 0 {
		return nil
	}

	var err error

	for _, client := range t.ctx.Clients() {
		_, err = client.GetNamespace(ctx, t.ctx.Params().TestNamespace, metav1.GetOptions{})
		if err != nil {
			t.ctx.Logf("✨ [%s] Creating namespace %s for enterprise connectivity check...", client.ClusterName(), t.ctx.Params().TestNamespace)
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        t.ctx.Params().TestNamespace,
					Annotations: t.ctx.Params().NamespaceAnnotations,
				},
			}
			_, err = client.CreateNamespace(ctx, namespace, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %w", t.ctx.Params().TestNamespace, err)
			}
		}
	}

	for _, d := range t.mcastDeploys {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜[%s] Deploying %s deployment...", client.ClusterName(), d.Name)

			_, err = client.CreateServiceAccount(ctx, t.ctx.Params().TestNamespace, k8s.NewServiceAccount(d.Name), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", d.Name, err)
			}

			_, err = client.CreateDeployment(ctx, t.ctx.Params().TestNamespace, d, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", d.Name, err)
			}
		}
	}

	t.WithFinalizer(func(_ context.Context) error {
		// Use a detached context to make sure this call is not affected by
		// context cancellation. This deletion needs to happen event when the
		// user interrupted the program.
		if err := t.deleteDeployments(context.TODO()); err != nil {
			return fmt.Errorf("unable to delete deployments: %w", err)
		}
		return nil
	})

	// wait for the deployments to be ready
	for _, d := range t.mcastDeploys {
		for _, client := range t.Context().clients.clients() {
			err = check.WaitForDeployment(ctx, t.ctx, client.Client, t.ctx.Params().TestNamespace, d.Name)
			if err != nil {
				t.Failf("%s deployment is not ready: %s", d.Name, err)
			}
		}
	}

	return nil
}

func (t *EnterpriseTest) deleteDeployments(ctx context.Context) error {
	if len(t.mcastDeploys) == 0 {
		return nil
	}

	var err error

	for _, d := range t.mcastDeploys {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜[%s] Deleting %s deployment...", client.ClusterName(), d.Name)

			err = client.DeleteDeployment(ctx, t.ctx.Params().TestNamespace, d.Name, metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("unable to delete deployment %s: %w", d.Name, err)
			}

			err = client.DeleteServiceAccount(ctx, t.ctx.Params().TestNamespace, d.Name, metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("unable to delete service account %s: %w", d.Name, err)
			}
		}
	}

	if len(t.mcastDeploys) > 0 {
		t.Debugf("Successfully deleted %d Multicast deployments", len(t.mcastDeploys))
	}

	return nil
}

// ─── Inspection deployment / DaemonSet lifecycle ─────────────────────────────

// addInspectionDaemonSet registers a DaemonSet to be applied during test setup.
func (t *EnterpriseTest) addInspectionDaemonSet(ds *appsv1.DaemonSet) error {
	if ds == nil {
		return fmt.Errorf("nil DaemonSet")
	}
	if ds.Name == "" {
		return fmt.Errorf("DaemonSet name is empty")
	}
	if _, exists := t.inspectionDaemonSets[ds.Name]; exists {
		return fmt.Errorf("DaemonSet %s already registered in test scope", ds.Name)
	}
	t.inspectionDaemonSets[ds.Name] = ds
	return nil
}

// addInspectionDeployment registers a Deployment to be applied during test setup.
func (t *EnterpriseTest) addInspectionDeployment(dep *appsv1.Deployment) error {
	if dep == nil {
		return fmt.Errorf("nil Deployment")
	}
	if dep.Name == "" {
		return fmt.Errorf("Deployment name is empty")
	}
	if _, exists := t.inspectionDeploys[dep.Name]; exists {
		return fmt.Errorf("Deployment %s already registered in test scope", dep.Name)
	}
	t.inspectionDeploys[dep.Name] = dep
	return nil
}

// applyInspectionWorkloads creates all registered inspection DaemonSets and
// Deployments, waits for them to be ready, and registers a cleanup finalizer.
func (t *EnterpriseTest) applyInspectionWorkloads(ctx context.Context) error {
	if len(t.inspectionDaemonSets) == 0 && len(t.inspectionDeploys) == 0 {
		return nil
	}

	ns := t.ctx.Params().TestNamespace

	for _, client := range t.ctx.Clients() {
		_, err := client.GetNamespace(ctx, ns, metav1.GetOptions{})
		if err != nil {
			t.ctx.Logf("✨ [%s] Creating namespace %s for inspection connectivity check...", client.ClusterName(), ns)
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        ns,
					Annotations: t.ctx.Params().NamespaceAnnotations,
				},
			}
			if _, err = client.CreateNamespace(ctx, namespace, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("unable to create namespace %s: %w", ns, err)
			}
		}
	}

	for _, ds := range t.inspectionDaemonSets {
		for _, client := range t.ctx.clients.clients() {
			t.Infof("📜[%s] Deploying inspection sniffer DaemonSet %s...", client.ClusterName(), ds.Name)

			_, err := client.CreateServiceAccount(ctx, ns, k8s.NewServiceAccount(ds.Name), metav1.CreateOptions{})
			if err != nil && !k8sErrors.IsAlreadyExists(err) {
				return fmt.Errorf("unable to create service account %s: %w", ds.Name, err)
			}
			_, err = client.CreateDaemonSet(ctx, ns, ds, metav1.CreateOptions{})
			if err != nil && !k8sErrors.IsAlreadyExists(err) {
				return fmt.Errorf("unable to create DaemonSet %s: %w", ds.Name, err)
			}
		}
	}

	for _, dep := range t.inspectionDeploys {
		for _, client := range t.ctx.clients.clients() {
			t.Infof("📜[%s] Deploying inspection sender Deployment %s...", client.ClusterName(), dep.Name)

			_, err := client.CreateServiceAccount(ctx, ns, k8s.NewServiceAccount(dep.Name), metav1.CreateOptions{})
			if err != nil && !k8sErrors.IsAlreadyExists(err) {
				return fmt.Errorf("unable to create service account %s: %w", dep.Name, err)
			}
			_, err = client.CreateDeployment(ctx, ns, dep, metav1.CreateOptions{})
			if err != nil && !k8sErrors.IsAlreadyExists(err) {
				return fmt.Errorf("unable to create Deployment %s: %w", dep.Name, err)
			}
		}
	}

	t.WithFinalizer(func(_ context.Context) error {
		return t.deleteInspectionWorkloads(context.TODO())
	})

	for _, ds := range t.inspectionDaemonSets {
		for _, client := range t.ctx.clients.clients() {
			if err := check.WaitForDaemonSet(ctx, t.ctx, client.Client, ns, ds.Name); err != nil {
				t.Failf("inspection sniffer DaemonSet %s is not ready: %s", ds.Name, err)
			}
		}
	}
	for _, dep := range t.inspectionDeploys {
		for _, client := range t.ctx.clients.clients() {
			if err := check.WaitForDeployment(ctx, t.ctx, client.Client, ns, dep.Name); err != nil {
				t.Failf("inspection sender Deployment %s is not ready: %s", dep.Name, err)
			}
		}
	}

	return nil
}

func (t *EnterpriseTest) deleteInspectionWorkloads(ctx context.Context) error {
	ns := t.ctx.Params().TestNamespace

	for _, ds := range t.inspectionDaemonSets {
		for _, client := range t.ctx.clients.clients() {
			t.Infof("📜[%s] Deleting inspection sniffer DaemonSet %s...", client.ClusterName(), ds.Name)
			err := client.Clientset.AppsV1().DaemonSets(ns).Delete(ctx, ds.Name, metav1.DeleteOptions{})
			if err != nil && !k8sErrors.IsNotFound(err) {
				return fmt.Errorf("unable to delete DaemonSet %s: %w", ds.Name, err)
			}
			err = client.DeleteServiceAccount(ctx, ns, ds.Name, metav1.DeleteOptions{})
			if err != nil && !k8sErrors.IsNotFound(err) {
				return fmt.Errorf("unable to delete service account %s: %w", ds.Name, err)
			}
		}
	}

	for _, dep := range t.inspectionDeploys {
		for _, client := range t.ctx.clients.clients() {
			t.Infof("📜[%s] Deleting inspection sender Deployment %s...", client.ClusterName(), dep.Name)
			err := client.DeleteDeployment(ctx, ns, dep.Name, metav1.DeleteOptions{})
			if err != nil && !k8sErrors.IsNotFound(err) {
				return fmt.Errorf("unable to delete Deployment %s: %w", dep.Name, err)
			}
			err = client.DeleteServiceAccount(ctx, ns, dep.Name, metav1.DeleteOptions{})
			if err != nil && !k8sErrors.IsNotFound(err) {
				return fmt.Errorf("unable to delete service account %s: %w", dep.Name, err)
			}
		}
	}

	t.Debugf("Successfully deleted inspection workloads (%d DaemonSets, %d Deployments)",
		len(t.inspectionDaemonSets), len(t.inspectionDeploys))
	return nil
}

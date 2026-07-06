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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	enterpriseTests "github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/tests"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

const (
	kindMulticastName                       = "multicast"
	inspectionNamespaceDeletionPollInterval = 500 * time.Millisecond
	connDisruptEGWHASettleDelay             = 10 * time.Second
)

func waitForNamespaceDeletion(ctx context.Context, client *k8s.Client, ns string) error {
	ticker := time.NewTicker(inspectionNamespaceDeletionPollInterval)
	defer ticker.Stop()

	for {
		_, err := client.GetNamespace(ctx, ns, metav1.GetOptions{})
		if err != nil {
			if k8sErrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("unable to get namespace %s while waiting for deletion: %w", ns, err)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for namespace %s deletion: %w", ns, ctx.Err())
		case <-ticker.C:
		}
	}
}

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
	Resources                     corev1.ResourceRequirements
	Labels                        map[string]string
	Annotations                   map[string]string
	HostNetwork                   bool
	Tolerations                   []corev1.Toleration
	TerminationGracePeriodSeconds *int64
}

func (p *deploymentParameters) namedPort() string {
	if len(p.NamedPort) == 0 {
		return fmt.Sprintf("port-%d", p.Port)
	}
	return p.NamedPort
}

func (p *deploymentParameters) ports() (ports []corev1.ContainerPort) {
	if p.Port != 0 {
		ports = append(ports, corev1.ContainerPort{
			Name: p.namedPort(), ContainerPort: int32(p.Port), HostPort: int32(p.HostPort),
		})
	}
	return ports
}

func (p *deploymentParameters) envs() (envs []corev1.EnvVar) {
	if p.Port != 0 {
		envs = append(envs,
			corev1.EnvVar{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
			corev1.EnvVar{Name: "NAMED_PORT", Value: p.namedPort()},
		)
	}
	return envs
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
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
							Name:            p.Name,
							Env:             p.envs(),
							Ports:           p.ports(),
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
							ReadinessProbe:  p.ReadinessProbe,
							Resources:       p.Resources,
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

func (t *EnterpriseTest) addInspectionDaemonSet(ds *appsv1.DaemonSet) error {
	if ds == nil {
		return fmt.Errorf("nil DaemonSet")
	}
	if ds.Name == "" {
		return fmt.Errorf("DaemonSet name is empty")
	}
	if ds.Namespace == "" {
		ds.Namespace = t.ctx.Params().TestNamespace
	}
	key := fmt.Sprintf("%s/%s", ds.Namespace, ds.Name)
	if _, exists := t.inspectionDaemonSets[key]; exists {
		return fmt.Errorf("DaemonSet %s already registered in test scope", key)
	}
	t.inspectionDaemonSets[key] = ds
	return nil
}

func (t *EnterpriseTest) addInspectionDeployment(dep *appsv1.Deployment) error {
	if dep == nil {
		return fmt.Errorf("nil Deployment")
	}
	if dep.Name == "" {
		return fmt.Errorf("Deployment name is empty")
	}
	if dep.Namespace == "" {
		dep.Namespace = t.ctx.Params().TestNamespace
	}
	key := fmt.Sprintf("%s/%s", dep.Namespace, dep.Name)
	if _, exists := t.inspectionDeploys[key]; exists {
		return fmt.Errorf("Deployment %s already registered in test scope", key)
	}
	t.inspectionDeploys[key] = dep
	return nil
}

func (t *EnterpriseTest) applyInspectionWorkloads(ctx context.Context) error {
	if len(t.inspectionDaemonSets) == 0 && len(t.inspectionDeploys) == 0 {
		return nil
	}

	namespaces := map[string]struct{}{}
	for _, ds := range t.inspectionDaemonSets {
		namespaces[ds.Namespace] = struct{}{}
	}
	for _, dep := range t.inspectionDeploys {
		namespaces[dep.Namespace] = struct{}{}
	}
	createdNamespaces := map[string]map[string]struct{}{}

	for ns := range namespaces {
		for _, client := range t.ctx.Clients() {
			currentNS, err := client.GetNamespace(ctx, ns, metav1.GetOptions{})
			if err == nil && currentNS.Status.Phase == corev1.NamespaceTerminating {
				t.ctx.Logf("⏳ [%s] Waiting for terminating namespace %s to disappear before recreating it...", client.ClusterName(), ns)
				if err := waitForNamespaceDeletion(ctx, client, ns); err != nil {
					return err
				}
				err = k8sErrors.NewNotFound(corev1.Resource("namespaces"), ns)
			}
			if err != nil {
				if !k8sErrors.IsNotFound(err) {
					return fmt.Errorf("unable to get namespace %s: %w", ns, err)
				}

				t.ctx.Logf("✨ [%s] Creating namespace %s for inspection connectivity check...", client.ClusterName(), ns)
				namespace := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name:        ns,
						Annotations: t.ctx.Params().NamespaceAnnotations,
					},
				}
				if _, err = client.CreateNamespace(ctx, namespace, metav1.CreateOptions{}); err != nil && !k8sErrors.IsAlreadyExists(err) {
					return fmt.Errorf("unable to create namespace %s: %w", ns, err)
				}
				if ns != t.ctx.Params().TestNamespace {
					if _, ok := createdNamespaces[client.ClusterName()]; !ok {
						createdNamespaces[client.ClusterName()] = map[string]struct{}{}
					}
					createdNamespaces[client.ClusterName()][ns] = struct{}{}
				}
			}
		}
	}

	for _, ds := range t.inspectionDaemonSets {
		ns := ds.Namespace
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
		ns := dep.Namespace
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
		if err := t.deleteInspectionWorkloads(context.TODO()); err != nil {
			return err
		}
		for _, client := range t.ctx.clients.clients() {
			for ns := range createdNamespaces[client.ClusterName()] {
				t.Infof("📜[%s] Deleting inspection namespace %s...", client.ClusterName(), ns)
				err := client.DeleteNamespace(context.TODO(), ns, metav1.DeleteOptions{})
				if err != nil && !k8sErrors.IsNotFound(err) {
					return fmt.Errorf("unable to delete namespace %s: %w", ns, err)
				}
			}
		}
		return nil
	})

	for _, ds := range t.inspectionDaemonSets {
		ns := ds.Namespace
		for _, client := range t.ctx.clients.clients() {
			if err := check.WaitForDaemonSet(ctx, t.ctx, client.Client, ns, ds.Name); err != nil {
				t.Failf("inspection sniffer DaemonSet %s is not ready: %s", ds.Name, err)
			}
		}
	}
	for _, dep := range t.inspectionDeploys {
		ns := dep.Namespace
		for _, client := range t.ctx.clients.clients() {
			if err := check.WaitForDeployment(ctx, t.ctx, client.Client, ns, dep.Name); err != nil {
				t.Failf("inspection sender Deployment %s is not ready: %s", dep.Name, err)
			}
		}
	}

	return nil
}

func (t *EnterpriseTest) deleteInspectionWorkloads(ctx context.Context) error {
	for _, ds := range t.inspectionDaemonSets {
		ns := ds.Namespace
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
		ns := dep.Namespace
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

func (t *EnterpriseTest) applyExternalFRR(ctx context.Context) error {
	if t.frrDaemonSet == nil {
		return nil
	}

	ct := t.ctx
	client := ct.Clients()[0]
	params := ct.Params()

	// NOTE: FRR daemonset should be deployed only once per node as it is
	// running in the host network namespace, and multiple deployments could
	// cause issues with binding to the same ports - so deploy it in the
	// SharedTestNamespace.
	_, err := client.GetDaemonSet(ctx, params.SharedTestNamespace, t.frrDaemonSet.Name, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s daemonset...", client.ClusterName(), t.frrDaemonSet.Name)
		ds := check.NewFRRDaemonSet(params)
		_, err = client.CreateDaemonSet(ctx, params.TestNamespace, ds, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create daemonset %s: %w", t.frrDaemonSet.Name, err)
		}
		_, err = client.GetConfigMap(ctx, params.TestNamespace, t.frrDaemonSet.Name, metav1.GetOptions{})
		if err != nil {
			cm := check.NewFRRConfigMap()
			ct.Logf("✨ [%s] Deploying %s configmap...", client.ClusterName(), cm.Name)
			_, err = client.CreateConfigMap(ctx, params.TestNamespace, cm, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create configmap %s: %w", cm.Name, err)
			}
		}
		if err := check.WaitForDaemonSet(ctx, ct, client, params.SharedTestNamespace, t.frrDaemonSet.Name); err != nil {
			return err
		}
	}

	// Register FRR pods to the test context so that they can be used later.
	frrPods, err := client.ListPods(ctx, params.SharedTestNamespace, metav1.ListOptions{
		LabelSelector: "name=" + t.frrDaemonSet.Name,
	})
	if err != nil {
		return fmt.Errorf("unable to list FRR pods: %w", err)
	}

	pods := make([]check.Pod, 0, len(frrPods.Items))
	for _, pod := range frrPods.Items {
		pods = append(pods, check.Pod{
			K8sClient: client,
			Pod:       pod.DeepCopy(),
		})
	}

	ct.SetFRRPods(pods)

	return nil
}

// SetupConnDisruptEGWHA deploys the EGW HA conn-disrupt test resources
// (BGP peering, IEGP, server, clients, CNP).
//
//nolint:misspell
func (ect *EnterpriseConnectivityTest) SetupConnDisruptEGWHA(ctx context.Context, egressCIDRs []string) error {
	ct := ect.ConnectivityTest
	ct.Logf("Setting up EGW HA conn-disrupt test resources...")

	if len(enterpriseTests.Params.EgressGateway.PeerAddresses) > 0 {
		bfdProfileName := ""
		if bfdEnabled, _ := ct.Features.MatchRequirements(features.RequireEnabled(enterpriseFeatures.BFD)); bfdEnabled {
			if err := enterpriseTests.CreateEGWBFDProfile(ctx, ct, nil); err != nil {
				return fmt.Errorf("failed to configure BFD profile for conn-disrupt: %w", err)
			}
			bfdProfileName = enterpriseTests.EGWBFDProfileName
		}
		if err := enterpriseTests.CreateEGWBGPPeeringV1(ctx, ct, features.IPFamilyV4, bfdProfileName); err != nil {
			return fmt.Errorf("failed to configure BGP peering for conn-disrupt: %w", err)
		}
	}

	if len(egressCIDRs) != 0 && len(egressCIDRs) != 2 {
		return fmt.Errorf("--conn-disrupt-egw-ha-egress-cidrs requires exactly 2 CIDRs (first for single-GW IEGP, second for two-GW IEGP), got %d", len(egressCIDRs))
	}

	gwNode1, gwNode2, nonGWNode, err := enterpriseTests.GetNodesForConnDisrupt(ct)
	if err != nil {
		return fmt.Errorf("failed to get nodes for conn-disrupt: %w", err)
	}

	var egressCIDRsGWNode, egressCIDRsNonGWNode []string
	if len(egressCIDRs) == 2 {
		egressCIDRsGWNode = []string{egressCIDRs[0]}
		egressCIDRsNonGWNode = []string{egressCIDRs[1]}
	}

	// Deploy IEGP for GW-node client: single gateway (gwNode1),
	// so the client on gwNode1 is guaranteed to use the local gateway.
	if err := ect.deployConnDisruptIEGP(ctx, enterpriseTests.ConnDisruptEGWHAIEGPGWNodeName,
		enterpriseTests.ConnDisruptEGWHAClientGWNodeAppLabel, []string{gwNode1}, egressCIDRsGWNode); err != nil {
		return err
	}

	// Deploy IEGP for non-GW-node client: two gateways (gwNode1, gwNode2),
	// so the client on nonGWNode gets HA failover protection.
	if err := ect.deployConnDisruptIEGP(ctx, enterpriseTests.ConnDisruptEGWHAIEGPNonGWNodeName,
		enterpriseTests.ConnDisruptEGWHAClientNonGWNodeAppLabel, []string{gwNode1, gwNode2}, egressCIDRsNonGWNode); err != nil {
		return err
	}

	// Deploy server
	if err := ect.deployConnDisruptServer(ctx); err != nil {
		return err
	}

	// Deploy clients
	svcAddr := fmt.Sprintf("%s.%s.svc.cluster.local.:8081", enterpriseTests.ConnDisruptEGWHAServiceName, ct.Params().TestNamespace)
	if err := ect.deployConnDisruptClient(ctx, enterpriseTests.ConnDisruptEGWHAClientGWNodeDeploymentName,
		enterpriseTests.ConnDisruptEGWHAClientGWNodeAppLabel, svcAddr, map[string]string{"kubernetes.io/hostname": gwNode1}); err != nil {
		return err
	}
	if err := ect.deployConnDisruptClient(ctx, enterpriseTests.ConnDisruptEGWHAClientNonGWNodeDeploymentName,
		enterpriseTests.ConnDisruptEGWHAClientNonGWNodeAppLabel, svcAddr, map[string]string{"kubernetes.io/hostname": nonGWNode}); err != nil {
		return err
	}
	if err := ect.waitForConnDisruptClientsReady(ctx); err != nil {
		return err
	}

	// Wait for BPF egress-ha entries
	if err := enterpriseTests.WaitForConnDisruptBPFEntries(ctx, ct); err != nil {
		return fmt.Errorf("failed waiting for BPF egress-ha entries: %w", err)
	}

	// Depending on timing, the client may first connect before the egress BPF entry
	// is programmed, so the connection is initially masqueraded with the node IP.
	// Once the egress entry is installed, matching traffic is SNATed with the egress
	// IP, which can break that long-lived connection by changing its source address
	// mid-stream.
	//
	// If that happens, the client hits its 5s no-reply timeout, restarts once, and
	// reconnects with the egress IP. Sleep past this possible one-time transition
	// before taking the baseline restart counts, so it is not later miscounted as an
	// interrupted connection.
	ct.Logf("Waiting %s for conn-disrupt clients to settle through the egress-SNAT transition...", connDisruptEGWHASettleDelay)
	time.Sleep(connDisruptEGWHASettleDelay)

	// Re-check readiness: after the possible transition restart above, this blocks
	// until the clients have reconnected via the egress IP, so the baseline is taken
	// on a settled, connected state.
	if err := ect.waitForConnDisruptClientsReady(ctx); err != nil {
		return err
	}

	ct.Logf("EGW HA conn-disrupt test setup complete")
	return nil
}

//nolint:misspell
func (ect *EnterpriseConnectivityTest) waitForConnDisruptClientsReady(ctx context.Context) error {
	ct := ect.ConnectivityTest
	for _, name := range []string{enterpriseTests.ConnDisruptEGWHAClientGWNodeDeploymentName, enterpriseTests.ConnDisruptEGWHAClientNonGWNodeDeploymentName} {
		if err := check.WaitForDeployment(ctx, ct, ect.clients.dst.Client, ct.Params().TestNamespace, name); err != nil {
			return fmt.Errorf("%s deployment is not ready: %w", name, err)
		}
	}
	return nil
}

// CleanupConnDisruptEGWHA deletes the EGW HA conn-disrupt test resources.
//
//nolint:misspell
func (ect *EnterpriseConnectivityTest) CleanupConnDisruptEGWHA(ctx context.Context) error {
	ct := ect.ConnectivityTest
	ct.Debugf("Cleaning up EGW HA conn-disrupt test resources...")
	ns := ct.Params().TestNamespace

	enterpriseTests.DeleteEGWBGPPeeringV1(ctx, ct)
	enterpriseTests.DeleteEGWBFDProfile(ctx, ct)

	for _, client := range ect.EntClients() {
		_ = client.DeleteIsovalentEgressGatewayPolicy(ctx, enterpriseTests.ConnDisruptEGWHAIEGPGWNodeName, metav1.DeleteOptions{})
		_ = client.DeleteIsovalentEgressGatewayPolicy(ctx, enterpriseTests.ConnDisruptEGWHAIEGPNonGWNodeName, metav1.DeleteOptions{})
		_ = client.DeleteDeployment(ctx, ns, enterpriseTests.ConnDisruptEGWHAServerDeploymentName, metav1.DeleteOptions{})
		_ = client.DeleteServiceAccount(ctx, ns, enterpriseTests.ConnDisruptEGWHAServerDeploymentName, metav1.DeleteOptions{})
		_ = client.DeleteDeployment(ctx, ns, enterpriseTests.ConnDisruptEGWHAClientGWNodeDeploymentName, metav1.DeleteOptions{})
		_ = client.DeleteServiceAccount(ctx, ns, enterpriseTests.ConnDisruptEGWHAClientGWNodeDeploymentName, metav1.DeleteOptions{})
		_ = client.DeleteDeployment(ctx, ns, enterpriseTests.ConnDisruptEGWHAClientNonGWNodeDeploymentName, metav1.DeleteOptions{})
		_ = client.DeleteServiceAccount(ctx, ns, enterpriseTests.ConnDisruptEGWHAClientNonGWNodeDeploymentName, metav1.DeleteOptions{})
		_ = client.DeleteService(ctx, ns, enterpriseTests.ConnDisruptEGWHAServiceName, metav1.DeleteOptions{})
		_ = client.DeleteCiliumNetworkPolicy(ctx, ns, enterpriseTests.ConnDisruptEGWHACNPName, metav1.DeleteOptions{})
	}

	return nil
}

//nolint:misspell
func (ect *EnterpriseConnectivityTest) deployConnDisruptIEGP(ctx context.Context, iegpName, clientAppLabel string, gatewayNodes, egressCIDRs []string) error {
	ct := ect.ConnectivityTest
	iegpClient := ect.clients.src.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies()

	_, err := iegpClient.Get(ctx, iegpName, metav1.GetOptions{})
	if err == nil {
		ct.Logf("✨ [%s] IEGP %s already exists, skipping creation", ect.clients.src.ClusterName(), iegpName)
		return nil
	}

	egressGroups := make([]isovalentv1.EgressGroup, 0, len(gatewayNodes))
	for _, node := range gatewayNodes {
		egressGroups = append(egressGroups, isovalentv1.EgressGroup{
			NodeSelector: &slimmetav1.LabelSelector{
				MatchLabels: map[string]slimmetav1.MatchLabelsValue{
					"kubernetes.io/hostname": node,
				},
			},
		})
	}

	ipv4CIDRs := make([]isovalentv1.IPv4CIDR, 0, len(egressCIDRs))
	for _, cidr := range egressCIDRs {
		ipv4CIDRs = append(ipv4CIDRs, isovalentv1.IPv4CIDR(cidr))
	}

	iegp := &isovalentv1.IsovalentEgressGatewayPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IsovalentEgressGatewayPolicy",
			APIVersion: "isovalent.com/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   iegpName,
			Labels: map[string]string{"egw": "bgp-advertise"},
		},
		Spec: isovalentv1.IsovalentEgressGatewayPolicySpec{
			Selectors: []isovalentv1.EgressRule{
				{
					PodSelector: &slimmetav1.LabelSelector{
						MatchLabels: map[string]slimmetav1.MatchLabelsValue{
							k8sconst.PodNamespaceLabel: ct.Params().TestNamespace,
							"app":                      clientAppLabel,
						},
					},
				},
			},
			DestinationCIDRs: []isovalentv1.CIDR{"0.0.0.0/0"},
			EgressCIDRs:      ipv4CIDRs,
			EgressGroups:     egressGroups,
			AZAffinity:       "disabled",
		},
	}

	ct.Logf("✨ [%s] Deploying IEGP %s...", ect.clients.src.ClusterName(), iegpName)
	_, err = iegpClient.Create(ctx, iegp, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create IsovalentEgressGatewayPolicy %s: %w", iegpName, err)
	}

	return nil
}

func connDisruptReadinessProbe(readyFile string) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{"cat", readyFile},
			},
		},
		PeriodSeconds:       int32(3),
		InitialDelaySeconds: int32(1),
		FailureThreshold:    int32(20),
	}
}

func connDisruptResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU: *resource.NewMilliQuantity(100, resource.DecimalSI),
		},
	}
}

//nolint:misspell
func (ect *EnterpriseConnectivityTest) deployConnDisruptServer(ctx context.Context) error {
	ct := ect.ConnectivityTest
	deployName := enterpriseTests.ConnDisruptEGWHAServerDeploymentName

	_, err := ect.clients.src.GetDeployment(ctx, ct.Params().TestNamespace, deployName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ect.clients.src.ClusterName(), deployName)

		params := ct.Params()
		dep := newDeployment(deploymentParameters{
			Name:           deployName,
			Kind:           enterpriseTests.KindConnDisruptEGWHA,
			Image:          params.TestConnDisruptImage,
			Command:        []string{"tcd-server", "8081"},
			Port:           8081,
			Labels:         map[string]string{"app": enterpriseTests.ConnDisruptEGWHAServerAppLabel},
			ReadinessProbe: connDisruptReadinessProbe("/tmp/server-ready"),
			Resources:      connDisruptResources(),
			NodeSelector:   map[string]string{defaults.CiliumNoScheduleLabel: "true"},
			HostNetwork:    true,
			Tolerations: append(params.GetTolerations(), corev1.Toleration{
				Operator: corev1.TolerationOpExists,
			}),
		})

		_, err = ect.clients.src.CreateServiceAccount(ctx, ct.Params().TestNamespace, k8s.NewServiceAccount(deployName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %w", deployName, err)
		}

		_, err = ect.clients.src.CreateDeployment(ctx, ct.Params().TestNamespace, dep, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %w", deployName, err)
		}
	}

	// Make sure that the server deployment is ready to spread client connections
	if err := check.WaitForDeployment(ctx, ct, ect.clients.src.Client, ct.Params().TestNamespace, enterpriseTests.ConnDisruptEGWHAServerDeploymentName); err != nil {
		return fmt.Errorf("%s deployment is not ready: %w", enterpriseTests.ConnDisruptEGWHAServerDeploymentName, err)
	}

	for _, client := range ect.clients.clients() {
		_, getErr := client.GetService(ctx, ct.Params().TestNamespace, enterpriseTests.ConnDisruptEGWHAServiceName, metav1.GetOptions{})
		if getErr != nil {
			ct.Logf("✨ [%s] Deploying %s service...", client.ClusterName(), enterpriseTests.ConnDisruptEGWHAServiceName)
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: enterpriseTests.ConnDisruptEGWHAServiceName,
					Annotations: map[string]string{
						"service.cilium.io/global": "true",
					},
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceType(ct.Params().ServiceType),
					Ports: []corev1.ServicePort{{
						Name: "http",
						Port: 8081,
					}},
					Selector: map[string]string{"app": enterpriseTests.ConnDisruptEGWHAServerAppLabel},
				},
			}
			_, err = client.CreateService(ctx, ct.Params().TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service %s: %w", enterpriseTests.ConnDisruptEGWHAServiceName, err)
			}
		}
	}

	if enabled, _ := ct.Features.MatchRequirements(features.RequireEnabled(features.CNP)); enabled {
		for _, client := range ect.clients.clients() {
			ct.Logf("✨ [%s] Deploying CNP %s...", client.ClusterName(), enterpriseTests.ConnDisruptEGWHACNPName)
			cnp := &ciliumv2.CiliumNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       ciliumv2.CNPKindDefinition,
					APIVersion: ciliumv2.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{Name: enterpriseTests.ConnDisruptEGWHACNPName, Namespace: ct.Params().TestNamespace},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{
						LabelSelector: &slimmetav1.LabelSelector{
							MatchLabels: map[string]string{"kind": enterpriseTests.KindConnDisruptEGWHA},
						},
					},
					Egress: []policyapi.EgressRule{
						{
							EgressCommonRule: policyapi.EgressCommonRule{
								ToEntities: policyapi.EntitySlice{policyapi.EntityWorld},
							},
							ToPorts: []policyapi.PortRule{{
								Ports: []policyapi.PortProtocol{{
									Protocol: policyapi.ProtoTCP,
									Port:     "8081",
								}},
							}},
						},
						{
							ToPorts: []policyapi.PortRule{{
								Ports: []policyapi.PortProtocol{
									{Protocol: policyapi.ProtoUDP, Port: "53"},
									{Protocol: policyapi.ProtoUDP, Port: "5353"},
								},
							}},
						},
					},
				},
			}
			_, err := client.ApplyGeneric(ctx, cnp)
			if err != nil {
				return fmt.Errorf("unable to create CiliumNetworkPolicy %s: %w", enterpriseTests.ConnDisruptEGWHACNPName, err)
			}
		}
	}

	return nil
}

//nolint:misspell
func (ect *EnterpriseConnectivityTest) deployConnDisruptClient(ctx context.Context, deployName, appLabel, address string, nodeSelector map[string]string) error {
	ct := ect.ConnectivityTest

	_, err := ect.clients.dst.GetDeployment(ctx, ct.Params().TestNamespace, deployName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ect.clients.dst.ClusterName(), deployName)

		params := ct.Params()
		dep := newDeployment(deploymentParameters{
			Name:  deployName,
			Kind:  enterpriseTests.KindConnDisruptEGWHA,
			Image: params.TestConnDisruptImage,
			Command: []string{
				"tcd-client",
				"--dispatch-interval", params.ConnDisruptDispatchInterval.String(),
				address,
			},
			Labels:         map[string]string{"app": appLabel},
			ReadinessProbe: connDisruptReadinessProbe("/tmp/client-ready"),
			Resources:      connDisruptResources(),
			NodeSelector:   nodeSelector,
			Tolerations:    params.GetTolerations(),
		})

		_, err = ect.clients.dst.CreateServiceAccount(ctx, ct.Params().TestNamespace, k8s.NewServiceAccount(deployName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %w", deployName, err)
		}

		_, err = ect.clients.dst.CreateDeployment(ctx, ct.Params().TestNamespace, dep, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %w", deployName, err)
		}
	}

	return nil
}

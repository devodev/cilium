//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cilium_clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/time"
)

type ciliumCli struct {
	*cilium_clientset.Clientset
}

func NewCiliumAndK8sCli(f FailureReporter) (*ciliumCli, *k8s.Clientset) {
	restConfig := newK8sClientRestConfig(f)

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		f.Failedf("unable to create k8s REST client: %s", err)
	}

	cli, err := cilium_clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		f.Failedf("unable to create cilium k8s client: %s", err)
	}

	k8s, err := k8s.NewForConfig(restConfig)
	if err != nil {
		f.Failedf("unable to create k8s client: %s", err)
	}

	return &ciliumCli{cli}, k8s
}

func newK8sClientRestConfig(f FailureReporter) *rest.Config {
	kubeConfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

	// use KUBECONFIG env var if set
	kubeConfigEnv := os.Getenv("KUBECONFIG")
	if kubeConfigEnv != "" {
		kubeConfigPath = kubeConfigEnv
	}

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		f.Failedf("failed to read kube config: %s", err)
	}

	return restConfig
}

func (c *ciliumCli) CreateLBVIP(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBVIP, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBVIPs(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBVIP(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBVIPs(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) GetLBVIP(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBVIP, error) {
	return c.IsovalentV1alpha1().LBVIPs(namespace).Get(ctx, name, opts)
}

func (c *ciliumCli) GetCiliumLoadBalancerIPPool(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumLoadBalancerIPPool, error) {
	return c.CiliumV2().CiliumLoadBalancerIPPools().Get(ctx, name, opts)
}

func (c *ciliumCli) CreateLBDeployment(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBDeployment, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBDeployments(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) UpdateLBDeployment(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBDeployment, opts metav1.UpdateOptions) error {
	_, err := c.IsovalentV1alpha1().LBDeployments(namespace).Update(ctx, obj, opts)
	return err
}

func (c *ciliumCli) UpdateCiliumLoadBalancerIPPool(ctx context.Context, obj *ciliumv2.CiliumLoadBalancerIPPool, opts metav1.UpdateOptions) error {
	_, err := c.CiliumV2().CiliumLoadBalancerIPPools().Update(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBDeployments(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) GetLBDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBDeployment, error) {
	return c.IsovalentV1alpha1().LBDeployments(namespace).Get(ctx, name, opts)
}

func (c *ciliumCli) CreateLBService(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBService, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBServices(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) UpdateLBService(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBService, opts metav1.UpdateOptions) error {
	_, err := c.IsovalentV1alpha1().LBServices(namespace).Update(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBServices(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) GetLBService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBService, error) {
	return c.IsovalentV1alpha1().LBServices(namespace).Get(ctx, name, opts)
}

func (c *ciliumCli) CreateLBBackendPool(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBBackendPool, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBBackendPools(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) CreateWAFPolicy(ctx context.Context, namespace string, obj *isovalentv1alpha1.IsovalentWAFPolicy, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().IsovalentWAFPolicies(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteWAFPolicy(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().IsovalentWAFPolicies(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) GetWAFPolicy(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*isovalentv1alpha1.IsovalentWAFPolicy, error) {
	return c.IsovalentV1alpha1().IsovalentWAFPolicies(namespace).Get(ctx, name, opts)
}

func (c *ciliumCli) DeleteLBBackendPool(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBBackendPools(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) CreateLBIPPoolV2Alpha1(ctx context.Context, obj *ciliumv2alpha1.CiliumLoadBalancerIPPool, opts metav1.CreateOptions) error {
	_, err := c.CiliumV2alpha1().CiliumLoadBalancerIPPools().Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) CreateLBIPPool(ctx context.Context, obj *ciliumv2.CiliumLoadBalancerIPPool, opts metav1.CreateOptions) error {
	_, err := c.CiliumV2().CiliumLoadBalancerIPPools().Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBIPPoolV2Alpha1(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.CiliumV2alpha1().CiliumLoadBalancerIPPools().Delete(ctx, name, opts)
}

func (c *ciliumCli) DeleteLBIPPool(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.CiliumV2().CiliumLoadBalancerIPPools().Delete(ctx, name, opts)
}

func (c *ciliumCli) WaitForLBVIP(ctx context.Context, namespace, name string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, shortTimeout)
	defer cancel()

	for {
		obj, err := c.GetLBVIP(ctx, namespace, name, metav1.GetOptions{})
		if err != nil {
			return "", "", err
		}

		ipv4 := obj.Status.Addresses.IPv4
		ipv6 := obj.Status.Addresses.IPv6

		family := "ipv4"
		if obj.Spec.AddressFamily != nil && *obj.Spec.AddressFamily == isovalentv1alpha1.AddressFamilyDual {
			family = "dual"
		} else if obj.Spec.AddressFamily != nil && *obj.Spec.AddressFamily == isovalentv1alpha1.AddressFamilyIPv6 {
			family = "ipv6"
		}

		switch {
		case family == "dual" && ipv4 != nil && ipv6 != nil:
			return *ipv4, *ipv6, nil
		case family == "ipv4" && ipv4 != nil:
			return *ipv4, "", nil
		case family == "ipv6" && ipv6 != nil:
			return "", *ipv6, nil
		}

		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return "", "", fmt.Errorf("timeout reached waiting for LBVIP %s to get VIP assigned (status: %v)", name, obj.Status)
		}
	}
}

func (c *ciliumCli) EnsureBGPClusterConfig(ctx context.Context) error {
	cc := bgpClusterConfig(globalBGPClusterConfigName)
	if _, err := c.IsovalentV1().IsovalentBGPClusterConfigs().Create(ctx, cc, metav1.CreateOptions{}); err != nil {
		if !k8s_errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create BGP cluster config (%s): %w", globalBGPClusterConfigName, err)
		}
	}
	return nil
}

func (c *ciliumCli) DeleteBGPClusterConfig(ctx context.Context) error {
	if err := c.IsovalentV1().IsovalentBGPClusterConfigs().Delete(ctx, globalBGPClusterConfigName, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("failed to delete BGP cluster config (%s): %w", globalBGPClusterConfigName, err)
	}
	return nil
}

func (c *ciliumCli) EnsureLBIPPoolV2Alpha1(ctx context.Context, obj *ciliumv2alpha1.CiliumLoadBalancerIPPool) error {
	if err := c.CreateLBIPPoolV2Alpha1(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !k8s_errors.IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

func (c *ciliumCli) EnsureLBIPPool(ctx context.Context, obj *ciliumv2.CiliumLoadBalancerIPPool) error {
	if err := c.CreateLBIPPool(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !k8s_errors.IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

func (c *ciliumCli) CreateLBK8sBackendCluster(ctx context.Context, obj *isovalentv1alpha1.LBK8sBackendCluster, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBK8sBackendClusters().Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBK8sBackendCluster(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBK8sBackendClusters().Delete(ctx, name, opts)
}

func (c *ciliumCli) GetLBK8sBackendCluster(ctx context.Context, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBK8sBackendCluster, error) {
	return c.IsovalentV1alpha1().LBK8sBackendClusters().Get(ctx, name, opts)
}

func (c *ciliumCli) WaitForLBK8sBackendClusterConnected(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()

	for {
		obj, err := c.GetLBK8sBackendCluster(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		for _, cond := range obj.Status.Conditions {
			if cond.Type == isovalentv1alpha1.ConditionTypeClusterConnected && cond.Status == metav1.ConditionTrue {
				return nil
			}
		}

		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for LBK8sBackendCluster %s to be connected (status: %v)", name, obj.Status)
		}
	}
}

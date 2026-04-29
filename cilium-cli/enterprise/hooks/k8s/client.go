//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Register all auth providers (azure, gcp, oidc, openstack, ..).

	"github.com/cilium/cilium/cilium-cli/k8s"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	enterpriseCiliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
)

type EnterpriseClient struct {
	*k8s.Client

	EnterpriseCiliumClientset enterpriseCiliumClientset.Interface
}

func NewEnterpriseClient(client *k8s.Client) (*EnterpriseClient, error) {
	// Register the Cilium types in the default scheme.
	_ = isovalentv1.AddToScheme(scheme.Scheme)
	_ = isovalentv1alpha1.AddToScheme(scheme.Scheme)

	rawKubeConfigLoader := client.RESTClientGetter.ToRawKubeConfigLoader()

	config, err := rawKubeConfigLoader.ClientConfig()
	if err != nil {
		return nil, err
	}

	enterpriseCiliumClientset, err := enterpriseCiliumClientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &EnterpriseClient{
		Client:                    client,
		EnterpriseCiliumClientset: enterpriseCiliumClientset,
	}, nil
}

func (c *EnterpriseClient) ListIsovalentEgressGatewayPolicies(ctx context.Context, opts metav1.ListOptions) (*isovalentv1.IsovalentEgressGatewayPolicyList, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().List(ctx, opts)
}

func (c *EnterpriseClient) GetIsovalentEgressGatewayPolicy(ctx context.Context, name string, opts metav1.GetOptions) (*isovalentv1.IsovalentEgressGatewayPolicy, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(ctx, name, opts)
}

func (c *EnterpriseClient) CreateIsovalentEgressGatewayPolicy(ctx context.Context, cegp *isovalentv1.IsovalentEgressGatewayPolicy, opts metav1.CreateOptions) (*isovalentv1.IsovalentEgressGatewayPolicy, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Create(ctx, cegp, opts)
}

func (c *EnterpriseClient) UpdateIsovalentEgressGatewayPolicy(ctx context.Context, cegp *isovalentv1.IsovalentEgressGatewayPolicy, opts metav1.UpdateOptions) (*isovalentv1.IsovalentEgressGatewayPolicy, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Update(ctx, cegp, opts)
}

func (c *EnterpriseClient) PatchIsovalentEgressGatewayPolicy(ctx context.Context, name string, pt types.PatchType, data []byte) (*isovalentv1.IsovalentEgressGatewayPolicy, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Patch(ctx, name, pt, data, metav1.PatchOptions{})
}

func (c *EnterpriseClient) DeleteIsovalentEgressGatewayPolicy(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Delete(ctx, name, opts)
}

func (c *EnterpriseClient) ListIsovalentMulticastGroups(ctx context.Context, opts metav1.ListOptions) (*isovalentv1alpha1.IsovalentMulticastGroupList, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentMulticastGroups().List(ctx, opts)
}

func (c *EnterpriseClient) GetIsovalentMulticastGroup(ctx context.Context, name string, opts metav1.GetOptions) (*isovalentv1alpha1.IsovalentMulticastGroup, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentMulticastGroups().Get(ctx, name, opts)
}

func (c *EnterpriseClient) CreateIsovalentMulticastGroup(ctx context.Context, cmg *isovalentv1alpha1.IsovalentMulticastGroup, opts metav1.CreateOptions) (*isovalentv1alpha1.IsovalentMulticastGroup, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentMulticastGroups().Create(ctx, cmg, opts)
}

func (c *EnterpriseClient) GetIsovalentInspectionConfig(ctx context.Context, name string, opts metav1.GetOptions) (*isovalentv1alpha1.IsovalentInspectionConfig, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentInspectionConfigs().Get(ctx, name, opts)
}

func (c *EnterpriseClient) UpdateIsovalentMulticastGroup(ctx context.Context, cmg *isovalentv1alpha1.IsovalentMulticastGroup, opts metav1.UpdateOptions) (*isovalentv1alpha1.IsovalentMulticastGroup, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentMulticastGroups().Update(ctx, cmg, opts)
}

func (c *EnterpriseClient) DeleteIsovalentMulticastGroup(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentMulticastGroups().Delete(ctx, name, opts)
}

func (c *EnterpriseClient) ListLBVIPs(ctx context.Context, namespace string, opts metav1.ListOptions) (*isovalentv1alpha1.LBVIPList, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBVIPs(namespace).List(ctx, opts)
}

func (c *EnterpriseClient) GetLBVIP(ctx context.Context, namespace string, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBVIP, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBVIPs(namespace).Get(ctx, name, opts)
}

func (c *EnterpriseClient) CreateLBVIP(ctx context.Context, namespace string, lbvip *isovalentv1alpha1.LBVIP, opts metav1.CreateOptions) (*isovalentv1alpha1.LBVIP, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBVIPs(namespace).Create(ctx, lbvip, opts)
}

func (c *EnterpriseClient) UpdateLBVIP(ctx context.Context, namespace string, lbvip *isovalentv1alpha1.LBVIP, opts metav1.UpdateOptions) (*isovalentv1alpha1.LBVIP, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBVIPs(namespace).Update(ctx, lbvip, opts)
}

func (c *EnterpriseClient) DeleteLBVIP(ctx context.Context, namespace string, name string, opts metav1.DeleteOptions) error {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBVIPs(namespace).Delete(ctx, name, opts)
}

func (c *EnterpriseClient) ListLBServices(ctx context.Context, namespace string, opts metav1.ListOptions) (*isovalentv1alpha1.LBServiceList, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBServices(namespace).List(ctx, opts)
}

func (c *EnterpriseClient) GetLBService(ctx context.Context, namespace string, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBService, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBServices(namespace).Get(ctx, name, opts)
}

func (c *EnterpriseClient) CreateLBService(ctx context.Context, namespace string, lbsvc *isovalentv1alpha1.LBService, opts metav1.CreateOptions) (*isovalentv1alpha1.LBService, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBServices(namespace).Create(ctx, lbsvc, opts)
}

func (c *EnterpriseClient) UpdateLBService(ctx context.Context, namespace string, lbsvc *isovalentv1alpha1.LBService, opts metav1.UpdateOptions) (*isovalentv1alpha1.LBService, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBServices(namespace).Update(ctx, lbsvc, opts)
}

func (c *EnterpriseClient) DeleteLBService(ctx context.Context, namespace string, name string, opts metav1.DeleteOptions) error {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBServices(namespace).Delete(ctx, name, opts)
}

func (c *EnterpriseClient) ListLBBackendPools(ctx context.Context, namespace string, opts metav1.ListOptions) (*isovalentv1alpha1.LBBackendPoolList, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBBackendPools(namespace).List(ctx, opts)
}

func (c *EnterpriseClient) GetLBBackendPool(ctx context.Context, namespace string, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBBackendPool, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBBackendPools(namespace).Get(ctx, name, opts)
}

func (c *EnterpriseClient) CreateLBBackendPool(ctx context.Context, namespace string, lbbackendpool *isovalentv1alpha1.LBBackendPool, opts metav1.CreateOptions) (*isovalentv1alpha1.LBBackendPool, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBBackendPools(namespace).Create(ctx, lbbackendpool, opts)
}

func (c *EnterpriseClient) UpdateLBBackendPool(ctx context.Context, namespace string, lbbackendpool *isovalentv1alpha1.LBBackendPool, opts metav1.UpdateOptions) (*isovalentv1alpha1.LBBackendPool, error) {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBBackendPools(namespace).Update(ctx, lbbackendpool, opts)
}

func (c *EnterpriseClient) DeleteLBBackendPool(ctx context.Context, namespace string, name string, opts metav1.DeleteOptions) error {
	return c.EnterpriseCiliumClientset.IsovalentV1alpha1().LBBackendPools(namespace).Delete(ctx, name, opts)
}

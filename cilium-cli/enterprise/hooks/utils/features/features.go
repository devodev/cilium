//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package features

import (
	"context"
	"fmt"

	"github.com/blang/semver/v4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	enterpriseDefaults "github.com/cilium/cilium/cilium-cli/enterprise/defaults"
	"github.com/cilium/cilium/cilium-cli/sysdump"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/option"
)

const (
	CiliumDNSProxyHA features.Feature = "cilium-dnsproxy-ha"

	EgressGatewayHA features.Feature = "enable-ipv4-egress-gateway-ha"

	SRv6            features.Feature = "enable-srv6"
	SRv6LocatorPool features.Feature = "srv6-locator-pool-enabled"

	Multicast features.Feature = "multicast"

	EnterpriseBGPControlPlane features.Feature = "enable-enterprise-bgp-control-plane"
	BFD                       features.Feature = "enable-bfd"
	EVPN                      features.Feature = "enable-evpn"

	// RemoteClusterTunnel: the routing mode configured in the remote cluster.
	RemoteClusterTunnel features.Feature = "remote-cluster-tunnel"
	// RemoteClusterTunnelPort: the tunnel port configured in the remote cluster.
	RemoteClusterTunnelPort features.Feature = "remote-cluster-tunnel-port"
	// FallbackRoutingMode: whether a (and which) fallback routing mode is configured.
	FallbackRoutingMode features.Feature = "fallback-routing-mode"
	// MixedRoutingMode: whether local and remote clusters have different routing modes.
	MixedRoutingMode features.Feature = "mixed-routing-mode"

	PhantomServices features.Feature = "enable-phantom-services"
	// EncryptionPolicy: whether encryption policies are enabled in the local cluster
	EncryptionPolicy features.Feature = "enable-encryption-policy"
	// RemoteEncryptionPolicy: whether encryption policies are enabled in the remote cluster
	RemoteEncryptionPolicy features.Feature = "remote-encryption-policy"
	// EncryptionPolicyFallbackEncrypt: whether the encryption policy fallback behavior is set to encrypt
	EncryptionPolicyFallbackEncrypt features.Feature = "encryption-policy-fallback-encrypt"

	// LoadBalancer: whether standalone loadbalancer is enabled
	LoadBalancer features.Feature = "loadbalancer"

	// DedicatedEnvoyConfigPolicy is the indicator whether dedicated ingress policy is enabled
	DedicatedEnvoyConfigPolicy features.Feature = "envoy-config-policy-mode"

	// PassiveInspection: whether passive inspection is enabled for pod traffic.
	// When enabled, a clone of every pod packet is mirrored to a dedicated
	// inspection interface for out-of-band IDS analysis.
	PassiveInspection features.Feature = "enable-passive-inspection"
)

func Detect(ctx context.Context, ct *check.ConnectivityTest) error {
	err := extractFromConfigMap(ctx, ct)
	if err != nil {
		return err
	}

	err = extractFromRemoteConfigMap(ctx, ct)
	if err != nil {
		return err
	}

	// Only check whether the cilium-dnsproxy DaemonSet is deployed if the feature is enabled in
	// the ConfigMap.
	if ct.Features[CiliumDNSProxyHA].Enabled {
		err = extractExternalDNSProxyFeature(ctx, ct)
		if err != nil {
			return fmt.Errorf("failed to extract feature %s: %w", CiliumDNSProxyHA, err)
		}
	}

	return nil
}

func extractExternalDNSProxyFeature(ctx context.Context, ct *check.ConnectivityTest) error {
	for _, client := range ct.Clients() {
		// cilium-dnsproxy pods are labelled with `k8s-app=ciliumdns-proxy`, let's filter on it.
		ciliumDNSProxyLabelSelector := fmt.Sprintf("k8s-app=%s", enterpriseDefaults.ExternalCiliumDNSProxyName)
		pods, err := client.ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{LabelSelector: ciliumDNSProxyLabelSelector})
		if err != nil {
			return fmt.Errorf("unable to list %s pods: %w", enterpriseDefaults.ExternalCiliumDNSProxyName, err)
		}

		if len(pods.Items) == 0 {
			ct.Features[CiliumDNSProxyHA] = features.Status{Enabled: false}
			return nil
		}
	}

	return nil
}

func extractFromConfigMap(ctx context.Context, ct *check.ConnectivityTest) error {
	cm, err := ct.K8sClient().GetConfigMap(ctx, ct.Params().CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		return fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	ct.Features[EgressGatewayHA] = features.Status{
		Enabled: cm.Data["enable-ipv4-egress-gateway-ha"] == "true",
	}

	ct.Features[CiliumDNSProxyHA] = features.Status{
		Enabled: cm.Data["external-dns-proxy"] == "true",
	}

	ct.Features[FallbackRoutingMode] = features.Status{
		Enabled: cm.Data["fallback-routing-mode"] != "",
		Mode:    cm.Data["fallback-routing-mode"],
	}

	ct.Features[Multicast] = features.Status{
		Enabled: cm.Data["multicast-enabled"] == "true",
	}

	ct.Features[EnterpriseBGPControlPlane] = features.Status{
		Enabled: cm.Data[string(EnterpriseBGPControlPlane)] == "true",
	}

	ct.Features[BFD] = features.Status{
		Enabled: cm.Data[string(BFD)] == "true",
	}

	ct.Features[EVPN] = features.Status{
		Enabled: cm.Data[string(EVPN)] == "true",
	}

	ct.Features[PhantomServices] = features.Status{
		Enabled: phantomServicesEnabled(cm.Data, ct.CiliumVersion),
	}

	ct.Features[EncryptionPolicy] = features.Status{
		Enabled: cm.Data[string(EncryptionPolicy)] == "true",
	}

	ct.Features[EncryptionPolicyFallbackEncrypt] = features.Status{
		Enabled: cm.Data["encryption-policy-fallback-behavior"] == "encrypt",
	}

	ct.Features[DedicatedEnvoyConfigPolicy] = features.Status{
		Enabled: cm.Data[string(DedicatedEnvoyConfigPolicy)] == "dedicated",
	}

	ct.Features[PassiveInspection] = features.Status{
		Enabled: cm.Data[string(PassiveInspection)] == "true",
	}

	return nil
}

func extractFromRemoteConfigMap(ctx context.Context, ct *check.ConnectivityTest) error {
	if ct.Params().MultiCluster == "" {
		ct.Features[MixedRoutingMode] = features.Status{Enabled: false}
		return nil
	}

	cm, err := ct.Clients()[1].GetConfigMap(ctx, ct.Params().CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve remote ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		return fmt.Errorf("remote ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	ct.Features[RemoteClusterTunnel], ct.Features[RemoteClusterTunnelPort] = features.ExtractTunnelFeatureFromConfigMap(cm)
	ct.Features[MixedRoutingMode] = features.Status{Enabled: ct.Features[features.Tunnel].Enabled != ct.Features[RemoteClusterTunnel].Enabled}

	// PhantomServices must be enabled in both clusters to be considered enabled.
	ct.Features[PhantomServices] = features.Status{
		Enabled: ct.Features[PhantomServices].Enabled && phantomServicesEnabled(cm.Data, ct.CiliumVersion),
	}

	ct.Features[RemoteEncryptionPolicy] = features.Status{Enabled: cm.Data[string(EncryptionPolicy)] == "true"}
	return nil
}

func ExtractFromSysdumpCollector(collector *sysdump.Collector) error {
	cm := collector.CiliumConfigMap

	collector.FeatureSet[SRv6] = features.Status{
		Enabled: cm != nil && cm.Data[string(SRv6)] == "true",
	}

	collector.FeatureSet[SRv6LocatorPool] = features.Status{
		Enabled: cm != nil && cm.Data[string(SRv6LocatorPool)] == "true",
	}

	collector.FeatureSet[EnterpriseBGPControlPlane] = features.Status{
		Enabled: cm != nil && cm.Data[string(EnterpriseBGPControlPlane)] == "true",
	}

	collector.FeatureSet[BFD] = features.Status{
		Enabled: cm != nil && cm.Data[string(BFD)] == "true",
	}

	collector.FeatureSet[EVPN] = features.Status{
		Enabled: cm != nil && cm.Data[string(EVPN)] == "true",
	}

	collector.FeatureSet[EncryptionPolicy] = features.Status{
		Enabled: cm != nil && cm.Data[string(EncryptionPolicy)] == "true",
	}

	collector.FeatureSet[LoadBalancer] = features.Status{
		Enabled: cm != nil && cm.Data[option.LoadbalancerControlplaneEnabled] == "true",
	}

	collector.FeatureSet[DedicatedEnvoyConfigPolicy] = features.Status{
		Enabled: cm != nil && cm.Data[string(DedicatedEnvoyConfigPolicy)] == "dedicated",
	}

	return nil
}

func phantomServicesEnabled(cfg map[string]string, ciliumVersion semver.Version) bool {
	value, ok := cfg[string(PhantomServices)]

	// Until Cilium v1.16-ce, the phantom service support was not guarded by a feature
	// flag, and was always enabled. However, we are conservative and consider it to be
	// enabled only if the the feature flag is not specified, to always respect the
	// setting in case of mixed version clusters (given that ciliumVersion is the
	// minimum version across all agents).
	if !ok && ciliumVersion.LT(semver.MustParse("1.16.0")) {
		return true
	}

	return value == "true"
}

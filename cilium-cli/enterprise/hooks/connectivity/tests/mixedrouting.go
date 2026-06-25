//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/deploy"
	enterpriseSniff "github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/sniff"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/node/addressing"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type mixedRoutingSetupFnType func(context.Context, *check.ConnectivityTest) error

func MixedRouting() (check.Scenario, mixedRoutingSetupFnType) {
	mr := &mixedRouting{
		ScenarioBase:     check.NewScenarioBase(),
		clusterUseTunnel: make(map[string]bool),
		nativeSniffers:   make(map[sniff.Mode]map[check.NodeIdentity]*sniff.Sniffer),
		tunnelSniffers:   make(map[sniff.Mode]map[check.NodeIdentity]*sniff.Sniffer),
	}

	for _, sm := range []sniff.Mode{sniff.ModeAssert, sniff.ModeSanity} {
		mr.nativeSniffers[sm] = make(map[check.NodeIdentity]*sniff.Sniffer)
		mr.tunnelSniffers[sm] = make(map[check.NodeIdentity]*sniff.Sniffer)
	}

	return mr, mr.setup
}

type mixedRouting struct {
	check.ScenarioBase
	clusterUseTunnel      map[string]bool
	crossClusterUseTunnel bool

	nativeSniffers map[sniff.Mode]map[check.NodeIdentity]*sniff.Sniffer
	tunnelSniffers map[sniff.Mode]map[check.NodeIdentity]*sniff.Sniffer
	finalizers     []func() error
}

func (mr *mixedRouting) Name() string {
	return "mixed-routing"
}

func (mr *mixedRouting) setup(ctx context.Context, ct *check.ConnectivityTest) error {
	// Requirements changes should be additionally applied to the ones guarding
	// the execution of the mixed-routing test, so that they always match.
	fallback := ct.Features[enterpriseFeatures.FallbackRoutingMode]
	if !fallback.Enabled || !ct.Params().IncludeUnsafeTests {
		return nil
	}

	ct.Debug("Configuring mixed routing mode validation sniffers")
	tunnel := []bool{ct.Features[features.Tunnel].Enabled, ct.Features[enterpriseFeatures.RemoteClusterTunnel].Enabled}
	for i, client := range ct.Clients() {
		mr.clusterUseTunnel[client.ClusterName()] = tunnel[i]
	}
	mr.crossClusterUseTunnel = (tunnel[0] && tunnel[1]) || ((tunnel[0] || tunnel[1]) && fallback.Mode == "tunnel")

	for _, hp := range ct.HostNetNSPodsByNode() {
		if hp.Outside {
			continue
		}

		nodeID := check.NodeIdentity{Cluster: hp.K8sClient.ClusterName(), Name: hp.NodeName()}

		iface, err := mr.getIface(ctx, ct, &hp)
		if err != nil {
			return err
		}

		for _, sm := range []sniff.Mode{sniff.ModeAssert, sniff.ModeSanity} {
			if filter := mr.buildNativeFilter(ct, nodeID, sm); filter != "" {
				sniffer, cancel, err := sniff.Sniff(ctx, "mixed-routing-native-"+string(sm), &hp, iface, filter, sm, enterpriseSniff.SniffKillTimeout, ct)
				if err != nil {
					return fmt.Errorf("failed to setup mixed routing mode sniff on %s (%s): %w", hp.String(), hp.NodeName(), err)
				}
				mr.finalizers = append(mr.finalizers, cancel)

				mr.nativeSniffers[sm][nodeID] = sniffer
			}

			if filter := mr.buildTunnelFilter(ct, nodeID, sm); filter != "" {
				sniffer, cancel, err := sniff.Sniff(ctx, "mixed-routing-tunnel-"+string(sm), &hp, iface, filter, sm, enterpriseSniff.SniffKillTimeout, ct)
				if err != nil {
					return fmt.Errorf("failed to setup mixed routing mode sniff on %s (%s): %w", hp.String(), hp.NodeName(), err)
				}
				mr.finalizers = append(mr.finalizers, cancel)

				mr.tunnelSniffers[sm][nodeID] = sniffer
			}
		}
	}

	return nil
}

func (mr *mixedRouting) Run(ctx context.Context, t *check.Test) {
	// on exit, run registered finalizers
	defer func() {
		for _, f := range mr.finalizers {
			if err := f(); err != nil {
				t.Infof("Failed to run finalizer: %w", err)
			}
		}
	}()

	for _, sm := range []sniff.Mode{sniff.ModeAssert, sniff.ModeSanity} {
		for id, sniff := range mr.nativeSniffers[sm] {
			t.NewGenericAction(mr, "native-routing-"+string(sm)+"-"+id.Name).Run(func(a *check.Action) { sniff.Validate(a) })
		}

		for id, sniff := range mr.tunnelSniffers[sm] {
			t.NewGenericAction(mr, "tunnel-routing-"+string(sm)+"-"+id.Name).Run(func(a *check.Action) { sniff.Validate(a) })
		}
	}
}

func (mr *mixedRouting) getIface(ctx context.Context, ct *check.ConnectivityTest, hp *check.Pod) (string, error) {
	encryption := ct.Features[features.EncryptionPod]
	encryptionPolicy := ct.Features[enterpriseFeatures.EncryptionPolicy]

	if encryption.Enabled && encryption.Mode == "wireguard" && !encryptionPolicy.Enabled {
		return wgtypes.IfaceName, nil
	}

	cmd := []string{"/bin/sh", "-c", "ip route list | awk '/^default/ { print $5 }'"}
	ct.Debugf("Retrieving default interface on %s (%s): %s", hp.Name, hp.NodeName(), strings.Join(cmd, " "))
	out, err := hp.K8sClient.ExecInPod(ctx, hp.Pod.Namespace, hp.Pod.Name, "", cmd)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve default interface on %s (%s): %w", hp.String(), hp.NodeName(), err)
	}

	return strings.TrimRight(out.String(), "\n\r"), nil
}

func (mr *mixedRouting) buildTunnelFilter(ct *check.ConnectivityTest, self check.NodeIdentity, mode sniff.Mode) string {
	var hostIPs []string

	for other, cn := range ct.CiliumNodes() {
		if self == other {
			continue
		}

		// When running in assert mode, we want to construct a filter which includes
		// the IP addresses of the nodes configured in native routing mode (as we
		// should observe no tunneled traffic from/towards them). Vice versa, in
		// sanity mode we want to include the nodes configured in tunnel mode.
		if mr.shouldUseTunnel(self, other) == (mode == sniff.ModeAssert) {
			continue
		}

		for _, addr := range cn.Spec.Addresses {
			if addr.Type == addressing.NodeInternalIP {
				hostIPs = append(hostIPs, "host "+addr.IP)
			}
		}
	}

	if len(hostIPs) == 0 {
		return ""
	}

	tunnelFilter, err := enterpriseSniff.GetTunnelFilter(ct)
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%s and (%s)", tunnelFilter, strings.Join(hostIPs, " or "))
}

func (mr *mixedRouting) buildNativeFilter(ct *check.ConnectivityTest, self check.NodeIdentity, mode sniff.Mode) string {
	var cidrs, ingresses []string

	for other, cn := range ct.CiliumNodes() {
		if self == other {
			register := func(address string) {
				if address != "" {
					ingresses = append(ingresses, "dst host "+address)
				}
			}

			register(cn.Spec.IngressAddressing.IPV4)
			register(cn.Spec.IngressAddressing.IPV6)
			continue
		}

		// When running in assert mode, we want to construct a filter which includes
		// the PodCIDRs associated with the nodes configured in tunnel mode (as they
		// should be tunneled). Vice versa, in sanity mode we want to include the
		// CIDRs associated with nodes configured in native routing mode.
		if mr.shouldUseTunnel(self, other) != (mode == sniff.ModeAssert) {
			continue
		}

		for _, cidr := range cn.Spec.IPAM.PodCIDRs {
			cidrs = append(cidrs, "net "+cidr.String())
		}
	}

	switch {
	case len(cidrs) == 0:
		return ""
	case len(ingresses) == 0:
		return strings.Join(cidrs, " or ")
	default:
		// Skip packets having one of the local ingress IP addresses as destination.
		// Indeed, they can lead to flakes if the destination port does not match
		// that of an open envoy socket, as the packet gets then incorrectly forwarded
		// according to the default route. However, this can happen if the network
		// policies configured by the subsequent connectivity tests block the reception
		// of the FIN packet for a certain time window, and the socket gets removed
		// in the meanwhile. In any case, we don't reduce the overall coverage, because
		// we would still detect every legitimate failure on the source node side.
		return fmt.Sprintf("(%s) and not (%s)", strings.Join(cidrs, " or "), strings.Join(ingresses, " or "))
	}
}

func (mr *mixedRouting) shouldUseTunnel(self, other check.NodeIdentity) bool {
	sameCluster := self.Cluster == other.Cluster
	return (sameCluster && mr.clusterUseTunnel[self.Cluster]) ||
		(!sameCluster && mr.crossClusterUseTunnel)
}

type mixedRoutingExtraTraffic struct {
	check.ScenarioBase
}

func MixedRoutingExtraTraffic() check.Scenario {
	return &mixedRoutingExtraTraffic{
		ScenarioBase: check.NewScenarioBase(),
	}
}

func (mrt *mixedRoutingExtraTraffic) Name() string {
	return "mixed-routing-extra-traffic"
}

func (mrt *mixedRoutingExtraTraffic) Run(ctx context.Context, t *check.Test) {
	var (
		ct     = t.Context()
		client = ct.RandomClientPod()
		echo   = deploy.MustGetEchoPodOtherNode(ct)
	)

	for other, cn := range ct.CiliumNodes() {
		t.ForEachIPFamily(func(ipFam features.IPFamily) {
			addr := cn.Spec.HealthAddressing.IPv4
			if ipFam == features.IPFamilyV6 {
				addr = cn.Spec.HealthAddressing.IPv6
			}

			if addr == "" {
				return
			}

			dst := check.HTTPEndpoint(other.Name, "http://"+net.JoinHostPort(addr, "4240")+"/hello")
			fn := func(a *check.Action) { a.ExecInPod(ctx, ct.CurlCommand(dst, ipFam, true, nil)) }
			t.NewAction(mrt, other.Name, client, dst, ipFam).Run(fn)
			t.NewAction(mrt, other.Name, &echo, dst, ipFam).Run(fn)
		})
	}
}

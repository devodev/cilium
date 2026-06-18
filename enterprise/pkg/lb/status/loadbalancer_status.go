// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/api/v1/models"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (s *LoadbalancerClient) GetLoadbalancerStatusModel(ctx context.Context) (*LoadbalancerStatusModel, error) {
	bgpPeersFromCRDByName, bgpPeersFromCRDByAddr, err := s.getBGPPeersFromBGPClusterConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch BGP peers from CRD: %w", err)
	}

	bgpRoutes, err := s.getBGPRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T1 BGP routes: %w", err)
	}

	bgpPeers, err := s.getBGPPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T1 BGP peers: %w", err)
	}
	t1ServicesRoutes, err := s.getHealthcheckT1(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T1 Services: %w", err)
	}

	t2EnvoyConfigs, err := s.getHealthcheckT2(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T2 Envoyconfigs: %w", err)
	}

	vips, err := s.client.ciliumClient.IsovalentV1alpha1().LBVIPs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	services, err := s.client.ciliumClient.IsovalentV1alpha1().LBServices(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	lsm := &LoadbalancerStatusModel{}

	// Summary
	lsm.Summary = LoadbalancerStatusModelSummary{
		NrOfT1Nodes:  len(s.t1AgentPods),
		NrOfT2Nodes:  len(s.t2AgentPods),
		NrOfServices: len(services.Items),
		NrOfVIPs:     len(vips.Items),
	}

	bgpPeerCfgList, err := s.client.ciliumClient.IsovalentV1().IsovalentBGPPeerConfigs().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	bgpAdvList, err := s.client.ciliumClient.IsovalentV1().IsovalentBGPAdvertisements().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, f := range services.Items {
		bgpPeersForSvc, err := s.getBGPPeersForSvc(ctx, f, bgpPeersFromCRDByName, bgpPeerCfgList, bgpAdvList)
		if err != nil {
			return nil, err
		}

		bgpPeerStatus := s.getBGPPeerStatus(f, bgpPeers, bgpPeersFromCRDByAddr, bgpPeersForSvc)
		bgpRouteStatus := s.getBGPRoutesStatus(f, bgpRoutes)

		serviceModel := LoadbalancerStatusModelService{
			Namespace:         f.Namespace,
			Name:              f.Name,
			VIP:               s.getVIP(f),
			Port:              uint(f.Spec.Port),
			Type:              s.getType(f),
			DeploymentMode:    s.getDeploymentMode(f),
			BGPPeerStatus:     bgpPeerStatus,
			BGPRouteStatus:    bgpRouteStatus,
			T1NodeStatus:      s.getT1Status(f, t1ServicesRoutes),
			T1T2HCStatus:      s.getHCT1T2(f, t1ServicesRoutes),
			T2NodeStatus:      s.getT2Status(f, t2EnvoyConfigs),
			T2BackendHCStatus: s.getHCT2Backends(f, t2EnvoyConfigs),
			BackendpoolStatus: s.getBackends(f, t1ServicesRoutes, t2EnvoyConfigs),
			Status:            overallStatus(bgpRouteStatus, bgpPeerStatus.LoadbalancerStatusModelSimpleStatus),
		}

		if s.includedInFilter(serviceModel) {
			lsm.Services = append(lsm.Services, serviceModel)
		}

	}

	lsm.sort()

	return lsm, nil
}

func (s *LoadbalancerClient) includedInFilter(serviceModel LoadbalancerStatusModelService) bool {
	if s.params.ServiceNamespace != "" && serviceModel.Namespace != s.params.ServiceNamespace {
		return false
	}

	if s.params.ServiceName != "" && serviceModel.Name != s.params.ServiceName {
		return false
	}

	if s.params.ServiceVIP != "" && serviceModel.VIP != s.params.ServiceVIP {
		return false
	}

	if s.params.ServicePort != 0 && serviceModel.Port != s.params.ServicePort {
		return false
	}

	if s.params.ServiceStatus != "" && serviceModel.Status != s.params.ServiceStatus {
		return false
	}

	return true
}

func (s *LoadbalancerClient) getType(service isovalentv1alpha1.LBService) string {
	switch {
	case service.Spec.Applications.HTTPProxy != nil:
		return "HTTP Proxy"
	case service.Spec.Applications.HTTPSProxy != nil:
		return "HTTPS Proxy"
	case service.Spec.Applications.TLSPassthrough != nil:
		return "TLS Passthrough"
	case service.Spec.Applications.TLSProxy != nil:
		return "TLS Proxy"
	case service.Spec.Applications.TCPProxy != nil:
		return "TCP Proxy"
	case service.Spec.Applications.UDPProxy != nil:
		return "UDP Proxy"
	}

	return "N/A"
}

func (s *LoadbalancerClient) getDeploymentMode(service isovalentv1alpha1.LBService) string {
	switch {
	case service.Spec.Applications.TCPProxy != nil:
		if service.Status.Applications.TCPProxy == nil {
			return "N/A"
		}

		if service.Status.Applications.TCPProxy.DeploymentMode != nil &&
			*service.Status.Applications.TCPProxy.DeploymentMode == isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1Only {
			return "T1"
		}
	case service.Spec.Applications.UDPProxy != nil:
		if service.Status.Applications.UDPProxy == nil {
			return "N/A"
		}

		if service.Status.Applications.UDPProxy.DeploymentMode != nil &&
			*service.Status.Applications.UDPProxy.DeploymentMode == isovalentv1alpha1.LBUDPProxyDeploymentModeTypeT1Only {
			return "T1"
		}
	}

	return "T1-T2"
}

func (s *LoadbalancerClient) getVIP(lbsvc isovalentv1alpha1.LBService) string {
	if lbsvc.Status.Addresses.IPv4 != nil {
		return *lbsvc.Status.Addresses.IPv4
	}

	return "N/A"
}

func (s *LoadbalancerClient) getBGPPeersForSvc(ctx context.Context,
	lbsvc isovalentv1alpha1.LBService,
	bgpPeersByNameFromT1ClusterCfg map[string][]string,
	bgpPeerConfigs *isovalentv1.IsovalentBGPPeerConfigList,
	bgpAdvertisements *isovalentv1.IsovalentBGPAdvertisementList,
) ([]string, error) {
	// Find IsovalentBGPAdvertisements which apply to a given LBService
	var advs []*isovalentv1.IsovalentBGPAdvertisement

	for i, adv := range bgpAdvertisements.Items {
		for _, a := range adv.Spec.Advertisements {
			if a.AdvertisementType != isovalentv1.BGPServiceAdvert {
				continue
			}
			if a.Service == nil || !slices.Contains(a.Service.Addresses, v2.BGPLoadBalancerIPAddr) {
				continue
			}
			selector, err := slim_meta_v1.LabelSelectorAsSelector(a.Selector)
			if err != nil {
				return nil, err
			}
			if selector.Matches(labels.Set(lbsvc.ObjectMeta.Labels)) ||
				selector.Matches(labels.Set{"loadbalancer.isovalent.com/vip-name": lbsvc.Spec.VIPRef.Name}) {

				advs = append(advs, &bgpAdvertisements.Items[i])
				break
			}
		}
	}

	// Find BGPPeers which match the IsovalentBGPAdvertisements from above

	peers := []string{}

	for _, peerCfg := range bgpPeerConfigs.Items {
		// Ignore peers which are not listed in the T1's IsovalentBGPClusterConfig
		if _, found := bgpPeersByNameFromT1ClusterCfg[peerCfg.GetName()]; !found {
			continue
		}

		for _, peerAdv := range peerCfg.Spec.Families {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(peerAdv.Advertisements)
			if err != nil {
				return nil, err
			}
			match := false
			// Find which LBService's IsovalentBGPAdvertisement a peer matches
			for _, adv := range advs {
				if selector.Matches(labels.Set(adv.GetLabels())) {
					match = true
					break
				}
			}
			if match {
				peers = append(peers, peerCfg.GetName())
				break
			}
		}
	}

	return peers, nil
}

func (s *LoadbalancerClient) getBGPPeerStatus(lbsvc isovalentv1alpha1.LBService, nodeBGPPeers map[string][]*models.BgpPeer, bgpPeersFromCRDByAddr map[string]string, svcPeers []string) BGPPeerStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return BGPPeerStatus{
			LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "N/A",
				OK:     0,
				Total:  0,
			},
		}
	}

	nrOk := 0
	nrPeersTotal := 0
	activePeers := []BGPPeer{}

	// Find out a number of svcPeers which has the session state == "established"
	for _, p := range nodeBGPPeers {
		for _, pp := range p {
			addr := fmt.Sprintf("%s-%d", pp.PeerAddress, pp.PeerAsn)
			name, found := bgpPeersFromCRDByAddr[addr]
			if !found {
				continue
			}

			if !slices.Contains(svcPeers, name) {
				continue
			}

			nrPeersTotal++
			isHealthy := pp.SessionState == "established"
			if isHealthy {
				nrOk++
			}

			activePeers = append(activePeers, BGPPeer{addr, isHealthy})
		}
	}

	return BGPPeerStatus{
		LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
			Status: s.statusText(nrOk, nrPeersTotal),
			OK:     nrOk,
			Total:  nrPeersTotal,
		},
		Peers: activePeers,
	}
}

func (s *LoadbalancerClient) getBGPRoutesStatus(lbsvc isovalentv1alpha1.LBService, nodeBGPRoutes map[string][]*models.BgpRoute) LoadbalancerStatusModelSimpleStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	nrOk := 0

	for _, r := range nodeBGPRoutes {
		for _, br := range r {
			if br.Prefix == *lbsvc.Status.Addresses.IPv4+"/32" {
				nrOk++
				// break and don't take other announcements to other peers into account
				break
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(nrOk, len(nodeBGPRoutes)),
		OK:     nrOk,
		Total:  len(nodeBGPRoutes),
	}
}

func (s *LoadbalancerClient) getT1Status(lbsvc isovalentv1alpha1.LBService, nodeServices map[string][]*models.Service) LoadbalancerStatusModelSimpleStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	usedNodes := map[string]struct{}{}

	for nodeName, sn := range nodeServices {
		for _, s := range sn {
			if s.Status != nil && s.Status.Realized != nil && s.Status.Realized.FrontendAddress != nil && s.Status.Realized.Flags != nil &&
				s.Status.Realized.Flags.Type == "LoadBalancer" &&
				s.Status.Realized.Flags.Name == "lbfe-"+lbsvc.Name &&
				s.Status.Realized.FrontendAddress.IP == *lbsvc.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(lbsvc.Spec.Port) {

				for _, b := range s.Status.Realized.BackendAddresses {
					if b.State == "active" {
						usedNodes[nodeName] = struct{}{}
						break
					}
				}
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(len(usedNodes), len(nodeServices)),
		OK:     len(usedNodes),
		Total:  len(nodeServices),
	}
}

func (s *LoadbalancerClient) getHCT1T2(lbsvc isovalentv1alpha1.LBService, nodeServices map[string][]*models.Service) HealthChecksStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return HealthChecksStatus{
			LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "N/A",
				OK:     0,
				Total:  0,
			},
		}
	}

	nrOk := 0
	nrTotal := 0

	hcs := []HCStatus{}

	for node, sn := range nodeServices {
		for _, s := range sn {
			if s.Status != nil && s.Status.Realized != nil && s.Status.Realized.FrontendAddress != nil && s.Status.Realized.Flags != nil &&
				s.Status.Realized.Flags.Type == "LoadBalancer" &&
				s.Status.Realized.Flags.Name == "lbfe-"+lbsvc.Name &&
				s.Status.Realized.FrontendAddress.IP == *lbsvc.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(lbsvc.Spec.Port) {

				for _, b := range s.Status.Realized.BackendAddresses {
					nrTotal++
					healthy := false
					if b.State == "active" {
						nrOk++
						healthy = true
					}
					hcs = append(hcs,
						HCStatus{
							From:      node,
							Endpoint:  fmt.Sprintf("%s:%d", *lbsvc.Status.Addresses.IPv4, lbsvc.Spec.Port),
							IsHealthy: healthy,
						})
				}
			}
		}
	}

	return HealthChecksStatus{
		LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
			Status: s.statusText(nrOk, nrTotal),
			OK:     nrOk,
			Total:  nrTotal,
		},
		HealthChecks: hcs,
	}
}

// IsT1Only evaluates whether the given LBService uses T1-only TCP- or UDP proxy functionality.
// It first uses the evaluated deployment mode from the  CRD status and falls back to assuming
// T1-only if forceDeploymentMode isn't set or set to 'auto' or 't1-only'. Auto could potentially
// still evaluate to t1-t2 if some features are used that aren't compatible with t1-only.
//
// Note: the fallback needs to check whether status is set at all to avoid overriding it.
func (s *LoadbalancerClient) isT1Only(lbsvc isovalentv1alpha1.LBService) bool {
	switch {
	case lbsvc.Status.IsEvaluatedTCPT1Only():
		return true
	case lbsvc.Status.Applications.TCPProxy == nil && lbsvc.Spec.ConfiguresTCPT1OnlyOrAuto():
		return true
	case lbsvc.Status.IsEvaluatedUDPT1Only():
		return true
	case lbsvc.Status.Applications.UDPProxy == nil && lbsvc.Spec.ConfiguresUDPT1OnlyOrAuto():
		return true
	default:
		return false
	}
}

func (s *LoadbalancerClient) getT2Status(lbsvc isovalentv1alpha1.LBService, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelSimpleStatus {
	if s.isT1Only(lbsvc) {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "",
			OK:     0,
			Total:  0,
		}
	}

	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	usedNodes := map[string]struct{}{}

	clusterNamePrefix := fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)
	for nodeName, ecn := range nodeEnvoyConfigs {
		for _, c := range ecn.Configs {
			if c.Type != "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump" {
				continue
			}
			// default/lbfe-lb-1/backend_cluster_https_0
			for _, e := range c.DynamicEndpointConfigs {
				if strings.HasPrefix(e.EndpointConfig.ClusterName, clusterNamePrefix) {
					for _, ep := range e.EndpointConfig.Endpoints {
						for _, epc := range ep.LbEndpoints {
							if epc.HealthStatus == "HEALTHY" {
								usedNodes[nodeName] = struct{}{}
							}
						}
					}
				}
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(len(usedNodes), len(nodeEnvoyConfigs)),
		OK:     len(usedNodes),
		Total:  len(nodeEnvoyConfigs),
	}
}

func (s *LoadbalancerClient) getHCT2Backends(lbsvc isovalentv1alpha1.LBService, nodeEnvoyConfigs map[string]*EnvoyConfigModel) HealthChecksStatus {
	if s.isT1Only(lbsvc) {
		return HealthChecksStatus{
			LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "",
				OK:     0,
				Total:  0,
			},
		}
	}

	if lbsvc.Status.Addresses.IPv4 == nil {
		return HealthChecksStatus{
			LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "N/A",
				OK:     0,
				Total:  0,
			},
		}
	}

	nrOk := 0
	nrTotal := 0

	hcs := []HCStatus{}

	for node, ecn := range nodeEnvoyConfigs {
		for _, c := range ecn.Configs {
			if c.Type == "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump" {
				// default/lbfe-lb-1/backend_cluster_https_0
				for _, e := range c.DynamicEndpointConfigs {
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)) {
						for _, ep := range e.EndpointConfig.Endpoints {
							for _, epc := range ep.LbEndpoints {
								nrTotal++
								healthy := false
								if epc.HealthStatus == "HEALTHY" {
									healthy = true
									nrOk++
								}
								hcs = append(hcs,
									HCStatus{
										From:      node,
										Endpoint:  fmt.Sprintf("%s:%d", epc.Endpoint.Address.SocketAddress.Address, epc.Endpoint.Address.SocketAddress.PortValue),
										IsHealthy: healthy,
									})
							}
						}
					}
				}
			}
		}
	}

	return HealthChecksStatus{
		LoadbalancerStatusModelSimpleStatus: LoadbalancerStatusModelSimpleStatus{
			Status: s.statusText(nrOk, nrTotal),
			OK:     nrOk,
			Total:  nrTotal,
		},
		HealthChecks: hcs,
	}
}

func (s *LoadbalancerClient) getBackends(lbsvc isovalentv1alpha1.LBService, nodeT1Services map[string][]*models.Service, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelGroupedStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelGroupedStatus{
			Status: "N/A",
		}
	}

	if s.isT1Only(lbsvc) {
		return s.groupBackendStatusCounts(s.getBackendStatusFromT1(lbsvc, nodeT1Services))
	}

	return s.groupBackendStatusCounts(s.getBackendStatusFromT2(lbsvc, nodeEnvoyConfigs))
}

type backendStatusCounter struct {
	active   int
	expected int
}

func (s *LoadbalancerClient) groupBackendStatusCounts(status map[string]map[string]backendStatusCounter) LoadbalancerStatusModelGroupedStatus {
	total := 0
	totalOK := 0
	groups := make([]LoadbalancerStatusModelSimpleStatus, 0, len(status))

	for _, endpoints := range status {
		groupOK := 0
		for _, counts := range endpoints {
			total++
			if counts.expected > 0 && counts.active == counts.expected {
				groupOK++
				totalOK++
			}
		}

		groups = append(groups, LoadbalancerStatusModelSimpleStatus{
			Status: s.statusText(groupOK, len(endpoints)),
			OK:     groupOK,
			Total:  len(endpoints),
		})
	}

	return LoadbalancerStatusModelGroupedStatus{
		Status: s.statusText(totalOK, total),
		Groups: groups,
	}
}

func (c *LoadbalancerClient) getBackendStatusFromT1(lbsvc isovalentv1alpha1.LBService, nodeT1Services map[string][]*models.Service) map[string]map[string]backendStatusCounter {
	status := map[string]map[string]backendStatusCounter{}

	for _, sn := range nodeT1Services {
		for _, s := range sn {
			if s.Status != nil && s.Status.Realized != nil && s.Status.Realized.FrontendAddress != nil && s.Status.Realized.Flags != nil &&
				s.Status.Realized.Flags.Type == "LoadBalancer" &&
				s.Status.Realized.Flags.Name == "lbfe-"+lbsvc.Name &&
				s.Status.Realized.FrontendAddress.IP == *lbsvc.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(lbsvc.Spec.Port) {

				groupKey := s.Spec.Flags.Namespace + "-" + s.Spec.Flags.Name
				if _, ok := status[groupKey]; !ok {
					status[groupKey] = map[string]backendStatusCounter{}
				}

				for _, b := range s.Status.Realized.BackendAddresses {
					key := fmt.Sprintf("%s-%d", *b.IP, b.Port)
					counter := status[groupKey][key]
					counter.expected = c.expectedT1BackendNodeCount(lbsvc, nodeT1Services, b.Zone)
					if b.State == "active" {
						counter.active++
					}
					status[groupKey][key] = counter
				}
			}
		}
	}

	return status
}

func (s *LoadbalancerClient) expectedT1BackendNodeCount(lbsvc isovalentv1alpha1.LBService, nodeT1Services map[string][]*models.Service, backendZone string) int {
	if !s.isZoneAware(lbsvc) || backendZone == "" {
		return len(nodeT1Services)
	}

	// If at least one T1 node has no known zone, fall back to the non-zone-aware
	// expectation to keep status deterministic.
	if len(s.t1NodeZones) != len(nodeT1Services) {
		return len(nodeT1Services)
	}

	expected := 0
	for candidateNode := range nodeT1Services {
		if s.t1NodeZones[candidateNode] == backendZone {
			expected++
		}
	}
	return expected
}

func (s *LoadbalancerClient) isZoneAware(lbsvc isovalentv1alpha1.LBService) bool {
	return lbsvc.Spec.TrafficPolicy != nil && lbsvc.Spec.TrafficPolicy.ZoneAware != nil
}

func (s *LoadbalancerClient) getBackendStatusFromT2(lbsvc isovalentv1alpha1.LBService, nodeEnvoyConfigs map[string]*EnvoyConfigModel) map[string]map[string]backendStatusCounter {
	status := map[string]map[string]backendStatusCounter{}

	for _, ecn := range nodeEnvoyConfigs {
		for _, c := range ecn.Configs {
			switch c.Type {
			case "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump":
				// default/lbfe-lb-1/backend_cluster_https_0
				for _, e := range c.DynamicEndpointConfigs {
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)) {
						for _, ep := range e.EndpointConfig.Endpoints {
							for _, epc := range ep.LbEndpoints {
								if _, ok := status[e.EndpointConfig.ClusterName]; !ok {
									status[e.EndpointConfig.ClusterName] = map[string]backendStatusCounter{}
								}

								key := fmt.Sprintf("%s-%d", epc.Endpoint.Address.SocketAddress.Address, epc.Endpoint.Address.SocketAddress.PortValue)
								counter := status[e.EndpointConfig.ClusterName][key]
								counter.expected = len(nodeEnvoyConfigs)
								if epc.HealthStatus == "HEALTHY" {
									counter.active++
								}
								status[e.EndpointConfig.ClusterName][key] = counter
							}
						}
					}
				}
			}
		}
	}

	return status
}

func (s *LoadbalancerClient) statusText(ok, total int) string {
	if total > 0 && ok == total {
		return "OK"
	}

	return "DEG"
}

func overallStatus(bgpRouteStatus LoadbalancerStatusModelSimpleStatus, bgpPeerStatus LoadbalancerStatusModelSimpleStatus) string {
	if bgpRouteStatus.Status == "N/A" || bgpPeerStatus.Status == "N/A" {
		return "OFFLINE"
	}

	if bgpRouteStatus.OK == 0 || bgpPeerStatus.OK == 0 {
		return "OFFLINE"
	}

	return "ONLINE"
}

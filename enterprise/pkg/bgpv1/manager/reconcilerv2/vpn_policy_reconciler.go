// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
)

type VPNRoutePolicyReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseConfigReconciler `group:"enterprise-bgp-config-reconciler"`
}

type VPNRoutePolicyReconcilerIn struct {
	cell.In

	Config       config.Config
	EVPNConfig   evpnConfig.Config
	DaemonConfig *option.DaemonConfig

	Logger          *slog.Logger
	PeerConfigStore resource.Resource[*v1.IsovalentBGPPeerConfig]
	Group           job.Group
}

// VPNRoutePolicyReconciler is a reconciler that configures VPNv4//EVPN related route policies:
//   - import route policy per peer allowing VPNv4/EVPN routes from adj-in to loc-rib.
//   - export route policy per peer allowing VPNv4/EVPN routes from loc-rib to adj-out.
type VPNRoutePolicyReconciler struct {
	initialized     atomic.Bool
	logger          *slog.Logger
	peerConfigStore resource.Store[*v1.IsovalentBGPPeerConfig]
	metadata        map[string]VPNRoutePolicyMetadata
}

type VPNRoutePolicyMetadata struct {
	VPNPolicies RoutePolicyMap
}

func NewVPNRoutePolicyReconciler(in VPNRoutePolicyReconcilerIn) VPNRoutePolicyReconcilerOut {
	if !in.Config.Enabled || (!in.EVPNConfig.Enabled && !in.DaemonConfig.EnableSRv6) {
		return VPNRoutePolicyReconcilerOut{}
	}

	rp := &VPNRoutePolicyReconciler{
		metadata: make(map[string]VPNRoutePolicyMetadata),
		logger:   in.Logger.With(types.ReconcilerLogField, "VPNRoutePolicy"),
	}

	in.Group.Add(job.OneShot("init-vpn-route-policy", func(ctx context.Context, health cell.Health) error {
		pcs, err := in.PeerConfigStore.Store(ctx)
		if err != nil {
			return err
		}

		rp.peerConfigStore = pcs
		rp.initialized.Store(true)
		return nil
	}))

	return VPNRoutePolicyReconcilerOut{
		EnterpriseReconciler: rp,
	}
}

func (r *VPNRoutePolicyReconciler) Name() string {
	return VPNRoutePolicyReconcilerName
}

func (r *VPNRoutePolicyReconciler) Priority() int {
	// This reconciler should run just before the OSS Neighbor reconciler,
	// so gobgp will already have desired VPN policies in place.
	return VPNRoutePolicyReconcilerPriority
}

func (r *VPNRoutePolicyReconciler) Init(i *instance.EnterpriseBGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = VPNRoutePolicyMetadata{
		VPNPolicies: make(RoutePolicyMap),
	}
	return nil
}

func (r *VPNRoutePolicyReconciler) Cleanup(i *instance.EnterpriseBGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *VPNRoutePolicyReconciler) Reconcile(ctx context.Context, p EnterpriseReconcileParams) error {
	if !r.initialized.Load() {
		r.logger.Debug("Not initialized yet, skipping VPN route policy reconciliation")
		return nil
	}

	desiredPolicies, err := r.getDesiredRoutePolicies(p.DesiredConfig)
	if err != nil {
		return err
	}

	updatedPolicies, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
		Logger:          r.logger.With(types.InstanceLogField, p.BGPInstance.Name),
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredPolicies,
		CurrentPolicies: r.GetMetadata(p.BGPInstance).VPNPolicies,
	})

	r.SetMetadata(p.BGPInstance, VPNRoutePolicyMetadata{
		VPNPolicies: updatedPolicies,
	})

	return err
}

func (r *VPNRoutePolicyReconciler) getDesiredRoutePolicies(desiredConfig *v1.IsovalentBGPNodeInstance) (RoutePolicyMap, error) {
	desiredPolicies := make(RoutePolicyMap)

	for _, peer := range desiredConfig.Peers {
		if peer.PeerAddress == nil || *peer.PeerAddress == "" {
			continue // peer address not known yet
		}
		peerAddr, err := netip.ParseAddr(*peer.PeerAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}

		// get the peer config
		if peer.PeerConfigRef == nil {
			r.logger.Debug("Peer config reference not set, skipping peer for import policy inspection", types.PeerLogField, peer.Name)
			continue
		}

		peerConfig, exists, err := r.peerConfigStore.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
		if err != nil {
			return nil, err
		}

		if !exists {
			r.logger.Debug("Peer config not found, skipping peer for import policy inspection", types.PeerLogField, peer.Name)
			continue
		}

		// allow importing routes from peers which have ipv4-l3vpn or
		// l2vpn/evpn family configured.
		vpnFamilies := []types.Family{}
		for _, fam := range peerConfig.Spec.Families {
			agentFamily := types.ToAgentFamily(fam.CiliumBGPFamily)
			if (agentFamily.Afi == types.AfiIPv4 && agentFamily.Safi == types.SafiMplsVpn) ||
				(agentFamily.Afi == types.AfiL2VPN && agentFamily.Safi == types.SafiEvpn) {
				vpnFamilies = append(vpnFamilies, agentFamily)
			}
		}

		if len(vpnFamilies) > 0 {
			// import route policy allowing VPNv4/EVPN routes from adj-in to loc-rib
			importPolicyName := fmt.Sprintf("%s-import-%s", r.Name(), peer.Name)
			desiredPolicies[importPolicyName] = acceptRoutePolicy(types.RoutePolicyTypeImport, importPolicyName, peerAddr, vpnFamilies)

			// export route policy allowing all VPNv4/EVPN routes from  loc-rib to adj-out
			exportPolicyName := fmt.Sprintf("%s-export-%s", r.Name(), peer.Name)
			desiredPolicies[exportPolicyName] = acceptRoutePolicy(types.RoutePolicyTypeExport, exportPolicyName, peerAddr, vpnFamilies)
		}
	}

	return desiredPolicies, nil
}

func acceptRoutePolicy(policyType types.RoutePolicyType, name string, peerAddr netip.Addr, vpnFamilies []types.Family) *entTypes.ExtendedRoutePolicy {
	return &entTypes.ExtendedRoutePolicy{
		Name: name,
		Type: policyType,
		Statements: []*entTypes.ExtendedRoutePolicyStatement{
			{
				Conditions: entTypes.ExtendedRoutePolicyConditions{
					RoutePolicyConditions: types.RoutePolicyConditions{
						MatchNeighbors: &types.RoutePolicyNeighborMatch{
							Type:      types.RoutePolicyMatchAny,
							Neighbors: []netip.Addr{peerAddr},
						},
						MatchFamilies: vpnFamilies,
					},
				},
				Actions: entTypes.ExtendedRoutePolicyActions{
					RoutePolicyActions: types.RoutePolicyActions{
						RouteAction: types.RoutePolicyActionAccept,
					},
				},
			},
		},
	}
}

func (r *VPNRoutePolicyReconciler) GetMetadata(i *EnterpriseBGPInstance) VPNRoutePolicyMetadata {
	return r.metadata[i.Name]
}

func (r *VPNRoutePolicyReconciler) SetMetadata(i *EnterpriseBGPInstance, m VPNRoutePolicyMetadata) {
	r.metadata[i.Name] = m
}

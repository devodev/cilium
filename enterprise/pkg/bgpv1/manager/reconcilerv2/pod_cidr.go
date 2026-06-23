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

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	ossReconciler "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/option"
)

type PodCIDRReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseConfigReconciler `group:"enterprise-bgp-config-reconciler"`
}

type PodCIDRReconcilerIn struct {
	cell.In

	BGPConfig    config.Config
	Logger       *slog.Logger
	PeerAdvert   *IsovalentAdvertisement
	DaemonConfig *option.DaemonConfig
}

type PodCIDRReconciler struct {
	logger     *slog.Logger
	peerAdvert *IsovalentAdvertisement
	metadata   map[string]PodCIDRReconcilerMetadata
}

// PodCIDRReconcilerMetadata is a map of advertisements per family, key is family type
type PodCIDRReconcilerMetadata struct {
	AFPaths       ossReconciler.AFPathsMap
	RoutePolicies RoutePolicyMap
}

func NewPodCIDRReconciler(params PodCIDRReconcilerIn) PodCIDRReconcilerOut {
	if !params.BGPConfig.Enabled {
		return PodCIDRReconcilerOut{}
	}

	// Don't provide the reconciler if the IPAM mode is not supported
	if !types.CanAdvertisePodCIDR(params.DaemonConfig.IPAMMode()) {
		params.Logger.Info("Unsupported IPAM mode, disabling PodCIDR advertisements.")
		return PodCIDRReconcilerOut{}
	}
	r := &PodCIDRReconciler{
		logger:     params.Logger.With(types.ReconcilerLogField, "PodCIDR"),
		peerAdvert: params.PeerAdvert,
		metadata:   make(map[string]PodCIDRReconcilerMetadata),
	}
	return PodCIDRReconcilerOut{
		EnterpriseReconciler: r,
	}
}

func (r *PodCIDRReconciler) Name() string {
	return PodCIDRReconcilerName
}

func (r *PodCIDRReconciler) Priority() int {
	return PodCIDRReconcilerPriority
}

func (r *PodCIDRReconciler) Init(i *instance.EnterpriseBGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = PodCIDRReconcilerMetadata{
		AFPaths:       make(ossReconciler.AFPathsMap),
		RoutePolicies: make(RoutePolicyMap),
	}
	return nil
}

func (r *PodCIDRReconciler) Cleanup(i *instance.EnterpriseBGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *PodCIDRReconciler) Reconcile(ctx context.Context, p EnterpriseReconcileParams) error {
	// get pod CIDR prefixes
	var podCIDRPrefixes []netip.Prefix
	for _, cidr := range p.CiliumNode.Spec.IPAM.PodCIDRs {
		podCIDRPrefixes = append(podCIDRPrefixes, cidr.Prefix)
	}

	// get per peer per family pod cidr advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredPeerAdvertisements(p.DesiredConfig, v1.BGPPodCIDRAdvert)
	if err != nil {
		return err
	}

	err = r.reconcileRoutePolicies(ctx, p, desiredPeerAdverts, podCIDRPrefixes)
	if err != nil {
		return err
	}

	return r.reconcilePaths(ctx, p, desiredPeerAdverts, podCIDRPrefixes)
}

func (r *PodCIDRReconciler) reconcilePaths(ctx context.Context, p EnterpriseReconcileParams, desiredPeerAdverts PeerAdvertisements, podPrefixes []netip.Prefix) error {
	metadata := r.getMetadata(p.BGPInstance)

	// get desired paths per address family
	desiredFamilyAdverts, err := r.getDesiredPathsPerFamily(desiredPeerAdverts, podPrefixes)
	if err != nil {
		return err
	}

	// reconcile family advertisements
	updatedAFPaths, err := ossReconciler.ReconcileAFPaths(&ossReconciler.ReconcileAFPathsParams{
		Logger:       r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:          ctx,
		Router:       p.BGPInstance.Router,
		DesiredPaths: desiredFamilyAdverts,
		CurrentPaths: metadata.AFPaths,
	})

	metadata.AFPaths = updatedAFPaths
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *PodCIDRReconciler) reconcileRoutePolicies(ctx context.Context, p EnterpriseReconcileParams, desiredPeerAdverts PeerAdvertisements, podPrefixes []netip.Prefix) error {
	metadata := r.getMetadata(p.BGPInstance)

	// get desired policies
	desiredRoutePolicies, err := r.getDesiredRoutePolicies(desiredPeerAdverts, podPrefixes)
	if err != nil {
		return err
	}

	// reconcile route policies
	updatedPolicies, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
		Logger:          r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredRoutePolicies,
		CurrentPolicies: r.getMetadata(p.BGPInstance).RoutePolicies,
	})

	metadata.RoutePolicies = updatedPolicies
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

// getDesiredPathsPerFamily returns a map of desired paths per address family.
// Note: This returns prefixes per address family. Global routing table will contain prefix per family not per neighbor.
// Per neighbor advertisement will be controlled by BGP Policy.
func (r *PodCIDRReconciler) getDesiredPathsPerFamily(desiredPeerAdverts PeerAdvertisements, desiredPrefixes []netip.Prefix) (ossReconciler.AFPathsMap, error) {
	// Calculate desired paths per address family, collapsing per-peer advertisements into per-family advertisements.
	desiredFamilyAdverts := make(ossReconciler.AFPathsMap)
	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			pathsPerFamily, exists := desiredFamilyAdverts[agentFamily]
			if !exists {
				pathsPerFamily = make(ossReconciler.PathMap)
				desiredFamilyAdverts[agentFamily] = pathsPerFamily
			}

			// there are some advertisements which have pod CIDR advert enabled.
			// we need to add podCIDR prefixes to the desiredFamilyAdverts.
			if len(familyAdverts) != 0 {
				for _, prefix := range desiredPrefixes {
					path, err := types.NewPathForPrefix(prefix)
					if err != nil {
						return nil, fmt.Errorf("failed to create path for prefix %s: %w", prefix, err)
					}
					path.Family = agentFamily

					// we only add path corresponding to the family of the prefix.
					if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
						pathsPerFamily[path.NLRI.String()] = path
					}
					if agentFamily.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
						pathsPerFamily[path.NLRI.String()] = path
					}
				}
			}
		}
	}
	return desiredFamilyAdverts, nil
}

func (r *PodCIDRReconciler) getDesiredRoutePolicies(desiredPeerAdverts PeerAdvertisements, desiredPrefixes []netip.Prefix) (RoutePolicyMap, error) {
	desiredPolicies := make(RoutePolicyMap)

	for peer, afAdverts := range desiredPeerAdverts {
		if peer.Address == "" {
			continue // peer address not known yet
		}
		peerAddr, err := netip.ParseAddr(peer.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}

		for family, adverts := range afAdverts {
			fam := types.ToAgentFamily(family)

			for _, advert := range adverts {
				var v4Prefixes, v6Prefixes types.PolicyPrefixList
				for _, prefix := range desiredPrefixes {
					match := types.RoutePolicyPrefix{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()}

					if fam.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
						v4Prefixes = append(v4Prefixes, match)
					}

					if fam.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
						v6Prefixes = append(v6Prefixes, match)
					}
				}

				if len(v6Prefixes) > 0 || len(v4Prefixes) > 0 {
					name := PolicyName(peer.Name, fam.Afi.String(), advert.AdvertisementType, "")
					policy, err := CreatePolicy(name, peerAddr, v4Prefixes, v6Prefixes, advert)
					if err != nil {
						return nil, err
					}
					desiredPolicies[name] = policy
				}
			}
		}
	}

	return desiredPolicies, nil
}

func (r *PodCIDRReconciler) getMetadata(i *EnterpriseBGPInstance) PodCIDRReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *PodCIDRReconciler) setMetadata(i *EnterpriseBGPInstance, metadata PodCIDRReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	ossReconciler "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type EGWIPsReconcilerIn struct {
	cell.In

	Logger         *slog.Logger
	BGPConfig      config.Config
	DaemonConfig   *option.DaemonConfig
	EGWIPsProvider egressgatewayha.EgressIPsProvider
	Upgrader       paramUpgrader
	PeerAdvert     *IsovalentAdvertisement
}

type EGWIPsReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseConfigReconciler     `group:"enterprise-bgp-config-reconciler"`
	Reconciler           ossReconciler.ConfigReconciler `group:"bgp-config-reconciler"`
}

func NewEgressGatewayIPsReconciler(params EGWIPsReconcilerIn) EGWIPsReconcilerOut {
	if !params.BGPConfig.Enabled || !params.DaemonConfig.EnableIPv4EgressGatewayHA {
		return EGWIPsReconcilerOut{}
	}

	r := &EgressGatewayIPsReconciler{
		logger:         params.Logger.With(types.ReconcilerLogField, "EgressGatewayIP"),
		egwIPsProvider: params.EGWIPsProvider,
		peerAdvert:     params.PeerAdvert,
		metadata:       make(map[string]EgressGatewayIPsMetadata),
	}
	return EGWIPsReconcilerOut{
		EnterpriseReconciler: r,
		Reconciler:           newOSSConfigReconcilerAdapter(r, params.Upgrader),
	}
}

type EgressGatewayIPsReconciler struct {
	logger         *slog.Logger
	egwIPsProvider egressgatewayha.EgressIPsProvider
	peerAdvert     *IsovalentAdvertisement
	metadata       map[string]EgressGatewayIPsMetadata
}

type EgressGatewayIPsMetadata struct {
	EGWAFPaths       ossReconciler.ResourceAFPathsMap
	EGWRoutePolicies ResourceRoutePolicyMap
}

func (r *EgressGatewayIPsReconciler) Priority() int {
	return EgressGatewayIPsReconcilerPriority
}

func (r *EgressGatewayIPsReconciler) Name() string {
	return EgressGatewayIPsReconcilerName
}

func (r *EgressGatewayIPsReconciler) Init(i *instance.EnterpriseBGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = EgressGatewayIPsMetadata{
		EGWAFPaths:       make(ossReconciler.ResourceAFPathsMap),
		EGWRoutePolicies: make(ResourceRoutePolicyMap),
	}
	return nil
}

func (r *EgressGatewayIPsReconciler) Cleanup(i *instance.EnterpriseBGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *EgressGatewayIPsReconciler) Reconcile(ctx context.Context, params EnterpriseReconcileParams) error {
	// get per peer per family egw advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredPeerAdvertisements(params.DesiredConfig, v1.BGPEGWAdvert)
	if err != nil {
		return err
	}

	// reconcile route policies
	if err = r.reconcileRoutePolicies(ctx, params, desiredPeerAdverts); err != nil {
		return err
	}

	return r.reconcilePaths(ctx, params, desiredPeerAdverts)
}

func (r *EgressGatewayIPsReconciler) reconcilePaths(ctx context.Context, params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) error {
	egwAFPaths, err := r.getDesiredEGWAFPaths(desiredFamilyAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(params.BGPInstance)

	// mark policies for deletion
	for key := range metadata.EGWAFPaths {
		if _, exists := egwAFPaths[key]; !exists {
			egwAFPaths[key] = nil
		}
	}

	metadata.EGWAFPaths, err = ossReconciler.ReconcileResourceAFPaths(ossReconciler.ReconcileResourceAFPathsParams{
		Logger:                 r.logger.With(types.InstanceLogField, params.DesiredConfig.Name),
		Ctx:                    ctx,
		Router:                 params.BGPInstance.Router,
		DesiredResourceAFPaths: egwAFPaths,
		CurrentResourceAFPaths: metadata.EGWAFPaths,
	})

	r.setMetadata(params.BGPInstance, metadata)
	return err
}

func (r *EgressGatewayIPsReconciler) reconcileRoutePolicies(ctx context.Context, params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) error {
	desiredRoutePolicies, err := r.getDesiredEGWRoutePolicies(desiredFamilyAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(params.BGPInstance)

	// mark policies for deletion
	for key := range metadata.EGWRoutePolicies {
		if _, exists := desiredRoutePolicies[key]; !exists {
			desiredRoutePolicies[key] = nil
		}
	}

	for key, policies := range desiredRoutePolicies {
		currentPolicies, exists := metadata.EGWRoutePolicies[key]
		if !exists && len(policies) == 0 {
			continue
		}

		updatedRoutePolicies, rErr := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
			Logger: r.logger.With(
				types.InstanceLogField, params.DesiredConfig.Name,
				entTypes.EgressGatewayLogField, key,
			),
			Ctx:             ctx,
			Router:          params.BGPInstance.Router,
			DesiredPolicies: policies,
			CurrentPolicies: currentPolicies,
		})
		if rErr == nil && len(policies) == 0 {
			delete(metadata.EGWRoutePolicies, key)
		} else {
			metadata.EGWRoutePolicies[key] = updatedRoutePolicies
		}
		err = errors.Join(err, rErr)
	}

	r.setMetadata(params.BGPInstance, metadata)
	return err
}

// getDesiredEGWAFPaths returns the desired egress gateway paths per family per egress policy. The desired paths are calculated based on the
// BGP advertisements of type BGPEGWAdvert. Advertisement contains a label selector for the egress gateway policy. We
// call EGWManager with the selector field to get the egress gateway IPs present on the node. The desired paths are created
// based on the returned IPs. Exact match /32 paths are created for each IP.
func (r *EgressGatewayIPsReconciler) getDesiredEGWAFPaths(desiredFamilyAdverts PeerAdvertisements) (ossReconciler.ResourceAFPathsMap, error) {
	desiredEGWResourceAFPaths := make(ossReconciler.ResourceAFPathsMap)

	for _, egwFamilyAdverts := range desiredFamilyAdverts {
		for family, familyAdverts := range egwFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// sanity check
				if advert.AdvertisementType != v1.BGPEGWAdvert {
					r.logger.Error("BUG: unexpected advertisement type", types.AdvertTypeLogField, advert.AdvertisementType)
					continue
				}

				egwPolicyResult, err := r.egwIPsProvider.AdvertisedEgressIPs(advert.Selector)
				if err != nil {
					r.logger.Error("failed to get egress gateway IPs", logfields.Error, err)
					continue
				}

				for egwID, egwIPs := range egwPolicyResult {
					desiredEGWAFPaths := make(ossReconciler.AFPathsMap)

					for _, egwIP := range egwIPs {
						if !egwIP.IsValid() {
							r.logger.Error("invalid egress gateway IP", logfields.EgressIP, egwIP)
							continue
						}
						switch {
						case agentFamily.Afi == types.AfiIPv4 && egwIP.Is4():
							prefix := netip.PrefixFrom(egwIP, egwIP.BitLen())
							path, err := types.NewPathForPrefix(prefix)
							if err != nil {
								return nil, fmt.Errorf("failed to create path for prefix %s: %w", prefix, err)
							}
							path.Family = agentFamily
							ossReconciler.AddPathToAFPathsMap(desiredEGWAFPaths, agentFamily, path, path.NLRI.String())

						case agentFamily.Afi == types.AfiIPv6 && egwIP.Is6():
							prefix := netip.PrefixFrom(egwIP, egwIP.BitLen())
							path, err := types.NewPathForPrefix(prefix)
							if err != nil {
								return nil, fmt.Errorf("failed to create path for prefix %s: %w", prefix, err)
							}
							path.Family = agentFamily
							ossReconciler.AddPathToAFPathsMap(desiredEGWAFPaths, agentFamily, path, path.NLRI.String())

						default:
							continue
						}
					}

					desiredEGWResourceAFPaths[resource.Key{
						Name:      egwID.Name,
						Namespace: egwID.Namespace,
					}] = desiredEGWAFPaths
				}
			}
		}
	}

	return desiredEGWResourceAFPaths, nil
}

// getDesiredEGWRoutePolicies returns the desired bgp route policies per egress policy. Similar to
// getDesiredEGWAFPaths, the desired route policies are calculated based on the BGP advertisements of type BGPEGWAdvert
// and selector field. Route policy is created based on BGP attributes present in BGP advertisement and peer/prefix calculated
// from advertisement and egress gateway IPs.
func (r *EgressGatewayIPsReconciler) getDesiredEGWRoutePolicies(desiredFamilyAdverts PeerAdvertisements) (ResourceRoutePolicyMap, error) {
	desiredRoutePolicies := make(ResourceRoutePolicyMap)

	for peer, egwFamilyAdverts := range desiredFamilyAdverts {
		if peer.Address == "" {
			continue // peer address not known yet
		}
		peerAddr, err := netip.ParseAddr(peer.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}

		for family, familyAdverts := range egwFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// sanity check
				if advert.AdvertisementType != v1.BGPEGWAdvert {
					r.logger.Error("BUG: unexpected advertisement type", types.AdvertTypeLogField, advert.AdvertisementType)
					continue
				}

				egwPolicyResult, err := r.egwIPsProvider.AdvertisedEgressIPs(advert.Selector)
				if err != nil {
					r.logger.Error("failed to get egress gateway IPs", logfields.Error, err)
					continue
				}

				for egwID, egwIPs := range egwPolicyResult {
					var v4Prefixes, v6Prefixes types.PolicyPrefixList
					for _, egwIP := range egwIPs {
						if !egwIP.IsValid() {
							r.logger.Error("invalid egress gateway IP", logfields.EgressIP, egwIP)
							continue
						}
						switch {
						case agentFamily.Afi == types.AfiIPv4 && egwIP.Is4():
							v4Prefixes = append(v4Prefixes, types.RoutePolicyPrefix{
								CIDR:         netip.PrefixFrom(egwIP, egwIP.BitLen()),
								PrefixLenMin: egwIP.BitLen(),
								PrefixLenMax: egwIP.BitLen(),
							})

						case agentFamily.Afi == types.AfiIPv6 && egwIP.Is6():
							v6Prefixes = append(v6Prefixes, types.RoutePolicyPrefix{
								CIDR:         netip.PrefixFrom(egwIP, egwIP.BitLen()),
								PrefixLenMin: egwIP.BitLen(),
								PrefixLenMax: egwIP.BitLen(),
							})

						default:
							continue
						}
					}

					if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
						continue
					}

					policyName := PolicyName(peer.Name, agentFamily.Afi.String(), v1.BGPEGWAdvert, egwID.Name)
					policy, err := CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, advert)
					if err != nil {
						return nil, fmt.Errorf("failed to create egress gateway route policy: %w", err)
					}

					egwKey := resource.Key{
						Name:      egwID.Name,
						Namespace: egwID.Namespace,
					}

					if _, exists := desiredRoutePolicies[egwKey]; !exists {
						desiredRoutePolicies[egwKey] = make(RoutePolicyMap)
					}
					desiredRoutePolicies[egwKey][policyName] = policy
				}
			}
		}

	}

	return desiredRoutePolicies, nil
}

func (r *EgressGatewayIPsReconciler) getMetadata(i *EnterpriseBGPInstance) EgressGatewayIPsMetadata {
	return r.metadata[i.Name]
}

func (r *EgressGatewayIPsReconciler) setMetadata(i *EnterpriseBGPInstance, metadata EgressGatewayIPsMetadata) {
	r.metadata[i.Name] = metadata
}

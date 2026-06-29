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
	"github.com/cilium/hive/job"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	ossReconciler "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type PodCIDRVRFReconcilerIn struct {
	cell.In

	Logger       *slog.Logger
	Group        job.Group
	DaemonConfig *option.DaemonConfig
	Config       config.Config
	Adverts      *IsovalentAdvertisement
	Upgrader     paramUpgrader
	SRv6Paths    *srv6Paths
	SRv6Manager  *srv6.Manager
}

type PodCIDRVRFReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseConfigReconciler     `group:"enterprise-bgp-config-reconciler"`
	Reconciler           ossReconciler.ConfigReconciler `group:"bgp-config-reconciler"`
}

type PodCIDRVRFReconciler struct {
	Logger      *slog.Logger
	Adverts     *IsovalentAdvertisement
	SRv6Paths   *srv6Paths
	SRv6Manager SRv6Manager
	metadata    map[string]PodCIDRVRFReconcilerMetadata
}

type PodCIDRVRFReconcilerMetadata struct {
	VRFAFPaths ossReconciler.ResourceAFPathsMap
}

func NewPodCIDRVRFReconciler(in PodCIDRVRFReconcilerIn) PodCIDRVRFReconcilerOut {
	// Don't provide the reconciler if the SRv6 manager or Enterprise BGP is not enabled
	if !in.Config.Enabled || !in.DaemonConfig.EnableSRv6 {
		return PodCIDRVRFReconcilerOut{}
	}

	// Don't provide the reconciler if the IPAM mode is not supported
	if !types.CanAdvertisePodCIDR(in.DaemonConfig.IPAMMode()) {
		in.Logger.Info("Unsupported IPAM mode, disabling PodCIDR VPN advertisements.")
		return PodCIDRVRFReconcilerOut{}
	}

	pr := &PodCIDRVRFReconciler{
		Logger:      in.Logger.With(types.ReconcilerLogField, "PodCIDRVRF"),
		Adverts:     in.Adverts,
		SRv6Paths:   in.SRv6Paths,
		SRv6Manager: in.SRv6Manager,
		metadata:    make(map[string]PodCIDRVRFReconcilerMetadata),
	}

	return PodCIDRVRFReconcilerOut{
		EnterpriseReconciler: pr,
		Reconciler:           newOSSConfigReconcilerAdapter(pr, in.Upgrader),
	}
}

func (r *PodCIDRVRFReconciler) Name() string {
	return PodCIDRVRFReconcilerName
}

func (r *PodCIDRVRFReconciler) Priority() int {
	return PodCIDRVRFReconcilerPriority
}

func (r *PodCIDRVRFReconciler) Init(i *instance.EnterpriseBGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = PodCIDRVRFReconcilerMetadata{
		VRFAFPaths: make(ossReconciler.ResourceAFPathsMap),
	}
	return nil
}

func (r *PodCIDRVRFReconciler) Cleanup(i *instance.EnterpriseBGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *PodCIDRVRFReconciler) Reconcile(ctx context.Context, p EnterpriseReconcileParams) error {
	// get pod CIDRs
	podCIDRPrefixes, err := r.getPodCIDRs(p.CiliumNode)
	if err != nil {
		return err
	}

	// get PodCIDR VPN advertisements
	desiredVRFAdverts, err := r.Adverts.GetConfiguredVRFAdvertisements(p.DesiredConfig, v1.BGPPodCIDRAdvert)
	if err != nil {
		return err
	}

	return r.reconcilePaths(ctx, p, podCIDRPrefixes, desiredVRFAdverts)
}

func (r *PodCIDRVRFReconciler) getPodCIDRs(cn *v2.CiliumNode) ([]netip.Prefix, error) {
	if cn == nil {
		return nil, fmt.Errorf("CiliumNode is nil")
	}

	var podCIDRPrefixes []netip.Prefix
	for _, cidr := range cn.Spec.IPAM.PodCIDRs {
		podCIDRPrefixes = append(podCIDRPrefixes, cidr.Prefix)
	}

	return podCIDRPrefixes, nil
}

func (r *PodCIDRVRFReconciler) reconcilePaths(ctx context.Context, p EnterpriseReconcileParams, podCIDRPrefixes []netip.Prefix, desiredVRFAdverts VRFAdvertisements) error {
	allVRFsPodCIDRAFPaths, err := r.getDesiredVRFAFPaths(p, podCIDRPrefixes, desiredVRFAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(p.BGPInstance)

	metadata.VRFAFPaths, err = ossReconciler.ReconcileResourceAFPaths(ossReconciler.ReconcileResourceAFPathsParams{
		Logger:                 r.Logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:                    ctx,
		Router:                 p.BGPInstance.Router,
		DesiredResourceAFPaths: allVRFsPodCIDRAFPaths,
		CurrentResourceAFPaths: metadata.VRFAFPaths,
	})

	r.setMetadata(p.BGPInstance, metadata)

	return err
}

func (r *PodCIDRVRFReconciler) getDesiredVRFAFPaths(p EnterpriseReconcileParams, podCIDRPrefixes []netip.Prefix, desiredVRFAdverts VRFAdvertisements) (ossReconciler.ResourceAFPathsMap, error) {
	desiredVRFsAFPaths := make(ossReconciler.ResourceAFPathsMap)

	metadata := r.getMetadata(p.BGPInstance)

	// check if IsovalentVRF is deleted or removed from desired config
	for vrfNamespacedName := range metadata.VRFAFPaths {
		_, exists := r.SRv6Manager.GetVRFByName(k8sTypes.NamespacedName{Name: vrfNamespacedName.Name, Namespace: vrfNamespacedName.Namespace})
		if !exists {
			// vrf is deleted, mark it for removal
			desiredVRFsAFPaths[vrfNamespacedName] = nil
			continue
		}

		found := false
		for _, bgpVRF := range p.DesiredConfig.VRFs {
			if bgpVRF.VRFRef == nil {
				continue
			}
			bgpVRFKey := resource.Key{Name: *bgpVRF.VRFRef}
			if vrfNamespacedName == bgpVRFKey {
				found = true
				break
			}
		}
		if !found {
			// vrf is deleted from desired config, mark it for removal
			desiredVRFsAFPaths[vrfNamespacedName] = nil
		}
	}

	for _, bgpVRF := range p.DesiredConfig.VRFs {
		if bgpVRF.VRFRef == nil {
			continue
		}
		// check if pod CIDR advertisement is configured for this BGP VRF
		afAdverts, exists := desiredVRFAdverts[*bgpVRF.VRFRef]
		if !exists {
			continue
		}

		// get isoVRF resource
		_, exists = r.SRv6Manager.GetVRFByName(k8sTypes.NamespacedName{Name: *bgpVRF.VRFRef})
		if !exists {
			r.Logger.Warn("VRF not found in SRv6 Manager", entTypes.VRFLogField, bgpVRF.VRFRef)
			continue
		}

		desiredVRFAFPaths := make(ossReconciler.AFPathsMap)
		for fam, adverts := range afAdverts {
			family := types.ToAgentFamily(fam)

			// we do not care about advertisements for pod CIDRs, as long as there is one,
			// we will advertise the pod CIDRs
			if len(adverts) == 0 {
				continue
			}

			for _, prefix := range podCIDRPrefixes {
				if prefix.Addr().Is4() && family.Afi == types.AfiIPv4 {
					path, pathKey, err := r.SRv6Paths.GetSRv6VPNPath(prefix, bgpVRF)
					if err != nil {
						r.Logger.Error("failed to get SRv6 paths for prefix",
							logfields.Prefix, prefix,
							logfields.Error, err,
						)
						continue
					}
					path.Family = family
					ossReconciler.AddPathToAFPathsMap(desiredVRFAFPaths, family, path, pathKey)
				}

				if prefix.Addr().Is6() && family.Afi == types.AfiIPv6 {
					path, pathKey, err := r.SRv6Paths.GetSRv6VPNPath(prefix, bgpVRF)
					if err != nil {
						r.Logger.Error("failed to get SRv6 paths for prefix",
							logfields.Prefix, prefix,
							logfields.Error, err,
						)
						continue
					}
					path.Family = family
					ossReconciler.AddPathToAFPathsMap(desiredVRFAFPaths, family, path, pathKey)
				}
			}
		}
		desiredVRFsAFPaths[resource.Key{Name: *bgpVRF.VRFRef}] = desiredVRFAFPaths
	}
	return desiredVRFsAFPaths, nil
}

func (r *PodCIDRVRFReconciler) getMetadata(i *EnterpriseBGPInstance) PodCIDRVRFReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *PodCIDRVRFReconciler) setMetadata(i *EnterpriseBGPInstance, metadata PodCIDRVRFReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

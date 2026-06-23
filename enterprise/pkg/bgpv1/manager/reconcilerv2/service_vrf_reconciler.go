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
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	ossReconciler "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
)

type ServiceVRFReconcilerIn struct {
	cell.In

	Logger       *slog.Logger
	Config       config.Config
	DaemonConfig *option.DaemonConfig
	DB           *statedb.DB
	Frontends    statedb.Table[*loadbalancer.Frontend]
	Adverts      *IsovalentAdvertisement
	SRv6Paths    *srv6Paths
	SRv6Manager  *srv6.Manager
}

type ServiceVRFReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseConfigReconciler `group:"enterprise-bgp-config-reconciler"`
}

type ServiceVRFReconciler struct {
	logger      *slog.Logger
	db          *statedb.DB
	frontends   statedb.Table[*loadbalancer.Frontend]
	adverts     *IsovalentAdvertisement
	srv6Paths   *srv6Paths
	srv6Manager SRv6Manager
	metadata    map[string]ServiceVRFReconcilerMetadata
}

func NewServiceVRFReconciler(in ServiceVRFReconcilerIn) ServiceVRFReconcilerOut {
	if !in.Config.Enabled || !in.DaemonConfig.EnableSRv6 {
		return ServiceVRFReconcilerOut{}
	}

	r := &ServiceVRFReconciler{
		logger:      in.Logger.With(types.ReconcilerLogField, "ServiceVRF"),
		db:          in.DB,
		frontends:   in.Frontends,
		adverts:     in.Adverts,
		srv6Paths:   in.SRv6Paths,
		srv6Manager: in.SRv6Manager,
		metadata:    make(map[string]ServiceVRFReconcilerMetadata),
	}

	return ServiceVRFReconcilerOut{
		EnterpriseReconciler: r,
	}
}

// VRFSIDInfo is a map type that contains SRv6 SID information for a VRF, key being the VRF name.
type VRFSIDInfo map[string]*sidmanager.SIDInfo

// ServiceVRFReconcilerMetadata contains metadata for service VRF reconciler, metadata is stored per
// BGP instance.
type ServiceVRFReconcilerMetadata struct {
	// path programmed in underlying bgp instance
	vrfPaths VRFPaths

	// vrfAdverts contains BGP advertisements associated with VRFs
	vrfAdverts VRFAdvertisements

	// vrfConfigs contains BGP RD/RT configuration for VRFs
	vrfConfigs []v1.IsovalentBGPNodeVRF

	// vrfSIDs contains SRv6 SID information for VRFs, like SID structure and behavior
	vrfSIDs VRFSIDInfo

	// frontendChanges is an iterator of changes in frontends since the last reconciliation
	frontendChanges            statedb.ChangeIterator[*loadbalancer.Frontend]
	frontendChangesInitialized bool
}

func (r *ServiceVRFReconciler) getMetadata(i *EnterpriseBGPInstance) ServiceVRFReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *ServiceVRFReconciler) setMetadata(i *EnterpriseBGPInstance, metadata ServiceVRFReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

func (r *ServiceVRFReconciler) Name() string {
	return ServiceVRFReconcilerName
}

func (r *ServiceVRFReconciler) Init(i *instance.EnterpriseBGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}

	r.metadata[i.Name] = ServiceVRFReconcilerMetadata{
		vrfPaths:   make(VRFPaths),
		vrfAdverts: make(VRFAdvertisements),
		vrfSIDs:    make(VRFSIDInfo),
	}
	return nil
}

func (r *ServiceVRFReconciler) Cleanup(i *instance.EnterpriseBGPInstance) {
	if i != nil {

		delete(r.metadata, i.Name)
	}
}

func (r *ServiceVRFReconciler) Priority() int {
	return ServiceVRFReconcilerPriority
}

func (r *ServiceVRFReconciler) Reconcile(ctx context.Context, p EnterpriseReconcileParams) error {
	desiredVRFAdverts, err := r.adverts.GetConfiguredVRFAdvertisements(p.DesiredConfig, v1.BGPServiceAdvert)
	if err != nil {
		return fmt.Errorf("failed to get configured VRF advertisements: %w", err)
	}

	desiredVRFSIDInfo, err := r.getConfiguredSIDInfo(p.DesiredConfig)
	if err != nil {
		return fmt.Errorf("failed to get SID info: %w", err)
	}

	metadata := r.getMetadata(p.BGPInstance)
	err = r.reconcileServices(ctx, p, &metadata, desiredVRFAdverts, desiredVRFSIDInfo)
	if err != nil {
		return fmt.Errorf("failed to reconcile services: %w", err)
	}

	// update metadata with the latest configuration
	metadata.vrfAdverts = desiredVRFAdverts
	metadata.vrfConfigs = p.DesiredConfig.VRFs
	metadata.vrfSIDs = desiredVRFSIDInfo
	r.setMetadata(p.BGPInstance, metadata)
	return nil
}

func (r *ServiceVRFReconciler) reconcileServices(
	ctx context.Context,
	p EnterpriseReconcileParams,
	metadata *ServiceVRFReconcilerMetadata,
	desiredVRFAdverts VRFAdvertisements,
	desiredVRFSIDInfo VRFSIDInfo,
) error {
	desiredVRFPaths := make(VRFPaths)

	// check if vrf is removed, we clean up the service paths.
	for runningVRF := range metadata.vrfPaths {
		found := false
		for _, desiredVRF := range p.DesiredConfig.VRFs {
			if desiredVRF.VRFRef != nil && runningVRF == *desiredVRF.VRFRef {
				found = true
				break
			}
		}

		if !found {
			// mark VRF for cleanup
			desiredVRFPaths[runningVRF] = nil
		}
	}

	reqFullReconcile := r.configModified(p, metadata, desiredVRFAdverts, desiredVRFSIDInfo)

	// if frontend changes iterator has not been initialized yet (first reconcile), perform full reconciliation
	if !metadata.frontendChangesInitialized {
		reqFullReconcile = true
	}

	if reqFullReconcile {
		r.logger.Debug("performing all services reconciliation")

		// BGP configuration for service advertisement changed, we should reconcile all services.
		toReconcile, rx, err := r.fullReconciliationServiceList(metadata) // note: can be called only once per reconcile
		if err != nil {
			return err
		}
		for _, vrf := range p.DesiredConfig.VRFs {
			if vrf.VRFRef == nil {
				continue
			}
			desiredSvcPaths, err := r.getDesiredPaths(p, toReconcile, vrf, desiredVRFAdverts, rx)
			if err != nil {
				return err
			}
			// check for services which are no longer present
			for serviceKey := range metadata.vrfPaths[*vrf.VRFRef] {
				// if the service no longer exists, withdraw it
				if _, exists := desiredSvcPaths[serviceKey]; !exists {
					desiredSvcPaths[serviceKey] = nil
				}
			}
			desiredVRFPaths[*vrf.VRFRef] = desiredSvcPaths
		}
	} else {
		r.logger.Debug("performing modified services reconciliation")

		// BGP configuration is unchanged, only reconcile modified services.
		toReconcile, rx, err := r.diffReconciliationServiceList(metadata) // note: can be called only once per reconcile
		if err != nil {
			return err
		}
		for _, vrf := range p.DesiredConfig.VRFs {
			if vrf.VRFRef == nil {
				continue
			}
			updatedSvcPaths, err := r.getDesiredPaths(p, toReconcile, vrf, desiredVRFAdverts, rx)
			if err != nil {
				return err
			}

			// We need to only update modified services in the VRF. If VRF does not exist
			// in metadata, we just create a new entry with updatedSvcPaths. Otherwise,
			// we need to only touch services which are modified.

			// check if vrf is present
			currentSvcPaths, exists := metadata.vrfPaths[*vrf.VRFRef]
			if !exists {
				desiredVRFPaths[*vrf.VRFRef] = updatedSvcPaths
				continue
			}

			// update modified services
			desiredSvcPaths := make(ossReconciler.ResourceAFPathsMap)
			maps.Copy(desiredSvcPaths, currentSvcPaths)

			// override only modified services
			maps.Copy(desiredSvcPaths, updatedSvcPaths)
			desiredVRFPaths[*vrf.VRFRef] = desiredSvcPaths
		}
	}

	return ReconcileVRFPaths(ReconcileVRFPathsParams{
		Logger:       r.logger,
		Ctx:          ctx,
		BGPInstance:  p.BGPInstance,
		CurrentPaths: metadata.vrfPaths,
		DesiredPaths: desiredVRFPaths,
	})
}

func (r *ServiceVRFReconciler) fullReconciliationServiceList(metadata *ServiceVRFReconcilerMetadata) (toReconcile []*loadbalancer.Service, rx statedb.ReadTxn, err error) {
	// re-init changes interator, so that it contains changes since the last full reconciliation
	tx := r.db.WriteTxn(r.frontends)
	metadata.frontendChanges, err = r.frontends.Changes(tx)
	if err != nil {
		tx.Abort()
		return nil, nil, fmt.Errorf("error subscribing to frontends changes: %w", err)
	}
	rx = tx.Commit()
	metadata.frontendChangesInitialized = true

	// the initial set of changes emits all existing frontends
	events, _ := metadata.frontendChanges.Next(rx)

	svcMap := make(map[loadbalancer.ServiceName]*loadbalancer.Service)
	for frontendEvent := range events {
		frontend := frontendEvent.Object
		svcMap[frontend.Service.Name] = frontend.Service
	}

	toReconcile = slices.Collect(maps.Values(svcMap))
	return
}

func (r *ServiceVRFReconciler) diffReconciliationServiceList(metadata *ServiceVRFReconcilerMetadata) (toReconcile []*loadbalancer.Service, rx statedb.ReadTxn, err error) {
	rx = r.db.ReadTxn()

	// list frontends which changed since the last reconciliation (includes frontends with just backend changed)
	if !metadata.frontendChangesInitialized {
		return nil, rx, fmt.Errorf("BUG: frontend changes tracker not initialized, cannot perform diff reconciliation")
	}
	events, _ := metadata.frontendChanges.Next(rx)

	svcMap := make(map[loadbalancer.ServiceName]*loadbalancer.Service)
	for frontendEvent := range events {
		frontend := frontendEvent.Object
		// even if the frontend was deleted, we still don't know whether whole service was deleted,
		// so we need to perform its reconciliation instead of just withdrawal
		svcMap[frontend.Service.Name] = frontend.Service
	}
	toReconcile = slices.Collect(maps.Values(svcMap))
	return
}

func (r *ServiceVRFReconciler) getDesiredPaths(p EnterpriseReconcileParams, toReconcile []*loadbalancer.Service, bgpVRF v1.IsovalentBGPNodeVRF, desiredVRFAdverts VRFAdvertisements, rx statedb.ReadTxn) (ossReconciler.ResourceAFPathsMap, error) {
	desiredServiceAFPaths := make(ossReconciler.ResourceAFPathsMap)
	for _, svc := range toReconcile {
		svcKey := resource.Key{Name: svc.Name.Name(), Namespace: svc.Name.Namespace()}

		afPaths, err := r.getServiceAFPaths(p, svc, bgpVRF, desiredVRFAdverts, rx)
		if err != nil {
			return nil, err
		}
		desiredServiceAFPaths[svcKey] = afPaths
	}

	return desiredServiceAFPaths, nil
}

func (r *ServiceVRFReconciler) getServiceAFPaths(p EnterpriseReconcileParams, svc *loadbalancer.Service, bgpVRF v1.IsovalentBGPNodeVRF, desiredVRFAdverts VRFAdvertisements, rx statedb.ReadTxn) (ossReconciler.AFPathsMap, error) {
	desiredFamilyPaths := make(ossReconciler.AFPathsMap)
	if bgpVRF.VRFRef == nil {
		return desiredFamilyPaths, nil
	}

	vrfFamilyAdvertisements, exists := desiredVRFAdverts[*bgpVRF.VRFRef]
	if !exists {
		// no advertisement found for this VRF, nothing to do.
		return nil, nil
	}

	for family, familyAdverts := range vrfFamilyAdvertisements {
		agentFamily := types.ToAgentFamily(family)

		for _, advert := range familyAdverts {
			// get prefixes for the service
			desiredPrefixes, err := r.getServicePrefixes(p, svc, advert, rx)
			if err != nil {
				return nil, err
			}

			for _, prefix := range desiredPrefixes {
				path, pathKey, err := r.srv6Paths.GetSRv6VPNPath(prefix, bgpVRF)
				if err != nil {
					return nil, err
				}
				path.Family = agentFamily

				// we only support ipv4/mpls_vpn address family
				if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
					ossReconciler.AddPathToAFPathsMap(desiredFamilyPaths, agentFamily, path, pathKey)
				}
			}
		}
	}
	return desiredFamilyPaths, nil
}

// configModified checks if any of the following configurations have modified
// BGP advertisements, BGP VRF configurations, SID info for VRFs
func (r *ServiceVRFReconciler) configModified(p EnterpriseReconcileParams, metadata *ServiceVRFReconcilerMetadata, desiredVRFAdverts VRFAdvertisements, desiredVRFSIDInfo VRFSIDInfo) bool {
	return !VRFAdvertisementsEqual(metadata.vrfAdverts, desiredVRFAdverts) ||
		!r.vrfConfigsEqual(metadata.vrfConfigs, p.DesiredConfig.VRFs) ||
		!r.vrfSIDInfoEqual(metadata.vrfSIDs, desiredVRFSIDInfo)
}

func (r *ServiceVRFReconciler) vrfConfigsEqual(firstVRFs, secondVRFs []v1.IsovalentBGPNodeVRF) bool {
	if len(firstVRFs) != len(secondVRFs) {
		return false
	}

	for _, firstVRF := range firstVRFs {
		found := false
		for _, secondVRF := range secondVRFs {
			if firstVRF.VRFRef == secondVRF.VRFRef {
				found = true
				if !firstVRF.DeepEqual(&secondVRF) {
					return false
				}
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (r *ServiceVRFReconciler) vrfSIDInfoEqual(firstVRFs, secondVRFs VRFSIDInfo) bool {
	if len(firstVRFs) != len(secondVRFs) {
		return false
	}

	for vrf, firstSIDInfo := range firstVRFs {
		secondSIDInfo, exists := secondVRFs[vrf]
		if !exists {
			return false
		}

		if !firstSIDInfo.SIDAndBehaviorEqual(secondSIDInfo) {
			return false
		}
	}

	return true
}

func (r *ServiceVRFReconciler) getServicePrefixes(p EnterpriseReconcileParams, svc *loadbalancer.Service, advert v1.BGPAdvertisement, rx statedb.ReadTxn) ([]netip.Prefix, error) {
	if advert.AdvertisementType != v1.BGPServiceAdvert {
		return nil, fmt.Errorf("BUG: unexpected advertisement type: %s", advert.AdvertisementType)
	}

	if advert.Selector == nil || advert.Service == nil {
		// advertisement has no selector or no service options, default behavior is not to match any service.
		return nil, nil
	}

	// Ignore non matching services.
	svcSelector, err := slimmetav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}
	if !svcSelector.Matches(svcLabelSet(svc)) {
		return nil, nil
	}

	// Lookup service frontends
	frontends := slices.Collect(statedb.ToSeq(r.frontends.List(rx, loadbalancer.FrontendByServiceName(svc.Name))))

	var desiredRoutes []netip.Prefix
	// Loop over the service upsertAdverts and determine the desired routes.
	for _, svcAdv := range advert.Service.Addresses {
		if svcAdv == v2.BGPLoadBalancerIPAddr {
			desiredRoutes = append(desiredRoutes, r.getETPLocalLBSvcPaths(p, svc, frontends)...)
		}
	}

	return desiredRoutes, nil
}

func (r *ServiceVRFReconciler) getETPLocalLBSvcPaths(p EnterpriseReconcileParams, svc *loadbalancer.Service, frontends []*loadbalancer.Frontend) []netip.Prefix {
	desiredPrefixes := sets.New[netip.Prefix]()

	// Ignore service managed by an unsupported LB class.
	if svc.LoadBalancerClass != nil && *svc.LoadBalancerClass != v2.BGPLoadBalancerClass {
		return nil
	}

	// Ignore externalTrafficPolicy other than local. Current SRv6 datapath does not support eTP cluster.
	if svc.ExtTrafficPolicy != loadbalancer.SVCTrafficPolicyLocal {
		return nil
	}

	for _, fe := range frontends {
		if fe.Type != loadbalancer.SVCTypeLoadBalancer {
			continue
		}
		// Ignore if there is no local EPs.
		if _, hasLocalBackends := hasBackends(p, fe); !hasLocalBackends {
			continue
		}
		addr := fe.Address.Addr()
		desiredPrefixes.Insert(netip.PrefixFrom(addr, addr.BitLen()))
	}

	return desiredPrefixes.UnsortedList()
}

func (r *ServiceVRFReconciler) getConfiguredSIDInfo(bgpConfig *v1.IsovalentBGPNodeInstance) (VRFSIDInfo, error) {
	desiredVRFSIDInfo := make(VRFSIDInfo)
	for _, bgpVRF := range bgpConfig.VRFs {
		if bgpVRF.VRFRef == nil {
			continue
		}
		vrfInfo, exists := r.srv6Manager.GetVRFByName(k8stypes.NamespacedName{Name: *bgpVRF.VRFRef})
		if !exists {
			r.logger.Debug("VRF not found in SRv6 Manager", entTypes.VRFLogField, bgpVRF.VRFRef)
			continue
		}
		desiredVRFSIDInfo[*bgpVRF.VRFRef] = vrfInfo.SIDInfo
	}
	return desiredVRFSIDInfo, nil
}

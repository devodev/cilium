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
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	ossReconciler "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/container/bitlpm"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type importVPNRouteReconcilerOut struct {
	cell.Out

	EnterpriseReconciler EnterpriseStateReconciler     `group:"enterprise-bgp-state-reconciler"`
	Reconciler           ossReconciler.StateReconciler `group:"bgp-state-reconciler"`
}

func newImportVPNRouteStateReconciler(
	logger *slog.Logger,
	config config.Config,
	enterpriseConfig Config,
	daemonConfig *option.DaemonConfig,
	reconciler *importVPNRouteReconciler,
	legacyReconciler *legacyImportVPNRouteReconciler,
	upgrader paramUpgrader,
) importVPNRouteReconcilerOut {
	if !config.Enabled || !daemonConfig.EnableSRv6 {
		return importVPNRouteReconcilerOut{}
	}
	if enterpriseConfig.EnableLegacySRv6Responder {
		logger.Info("Using legacy SRv6 Import VPN Route Reconciler")
		return importVPNRouteReconcilerOut{
			EnterpriseReconciler: legacyReconciler,
			Reconciler:           newOSSStateReconcilerAdapter(legacyReconciler, upgrader),
		}
	}
	return importVPNRouteReconcilerOut{
		EnterpriseReconciler: reconciler,
		Reconciler:           newOSSStateReconcilerAdapter(reconciler, upgrader),
	}
}

type importVPNRouteReconciler struct {
	logger      *slog.Logger
	rib         *rib.RIB
	vrfStore    resource.Store[*v1alpha1.IsovalentVRF]
	initialized atomic.Bool
}

type importVPNRouteReconcilerIn struct {
	cell.In

	Config           config.Config
	EnterpriseConfig Config
	DaemonConfig     *option.DaemonConfig
	JobGroup         job.Group
	Logger           *slog.Logger
	RIB              *rib.RIB
	VRFResource      resource.Resource[*v1alpha1.IsovalentVRF]
}

func newImportVPNRouteReconciler(in importVPNRouteReconcilerIn) *importVPNRouteReconciler {
	if !in.Config.Enabled || !in.DaemonConfig.EnableSRv6 || in.EnterpriseConfig.EnableLegacySRv6Responder {
		return nil
	}

	r := &importVPNRouteReconciler{
		logger: in.Logger.With(types.ReconcilerLogField, "ImportVPNRoute"),
		rib:    in.RIB,
	}

	in.JobGroup.Add(job.OneShot("init", func(ctx context.Context, health cell.Health) error {
		vrfStore, err := in.VRFResource.Store(ctx)
		if err != nil {
			return fmt.Errorf("failed to create VRF store: %w", err)
		}
		r.vrfStore = vrfStore
		r.initialized.Store(true)
		return nil
	}))

	return r
}

func (r *importVPNRouteReconciler) Name() string {
	return ImportedVPNRouteReconcilerName
}

func (r *importVPNRouteReconciler) Priority() int {
	return ImportedVPNRouteReconcilerPriority
}

func (r *importVPNRouteReconciler) Reconcile(ctx context.Context, p EnterpriseStateReconcileParams) error {
	if !r.initialized.Load() {
		return fmt.Errorf("init job is not yet done")
	}

	// Clear all RIB entries inserted by the deleted instance
	if p.DeletedInstance != "" {
		owner := ribOwnerName(p.DeletedInstance)
		r.rib.DeleteRoutesByOwner(owner)
		return nil
	}

	res, err := p.UpdatedInstance.Router.GetRoutes(
		ctx,
		&types.GetRoutesRequest{
			TableType: types.TableTypeLocRIB,
			Family: types.Family{
				Afi:  types.AfiIPv4,
				Safi: types.SafiMplsVpn,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to get BGP routes: %w", err)
	}

	config := p.UpdatedInstance.Config

	owner := ribOwnerName(config.Name)

	// Obtain the desired routes from BGP RIB
	desiredRoutes, err := r.desiredRoutes(
		owner,
		uint32(*config.LocalASN),
		res.Routes,
		config.VRFs,
	)
	if err != nil {
		return fmt.Errorf("failed to get desired routes: %w", err)
	}

	// Obtain the current routes from the Cilium RIB
	currentRoutes := r.rib.ListRoutes(owner)

	// Reconcile Cilium RIB
	reconcileRIB(r.rib, desiredRoutes, currentRoutes)

	return nil
}

func (r *importVPNRouteReconciler) desiredRoutes(
	owner string,
	localASN uint32,
	bgpRoutes []*types.Route,
	bgpVRFs []v1.IsovalentBGPNodeVRF,
) (map[uint32]*bitlpm.CIDRTrie[*rib.Route], error) {
	// First parse the BGP routes to extract prefix + SID and Route Targets
	vpnPaths, err := r.parseVPNRoutes(bgpRoutes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VPN paths: %w", err)
	}

	// Populate the VRF Name => VRF ID mapping
	vrfIDs := map[string]uint32{}
	for _, vrfr := range r.vrfStore.List() {
		vrfIDs[vrfr.Name] = vrfr.Spec.VRFID
	}

	// Map VRF ID to the list of routes
	desiredRoutes := map[uint32]*bitlpm.CIDRTrie[*rib.Route]{}
	for _, vrf := range bgpVRFs {
		if vrf.VRFRef == nil {
			continue
		}
		vrfID, ok := vrfIDs[*vrf.VRFRef]
		if !ok {
			continue
		}
		routes := bitlpm.NewCIDRTrie[*rib.Route]()
		for _, vpnPath := range vpnPaths {
			if !rtMatches(vpnPath.rts, vrf.ImportRTs) {
				continue
			}
			proto := rib.ProtocolIBGP
			if vpnPath.sourceASN != localASN {
				proto = rib.ProtocolEBGP
			}
			routes.Upsert(vpnPath.prefix, &rib.Route{
				Prefix:   vpnPath.prefix,
				Owner:    owner,
				Protocol: proto,
				NextHop: &rib.HEncaps{
					Segments: []srv6Types.SID{vpnPath.sid},
				},
			})
		}
		if routes.Len() > 0 {
			desiredRoutes[vrfID] = routes
		}
	}

	return desiredRoutes, nil
}

type vpnPath struct {
	prefix    netip.Prefix
	sid       srv6Types.SID
	rts       []string
	sourceASN uint32
}

func (r *importVPNRouteReconciler) parseVPNRoutes(routes []*types.Route) ([]*vpnPath, error) {
	paths := []*vpnPath{}

	for _, route := range routes {
		for _, path := range route.Paths {
			if !path.Best {
				// Ignore non-best paths
				continue
			}

			path, err := r.parseVPNPath(path)
			if err != nil {
				if !errors.Is(err, errSelfOriginatedRoute) {
					// Self-originated route is pretty
					// common, so don't need to log it.
					// Maybe it's worth logging others for
					// debugging purposes.
					r.logger.Debug("Cannot parse VPN path", logfields.Reason, err.Error())
				}
				continue
			}

			// There's only one best path. GoBGP's RIB doesn't have
			// a concept of ECMP as of today. It does support ECMP
			// with Zebra, but what they do is lazily calculate
			// ECMP paths when they notify the best path watchers
			// (that watche best paths with Watch API) and they
			// don't keep that information in the RIB. We're not
			// using Watch API, so we cannot see ECMP.
			//
			// https://github.com/osrg/gobgp/blob/f733438a965b33813b23200ea10adfa1939f5a36/pkg/server/server.go#L1392-L1395
			//
			// Also, our dataplane cannot handle it, so we anyways
			// should break here. Once we migrate to the
			// GoBGP-Watcher-based implementation and add support
			// in the datapath, we can get rid of this problem.
			paths = append(paths, path)
			break
		}
	}

	return paths, nil
}

var (
	errMoreThanOneLabel = errors.New("more than one label in the NLRI")
)

func (r *importVPNRouteReconciler) parseMPReachNLRI(p *bgp.PathAttributeMpReachNLRI) (netip.Prefix, uint32, error) {
	// GoBGP creates one Path per NLRI when it stores routes to the RIB,
	// even if the MP-Reach-NLRI attribute contains multiple NLRIs. So, we
	// should have only one NLRI. Here we do sanity check and skip the path
	// if there's more than one NLRI.
	//
	// https://github.com/osrg/gobgp/blob/f733438a965b33813b23200ea10adfa1939f5a36/internal/pkg/table/table_manager.go#L93-L107
	if len(p.Value) != 1 {
		return netip.Prefix{}, 0, errUnexpectedNumberOfNLRI
	}

	// Skip if not VPNv4
	if p.AFI != bgp.AFI_IP {
		return netip.Prefix{}, 0, errUnexpectedAFI
	}
	if p.SAFI != bgp.SAFI_MPLS_VPN {
		return netip.Prefix{}, 0, errUnexpectedSAFI
	}

	// FIXME: Skip self-originated routes. We determine this by checking if
	// the NextHop in the MP-Reach-NLRI attribute is zero address. This is
	// not a proper way to do this. This depends on the fact that our
	// reconciler set the NextHop to zero address when it creates the
	// route. We should fix this by exposing route origin information of
	// GoBGP Path to our agent Path struct.
	if p.Nexthop.IsUnspecified() {
		return netip.Prefix{}, 0, errSelfOriginatedRoute
	}

	// It is safe to deref Value[0] here because we already checked the
	// length of mpReachNLRIAttr.Value above.
	prefix, ok := p.Value[0].NLRI.(*bgp.LabeledVPNIPAddrPrefix)
	if !ok {
		// AFI/SAFI and type is mismatched. This is maybe a GoBGP's bug.
		return netip.Prefix{}, 0, fmt.Errorf("type mismatch between AFI/SAFI and NLRI type")
	}

	// Zero label is ok as it may implies SRv6 route without transposition
	// encoding. If there are more than one label, it is invalid SRv6 route
	// because transposing the Transposition Length MUST be less than or
	// equal to 20 which is a length of the single label (RFC9252 Sec 5.1).
	if len(prefix.Labels.Labels) > 1 {
		return netip.Prefix{}, 0, errMoreThanOneLabel
	}

	// It is possible that the label is holding the part of the SID.
	// This called "transposition encoding" (RFC9252 Sec 5.1).
	label := uint32(0)
	if len(prefix.Labels.Labels) == 1 {
		label = prefix.Labels.Labels[0]
	}

	return netip.PrefixFrom(prefix.Prefix.Addr(), int(prefix.IPPrefixLen())), label, nil
}

func (r *importVPNRouteReconciler) parsePrefixSID(p *bgp.PathAttributePrefixSID) ([]byte, uint8, uint8, error) {
	var l3Srv *bgp.SRv6ServiceTLV
	for _, tlv := range p.TLVs {
		v, ok := tlv.(*bgp.SRv6ServiceTLV)
		if ok {
			l3Srv = v
			break
		}
	}
	if l3Srv == nil {
		return nil, 0, 0, fmt.Errorf("missing SRv6 L3 Service TLV")
	}

	// First extract SRv6 SID Information Sub-TLV (RFC9252 Sec 3.1) to
	// obtain destination SID.
	//
	// We will only utilize the first SID Info Sub-TLV because, RFC9252 Sec
	// 3.1 says, when multiple SRv6 SID Information Sub-TLVs are present,
	// the ingress PE SHOULD use the SRv6 SID from the first instance of
	// the Sub-TLV.
	var info *bgp.SRv6InformationSubTLV
	for _, subtlv := range l3Srv.SubTLVs {
		v, ok := subtlv.(*bgp.SRv6InformationSubTLV)
		if ok {
			info = v
			break
		}
	}
	if info == nil {
		return nil, 0, 0, fmt.Errorf("missing SRv6 Information Sub-TLV")
	}

	// Extract SID Structure Sub-Sub-TLV. Use the first one as well.
	var sidStructure *bgp.SRv6SIDStructureSubSubTLV
	for _, subsubtlv := range info.SubSubTLVs {
		v, ok := subsubtlv.(*bgp.SRv6SIDStructureSubSubTLV)
		if ok {
			sidStructure = v
			break
		}
	}
	if sidStructure == nil {
		return nil, 0, 0, fmt.Errorf("missing SRv6 SID Structure Sub-Sub-TLV")
	}

	return info.SID, sidStructure.TranspositionOffset, sidStructure.TranspositionLength, nil
}

func (r *importVPNRouteReconciler) parseExtendedCommunity(p *bgp.PathAttributeExtendedCommunities) ([]string, error) {
	rts := []string{}

	for _, val := range p.Value {
		switch v := val.(type) {
		case *bgp.FourOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				rts = append(rts, fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin))
			}
		case *bgp.TwoOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				rts = append(rts, fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin))
			}
		}
	}

	if len(rts) == 0 {
		return nil, fmt.Errorf("missing route target")
	}

	return rts, nil
}

func (r *importVPNRouteReconciler) parseVPNPath(path *types.Path) (*vpnPath, error) {
	var (
		mpReachNLRIAttr    *bgp.PathAttributeMpReachNLRI
		prefixSIDAttr      *bgp.PathAttributePrefixSID
		extCommunitiesAttr *bgp.PathAttributeExtendedCommunities
	)

	for _, attr := range path.PathAttributes {
		switch v := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			mpReachNLRIAttr = v
		case *bgp.PathAttributePrefixSID:
			prefixSIDAttr = v
		case *bgp.PathAttributeExtendedCommunities:
			extCommunitiesAttr = v
		}
	}

	if mpReachNLRIAttr == nil {
		return nil, fmt.Errorf("missing MP-Reach-NLRI attribute")
	}

	if prefixSIDAttr == nil {
		return nil, fmt.Errorf("missing Prefix-SID attribute")
	}

	if extCommunitiesAttr == nil {
		return nil, fmt.Errorf("missing Extended-Community attribute")
	}

	prefix, label, err := r.parseMPReachNLRI(mpReachNLRIAttr)
	if err != nil {
		return nil, err
	}

	transSID, transOfs, transLen, err := r.parsePrefixSID(prefixSIDAttr)
	if err != nil {
		return nil, err
	}

	rts, err := r.parseExtendedCommunity(extCommunitiesAttr)
	if err != nil {
		return nil, err
	}

	sid, err := srv6Types.NewSIDFromTransposed(
		transSID,
		label,
		transOfs,
		transLen,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transposed SID: %w", err)
	}

	return &vpnPath{
		prefix:    prefix,
		sid:       sid,
		rts:       rts,
		sourceASN: path.SourceASN,
	}, nil
}

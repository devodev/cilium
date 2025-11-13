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
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// AdminDistance must be farer than default AD (100) to avoid
	// overriding Cilium-managed routes. iBGP routes must have higher AD
	// than eBGP routes (this aligns with the conventional routers).
	AdminDistanceIBGP = routeReconciler.AdminDistance(200)
	AdminDistanceEBGP = routeReconciler.AdminDistance(150)
)

type importRouteReconcilerOut struct {
	cell.Out

	Reconciler reconciler.StateReconciler `group:"bgp-state-reconciler"`
}

type importRouteReconcilerIn struct {
	cell.In

	Logger              *slog.Logger
	Config              config.Config
	EnterpriseConfig    Config
	Upgrader            paramUpgrader
	DB                  *statedb.DB
	DesiredRouteManager *routeReconciler.DesiredRouteManager
	DesiredRouteTable   statedb.Table[*routeReconciler.DesiredRoute]
	DeviceTable         statedb.Table[*tables.Device]
	ErrorPathStore      *ErrorPathStore
}

type importRouteReconciler struct {
	logger            *slog.Logger
	upgrader          paramUpgrader
	drm               *routeReconciler.DesiredRouteManager
	db                *statedb.DB
	desiredRoutetable statedb.Table[*routeReconciler.DesiredRoute]
	deviceTable       statedb.Table[*tables.Device]
	errorPathStore    *ErrorPathStore
}

func newImportRouteReconciler(in importRouteReconcilerIn) importRouteReconcilerOut {
	if !in.Config.Enabled || !in.EnterpriseConfig.RouteImportEnabled {
		return importRouteReconcilerOut{}
	}
	return importRouteReconcilerOut{
		Reconciler: &importRouteReconciler{
			logger:            in.Logger,
			upgrader:          in.Upgrader,
			drm:               in.DesiredRouteManager,
			db:                in.DB,
			desiredRoutetable: in.DesiredRouteTable,
			deviceTable:       in.DeviceTable,
			errorPathStore:    in.ErrorPathStore,
		},
	}
}

func (r *importRouteReconciler) Name() string {
	return ImportRouteReconcilerName
}

func (r *importRouteReconciler) Priority() int {
	return ImportRouteReconcilerPriority
}

func (r *importRouteReconciler) Reconcile(ctx context.Context, _p reconciler.StateReconcileParams) error {
	p, err := r.upgrader.upgradeState(_p)
	if err != nil {
		if errors.Is(err, ErrEntNodeConfigNotFound) {
			r.logger.Debug("Enterprise node config not found yet, skipping reconciliation")
			return nil
		}
		if errors.Is(err, ErrNotInitialized) {
			r.logger.Debug("Initialization is not done, skipping reconciliation")
			return nil
		}
		if errors.Is(err, ErrUpdateConfigNotSet) {
			r.logger.Debug("Instance config not yet set, skipping reconciliation")
			return nil
		}
		return err
	}

	// Clear all desired route entries inserted by the deleted instance.
	// Also remove all routes when the instance becomes a part of the route
	// reflector cluster. Route importing with RR is not supported yet.
	if p.DeletedInstance != "" || (p.DesiredConfig != nil && p.DesiredConfig.RouteReflector != nil) {
		instanceName := p.DeletedInstance
		if p.DeletedInstance == "" {
			instanceName = p.UpdatedInstance.Name
		}
		r.errorPathStore.Delete(instanceName, ossTypes.Family{
			Afi:  ossTypes.AfiIPv4,
			Safi: ossTypes.SafiUnicast,
		})
		r.errorPathStore.Delete(instanceName, ossTypes.Family{
			Afi:  ossTypes.AfiIPv6,
			Safi: ossTypes.SafiUnicast,
		})
		owner, err := r.drm.GetOwner(r.ownerName(instanceName))
		if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
			return nil
		}
		return r.drm.RemoveOwner(owner)
	}

	owner, err := r.drm.GetOrRegisterOwner(r.ownerName(p.UpdatedInstance.Name))
	if err != nil {
		return err
	}

	desiredDsts, v4ErrPaths, v6ErrPaths, err := r.desiredDestinations(ctx, p.UpdatedInstance.Router)
	if err != nil {
		return err
	}

	r.errorPathStore.Update(
		p.UpdatedInstance.Name,
		ossTypes.Family{
			Afi:  ossTypes.AfiIPv4,
			Safi: ossTypes.SafiUnicast,
		},
		v4ErrPaths,
	)
	r.errorPathStore.Update(
		p.UpdatedInstance.Name,
		ossTypes.Family{
			Afi:  ossTypes.AfiIPv6,
			Safi: ossTypes.SafiUnicast,
		},
		v6ErrPaths,
	)

	rtxn := r.db.ReadTxn()

	currentDsts, err := r.currentDestinations(rtxn, owner)
	if err != nil {
		return err
	}

	toUpsert, toDelete := r.calculateDiff(desiredDsts, currentDsts)

	return r.reconcileDesiredRoutes(rtxn, owner, toUpsert, toDelete)
}

type destination struct {
	prefix netip.Prefix
	paths  []*path
	isIBGP bool
}

func (dst *destination) sortPaths() {
	slices.SortFunc(dst.paths, func(a, b *path) int {
		return a.nexthop.Compare(b.nexthop)
	})
}

func (dst *destination) equal(other *destination) bool {
	if dst.prefix != other.prefix {
		return false
	}
	if dst.isIBGP != other.isIBGP {
		return false
	}
	if len(dst.paths) != len(other.paths) {
		return false
	}
	for i := range dst.paths {
		if dst.paths[i].nexthop != other.paths[i].nexthop {
			return false
		}
	}
	return true
}

type path struct {
	nexthop netip.Addr
}

func (r *importRouteReconciler) desiredDestinations(ctx context.Context, router types.EnterpriseRouter) (
	map[netip.Prefix]*destination,
	map[ErrorPathKey]ErrorPath,
	map[ErrorPathKey]ErrorPath,
	error,
) {
	global, err := router.GetBGP(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	resv4, err := router.GetRoutesExtended(ctx, &types.GetRoutesExtendedRequest{
		GetRoutesRequest: ossTypes.GetRoutesRequest{
			TableType: ossTypes.TableTypeLocRIB,
			Family: ossTypes.Family{
				Afi:  ossTypes.AfiIPv4,
				Safi: ossTypes.SafiUnicast,
			},
		},
	})
	if err != nil {
		r.logger.Error("Error getting IPv4 routes", logfields.Error, err)
		return nil, nil, nil, err
	}

	v4Dsts, v4ErrPaths := r.parseRoutes(resv4.Routes, true, global.Global.ASN)

	resv6, err := router.GetRoutesExtended(ctx, &types.GetRoutesExtendedRequest{
		GetRoutesRequest: ossTypes.GetRoutesRequest{
			TableType: ossTypes.TableTypeLocRIB,
			Family: ossTypes.Family{
				Afi:  ossTypes.AfiIPv6,
				Safi: ossTypes.SafiUnicast,
			},
		},
	})
	if err != nil {
		r.logger.Error("Error getting IPv6 routes", logfields.Error, err)
		return nil, nil, nil, err
	}

	v6Dsts, v6ErrPaths := r.parseRoutes(resv6.Routes, false, global.Global.ASN)

	maps.Copy(v4Dsts, v6Dsts)

	return v4Dsts, v4ErrPaths, v6ErrPaths, nil
}

func (r *importRouteReconciler) parseRoutes(routes []*types.ExtendedRoute, isV4 bool, selfASN uint32) (map[netip.Prefix]*destination, map[ErrorPathKey]ErrorPath) {
	dsts := map[netip.Prefix]*destination{}
	errPaths := map[ErrorPathKey]ErrorPath{}

	for _, route := range routes {
		bestPaths := []*types.ExtendedPath{}
		for _, p := range route.Paths {
			if !p.Best {
				continue
			}
			bestPaths = append(bestPaths, p)
		}

		if len(bestPaths) == 0 {
			continue
		}

		p, err := netip.ParsePrefix(route.Prefix)
		if err != nil {
			// This is not really possible since the route is
			// already in the BGP RIB, but we record the error just
			// in case (e.g. GoBGP's bug).
			for _, path := range route.Paths {
				k := ErrorPathKeyFromPath(path)
				errPaths[k] = ErrorPath{
					ErrorPathKey: k,
					Error:        errMalformedPath,
				}
			}
			continue
		}

		dst := &destination{
			prefix: p,
			// All best paths should have a same protocol (eBGP
			// beats iBGP in the best path selection), so we can
			// check the first one to determine if it's iBGP or
			// eBGP.
			isIBGP: bestPaths[0].SourceASN == selfASN,
		}

		for _, bestPath := range bestPaths {
			var parsed *path

			if isV4 {
				parsed, err = r.parseV4Path(bestPath)
			} else {
				parsed, err = r.parseV6Path(bestPath)
			}

			if errors.Is(err, errSelfOriginatedRoute) {
				// Skip self-originated routes
				continue
			}

			if err != nil {
				k := ErrorPathKeyFromPath(bestPath)
				errPaths[k] = ErrorPath{
					ErrorPathKey: k,
					Error:        err,
				}
				continue
			}

			dst.paths = append(dst.paths, parsed)
		}

		if len(dst.paths) == 0 {
			// No valid paths for this route, skip it.
			continue
		}

		// Sort paths to have a deterministic order
		dst.sortPaths()

		dsts[dst.prefix] = dst
	}

	return dsts, errPaths
}

func (r *importRouteReconciler) parseV4Path(p *types.ExtendedPath) (*path, error) {
	// For IPv4, we have two possible nexthopAttr encodings. One is the legacy
	// IPv4 NEXT_HOP attribute, and the other is the MP_REACH_NLRI
	// attribute. We need to handle both cases.
	var (
		nexthopAttr     *bgp.PathAttributeNextHop
		mpReachNLRIAttr *bgp.PathAttributeMpReachNLRI
	)

	for _, attr := range p.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			nexthopAttr = a
		case *bgp.PathAttributeMpReachNLRI:
			mpReachNLRIAttr = a
		}
	}

	if nexthopAttr == nil && mpReachNLRIAttr == nil {
		return nil, errMalformedPath
	}

	var (
		err     error
		nexthop netip.Addr
	)
	if mpReachNLRIAttr != nil {
		// Whenever MP_REACH_NLRI is present, it takes precedence over
		// the legacy NEXT_HOP attribute.
		nexthop, err = r.parseMPReachNLRINexthop(mpReachNLRIAttr, p.NeighborAddr)
		if err != nil {
			return nil, err
		}
	} else {
		nexthop = nexthopAttr.Value
		if !nexthop.IsValid() {
			return nil, errMalformedNexthop
		}
		if !nexthop.Is4() {
			return nil, errUnsupportedNexthop
		}
		if nexthop == netip.IPv4Unspecified() {
			return nil, errSelfOriginatedRoute
		}
	}

	return &path{
		nexthop: nexthop,
	}, nil
}

func (r *importRouteReconciler) parseV6Path(p *types.ExtendedPath) (*path, error) {
	// For IPv6, we only expect the MP_REACH_NLRI attribute to be present.
	var mpReachNLRIAttr *bgp.PathAttributeMpReachNLRI

	for _, attr := range p.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			mpReachNLRIAttr = a
		}
	}

	if mpReachNLRIAttr == nil {
		return nil, errMalformedPath
	}

	nexthop, err := r.parseMPReachNLRINexthop(mpReachNLRIAttr, p.NeighborAddr)
	if err != nil {
		return nil, err
	}

	// Non-IPv6 nexthop in IPv6 route is not supported.
	if !nexthop.Is6() {
		return nil, errUnsupportedNexthop
	}

	return &path{
		nexthop: nexthop,
	}, nil
}

func (r *importRouteReconciler) parseMPReachNLRINexthop(mpReachNLRIAttr *bgp.PathAttributeMpReachNLRI, neighborAddr netip.Addr) (netip.Addr, error) {
	var (
		linkLocalNexthop netip.Addr
		globalNexthop    netip.Addr
	)

	if mpReachNLRIAttr.LinkLocalNexthop.IsValid() {
		nh := mpReachNLRIAttr.LinkLocalNexthop
		if !nh.IsValid() {
			return netip.Addr{}, errMalformedNexthop
		}
		if !nh.IsLinkLocalUnicast() {
			return netip.Addr{}, errMalformedNexthop
		}
		linkLocalNexthop = nh
	}

	if mpReachNLRIAttr.Nexthop.IsValid() {
		nh := mpReachNLRIAttr.Nexthop
		if !nh.IsValid() {
			return netip.Addr{}, errMalformedNexthop
		}
		globalNexthop = nh // This can be link-local (possible with BGP Unnumbered) or global
	}

	if !linkLocalNexthop.IsValid() && globalNexthop.IsUnspecified() {
		return netip.Addr{}, errSelfOriginatedRoute
	}

	switch {
	case linkLocalNexthop.IsValid() && linkLocalNexthop.Is6() && neighborAddr.Zone() != "":
		// IPv6 link-local nexthop present and we can derive the
		// interface from the neighbor address zone. Use it. This
		// covers BGP Unnumbered ::/LL and LL/LL encodings.
		return linkLocalNexthop.WithZone(neighborAddr.Zone()), nil
	case globalNexthop.IsValid() && globalNexthop.Is6() && globalNexthop.IsLinkLocalUnicast() && neighborAddr.Zone() != "":
		// IPv6 global nexthop is link-local address and we can derive
		// the interface from the neighbor address zone. Use it. This
		// covers BGP Unnumbered LL encoding.
		return globalNexthop.WithZone(neighborAddr.Zone()), nil
	case globalNexthop.IsValid() && !globalNexthop.IsUnspecified() && !globalNexthop.IsLinkLocalUnicast():
		// The true global nexthop case.
		return globalNexthop, nil
	default:
		// We cannot support any other cases.
		return netip.Addr{}, errUnsupportedNexthop
	}
}

func (r *importRouteReconciler) currentDestinations(rtxn statedb.ReadTxn, owner *routeReconciler.RouteOwner) (map[netip.Prefix]*destination, error) {
	dsts := map[netip.Prefix]*destination{}

	// List all routes owned by this BGP instance
	for rt := range r.desiredRoutetable.Prefix(rtxn, routeReconciler.DesiredRouteIndex.Query(routeReconciler.DesiredRouteKey{Owner: owner})) {
		if rt.Table != routeReconciler.TableMain {
			continue
		}
		dst, err := r.toDestination(owner, rt)
		if err != nil {
			continue
		}
		dsts[rt.Prefix] = dst
	}

	return dsts, nil
}

func (r *importRouteReconciler) calculateDiff(desired, current map[netip.Prefix]*destination) ([]*destination, []*destination) {
	var (
		toUpsert []*destination
		toDelete []*destination
	)

	for prefix, d := range desired {
		c, exists := current[prefix]
		if !exists || !d.equal(c) {
			toUpsert = append(toUpsert, d)
		}
	}

	for prefix, c := range current {
		_, exists := desired[prefix]
		if !exists {
			toDelete = append(toDelete, c)
		}
	}

	return toUpsert, toDelete
}

func (r *importRouteReconciler) toTableRoute(rtxn statedb.ReadTxn, owner *routeReconciler.RouteOwner, dst *destination) (routeReconciler.DesiredRoute, error) {
	ad := AdminDistanceEBGP
	if dst.isIBGP {
		ad = AdminDistanceIBGP
	}

	desiredRoute := routeReconciler.DesiredRoute{
		Owner:         owner,
		Prefix:        dst.prefix,
		Table:         routeReconciler.TableMain,
		AdminDistance: ad,
		Type:          routeReconciler.RTN_UNICAST,
	}

	if len(dst.paths) == 1 {
		device, err := r.getDevice(rtxn, dst.paths[0].nexthop)
		if err != nil {
			// We can immediately return here since there's only
			// one path. Nothing else to process.
			return routeReconciler.DesiredRoute{}, err
		}

		desiredRoute.Nexthop = dst.paths[0].nexthop
		desiredRoute.Device = device
	} else {
		var errs error

		for _, p := range dst.paths {
			device, err := r.getDevice(rtxn, p.nexthop)
			if err != nil {
				// Continue processing other paths to collect
				// all errors.
				errs = errors.Join(errs, err)
				continue
			}
			desiredRoute.MultiPath = append(desiredRoute.MultiPath, &routeReconciler.NexthopInfo{
				Nexthop: p.nexthop,
				Device:  device,
			})
		}

		// If there were errors for any of the paths, return them.
		if errs != nil {
			return routeReconciler.DesiredRoute{}, errs
		}
	}

	return desiredRoute, nil
}

func (r *importRouteReconciler) getDevice(rtxn statedb.ReadTxn, nexthop netip.Addr) (*tables.Device, error) {
	if nexthop.Zone() != "" {
		dev, _, found := r.deviceTable.Get(rtxn, tables.DeviceNameIndex.Query(nexthop.Zone()))
		if !found {
			return nil, fmt.Errorf("device %q not found for nexthop %q", nexthop.Zone(), nexthop)
		}
		return dev, nil
	}
	return nil, nil
}

// toPath converts a DesiredRoute to an intermediate path representation. This
// must be the inverse of toTableRoute.
func (r *importRouteReconciler) toDestination(owner *routeReconciler.RouteOwner, rt *routeReconciler.DesiredRoute) (*destination, error) {
	// Sanity checks for the constant fields.
	if rt.Owner != owner {
		return nil, fmt.Errorf("owner mismatch: got %v, want %v", rt.Owner, owner)
	}
	if rt.Table != routeReconciler.TableMain {
		return nil, fmt.Errorf("table is not main: %d", rt.Table)
	}
	if rt.AdminDistance != AdminDistanceIBGP && rt.AdminDistance != AdminDistanceEBGP {
		return nil, fmt.Errorf("AD is not IBGP or EBGP: %d", rt.AdminDistance)
	}
	if rt.Type != routeReconciler.RTN_UNICAST {
		return nil, fmt.Errorf("route type is not unicast: %d", rt.Type)
	}

	dst := &destination{
		prefix: rt.Prefix,
		isIBGP: rt.AdminDistance == AdminDistanceIBGP,
	}
	if rt.Nexthop.IsValid() {
		nexthop := r.maybeWithZone(rt.Nexthop, rt.Device)
		dst.paths = append(dst.paths, &path{
			nexthop: nexthop,
		})
	} else {
		for _, nhi := range rt.MultiPath {
			nexthop := r.maybeWithZone(nhi.Nexthop, rt.Device)
			dst.paths = append(dst.paths, &path{
				nexthop: nexthop,
			})
		}
	}

	// Sort paths to have a deterministic order
	dst.sortPaths()

	return dst, nil
}

func (r *importRouteReconciler) maybeWithZone(nexthop netip.Addr, device *tables.Device) netip.Addr {
	if nexthop.Is6() && nexthop.IsLinkLocalUnicast() && device != nil {
		// If the nexthop is IPv6 link-local address and a
		// device associated, add the zone to the nexthop.
		nexthop = nexthop.WithZone(device.Name)
	}
	return nexthop
}

func (r *importRouteReconciler) reconcileDesiredRoutes(rtxn statedb.ReadTxn, owner *routeReconciler.RouteOwner, toUpsert, toDelete []*destination) error {
	var errs error
	for _, dst := range toUpsert {
		route, err := r.toTableRoute(rtxn, owner, dst)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if err := r.drm.UpsertRoute(route); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	for _, dst := range toDelete {
		route, err := r.toTableRoute(rtxn, owner, dst)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if err := r.drm.DeleteRoute(route); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (r *importRouteReconciler) ownerName(instanceName string) string {
	return "bgp-" + instanceName
}

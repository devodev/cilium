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
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/slices"
)

var (
	linkOperStateUp      = netlink.LinkOperState(netlink.OperUp).String()
	linkOperStateUnknown = netlink.LinkOperState(netlink.OperUnknown).String()
)

type InterfaceReconcilerOut struct {
	cell.Out

	Reconciler reconciler.ConfigReconciler `group:"bgp-config-reconciler"`
}

type InterfaceReconcilerIn struct {
	cell.In

	Logger     *slog.Logger
	PeerAdvert *reconciler.CiliumPeerAdvertisement

	DB          *statedb.DB
	DeviceTable statedb.Table[*tables.Device]
}

type InterfaceReconciler struct {
	logger      *slog.Logger
	peerAdvert  *reconciler.CiliumPeerAdvertisement
	db          *statedb.DB
	deviceTable statedb.Table[*tables.Device]
	metadata    map[string]InterfaceReconcilerMetadata
}

type InterfaceReconcilerMetadata struct {
	AFPaths       reconciler.AFPathsMap
	RoutePolicies reconciler.RoutePolicyMap
}

func NewInterfaceReconciler(params InterfaceReconcilerIn) InterfaceReconcilerOut {
	return InterfaceReconcilerOut{
		Reconciler: &InterfaceReconciler{
			logger:      params.Logger.With(types.ReconcilerLogField, reconciler.InterfaceReconcilerName),
			peerAdvert:  params.PeerAdvert,
			db:          params.DB,
			deviceTable: params.DeviceTable,
			metadata:    make(map[string]InterfaceReconcilerMetadata),
		},
	}
	// NOTE: there is no need to trigger reconciliation upon Device table changes,
	// this is already done by the DefaultGatewayReconciler.
}

func (r *InterfaceReconciler) Name() string {
	return reconciler.InterfaceReconcilerName
}

func (r *InterfaceReconciler) Priority() int {
	return reconciler.InterfaceReconcilerPriority
}

func (r *InterfaceReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = InterfaceReconcilerMetadata{
		AFPaths:       make(reconciler.AFPathsMap),
		RoutePolicies: make(reconciler.RoutePolicyMap),
	}
	return nil
}

func (r *InterfaceReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *InterfaceReconciler) Reconcile(ctx context.Context, p reconciler.ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2.BGPInterfaceAdvert)
	if err != nil {
		return err
	}

	txn := r.db.ReadTxn()
	err = r.reconcileRoutePolicies(ctx, p, desiredPeerAdverts, txn)
	if err != nil {
		return err
	}

	return r.reconcilePaths(ctx, p, desiredPeerAdverts, txn)
}

func (r *InterfaceReconciler) getDesiredPaths(desiredPeerAdverts reconciler.PeerAdvertisements, txn statedb.ReadTxn) reconciler.AFPathsMap {
	desiredAdverts := make(reconciler.AFPathsMap)
	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			pathsPerFamily, exists := desiredAdverts[agentFamily]
			if !exists {
				pathsPerFamily = make(reconciler.PathMap)
				desiredAdverts[agentFamily] = pathsPerFamily
			}
			for _, advert := range familyAdverts {
				for _, prefix := range r.getInterfacePrefixes(advert, agentFamily, txn) {
					path := types.NewPathForPrefix(prefix)
					path.Family = agentFamily
					pathsPerFamily[path.NLRI.String()] = path
				}
			}
		}
	}
	return desiredAdverts
}

func (r *InterfaceReconciler) getDesiredRoutePolicies(desiredPeerAdverts reconciler.PeerAdvertisements, txn statedb.ReadTxn) (reconciler.RoutePolicyMap, error) {
	desiredPolicies := make(reconciler.RoutePolicyMap)
	for peer, peerFamilyAdverts := range desiredPeerAdverts {
		if peer.Address == "" {
			continue
		}
		peerAddr, err := netip.ParseAddr(peer.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			for _, advert := range familyAdverts {
				var v4Prefixes, v6Prefixes types.PolicyPrefixList
				for _, prefix := range r.getInterfacePrefixes(advert, agentFamily, txn) {
					rpPrefix := types.RoutePolicyPrefix{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()}
					if agentFamily.Afi == types.AfiIPv4 {
						v4Prefixes = append(v4Prefixes, rpPrefix)
					}
					if agentFamily.Afi == types.AfiIPv6 {
						v6Prefixes = append(v6Prefixes, rpPrefix)
					}
				}
				if len(v6Prefixes) > 0 || len(v4Prefixes) > 0 {
					name := reconciler.PolicyName(peer.Name, agentFamily.Afi.String(), advert.AdvertisementType, "")
					policy, err := reconciler.CreatePolicy(name, peerAddr, v4Prefixes, v6Prefixes, advert)
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

func (r *InterfaceReconciler) getInterfacePrefixes(advert v2.BGPAdvertisement, family types.Family, txn statedb.ReadTxn) []netip.Prefix {
	var prefixes []netip.Prefix
	if advert.Interface == nil {
		return nil
	}
	dev, _, found := r.deviceTable.Get(txn, tables.DeviceNameIndex.Query(advert.Interface.Name))
	if !found {
		return nil
	}
	// Skip devices which are not:
	// - administratively up,
	// - operationally up or unknown (loopbacks and dummy interfaces are always unknown).
	if dev.Flags&net.FlagUp == 0 ||
		(dev.OperStatus != linkOperStateUp && dev.OperStatus != linkOperStateUnknown) {
		return nil
	}
	for _, addr := range dev.Addrs {
		// Skip non-matching address families.
		if family.Afi == types.AfiIPv4 && !addr.Addr.Is4() ||
			family.Afi == types.AfiIPv6 && !addr.Addr.Is6() {
			continue
		}
		// Skip:
		// - IPv4-mapped IPv6 addresses,
		// - unspecified, loopback, multicast and link-local IPv6 addresses,
		// - unspecified, loopback and multicast IPv4 addresses (link-local IPv4 is allowed).
		if addr.Addr.Is4In6() ||
			(addr.Addr.Is6() && !addr.Addr.IsGlobalUnicast()) ||
			(addr.Addr.Is4() && !(addr.Addr.IsGlobalUnicast() || addr.Addr.IsLinkLocalUnicast())) {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr.Addr, addr.Addr.BitLen()))
	}
	return slices.Unique(prefixes) // avoid duplicates in case that the same IP is applied with a different mask
}

func (r *InterfaceReconciler) reconcilePaths(ctx context.Context, p reconciler.ReconcileParams, desiredPeerAdverts reconciler.PeerAdvertisements, txn statedb.ReadTxn) error {
	metadata := r.getMetadata(p.BGPInstance)

	// get desired paths per address family
	desiredFamilyAdverts := r.getDesiredPaths(desiredPeerAdverts, txn)

	// reconcile family advertisements
	updatedAFPaths, err := reconciler.ReconcileAFPaths(&reconciler.ReconcileAFPathsParams{
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

func (r *InterfaceReconciler) reconcileRoutePolicies(ctx context.Context, p reconciler.ReconcileParams, desiredPeerAdverts reconciler.PeerAdvertisements, txn statedb.ReadTxn) error {
	metadata := r.getMetadata(p.BGPInstance)

	// get desired policies
	desiredRoutePolicies, err := r.getDesiredRoutePolicies(desiredPeerAdverts, txn)
	if err != nil {
		return err
	}

	// reconcile route policies
	updatedPolicies, err := reconciler.ReconcileRoutePolicies(&reconciler.ReconcileRoutePoliciesParams{
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

func (r *InterfaceReconciler) getMetadata(i *instance.BGPInstance) InterfaceReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *InterfaceReconciler) setMetadata(i *instance.BGPInstance, metadata InterfaceReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

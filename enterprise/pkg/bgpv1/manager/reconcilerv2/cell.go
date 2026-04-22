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
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/k8s"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

// ConfigReconcilers contains cells of enterprise-only reconcilers
var ConfigReconcilers = cell.Group(
	cell.ProvidePrivate(
		newReconcileParamsUpgrader,
		newIsovalentAdvertisement,
		newSRv6Paths,
		newEVPNPaths,
		newRADaemon,
		newImportVPNRouteReconciler,
		newLegacyImportVPNRouteReconciler,
	),

	// provide stores
	cell.Provide(
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPPeerConfig],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPNodeConfig],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPAdvertisement],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPPolicy],
	),

	cell.Provide(
		k8s.IsovalentSRv6LocatorPoolResource,
	),

	cell.Provide(
		NewLinkLocalReconciler,
		NewServiceReconciler,
		NewEgressGatewayIPsReconciler,
		NewBFDStateReconciler,
		NewSRv6LocatorPoolReconciler,
		NewVPNRoutePolicyReconciler,
		NewPodCIDRVRFReconciler,
		NewServiceVRFReconciler,
		NewNeighborReconciler,
		NewPodCIDRReconciler,
		NewInterfaceReconciler,
		NewPodIPPoolReconciler,
		NewNodeStatusReconciler,
		NewPrivateNetworkReconciler,
	),

	// state reconcilers
	cell.Provide(
		newImportVPNRouteStateReconciler,
		newImportEVPNRouteReconciler,
		NewStatusReconciler,
		newImportRouteReconciler,
	),

	// error path store
	cell.Provide(newErrorPathStore),

	// config of the enterprise reconcilers
	cell.Config(defaultConfig),

	cell.Invoke(
		registerPrivnetStatusNotifier,
	),
)

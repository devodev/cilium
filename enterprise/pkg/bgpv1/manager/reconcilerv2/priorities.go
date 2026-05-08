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

import ossreconcilerv2 "github.com/cilium/cilium/pkg/bgp/manager/reconciler"

const (
	LinkLocalReconcilerName        = "LinkLocal"
	DefaultGatewayReconcilerName   = ossreconcilerv2.DefaultGatewayReconcilerName
	BFDStateReconcilerName         = "BFDState"
	NeighborReconcilerName         = ossreconcilerv2.NeighborReconcilerName  // needs to match the name of the OSS reconciler we are overriding
	ServiceReconcilerName          = ossreconcilerv2.ServiceReconcilerName   // needs to match the name of the OSS reconciler we are overriding
	PodCIDRReconcilerName          = ossreconcilerv2.PodCIDRReconcilerName   // needs to match the name of the OSS reconciler we are overriding
	InterfaceReconcilerName        = ossreconcilerv2.InterfaceReconcilerName // needs to match the name of the OSS reconciler we are overriding
	PodIPPoolReconcilerName        = ossreconcilerv2.PodIPPoolReconcilerName // needs to match the name of the OSS reconciler we are overriding
	EgressGatewayIPsReconcilerName = "EgressGatewayIPs"
	PodCIDRVRFReconcilerName       = "PodCIDRVRF"
	ServiceVRFReconcilerName       = "ServiceVRF"
	LocatorPoolReconcilerName      = "LocatorPool"
	VPNRoutePolicyReconcilerName   = "VPNRoutePolicy"
	PrivateNetworkReconcilerName   = "PrivateNetwork"
)

// Configuration Reconciler Priorities, lower number means higher priority. It is used to determine the
// order in which reconcilers are called. Reconcilers are called from lowest to highest on
// each Reconcile event.
const (
	LinkLocalReconcilerPriority = 5   // highest priority, must run before any neighbor or advertisement reconcilers, as it sets the peering address in BGPNodeInstance
	BFDStateReconcilerPriority  = 100 // low priority, let the configuration reconcilers do their work first
	// VPNRoutePolicyReconcilerPriority should be before the Neighbor reconciler,
	// so gobgp will already have desired VPN policies in place.
	VPNRoutePolicyReconcilerPriority   = NeighborReconcilerPriority - 1
	EgressGatewayIPsReconcilerPriority = 55
	NeighborReconcilerPriority         = ossreconcilerv2.NeighborReconcilerPriority - 1  // must be lower (higher priority) than the OSS reconciler we are overriding
	ServiceReconcilerPriority          = ossreconcilerv2.ServiceReconcilerPriority - 1   // must be lower (higher priority) than the OSS reconciler we are overriding
	PodCIDRReconcilerPriority          = ossreconcilerv2.PodCIDRReconcilerPriority - 1   // must be lower (higher priority) than the OSS reconciler we are overriding
	InterfaceReconcilerPriority        = ossreconcilerv2.InterfaceReconcilerPriority - 1 // must be lower (higher priority) than the OSS reconciler we are overriding
	PodIPPoolReconcilerPriority        = ossreconcilerv2.PodIPPoolReconcilerPriority - 1 // must be lower (higher priority) than the OSS reconciler we are overriding
	LocatorPoolReconcilerPriority      = 45
	PrivateNetworkReconcilerPriority   = 44
	ServiceVRFReconcilerPriority       = 41
	PodCIDRVRFReconcilerPriority       = 31
	DefaultGatewayReconcilerPriority   = ossreconcilerv2.DefaultGatewayReconcilerPriority
)

// State reconciler names
const (
	ImportedVPNRouteReconcilerName = "ImportedVPNRoute"
	CRDStatusReconcilerName        = "IsovalentBGPNodeConfigStatus"
	ImportRouteReconcilerName      = "ImportRoute"
	ImportEVPNRouteReconcilerName  = "ImportEVPNRouteReconciler"
)

// State reconciler priorities
const (
	ImportedVPNRouteReconcilerPriority = 20
	ImportEVPNRouteReconcilerPriority  = 30
	ImportRouteReconcilerPriority      = 40
	CRDStatusReconcilerPriority        = 50
)

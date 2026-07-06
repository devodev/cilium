// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"context"
	"log/slog"
	"net/netip"

	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

// EnterpriseRouter is an extension of the ossTypes.Router interface that adds
// enterprise-specific functionality. This is a superset of the OSS Router
// interface. We can add support for these enterprise-specific methods in the
// OSS Router implementations through enterprise_*.go file and on the
// enterprise side, we can upgrade the OSS Router to an EnterpriseRouter when
// needed (most likely through upgrader).
type EnterpriseRouter interface {
	ossTypes.Router

	// GetBGPExtended retrieves BGP global configuration from the
	// underlying router.
	GetBGPExtended(ctx context.Context) (*GetBGPExtendedResponse, error)

	// GetPeerStateExtended retrieves BGP peer states from the underlying router.
	GetPeerStateExtended(ctx context.Context, r *GetPeerStateExtendedRequest) (*GetPeerStateExtendedResponse, error)

	// GetRoutesExtended retrieves routes from the RIB of underlying router
	// implementation. The reply contains extended enterprise-specific
	// route information.
	GetRoutesExtended(ctx context.Context, r *GetRoutesExtendedRequest) (*GetRoutesExtendedResponse, error)

	// AddRoutePolicyExtended adds a new enterprise-specific routing policy into the underlying router.
	AddRoutePolicyExtended(ctx context.Context, p RoutePolicyExtendedRequest) error

	// RemoveRoutePolicyExtended removes an enterprise-specific routing policy from the underlying router.
	RemoveRoutePolicyExtended(ctx context.Context, p RoutePolicyExtendedRequest) error

	// GetRoutePoliciesExtended retrieves enterprise-specific route policies from the underlying router
	GetRoutePoliciesExtended(ctx context.Context) (*GetRoutePoliciesExtendedResponse, error)

	// AddNeighborExtended adds a new enterprise-specific BGP peer into the underlying router.
	AddNeighborExtended(ctx context.Context, n *EnterpriseNeighbor) error

	// UpdateNeighborExtended updates enterprise-specific BGP peer
	UpdateNeighborExtended(ctx context.Context, n *EnterpriseNeighbor) error
}

// EnterpriseRouterProvider provides enterprise BGP router instances.
type EnterpriseRouterProvider interface {
	NewEnterpriseRouter(ctx context.Context, log *slog.Logger, params EnterpriseServerParameters) (EnterpriseRouter, error)
}

// EnterpriseServerParameters contains Enterprise BGP router startup parameters.
type EnterpriseServerParameters struct {
	Global            EnterpriseBGPGlobal
	VRF               EnterpriseBGPVRF
	StateNotification ossTypes.StateNotificationCh
}

// EnterpriseBGPGlobal contains Enterprise BGP global startup parameters.
type EnterpriseBGPGlobal struct {
	ossTypes.BGPGlobal

	// BindToDevice restricts the GoBGP listen socket to the Linux device.
	BindToDevice string

	// BindToIfindex is an ifindex of the BindToDevice. This is used to
	// detect the case that BIndToDevice is recreated with the same name.
	// Linux's SO_BINDTODEVICE binds socket to the ifindex instead of the
	// device name and doesn't take care of changing ifindex when the device
	// is recreated. Therefore, we need to check if the ifindex of the
	// device is changed and recreate the socket if it is changed.
	BindToIfindex int
}

// EnterpriseBGPVRF holds the VRF information for the BGP instance.
type EnterpriseBGPVRF struct {
	Name          string
	TableID       uint32
	DeviceName    string
	DeviceIfindex int
}

type GetBGPExtendedResponse struct {
	Global EnterpriseBGPGlobal
}

type GetPeerStateExtendedRequest struct {
	ossTypes.GetPeerStateRequest
}

type GetPeerStateExtendedResponse struct {
	Peers []PeerStateExtended
}

// PeerStateExtended is an extension of ossTypes.PeerState with
// enterprise-specific peer state.
type PeerStateExtended struct {
	ossTypes.PeerState

	// BindInterface is the Linux device (e.g. a VRF device) the peer's
	// connect socket is bound to. Empty if not bound to any device.
	BindInterface string
}

type GetRoutesExtendedRequest struct {
	ossTypes.GetRoutesRequest
}

type GetRoutesExtendedResponse struct {
	Routes []*ExtendedRoute
}

type ExtendedRoute struct {
	Prefix string
	Paths  []*ExtendedPath
}

type ExtendedPath struct {
	ossTypes.Path

	// NeighborAddr is the address of the neighbor that advertised this
	// path. When the neighbor is a BGP Unnumbered Peer, the netip.Addr
	// will contain the zone information to identify the neighbor
	// interface.
	NeighborAddr netip.Addr
}

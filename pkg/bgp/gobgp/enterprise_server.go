// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gobgp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// NewEnterpriseGoBGPServer returns instance of go bgp router wrapper.
func NewEnterpriseGoBGPServer(ctx context.Context, log *slog.Logger, params types.EnterpriseServerParameters) (types.EnterpriseRouter, error) {
	logger := log.With(
		logfields.Component, "gobgp-server",
		ossTypes.LocalASNLogField, params.Global.ASN,
	)

	s := server.NewBgpServer(server.LoggerOption(logger, nil))
	go s.Serve()

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:          params.Global.ASN,
			RouterId:     params.Global.RouterID,
			ListenPort:   params.Global.ListenPort,
			BindToDevice: params.Global.BindToDevice,

			UseMultiplePaths: true, // CEE-specific
		},
	}

	if params.Global.RouteSelectionOptions != nil {
		startReq.Global.RouteSelectionOptions = &gobgp.RouteSelectionOptionsConfig{
			AdvertiseInactiveRoutes: params.Global.RouteSelectionOptions.AdvertiseInactiveRoutes,
		}
	}

	if err := s.StartBgp(ctx, startReq); err != nil {
		return nil, fmt.Errorf("failed starting BGP server: %w", err)
	}

	gobgpSrv := &GoBGPServer{
		logger: log,
		asn:    params.Global.ASN,
		server: s,
	}

	// Reject all paths announced toward Cilium from external peers. This first step configures an
	// "allow" policy for local routes. It was observed during testing that global policies are also
	// applied to local routes, which we need to permit.
	if err := gobgpSrv.server.AddPolicy(ctx, &gobgp.AddPolicyRequest{Policy: allowLocalPolicy}); err != nil {
		return nil, fmt.Errorf("failed to add %s policy: %w", allowLocalPolicy.Name, err)
	}

	// Reject all paths announced toward Cilium from external peers. This step configures the actual
	// import policy.
	err := gobgpSrv.server.SetPolicyAssignment(ctx, &gobgp.SetPolicyAssignmentRequest{
		Assignment: &gobgp.PolicyAssignment{
			Name:          globalPolicyAssignmentName,
			Direction:     gobgp.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: gobgp.RouteAction_ROUTE_ACTION_REJECT,
			Policies:      []*gobgp.Policy{allowLocalPolicy},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed configuring BGP server's global import policy: %w", err)
	}

	// send state notifications upon peer changes
	peerCallback := func(p *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
		if p.Type != apiutil.PEER_EVENT_STATE {
			return
		}
		gobgpSrv.stopMutex.Lock()
		defer gobgpSrv.stopMutex.Unlock()

		if gobgpSrv.stopping {
			return
		}
		// do not block when channel is nil (e.g. in tests)
		select {
		case params.StateNotification <- struct{}{}:
		default:
		}
	}
	// send state notifications upon table changes
	routeCallback := func(_ []*apiutil.Path, _ time.Time) {
		gobgpSrv.stopMutex.Lock()
		defer gobgpSrv.stopMutex.Unlock()

		if gobgpSrv.stopping {
			return
		}
		// do not block when channel is nil (e.g. in tests)
		select {
		case params.StateNotification <- struct{}{}:
		default:
		}
	}
	err = s.WatchEvent(ctx,
		server.WatchEventMessageCallbacks{
			OnPeerUpdate: peerCallback,
			OnBestPath:   routeCallback,
		},
		server.WatchPeer(),
		server.WatchBestPath(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to configure event watching for virtual router with local-asn %v: %w", startReq.Global.Asn, err)
	}

	// trigger initial state reconciliation
	select {
	case params.StateNotification <- struct{}{}:
	default:
	}

	return gobgpSrv, nil
}

func (g *GoBGPServer) GetBGPExtended(ctx context.Context) (*types.GetBGPExtendedResponse, error) {
	bgpConfig, err := g.server.GetBgp(ctx, &gobgp.GetBgpRequest{})
	if err != nil {
		return nil, err
	}

	if bgpConfig.Global == nil {
		return nil, fmt.Errorf("gobgp returned nil config")
	}

	res := ossTypes.BGPGlobal{
		ASN:        bgpConfig.Global.Asn,
		RouterID:   bgpConfig.Global.RouterId,
		ListenPort: bgpConfig.Global.ListenPort,
	}
	if bgpConfig.Global.RouteSelectionOptions != nil {
		res.RouteSelectionOptions = &ossTypes.RouteSelectionOptions{
			AdvertiseInactiveRoutes: bgpConfig.Global.RouteSelectionOptions.AdvertiseInactiveRoutes,
		}
	}

	return &types.GetBGPExtendedResponse{
		Global: types.EnterpriseBGPGlobal{
			BGPGlobal:    res,
			BindToDevice: bgpConfig.Global.BindToDevice,
		},
	}, nil
}

// GetPeerStateExtended retrieves BGP peering state from underlying GoBGP server.
func (g *GoBGPServer) GetPeerStateExtended(ctx context.Context, r *types.GetPeerStateExtendedRequest) (*types.GetPeerStateExtendedResponse, error) {
	var res types.GetPeerStateExtendedResponse

	fn := func(peer *gobgp.Peer) {
		if peer == nil {
			return
		}

		state := types.PeerStateExtended{}

		if peer.Transport != nil {
			state.Port = int64(peer.Transport.RemotePort)
			state.BindInterface = peer.Transport.BindInterface
		}

		if peer.Conf != nil {
			if peer.Conf.Description != "" {
				pd := peerDescription{}
				if err := json.Unmarshal([]byte(peer.Conf.Description), &pd); err == nil {
					// If unmarshal is not successful, we
					// ignore and do not set Name field.
					state.Name = pd.Name
				}
			}
			// We can just ignore error here. In that case, the addr
			// is invalid. Caller is responsible for handling the
			// invalid case.
			addr, _ := netip.ParseAddr(peer.Conf.NeighborAddress)
			state.Address = addr
			state.LocalAsn = int64(peer.Conf.LocalAsn)
			state.PeerAsn = int64(peer.Conf.PeerAsn)
			state.TCPPasswordEnabled = peer.Conf.AuthPassword != ""
		}

		if peer.State != nil {
			if peer.Conf.PeerAsn == 0 { // if peerAsn is not set, use peer state peerAsn
				state.PeerAsn = int64(peer.State.PeerAsn)
			}

			state.SessionState = toAgentSessionState(peer.State.SessionState)
			state.LocalCapabilities = toAgentCap(peer.State.LocalCap)
			state.RemoteCapabilities = toAgentCap(peer.State.RemoteCap)

			// Uptime is time since session got established. It is
			// calculated by difference in time from uptime
			// timestamp till now.
			if peer.State.SessionState == gobgp.PeerState_SESSION_STATE_ESTABLISHED && peer.Timers != nil && peer.Timers.State != nil {
				state.Uptime = time.Since(peer.Timers.State.Uptime.AsTime())
			}
		}

		for _, afiSafi := range peer.AfiSafis {
			if afiSafi.State == nil || afiSafi.State.Family == nil {
				continue
			}
			state.Families = append(state.Families, toAgentAfiSafiState(afiSafi.State))
		}

		if peer.EbgpMultihop != nil && peer.EbgpMultihop.Enabled {
			state.EbgpMultihopTTL = int64(peer.EbgpMultihop.MultihopTtl)
		} else {
			state.EbgpMultihopTTL = int64(v2.DefaultBGPEBGPMultihopTTL) // defaults to 1 if not enabled
		}

		if peer.Timers != nil {
			tConfig := peer.Timers.Config
			tState := peer.Timers.State
			if tConfig != nil {
				state.Timers.ConnectRetryTime = time.Duration(tConfig.ConnectRetry) * time.Second
				state.Timers.ConfiguredHoldTime = time.Duration(tConfig.HoldTime) * time.Second
				state.Timers.ConfiguredKeepAliveTime = time.Duration(tConfig.KeepaliveInterval) * time.Second
			}
			if tState != nil {
				if tState.NegotiatedHoldTime != 0 {
					state.Timers.AppliedHoldTime = time.Duration(tState.NegotiatedHoldTime) * time.Second
				}
				if tState.KeepaliveInterval != 0 {
					state.Timers.AppliedKeepAliveTime = time.Duration(tState.KeepaliveInterval) * time.Second
				}
			}
		}

		state.GracefulRestart = ossTypes.BgpGracefulRestart{}
		if peer.GracefulRestart != nil {
			state.GracefulRestart.Enabled = peer.GracefulRestart.Enabled
			state.GracefulRestart.RestartTime = time.Duration(peer.GracefulRestart.RestartTime) * time.Second
		}

		res.Peers = append(res.Peers, state)
	}

	// API to get peering list from gobgp, enableAdvertised is set to true
	// to get count of advertised routes.
	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{EnableAdvertised: true}, fn)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (g *GoBGPServer) GetRoutesExtended(ctx context.Context, r *types.GetRoutesExtendedRequest) (*types.GetRoutesExtendedResponse, error) {
	var (
		routes []*types.ExtendedRoute
	)

	tt, err := toGoBGPTableType(r.TableType)
	if err != nil {
		return nil, fmt.Errorf("invalid table type: %w", err)
	}

	family := bgp.NewFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))

	var neighbor string
	if r.Neighbor.IsValid() {
		neighbor = r.Neighbor.String()
	}

	req := apiutil.ListPathRequest{
		TableType: tt,
		Family:    family,
		Name:      neighbor,
	}

	var errs error

	err = g.server.ListPath(req, func(prefix bgp.NLRI, listedPaths []*apiutil.Path) {
		paths, err := ToAgentPathsExtended(listedPaths)
		if err != nil {
			errs = errors.Join(errs, err)
			return
		}
		routes = append(routes, &types.ExtendedRoute{
			Prefix: prefix.String(),
			Paths:  paths,
		})
	})
	if err != nil {
		errs = errors.Join(errs, err)
	}

	// We may return partial results along with an error. This is a safe
	// guard to avoid one bad route preventing the entire route listing.
	return &types.GetRoutesExtendedResponse{
		Routes: routes,
	}, errs
}

// AddRoutePolicyExtended adds a new routing policy into the global policies of the server.
func (g *GoBGPServer) AddRoutePolicyExtended(ctx context.Context, r types.RoutePolicyExtendedRequest) error {
	if r.Policy == nil {
		return fmt.Errorf("nil policy in the RoutePolicyRequest")
	}
	policy, definedSets := toGoBGPPolicyExtended(r.Policy)

	for i, ds := range definedSets {
		err := g.server.AddDefinedSet(ctx, &gobgp.AddDefinedSetRequest{DefinedSet: ds})
		if err != nil {
			g.deleteDefinedSets(ctx, definedSets[:i]) // clean up already created defined sets
			return fmt.Errorf("failed adding policy defined set %s: %w", ds.Name, err)
		}
	}

	err := g.server.AddPolicy(ctx, &gobgp.AddPolicyRequest{Policy: policy})
	if err != nil {
		g.deleteDefinedSets(ctx, definedSets) // clean up defined sets
		return fmt.Errorf("failed adding policy %s: %w", policy.Name, err)
	}

	// Note that we are using global policy assignment here (per-neighbor policies work only in the route-server mode)
	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type, r.DefaultExportAction)
	err = g.server.AddPolicyAssignment(ctx, &gobgp.AddPolicyAssignmentRequest{Assignment: assignment})
	if err != nil {
		g.deletePolicy(ctx, policy)           // clean up policy
		g.deleteDefinedSets(ctx, definedSets) // clean up defined sets
		return fmt.Errorf("failed adding policy assignment %s: %w", assignment.Name, err)
	}

	return nil
}

// RemoveRoutePolicyExtended removes a routing policy from the global policies of the server.
func (g *GoBGPServer) RemoveRoutePolicyExtended(ctx context.Context, r types.RoutePolicyExtendedRequest) error {
	if r.Policy == nil {
		return fmt.Errorf("nil policy in the RoutePolicyRequest")
	}
	policy, definedSets := toGoBGPPolicyExtended(r.Policy)

	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type, r.DefaultExportAction)
	err := g.server.DeletePolicyAssignment(ctx, &gobgp.DeletePolicyAssignmentRequest{Assignment: assignment})
	if err != nil {
		return fmt.Errorf("failed deleting policy assignment %s: %w", assignment.Name, err)
	}

	err = g.deletePolicy(ctx, policy)
	if err != nil {
		return err
	}

	err = g.deleteDefinedSets(ctx, definedSets)
	if err != nil {
		return err
	}

	return nil
}

// GetRoutePoliciesExtended retrieves route policies from the underlying router
func (g *GoBGPServer) GetRoutePoliciesExtended(ctx context.Context) (*types.GetRoutePoliciesExtendedResponse, error) {
	// list defined sets into a map for later use
	definedSets := make(map[string]*gobgp.DefinedSet)
	err := g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_DEFINED_TYPE_NEIGHBOR}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing neighbor defined sets: %w", err)
	}

	err = g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_DEFINED_TYPE_PREFIX}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing prefix defined sets: %w", err)
	}

	err = g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_DEFINED_TYPE_COMMUNITY}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing community defined sets: %w", err)
	}

	err = g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing extended community defined sets: %w", err)
	}

	// list policy assignments into a map for later use
	assignments := make(map[string]*gobgp.PolicyAssignment)
	err = g.server.ListPolicyAssignment(ctx, &gobgp.ListPolicyAssignmentRequest{}, func(a *gobgp.PolicyAssignment) {
		for _, p := range a.Policies {
			assignments[p.Name] = a
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing policy assignments: %w", err)
	}

	// list & convert policies
	var policies []*types.ExtendedRoutePolicy
	err = g.server.ListPolicy(ctx, &gobgp.ListPolicyRequest{}, func(p *gobgp.Policy) {
		// process only assigned policies
		if assignment, exists := assignments[p.Name]; exists {
			policies = append(policies, toAgentPolicyExtended(p, definedSets, assignment))
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing route policies: %w", err)
	}

	return &types.GetRoutePoliciesExtendedResponse{
		Policies: policies,
	}, nil
}

// AddNeighborExtended adds an enterprise BGP neighbor to the gobgp server.
func (g *GoBGPServer) AddNeighborExtended(ctx context.Context, n *types.EnterpriseNeighbor) error {
	peerReq := &gobgp.AddPeerRequest{
		Peer: toGoBGPPeerExtended(n, nil, n.Address.Is4()),
	}
	if err := g.server.AddPeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while adding peer %s with ASN %d: %w", n.Address, n.ASN, err)
	}
	return nil
}

// UpdateNeighborExtended will update the existing CiliumBGPNeighbor in the gobgp.BgpServer.
func (g *GoBGPServer) UpdateNeighborExtended(ctx context.Context, n *types.EnterpriseNeighbor) error {
	oldPeer, err := g.getExistingPeer(ctx, n.Address, n.ASN)
	if err != nil {
		return fmt.Errorf("failed to get existing peer: %w", err)
	}

	newPeer := toGoBGPPeerExtended(n, oldPeer, n.Address.Is4())

	needsHardReset := g.needsHardReset(oldPeer, newPeer)

	// update peer config
	peerReq := &gobgp.UpdatePeerRequest{
		Peer: toGoBGPPeerExtended(n, oldPeer, n.Address.Is4()),
	}

	updateRes, err := g.server.UpdatePeer(ctx, peerReq)
	if err != nil {
		return fmt.Errorf("failed while updating peer %v:%v with ASN %v: %w", oldPeer.Conf.NeighborAddress, oldPeer.Transport.RemotePort, oldPeer.Conf.PeerAsn, err)
	}

	// perform full / soft peer reset if necessary
	if needsHardReset || updateRes.NeedsSoftResetIn {
		resetReq := &gobgp.ResetPeerRequest{
			Address:       oldPeer.Conf.NeighborAddress,
			Communication: "Peer configuration changed",
		}
		if !needsHardReset {
			resetReq.Soft = true
			resetReq.Direction = gobgp.ResetPeerRequest_DIRECTION_IN
		}
		if err = g.server.ResetPeer(ctx, resetReq); err != nil {
			return fmt.Errorf("failed while resetting peer %v:%v in ASN %v: %w", oldPeer.Conf.NeighborAddress, oldPeer.Transport.RemotePort, oldPeer.Conf.PeerAsn, err)
		}
	}

	return nil
}

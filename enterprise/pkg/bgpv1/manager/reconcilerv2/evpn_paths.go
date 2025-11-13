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
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	ceeTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	asTransASN = 23456 // ASN assigned to AS_TRANS per RFC6793
)

// EvpnVRFInfo holds VRF-specific information for EVPN paths.
// +deepequal-gen=true
type EvpnVRFInfo struct {
	VNI        vni.VNI
	RD         string
	RTs        []string
	RoutersMAC string
}

type evpnPathsIn struct {
	cell.In

	JobGroup job.Group
	Logger   *slog.Logger
	Signaler *signaler.BGPCPSignaler

	BGPConfig  config.Config
	EVPNConfig evpnConfig.Config

	DB          *statedb.DB
	DeviceTable statedb.Table[*tables.Device]
}

// evpnPaths can be used to populate EVPN BGP routing Paths based on provided information and internal state.
type evpnPaths struct {
	lock.RWMutex

	logger     *slog.Logger
	signaler   *signaler.BGPCPSignaler
	evpnConfig evpnConfig.Config

	db          *statedb.DB
	deviceTable statedb.Table[*tables.Device]

	vxlanDeviceMAC string
}

func newEVPNPaths(in evpnPathsIn) *evpnPaths {
	if !in.BGPConfig.Enabled || !in.EVPNConfig.Enabled {
		return nil
	}
	p := &evpnPaths{
		logger:      in.Logger.With(types.ReconcilerLogField, "EVPNPaths"),
		evpnConfig:  in.EVPNConfig,
		signaler:    in.Signaler,
		db:          in.DB,
		deviceTable: in.DeviceTable,
	}
	in.JobGroup.Add(
		job.Observer("evpn-vxlan-device-mac-observer", p.evpnVxlanDeviceMACObserver(), statedb.Observable(p.db, p.deviceTable)),
	)
	return p
}

// evpnVxlanDeviceMACObserver tracks EVPN vxlan device MAC and triggers BGP reconciliation upon its change.
func (p *evpnPaths) evpnVxlanDeviceMACObserver() job.ObserverFunc[statedb.Change[*tables.Device]] {
	return func(ctx context.Context, event statedb.Change[*tables.Device]) error {
		device := event.Object
		if device.Name == p.evpnConfig.VxlanDevice {
			hwAddr := device.HardwareAddr.String()
			if event.Deleted {
				hwAddr = ""
			}
			p.Lock()
			if p.vxlanDeviceMAC != hwAddr {
				p.vxlanDeviceMAC = hwAddr
				p.signaler.Event(struct{}{})
			}
			p.Unlock()
		}
		return nil
	}
}

// GetEvpnRoutersMAC returns MAC address that can be used as EVPN Router's MAC in the EVPN advertisement.
func (p *evpnPaths) GetEvpnRoutersMAC() string {
	p.RLock()
	defer p.RUnlock()

	return p.vxlanDeviceMAC
}

// GetEvpnRT5Path returns EVPN RT-5 (L3VPN) path with Router’s MAC Extended Community (a.k.a. Pure-RT-5)
// for the provided prefix and EVPN VRF info.
func (p *evpnPaths) GetEvpnRT5Path(prefix netip.Prefix, vrfInfo *EvpnVRFInfo, securityGroupID *uint16, customAttrs *AdvertPathAttributes) (*types.Path, string, error) {
	if vrfInfo == nil {
		return nil, "", errMissingEvpnPathInfo
	}
	if !vrfInfo.VNI.IsValid() {
		return nil, "", errInvalidVNI
	}
	if vrfInfo.RD == "" {
		return nil, "", errMissingRD
	}
	if len(vrfInfo.RTs) == 0 {
		return nil, "", errMissingRTs
	}
	if vrfInfo.RoutersMAC == "" {
		return nil, "", errMissingRoutersMAC
	}

	pathAttrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
	}

	// EVPN Type-5 NLRI
	rd, err := bgp.ParseRouteDistinguisher(vrfInfo.RD)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse Route Distinguisher %v: %w", vrfInfo.RD, err)
	}
	esi := bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: nil}
	gw := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		gw = netip.IPv6Unspecified()
	}
	nlri, err := bgp.NewEVPNIPPrefixRoute(rd, esi, 0, uint8(prefix.Bits()), prefix.Addr(), gw, vrfInfo.VNI.AsUint32())
	if err != nil {
		return nil, "", fmt.Errorf("failed to build EVPN NLRI for prefix %s: %w", prefix, err)
	}

	// Next Hop: let GoBGP resolve it automatically
	nextHop := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		nextHop = netip.IPv6Unspecified()
	}
	mpReachNLRI, err := bgp.NewPathAttributeMpReachNLRI(
		bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN),
		[]bgp.PathNLRI{{NLRI: nlri}},
		nextHop,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build EVPN MP_REACH_NLRI for prefix %s: %w", prefix, err)
	}
	pathAttrs = append(pathAttrs, mpReachNLRI)

	// Extended Communities:
	extComms := []bgp.ExtendedCommunityInterface{
		bgp.NewEncapExtended(bgp.TUNNEL_TYPE_VXLAN),
	}
	for _, rt := range vrfInfo.RTs {
		extComm, err := bgp.ParseRouteTarget(rt)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse RT %s: %w", rt, err)
		}
		extComms = append(extComms, extComm)
	}
	extComms = append(extComms, bgp.NewRoutersMacExtended(vrfInfo.RoutersMAC))
	if securityGroupID != nil {
		extComms = append(extComms, ceeTypes.GetGroupPolicyIDExtendedCommunity(*securityGroupID))
	}
	pathAttrs = append(pathAttrs, bgp.NewPathAttributeExtendedCommunities(extComms))

	// Custom path attributes:
	if customAttrs != nil {
		if len(customAttrs.Communities) > 0 {
			pathAttrs = append(pathAttrs, bgp.NewPathAttributeCommunities(customAttrs.Communities))
		}
		if len(customAttrs.LargeCommunities) > 0 {
			pathAttrs = append(pathAttrs, bgp.NewPathAttributeLargeCommunities(customAttrs.LargeCommunities))
		}
		if customAttrs.LocalPreference != nil {
			pathAttrs = append(pathAttrs, bgp.NewPathAttributeLocalPref(*customAttrs.LocalPreference))
		}
	}

	path := &types.Path{
		NLRI:           nlri,
		PathAttributes: pathAttrs,
		Family:         types.Family{Afi: types.AfiL2VPN, Safi: types.SafiEvpn},
	}

	// Path key containing NLRI and path attributes
	h := sha256.New()
	data, err := path.NLRI.Serialize()
	if err != nil {
		return nil, "", fmt.Errorf("failed to serialize NLRI %s: %w", path.NLRI.String(), err)
	}
	h.Write(data)
	for _, attr := range path.PathAttributes {
		data, err = attr.Serialize()
		if err != nil {
			return nil, "", fmt.Errorf("failed to serialize path attribute %s: %w", attr.String(), err)
		}
		h.Write(data)
	}
	key := fmt.Sprintf("%x", h.Sum(nil))

	return path, key, nil
}

// DeriveEVPNRouteDistinguisher derives RD in the "Type 1" encoding format from RFC 4364 section 4.2.:
// 4-byte administrator subfield (router ID) + 2-byte assigned number subfield (internal VRF ID).
func DeriveEVPNRouteDistinguisher(routerID string, vrfID uint16) string {
	return fmt.Sprintf("%s:%d", routerID, vrfID)
}

// DeriveEVPNRouteTarget derives RD in the "Type 0" encoding format from RFC 4364 section 4.2.:
// 2-byte Administrator subfield (ASN) + 4-byte assigned number subfield (VNI).
// If ASN is out of 2-byte range (in case of 4-byte ASNs), the special AS_TRANS (23456) ASN is used as per RFC 6793,
// which is compatible with Cisco Nexus RT auto-derive logic.
func DeriveEVPNRouteTarget(asn uint32, vni vni.VNI) string {
	// derive RT: ASN (2B) + VNI (4B)
	if asn > math.MaxUint16 {
		// for 4-byte ASNs, the special AS_TRANS ASN is used
		asn = asTransASN
	}
	return fmt.Sprintf("%d:%d", asn, vni.AsUint32())
}

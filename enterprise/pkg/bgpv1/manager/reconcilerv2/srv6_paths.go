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
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/option"
)

type SRv6Manager interface {
	GetVRFByName(vrfName k8sTypes.NamespacedName) (*srv6.VRF, bool)
	GetEgressPolicies() []*srv6.EgressPolicy
}

type srv6PathsIn struct {
	cell.In
	Logger       *slog.Logger
	SRv6Manager  *srv6.Manager
	DaemonConfig *option.DaemonConfig
	Config       config.Config
}

type srv6Paths struct {
	Logger      *slog.Logger
	SRv6Manager SRv6Manager
}

func newSRv6Paths(in srv6PathsIn) *srv6Paths {
	if !in.DaemonConfig.EnableSRv6 || !in.Config.Enabled {
		return nil
	}

	return &srv6Paths{
		Logger:      in.Logger.With(types.ReconcilerLogField, "srv6_paths"),
		SRv6Manager: in.SRv6Manager,
	}
}

func (s *srv6Paths) GetSRv6VPNPath(prefix netip.Prefix, bgpVRF v1.IsovalentBGPNodeVRF) (*types.Path, string, error) {
	if bgpVRF.VRFRef == nil {
		return nil, "", fmt.Errorf("cannot map VRF without VRFRef")
	}
	if bgpVRF.RD == nil || *bgpVRF.RD == "" {
		return nil, "", fmt.Errorf("cannot map VRF without an RD")
	}

	srv6VRF, exists := s.SRv6Manager.GetVRFByName(k8sTypes.NamespacedName{Name: *bgpVRF.VRFRef})
	if !exists {
		return nil, "", fmt.Errorf("VRF %s not found in SRv6 manager", *bgpVRF.VRFRef)
	}

	if srv6VRF.SIDInfo == nil {
		return nil, "", fmt.Errorf("cannot map VRF %s without SID allocation", *bgpVRF.VRFRef)
	}

	var extComms []bgp.ExtendedCommunityInterface
	for _, rt := range bgpVRF.ExportRTs {
		extComm, err := bgp.ParseRouteTarget(rt)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse export RT %s: %w", rt, err)
		}
		extComms = append(extComms, extComm)
	}

	RD, err := bgp.ParseRouteDistinguisher(*bgpVRF.RD)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse RD %v into Route Distinguisher: %w", *bgpVRF.RD, err)
	}

	extCommsAttr := &bgp.PathAttributeExtendedCommunities{
		Value: extComms,
	}

	var (
		label               uint32
		transposedSID       []byte
		transpositionOffset uint8
		transpositionLength uint8
	)

	sidStructure := srv6VRF.SIDInfo.Structure

	// In End.DT4/6/46, when we have function length greater than zero, we
	// can transpose at least part of the function bits into MPLS label.
	if sidStructure.FunctionLenBits() != 0 {
		transpositionOffset = uint8(srv6VRF.SIDInfo.Locator.Bits())
		transpositionLength = (sidStructure.LocatorLenBits() + sidStructure.FunctionLenBits()) - uint8(srv6VRF.SIDInfo.Locator.Bits())
		label, transposedSID, err = srv6VRF.SIDInfo.SID.Transpose(transpositionOffset, transpositionLength)
		if err != nil {
			return nil, "", fmt.Errorf("failed to transpose SID: %w", err)
		}
	} else {
		// Fallback to the legacy format
		label = 4096
		transposedSID = srv6VRF.SIDInfo.SID.AsSlice()
		transpositionOffset = 0
		transpositionLength = 0
	}

	// The SRv6 SID and endpoint behavior is encoded as a set of nested
	// TLVs.
	//
	// The SRv6 TLVs are encoded as a Prefix SID BGP Attribute of type
	// See: https://www.rfc-editor.org/rfc/rfc9252.html#section-4

	// Pack SRv6SIDStructureSubSubTLV details into a SRv6InformationSubTLV
	SIDInfoTLV := &bgp.SRv6InformationSubTLV{
		SID:              transposedSID,
		EndpointBehavior: uint16(srv6VRF.SIDInfo.Behavior),
		SubSubTLVs: []bgp.PrefixSIDTLVInterface{
			&bgp.SRv6SIDStructureSubSubTLV{
				LocatorBlockLength:  sidStructure.LocatorBlockLenBits(),
				LocatorNodeLength:   sidStructure.LocatorNodeLenBits(),
				FunctionLength:      sidStructure.FunctionLenBits(),
				ArgumentLength:      sidStructure.ArgumentLenBits(),
				TranspositionOffset: transpositionOffset,
				TranspositionLength: transpositionLength,
			},
		},
	}

	// Pack SRv6InformationSubTLV into a SRv6L3ServiceAttribute
	L3ServTLV := &bgp.SRv6L3ServiceAttribute{
		SubTLVs: []bgp.PrefixSIDTLVInterface{
			SIDInfoTLV,
		},
	}

	// Encode SRv6L3ServiceAttribute as a PathAttributePrefixSID
	prefixSIDAttr := &bgp.PathAttributePrefixSID{
		TLVs: []bgp.PrefixSIDTLVInterface{
			L3ServTLV,
		},
	}

	labeledPrefix, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(label), RD)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate LabeledVPNIPAddrPrefix: %w", err)
	}

	MpReachAttr := &bgp.PathAttributeMpReachNLRI{
		AFI:     bgp.AFI_IP,
		SAFI:    bgp.SAFI_MPLS_VPN,
		Nexthop: netip.IPv4Unspecified(),
		Value:   []bgp.PathNLRI{{NLRI: labeledPrefix}}, // single labeled prefix is added to MP reachable attrs
	}

	// Mandatory Attributes, ASPATH will be set by GoBGP directly.
	origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE)
	nextHop, err := bgp.NewPathAttributeNextHop(netip.IPv4Unspecified())
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate PathAttributeNextHop: %w", err)
	}

	attrs := []bgp.PathAttributeInterface{
		origin,
		nextHop,
		extCommsAttr,
		prefixSIDAttr,
		MpReachAttr,
	}

	p := &types.Path{
		NLRI:           labeledPrefix,
		PathAttributes: attrs,
	}

	// TODO: improve hashing of path, use path serializer instead of stringifying it.
	// GoBGP serializer is broken if we do not pass correct lengths in SRv6 TLVs.
	var pathString string
	for _, attr := range attrs {
		pathString = fmt.Sprintf("%s-%s", pathString, attr.String())
	}

	h := sha256.New()
	h.Write([]byte(pathString))
	pathKey := fmt.Sprintf("%s-%s-%x", RD.String(), p.NLRI.String(), h.Sum(nil))

	return p, pathKey, nil
}

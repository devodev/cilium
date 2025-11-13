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
	"bytes"
	"encoding/binary"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	// GroupPolicyIDExtCommSubType is the subtype of the Group Policy ID Extended Community (transitive opaque extended BGP community)
	// containing Security Group ID. This is a Cisco-specific value implemented by Cisco Nexus, NOT matching the IANA allocation
	// for Group Policy ID Extended Community (0x17).
	GroupPolicyIDExtCommSubType = 0x0F
)

var (
	// groupPolicyIDReservedValue is the value of the "Reserved" field of the Group Policy ID Extended Community.
	// This is a Cisco-specific value implemented by Cisco Nexus, signalling to fabric that we do not support GPO in the dataplane.
	groupPolicyIDReservedValue = []byte{0x80, 0x00}
)

// GetGroupPolicyIDExtendedCommunity returns Group Policy ID Extended Community for the provided Security Group ID.
// It will be encoded using Cisco-specific encoding implemented by Cisco Nexus.
func GetGroupPolicyIDExtendedCommunity(groupID uint16) bgp.ExtendedCommunityInterface {
	// Format from https://www.ietf.org/archive/id/draft-wlin-bess-group-policy-id-extended-community-03.txt
	//
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Type=0x03   |   Sub-Type    |        Policy ID Scope        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |            Reserved           |    Group Policy ID            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// This is a Cisco-specific encoding verified to work with Cisco NX-OS and ACI.

	// All BGP multi-octet fields are in network byte order (big-endian) per RFC4360.
	groupIDValue := make([]byte, 2)
	binary.BigEndian.PutUint16(groupIDValue, groupID)

	return &bgp.OpaqueExtended{
		IsTransitive: true,
		Value: []byte{
			// Type is set automatically by GoBGP
			GroupPolicyIDExtCommSubType, // Sub-Type
			0x00, 0x00,                  // Policy ID Scope (unused)
			groupPolicyIDReservedValue[0], groupPolicyIDReservedValue[1], // Reserved
			groupIDValue[0], groupIDValue[1], // Group Policy ID
		},
	}
}

// IsGroupPolicyIDExtendedCommunity checks whether the provided opaque extended community is the
// Group Policy ID Extended Community in Cisco-specific encoding.
func IsGroupPolicyIDExtendedCommunity(o *bgp.OpaqueExtended) bool {
	if !o.IsTransitive {
		return false
	}
	if _, subType := o.GetTypes(); subType != GroupPolicyIDExtCommSubType {
		return false
	}
	if len(o.Value) != 7 {
		return false
	}
	if !bytes.Equal(o.Value[1:3], []byte{0, 0}) || !bytes.Equal(o.Value[3:5], groupPolicyIDReservedValue) {
		return false
	}
	return true
}

// GetGroupPolicyIDFromExtendedCommunity returns Security Group ID from the provided
// Group Policy ID Extended Community in Cisco-specific encoding.
// Call [IsGroupPolicyIDExtendedCommunity] before using this API to ensure the provided community is valid.
func GetGroupPolicyIDFromExtendedCommunity(o *bgp.OpaqueExtended) uint16 {
	if len(o.Value) != 7 {
		return 0 // sanity check, never happens if [IsGroupPolicyIDExtendedCommunity] was called
	}
	return binary.BigEndian.Uint16(o.Value[5:7])
}

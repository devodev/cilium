//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vrf

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"

	epTypes "github.com/cilium/cilium/pkg/endpoint/types"
)

const (
	RTInfoVRF epTypes.RTInfoEncoding = "vrf"
)

// endpointInfo scopes an endpoint.Endpoint's method set to the subset required
// by the VRF control plane.
//
// GetLabels is intentionally not part of this interface since pod labels for VRF
// matching are read from the pod statedb table so that user labels filtered
// out of the security identity remain visible to selectors.
type endpointInfo interface {
	GetID() uint64
	GetK8sNamespace() string
	GetK8sPodName() string
	GetRTInfo() (uint32, epTypes.RTInfoEncoding)
	SetRTInfo(info uint32, t epTypes.RTInfoEncoding)
	ClearRTInfo()
	RegenerateIfAlive(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool
	IPv4Address() netip.Addr
	IPv6Address() netip.Addr
}

// endpointSubscriber scopes the endpointmanager.EndpointManager method set to the
// subset required by the VRF control plane.
type endpointSubscriber interface {
	GetEndpoints() []endpointInfo
}

type epSubscriber struct {
	em endpointmanager.EndpointManager
}

func newEpSubscriber(em endpointmanager.EndpointManager) endpointSubscriber {
	return &epSubscriber{em: em}
}

func (a *epSubscriber) GetEndpoints() []endpointInfo {
	return endpointsToInfo(a.em.GetEndpoints())
}

func endpointsToInfo(eps []*endpoint.Endpoint) []endpointInfo {
	out := make([]endpointInfo, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep)
	}
	return out
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package connectionlog

import (
	netV1 "github.com/isovalent/ipa/common/net/v1alpha"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/lock"
)

// flowstatkey defines how Hubble flows are aggregated into different
// connections.
type flowstatkey struct {
	srcIP, dstIP     string
	srcID, dstID     uint32
	srcPort, dstPort uint32
	ipProtocol       netV1.IPProtocol
}

// endpointMetadata holds the endpoint information needed to build a graphV1
// vertex. Keeping this separate from a sample Flow prevents a later, less
// enriched observation from erasing information collected earlier in the
// export window.
type endpointMetadata struct {
	identity    uint32
	clusterName string
	namespace   string
	podName     string
	nodeName    string
	dnsName     string
}

func endpointMetadataFromFlow(ep *flowpb.Endpoint, nodeName, dnsName string) endpointMetadata {
	return endpointMetadata{
		identity:    ep.GetIdentity(),
		clusterName: ep.GetClusterName(),
		namespace:   ep.GetNamespace(),
		podName:     ep.GetPodName(),
		nodeName:    nodeName,
		dnsName:     dnsName,
	}
}

func (m *endpointMetadata) merge(other endpointMetadata) {
	if m.identity == 0 {
		m.identity = other.identity
	}
	if m.clusterName == "" {
		m.clusterName = other.clusterName
	}
	if m.namespace == "" {
		m.namespace = other.namespace
	}
	if m.podName == "" {
		m.podName = other.podName
	}
	if m.nodeName == "" {
		m.nodeName = other.nodeName
	}
	if m.dnsName == "" {
		m.dnsName = other.dnsName
	}
}

// flowObservation is the initiator-oriented view of a Hubble flow used by the
// ConnectionLog aggregator.
type flowObservation struct {
	key         flowstatkey
	source      endpointMetadata
	destination endpointMetadata
}

func flowObservationFromFlow(flow *flowpb.Flow) flowObservation {
	srcPort, dstPort, protocol := l4Tuple(flow.GetL4())
	source := endpointMetadataFromFlow(
		flow.GetSource(),
		flow.GetNodeName(),
		firstName(flow.GetSourceNames()),
	)
	destination := endpointMetadataFromFlow(
		flow.GetDestination(),
		flow.GetNodeName(),
		firstName(flow.GetDestinationNames()),
	)
	obs := flowObservation{
		key: flowstatkey{
			srcIP:      flow.GetIP().GetSource(),
			dstIP:      flow.GetIP().GetDestination(),
			srcID:      source.identity,
			dstID:      destination.identity,
			srcPort:    srcPort,
			dstPort:    dstPort,
			ipProtocol: protocol,
		},
		source:      source,
		destination: destination,
	}
	if isReply(flow) {
		obs.key.srcIP, obs.key.dstIP = obs.key.dstIP, obs.key.srcIP
		obs.key.srcID, obs.key.dstID = obs.key.dstID, obs.key.srcID
		obs.key.srcPort, obs.key.dstPort = obs.key.dstPort, obs.key.srcPort
		obs.source, obs.destination = obs.destination, obs.source
	}
	return obs
}

func l4Tuple(l4 *flowpb.Layer4) (srcPort, dstPort uint32, protocol netV1.IPProtocol) {
	switch l4 := l4.GetProtocol().(type) {
	case *flowpb.Layer4_TCP:
		return l4.TCP.GetSourcePort(), l4.TCP.GetDestinationPort(), netV1.IPProtocol_IP_PROTOCOL_TCP
	case *flowpb.Layer4_UDP:
		return l4.UDP.GetSourcePort(), l4.UDP.GetDestinationPort(), netV1.IPProtocol_IP_PROTOCOL_UDP
	case *flowpb.Layer4_SCTP:
		return l4.SCTP.GetSourcePort(), l4.SCTP.GetDestinationPort(), netV1.IPProtocol_IP_PROTOCOL_SCTP
	case *flowpb.Layer4_ICMPv4:
		return 0, 0, netV1.IPProtocol_IP_PROTOCOL_ICMP
	case *flowpb.Layer4_ICMPv6:
		return 0, 0, netV1.IPProtocol_IP_PROTOCOL_ICMPV6
	case *flowpb.Layer4_IGMP:
		return 0, 0, netV1.IPProtocol_IP_PROTOCOL_IGMP
	default:
		return 0, 0, netV1.IPProtocol_IP_PROTOCOL_UNSPECIFIED
	}
}

func isReply(flow *flowpb.Flow) bool {
	if reply := flow.GetIsReply(); reply != nil {
		return reply.GetValue()
	}
	if flow.GetReply() {
		return true
	}
	switch flow.GetSockXlatePoint() {
	case flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_PRE_DIRECTION_REV,
		flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_POST_DIRECTION_REV:
		return true
	default:
		return false
	}
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// flowstatval holds statistics from a "connection edge" (in the IPA graphV1
// API sense, not necessarily a 1:1 mapping to a networking connection).
type flowstatval struct {
	source      endpointMetadata
	destination endpointMetadata
	// the following values match distinct flowpb.Verdict and are mapped as a
	// graphV1.EdgeTypeRoutingTelemetry message at export time.
	forwarded  uint64
	dropped    uint64
	errored    uint64 // only generated from accesslog (proxy)
	audited    uint64 // only generated from policy verdict
	redirected uint64 // only generated from policy verdict
	traced     uint64 // only generated by socketlb
	translated uint64 // only generated by socketlb
}

func (v *flowstatval) add(obs flowObservation, verdict flowpb.Verdict) bool {
	switch verdict {
	case flowpb.Verdict_FORWARDED:
		v.forwarded++
	case flowpb.Verdict_DROPPED:
		v.dropped++
	case flowpb.Verdict_ERROR:
		v.errored++
	case flowpb.Verdict_AUDIT:
		v.audited++
	case flowpb.Verdict_REDIRECTED:
		v.redirected++
	case flowpb.Verdict_TRACED:
		v.traced++
	case flowpb.Verdict_TRANSLATED:
		v.translated++
	default:
		return false
	}
	v.source.merge(obs.source)
	v.destination.merge(obs.destination)
	return true
}

type connLogDB struct {
	mu    lock.Mutex
	store map[flowstatkey]flowstatval
}

func newConnLogDB() *connLogDB {
	return &connLogDB{
		store: make(map[flowstatkey]flowstatval),
	}
}

// add updates the database to account for the given flow. It is safe to call
// add() and reset() concurrently.
func (db *connLogDB) add(flow *flowpb.Flow) {
	// NOTE: add() is the "hot codepath" of the Hubble ConnLogger as it is
	// called for every Hubble flow, so keep it fast.
	verdict := flow.GetVerdict()
	if verdict == flowpb.Verdict_VERDICT_UNKNOWN {
		return
	}
	obs := flowObservationFromFlow(flow)

	db.mu.Lock()
	defer db.mu.Unlock()

	v := db.store[obs.key]
	if !v.add(obs, verdict) {
		return
	}
	db.store[obs.key] = v
}

// reset returns the current map store and reset it. It is safe to call add()
// and reset() concurrently.
func (db *connLogDB) reset() map[flowstatkey]flowstatval {
	// reset() is not called often, but it has to stay fast to avoid lock
	// contention with add() as both need to hold the db mutex.
	db.mu.Lock()
	defer db.mu.Unlock()

	ret := db.store
	db.store = make(map[flowstatkey]flowstatval)
	return ret
}

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
	"runtime"
	"sync"
	"testing"

	netV1 "github.com/isovalent/ipa/common/net/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestL4Tuple(t *testing.T) {
	tests := []struct {
		name         string
		l4           *flowpb.Layer4
		wantSrcPort  uint32
		wantDstPort  uint32
		wantProtocol netV1.IPProtocol
	}{
		{
			name:         "nil",
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_UNSPECIFIED,
		},
		{
			name:         "empty",
			l4:           &flowpb.Layer4{},
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_UNSPECIFIED,
		},
		{
			name: "TCP",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{SourcePort: 50000, DestinationPort: 443},
				},
			},
			wantSrcPort:  50000,
			wantDstPort:  443,
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_TCP,
		},
		{
			name: "TraceSock TCP with unknown source port",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{DestinationPort: 443},
				},
			},
			wantDstPort:  443,
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_TCP,
		},
		{
			name: "UDP",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_UDP{
					UDP: &flowpb.UDP{SourcePort: 53000, DestinationPort: 53},
				},
			},
			wantSrcPort:  53000,
			wantDstPort:  53,
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_UDP,
		},
		{
			name: "SCTP",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_SCTP{
					SCTP: &flowpb.SCTP{SourcePort: 2905, DestinationPort: 2906},
				},
			},
			wantSrcPort:  2905,
			wantDstPort:  2906,
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_SCTP,
		},
		{
			name: "ICMPv4",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{}},
			},
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_ICMP,
		},
		{
			name: "ICMPv6",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_ICMPv6{ICMPv6: &flowpb.ICMPv6{}},
			},
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_ICMPV6,
		},
		{
			name: "IGMP",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_IGMP{IGMP: &flowpb.IGMP{}},
			},
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_IGMP,
		},
		{
			name: "unsupported VRRP",
			l4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_VRRP{VRRP: &flowpb.VRRP{}},
			},
			wantProtocol: netV1.IPProtocol_IP_PROTOCOL_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcPort, dstPort, protocol := l4Tuple(tt.l4)
			assert.Equal(t, tt.wantSrcPort, srcPort)
			assert.Equal(t, tt.wantDstPort, dstPort)
			assert.Equal(t, tt.wantProtocol, protocol)
		})
	}
}

func TestFlowObservationUsesPreTranslationSourceIP(t *testing.T) {
	flow := dbTestFlow(flowpb.Verdict_FORWARDED)

	got := flowObservationFromFlow(flow)

	assert.Equal(t, flow.GetIP().GetSource(), got.key.srcIP)
	assert.NotEqual(t, flow.GetIP().GetSourceXlated(), got.key.srcIP)
}

func TestConnLogDBSeparatesFiveTuples(t *testing.T) {
	flows := []*flowpb.Flow{
		dbTestFlow(flowpb.Verdict_FORWARDED),
		dbTestFlow(flowpb.Verdict_FORWARDED),
		dbTestFlow(flowpb.Verdict_FORWARDED),
		dbTestFlow(flowpb.Verdict_FORWARDED),
	}
	flows[1].GetL4().GetTCP().SourcePort++
	flows[2].GetL4().GetTCP().DestinationPort++
	flows[3].L4 = &flowpb.Layer4{
		Protocol: &flowpb.Layer4_UDP{
			UDP: &flowpb.UDP{SourcePort: 50000, DestinationPort: 443},
		},
	}

	db := newConnLogDB()
	for _, flow := range flows {
		db.add(flow)
	}

	got := db.reset()
	require.Len(t, got, len(flows))
	for _, flow := range flows {
		obs := flowObservationFromFlow(flow)
		require.Contains(t, got, obs.key)
		assert.Equal(t, uint64(1), got[obs.key].forwarded)
	}
}

func TestFlowObservationCanonicalOrientation(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*flowpb.Flow)
		wantCanonical bool
	}{
		{
			name: "explicit reply",
			configure: func(flow *flowpb.Flow) {
				flow.IsReply = wrapperspb.Bool(true)
			},
			wantCanonical: true,
		},
		{
			name: "deprecated reply fallback",
			configure: func(flow *flowpb.Flow) {
				flow.Reply = true
			},
			wantCanonical: true,
		},
		{
			name: "TraceSock pre reverse fallback",
			configure: func(flow *flowpb.Flow) {
				flow.SockXlatePoint = flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_PRE_DIRECTION_REV
			},
			wantCanonical: true,
		},
		{
			name: "TraceSock post reverse fallback",
			configure: func(flow *flowpb.Flow) {
				flow.SockXlatePoint = flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_POST_DIRECTION_REV
			},
			wantCanonical: true,
		},
		{
			name: "explicit false overrides deprecated reply",
			configure: func(flow *flowpb.Flow) {
				flow.IsReply = wrapperspb.Bool(false)
				flow.Reply = true
			},
		},
		{
			name: "explicit false overrides reverse TraceSock",
			configure: func(flow *flowpb.Flow) {
				flow.IsReply = wrapperspb.Bool(false)
				flow.SockXlatePoint = flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_POST_DIRECTION_REV
			},
		},
		{
			name: "unknown reply with ingress traffic direction",
			configure: func(flow *flowpb.Flow) {
				flow.TrafficDirection = flowpb.TrafficDirection_INGRESS
			},
		},
		{
			name: "unknown reply with egress traffic direction",
			configure: func(flow *flowpb.Flow) {
				flow.TrafficDirection = flowpb.TrafficDirection_EGRESS
			},
		},
	}

	request := dbTestFlow(flowpb.Verdict_FORWARDED)
	canonical := flowObservationFromFlow(request)
	observedReply := dbTestReverseFlow(request)
	observed := flowObservationFromFlow(observedReply)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := dbTestCloneFlow(observedReply)
			tt.configure(flow)

			got := flowObservationFromFlow(flow)
			if tt.wantCanonical {
				assert.Equal(t, canonical, got)
			} else {
				assert.Equal(t, observed, got)
			}
		})
	}
}

func TestConnLogDBAggregatesRequestAndReply(t *testing.T) {
	tests := []struct {
		name  string
		flows func(request, reply *flowpb.Flow) []*flowpb.Flow
	}{
		{
			name: "request then reply",
			flows: func(request, reply *flowpb.Flow) []*flowpb.Flow {
				return []*flowpb.Flow{request, reply}
			},
		},
		{
			name: "reply then request",
			flows: func(request, reply *flowpb.Flow) []*flowpb.Flow {
				return []*flowpb.Flow{reply, request}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := dbTestFlow(flowpb.Verdict_FORWARDED)
			reply := dbTestReverseFlow(request)
			reply.IsReply = wrapperspb.Bool(true)

			db := newConnLogDB()
			for _, flow := range tt.flows(request, reply) {
				db.add(flow)
			}

			got := db.reset()
			require.Len(t, got, 1)
			key := flowObservationFromFlow(request).key
			value, ok := got[key]
			require.True(t, ok)
			assert.Equal(t, uint64(2), value.forwarded)
			assert.Equal(t, endpointMetadataFromFlow(
				request.GetSource(),
				request.GetNodeName(),
				request.GetSourceNames()[0],
			), value.source)
			assert.Equal(t, endpointMetadataFromFlow(
				request.GetDestination(),
				request.GetNodeName(),
				request.GetDestinationNames()[0],
			), value.destination)
		})
	}
}

func TestConnLogDBAggregatesTraceSockForwardAndReverse(t *testing.T) {
	const (
		serviceIP   = "10.96.0.10"
		servicePort = 8080
		serviceName = "server.server-ns.svc.cluster.local"
	)

	forward := dbTestFlow(flowpb.Verdict_TRACED)
	forward.Type = flowpb.FlowType_SOCK
	forward.IP.Destination = serviceIP
	forward.L4.GetTCP().SourcePort = 0
	forward.L4.GetTCP().DestinationPort = servicePort
	forward.Destination = &flowpb.Endpoint{}
	forward.DestinationNames = []string{serviceName}
	forward.SockXlatePoint = flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_PRE_DIRECTION_FWD

	reverse := dbTestReverseFlow(forward)
	reverse.Verdict = flowpb.Verdict_TRANSLATED
	reverse.SockXlatePoint = flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_POST_DIRECTION_REV

	db := newConnLogDB()
	db.add(forward)
	db.add(reverse)

	got := db.reset()
	require.Len(t, got, 1)

	key := flowstatkey{
		srcIP:      "10.0.0.1",
		dstIP:      serviceIP,
		srcID:      1001,
		srcPort:    0,
		dstPort:    servicePort,
		ipProtocol: netV1.IPProtocol_IP_PROTOCOL_TCP,
	}
	value, ok := got[key]
	require.True(t, ok)
	assert.Equal(t, flowstatval{
		source: endpointMetadata{
			identity:    1001,
			clusterName: "cluster-a",
			namespace:   "client-ns",
			podName:     "client",
			nodeName:    "node-a",
			dnsName:     "client.client-ns.svc.cluster.local",
		},
		destination: endpointMetadata{
			nodeName: "node-a",
			dnsName:  serviceName,
		},
		traced:     1,
		translated: 1,
	}, value)
}

func TestConnLogDBPreservesEndpointMetadata(t *testing.T) {
	tests := []struct {
		name  string
		flows func(enriched, sparse *flowpb.Flow) []*flowpb.Flow
	}{
		{
			name: "enriches an earlier sparse observation",
			flows: func(enriched, sparse *flowpb.Flow) []*flowpb.Flow {
				return []*flowpb.Flow{sparse, enriched}
			},
		},
		{
			name: "a later sparse observation does not erase metadata",
			flows: func(enriched, sparse *flowpb.Flow) []*flowpb.Flow {
				return []*flowpb.Flow{enriched, sparse}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enriched := dbTestFlow(flowpb.Verdict_FORWARDED)
			sparse := dbTestCloneFlow(enriched)
			sparse.Source.ClusterName = ""
			sparse.Source.Namespace = ""
			sparse.Source.PodName = ""
			sparse.Destination.ClusterName = ""
			sparse.Destination.Namespace = ""
			sparse.Destination.PodName = ""
			sparse.NodeName = ""
			sparse.SourceNames = nil
			sparse.DestinationNames = nil

			db := newConnLogDB()
			for _, flow := range tt.flows(enriched, sparse) {
				db.add(flow)
			}

			got := db.reset()
			require.Len(t, got, 1)
			value := got[flowObservationFromFlow(enriched).key]
			assert.Equal(t, endpointMetadataFromFlow(
				enriched.GetSource(),
				enriched.GetNodeName(),
				enriched.GetSourceNames()[0],
			), value.source)
			assert.Equal(t, endpointMetadataFromFlow(
				enriched.GetDestination(),
				enriched.GetNodeName(),
				enriched.GetDestinationNames()[0],
			), value.destination)
		})
	}
}

func TestConnLogDBAggregatesAllVerdicts(t *testing.T) {
	verdicts := []flowpb.Verdict{
		flowpb.Verdict_FORWARDED,
		flowpb.Verdict_DROPPED,
		flowpb.Verdict_ERROR,
		flowpb.Verdict_AUDIT,
		flowpb.Verdict_REDIRECTED,
		flowpb.Verdict_TRACED,
		flowpb.Verdict_TRANSLATED,
	}

	db := newConnLogDB()
	for _, verdict := range verdicts {
		db.add(dbTestFlow(verdict))
	}
	db.add(dbTestFlow(flowpb.Verdict_VERDICT_UNKNOWN))

	got := db.reset()
	require.Len(t, got, 1)
	value := got[flowObservationFromFlow(dbTestFlow(flowpb.Verdict_FORWARDED)).key]
	assert.Equal(t, flowstatval{
		source: endpointMetadata{
			identity:    1001,
			clusterName: "cluster-a",
			namespace:   "client-ns",
			podName:     "client",
			nodeName:    "node-a",
			dnsName:     "client.client-ns.svc.cluster.local",
		},
		destination: endpointMetadata{
			identity:    2002,
			clusterName: "cluster-a",
			namespace:   "server-ns",
			podName:     "server",
			nodeName:    "node-a",
			dnsName:     "server.server-ns.svc.cluster.local",
		},
		forwarded:  1,
		dropped:    1,
		errored:    1,
		audited:    1,
		redirected: 1,
		traced:     1,
		translated: 1,
	}, value)
}

func TestConnLogDBForwardedAndDroppedStates(t *testing.T) {
	tests := []struct {
		name          string
		verdicts      []flowpb.Verdict
		wantEntries   int
		wantForwarded uint64
		wantDropped   uint64
	}{
		{
			name:        "no observation",
			wantEntries: 0,
		},
		{
			name:        "unknown observation",
			verdicts:    []flowpb.Verdict{flowpb.Verdict_VERDICT_UNKNOWN},
			wantEntries: 0,
		},
		{
			name:          "forwarded only",
			verdicts:      []flowpb.Verdict{flowpb.Verdict_FORWARDED, flowpb.Verdict_FORWARDED},
			wantEntries:   1,
			wantForwarded: 2,
		},
		{
			name:        "dropped only",
			verdicts:    []flowpb.Verdict{flowpb.Verdict_DROPPED, flowpb.Verdict_DROPPED},
			wantEntries: 1,
			wantDropped: 2,
		},
		{
			name:          "mixed",
			verdicts:      []flowpb.Verdict{flowpb.Verdict_FORWARDED, flowpb.Verdict_DROPPED},
			wantEntries:   1,
			wantForwarded: 1,
			wantDropped:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newConnLogDB()
			for _, verdict := range tt.verdicts {
				db.add(dbTestFlow(verdict))
			}

			got := db.reset()
			require.Len(t, got, tt.wantEntries)
			if tt.wantEntries == 0 {
				return
			}
			for _, value := range got {
				assert.Equal(t, tt.wantForwarded, value.forwarded)
				assert.Equal(t, tt.wantDropped, value.dropped)
			}
		})
	}
}

func TestConnLogDBUnknownVerdictsDoNotCreateEntries(t *testing.T) {
	db := newConnLogDB()
	db.add(nil)
	db.add(dbTestFlow(flowpb.Verdict_VERDICT_UNKNOWN))
	db.add(dbTestFlow(flowpb.Verdict(1000)))

	assert.Empty(t, db.reset())
}

func TestConnLogDBConcurrentAddAndReset(t *testing.T) {
	const (
		workers       = 8
		addsPerWorker = 500
	)

	db := newConnLogDB()
	start := make(chan struct{})
	done := make(chan struct{})
	counted := make(chan uint64, 1)

	go func() {
		<-start
		var total uint64
		for {
			select {
			case <-done:
				total += dbTestForwardedCount(db.reset())
				counted <- total
				return
			default:
				total += dbTestForwardedCount(db.reset())
				runtime.Gosched()
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			flow := dbTestFlow(flowpb.Verdict_FORWARDED)
			<-start
			for range addsPerWorker {
				db.add(flow)
			}
		}()
	}

	close(start)
	wg.Wait()
	close(done)

	assert.Equal(t, uint64(workers*addsPerWorker), <-counted)
	assert.Empty(t, db.reset())
}

func BenchmarkConnLogDBAddRepeatedTuple(b *testing.B) {
	db := newConnLogDB()
	flow := dbTestFlow(flowpb.Verdict_FORWARDED)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		db.add(flow)
	}
}

func BenchmarkConnLogDBAddHighCardinality(b *testing.B) {
	const cardinality = 60_000

	db := newConnLogDB()
	flow := dbTestFlow(flowpb.Verdict_FORWARDED)
	tcp := flow.GetL4().GetTCP()

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if i > 0 && i%cardinality == 0 {
			db.reset()
		}
		tcp.SourcePort = 1024 + uint32(i%cardinality)
		db.add(flow)
	}
}

func dbTestFlow(verdict flowpb.Verdict) *flowpb.Flow {
	return &flowpb.Flow{
		Verdict: verdict,
		IP: &flowpb.IP{
			Source:       "10.0.0.1",
			SourceXlated: "192.0.2.1",
			Destination:  "10.0.0.2",
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{SourcePort: 50000, DestinationPort: 443},
			},
		},
		Source: &flowpb.Endpoint{
			Identity:    1001,
			ClusterName: "cluster-a",
			Namespace:   "client-ns",
			PodName:     "client",
		},
		Destination: &flowpb.Endpoint{
			Identity:    2002,
			ClusterName: "cluster-a",
			Namespace:   "server-ns",
			PodName:     "server",
		},
		NodeName:         "node-a",
		SourceNames:      []string{"client.client-ns.svc.cluster.local", "client-alias"},
		DestinationNames: []string{"server.server-ns.svc.cluster.local", "server-alias"},
	}
}

func dbTestCloneFlow(flow *flowpb.Flow) *flowpb.Flow {
	return proto.Clone(flow).(*flowpb.Flow)
}

func dbTestReverseFlow(flow *flowpb.Flow) *flowpb.Flow {
	reverse := dbTestCloneFlow(flow)
	reverse.IP.Source, reverse.IP.Destination = reverse.IP.Destination, reverse.IP.Source
	reverse.Source, reverse.Destination = reverse.Destination, reverse.Source
	reverse.SourceNames, reverse.DestinationNames = reverse.DestinationNames, reverse.SourceNames

	switch l4 := reverse.GetL4().GetProtocol().(type) {
	case *flowpb.Layer4_TCP:
		l4.TCP.SourcePort, l4.TCP.DestinationPort = l4.TCP.DestinationPort, l4.TCP.SourcePort
	case *flowpb.Layer4_UDP:
		l4.UDP.SourcePort, l4.UDP.DestinationPort = l4.UDP.DestinationPort, l4.UDP.SourcePort
	case *flowpb.Layer4_SCTP:
		l4.SCTP.SourcePort, l4.SCTP.DestinationPort = l4.SCTP.DestinationPort, l4.SCTP.SourcePort
	}
	return reverse
}

func dbTestForwardedCount(store map[flowstatkey]flowstatval) uint64 {
	var count uint64
	for _, value := range store {
		count += value.forwarded
	}
	return count
}

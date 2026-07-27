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
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	netV1 "github.com/isovalent/ipa/common/net/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleexporter "github.com/cilium/cilium/pkg/hubble/exporter"
)

func TestConnLogExporterTickSerializesCanonicalConnection(t *testing.T) {
	request := dbTestFlow(flowpb.Verdict_FORWARDED)
	request.IsReply = wrapperspb.Bool(false)

	reply := dbTestReverseFlow(request)
	reply.Verdict = flowpb.Verdict_FORWARDED
	reply.IsReply = wrapperspb.Bool(true)

	policyDrop := dbTestCloneFlow(request)
	policyDrop.Verdict = flowpb.Verdict_DROPPED
	policyDrop.DropReasonDesc = flowpb.DropReason_POLICY_DENIED
	policyDrop.IsReply = nil

	db := newConnLogDB()
	logger := newConnLogger(db)
	for _, flow := range []*flowpb.Flow{request, reply, policyDrop} {
		stop, err := logger.OnDecodedFlow(t.Context(), flow)
		require.NoError(t, err)
		require.False(t, stop)
	}

	var output bytes.Buffer
	encoder, err := hubbleexporter.JsonEncoder(&output)
	require.NoError(t, err)

	windowStart := time.Unix(1_000, 0).UTC()
	windowEnd := windowStart.Add(10 * time.Second)
	exporter := &connLogExporter{
		db:       db,
		encoder:  encoder,
		lastTick: windowStart,
	}

	require.NoError(t, exporter.tick(windowEnd))
	require.Empty(t, db.reset())

	var log graphV1.ConnectionLog
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &log))
	require.Equal(t, windowStart, log.GetWindowStart().AsTime())
	require.Equal(t, windowEnd, log.GetWindowEnd().AsTime())
	require.Equal(t, emitterName, log.GetEmitter().GetName())
	require.Equal(t, emitterVersion, log.GetEmitter().GetVersion())

	connections := log.GetConnections()
	require.Len(t, connections, 1)
	connection := connections[0]

	source := connection.GetSource().GetKubernetes()
	require.NotNil(t, source)
	require.Equal(t, "cluster-a", source.GetClusterName())
	require.Equal(t, "client-ns", source.GetNamespace())
	require.Equal(t, "client", source.GetPodName())
	require.Equal(t, "client", source.GetResourceName())
	require.Equal(t, "10.0.0.1", source.GetIp())
	require.Equal(t, uint32(50000), source.GetPort())
	require.Equal(t, netV1.IPProtocol_IP_PROTOCOL_TCP, source.GetIpProtocol())

	destination := connection.GetDestination().GetKubernetes()
	require.NotNil(t, destination)
	require.Equal(t, "cluster-a", destination.GetClusterName())
	require.Equal(t, "server-ns", destination.GetNamespace())
	require.Equal(t, "server", destination.GetPodName())
	require.Equal(t, "server", destination.GetResourceName())
	require.Equal(t, "10.0.0.2", destination.GetIp())
	require.Equal(t, uint32(443), destination.GetPort())
	require.Equal(t, netV1.IPProtocol_IP_PROTOCOL_TCP, destination.GetIpProtocol())

	links := connection.GetLinks()
	require.Len(t, links, 1)
	routing := links[0].GetRoutingTelemetry()
	require.NotNil(t, routing)
	require.Equal(t, uint64(2), routing.GetRoutingForwardedTotal())
	require.Equal(t, uint64(1), routing.GetRoutingDroppedTotal())
}

func BenchmarkConnLogExporterTickHighCardinality(b *testing.B) {
	const cardinality = 60_000

	flow := dbTestFlow(flowpb.Verdict_FORWARDED)
	tcp := flow.GetL4().GetTCP()
	store := make(map[flowstatkey]flowstatval, cardinality)
	for i := range cardinality {
		tcp.SourcePort = 1024 + uint32(i)
		observation := flowObservationFromFlow(flow)
		value := flowstatval{}
		value.add(observation, flow.GetVerdict())
		store[observation.key] = value
	}

	encoder, err := hubbleexporter.JsonEncoder(io.Discard)
	require.NoError(b, err)

	db := newConnLogDB()
	windowStart := time.Unix(1_000, 0).UTC()
	exporter := &connLogExporter{
		db:       db,
		encoder:  encoder,
		lastTick: windowStart,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		db.store = store
		windowEnd := windowStart.Add(time.Duration(i+1) * time.Second)
		b.StartTimer()

		if err := exporter.tick(windowEnd); err != nil {
			b.Fatal(err)
		}
	}
}

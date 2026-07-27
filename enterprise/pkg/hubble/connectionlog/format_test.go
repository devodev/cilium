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
	"testing"

	typeV1 "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	netV1 "github.com/isovalent/ipa/common/net/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
)

func TestFlowstatToConnectionKubernetesTuple(t *testing.T) {
	db := newConnLogDB()
	db.add(formatTestFlow(
		formatTestPodEndpoint(1001, "cluster-a", "client-ns", "client-pod"),
		formatTestPodEndpoint(1002, "cluster-a", "server-ns", "server-pod"),
		"10.0.0.1",
		"10.0.0.2",
		32000,
		443,
		flowpb.Verdict_FORWARDED,
	))

	conn := formatTestSingleConnection(t, db)
	src := conn.GetSource().GetKubernetes()
	require.NotNil(t, src)
	require.Equal(t, "cluster-a", src.GetClusterName())
	require.Equal(t, "client-ns", src.GetNamespace())
	require.Equal(t, "client-pod", src.GetPodName())
	require.Equal(t, "client-pod", src.GetResourceName())
	require.Equal(t, typeV1.ResourceKind_RESOURCE_KIND_WORKLOAD, src.GetResourceKind())
	require.Equal(t, typeV1.WorkloadKind_WORKLOAD_KIND_POD, src.GetWorkloadKind())
	require.Equal(t, "10.0.0.1", src.GetIp())
	require.Equal(t, uint32(32000), src.GetPort())
	require.Equal(t, netV1.IPProtocol_IP_PROTOCOL_TCP, src.GetIpProtocol())

	dst := conn.GetDestination().GetKubernetes()
	require.NotNil(t, dst)
	require.Equal(t, "server-pod", dst.GetResourceName())
	require.Equal(t, "10.0.0.2", dst.GetIp())
	require.Equal(t, uint32(443), dst.GetPort())
	require.Equal(t, netV1.IPProtocol_IP_PROTOCOL_TCP, dst.GetIpProtocol())
}

func TestFlowstatToConnectionWorldTuple(t *testing.T) {
	tests := []struct {
		name       string
		flow       *flowpb.Flow
		assertConn func(*testing.T, *graphV1.Connection)
	}{
		{
			name: "pod to world",
			flow: func() *flowpb.Flow {
				flow := formatTestFlow(
					formatTestPodEndpoint(1001, "cluster-a", "client-ns", "client-pod"),
					&flowpb.Endpoint{Identity: uint32(identity.ReservedIdentityWorld)},
					"10.0.0.1",
					"203.0.113.10",
					32000,
					443,
					flowpb.Verdict_FORWARDED,
				)
				flow.DestinationNames = []string{"api.example.com"}
				return flow
			}(),
			assertConn: func(t *testing.T, conn *graphV1.Connection) {
				require.NotNil(t, conn.GetSource().GetKubernetes())
				world := conn.GetDestination().GetWorldEntity()
				require.NotNil(t, world)
				require.Equal(t, "api.example.com", world.GetDnsName())
				require.Equal(t, "203.0.113.10", world.GetIp())
				require.Equal(t, uint32(443), world.GetPort())
				require.Equal(t, netV1.IPProtocol_IP_PROTOCOL_TCP, world.GetIpProtocol())
			},
		},
		{
			name: "world to pod",
			flow: func() *flowpb.Flow {
				flow := formatTestFlow(
					&flowpb.Endpoint{Identity: uint32(identity.ReservedIdentityWorldIPv4)},
					formatTestPodEndpoint(1001, "cluster-a", "server-ns", "server-pod"),
					"203.0.113.10",
					"10.0.0.1",
					443,
					32000,
					flowpb.Verdict_FORWARDED,
				)
				flow.SourceNames = []string{"api.example.com"}
				return flow
			}(),
			assertConn: func(t *testing.T, conn *graphV1.Connection) {
				world := conn.GetSource().GetWorldEntity()
				require.NotNil(t, world)
				require.Equal(t, "api.example.com", world.GetDnsName())
				require.Equal(t, "203.0.113.10", world.GetIp())
				require.Equal(t, uint32(443), world.GetPort())
				require.Equal(t, netV1.IPProtocol_IP_PROTOCOL_TCP, world.GetIpProtocol())
				require.NotNil(t, conn.GetDestination().GetKubernetes())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newConnLogDB()
			db.add(tt.flow)
			tt.assertConn(t, formatTestSingleConnection(t, db))
		})
	}
}

func TestFlowstatToConnectionHostTuple(t *testing.T) {
	flow := formatTestFlow(
		&flowpb.Endpoint{Identity: uint32(identity.ReservedIdentityHost)},
		formatTestPodEndpoint(1002, "cluster-a", "server-ns", "server-pod"),
		"10.0.0.10",
		"10.0.0.2",
		12345,
		8080,
		flowpb.Verdict_FORWARDED,
	)
	flow.NodeName = "node-a"

	db := newConnLogDB()
	db.add(flow)
	host := formatTestSingleConnection(t, db).GetSource().GetKubernetes()
	require.NotNil(t, host)
	require.Equal(t, "node-a", host.GetNodeName())
	require.Equal(t, "10.0.0.10", host.GetIp())
	require.Equal(t, uint32(12345), host.GetPort())
	require.Equal(t, netV1.IPProtocol_IP_PROTOCOL_TCP, host.GetIpProtocol())
}

func TestFlowstatToConnectionRoutingObservations(t *testing.T) {
	t.Run("mixed outcomes", func(t *testing.T) {
		db := newConnLogDB()
		for _, verdict := range []flowpb.Verdict{
			flowpb.Verdict_FORWARDED,
			flowpb.Verdict_DROPPED,
			flowpb.Verdict_ERROR,
			flowpb.Verdict_AUDIT,
			flowpb.Verdict_REDIRECTED,
			flowpb.Verdict_TRACED,
			flowpb.Verdict_TRANSLATED,
		} {
			db.add(formatTestFlow(
				formatTestPodEndpoint(1001, "cluster-a", "client-ns", "client-pod"),
				formatTestPodEndpoint(1002, "cluster-a", "server-ns", "server-pod"),
				"10.0.0.1",
				"10.0.0.2",
				32000,
				443,
				verdict,
			))
		}

		routing := formatTestSingleConnection(t, db).GetLinks()[0].GetRoutingTelemetry()
		require.NotNil(t, routing)
		require.Equal(t, uint64(1), routing.GetRoutingForwardedTotal())
		require.Equal(t, uint64(1), routing.GetRoutingDroppedTotal())
		require.Equal(t, uint64(1), routing.GetRoutingErrorTotal())
		require.Equal(t, uint64(1), routing.GetRoutingAuditTotal())
		require.Equal(t, uint64(1), routing.GetRoutingRedirectedTotal())
		require.Equal(t, uint64(1), routing.GetRoutingTracedTotal())
		require.Equal(t, uint64(1), routing.GetRoutingTranslatedTotal())
	})

	t.Run("dropped only", func(t *testing.T) {
		db := newConnLogDB()
		db.add(formatTestFlow(
			formatTestPodEndpoint(1001, "cluster-a", "client-ns", "client-pod"),
			formatTestPodEndpoint(1002, "cluster-a", "server-ns", "server-pod"),
			"10.0.0.1",
			"10.0.0.2",
			32000,
			443,
			flowpb.Verdict_DROPPED,
		))

		routing := formatTestSingleConnection(t, db).GetLinks()[0].GetRoutingTelemetry()
		require.Zero(t, routing.GetRoutingForwardedTotal())
		require.Equal(t, uint64(1), routing.GetRoutingDroppedTotal())
	})
}

func BenchmarkFlowstatToConnection(b *testing.B) {
	k := flowstatkey{
		srcIP:      "10.0.0.1",
		dstIP:      "10.0.0.2",
		srcID:      1001,
		dstID:      1002,
		srcPort:    32000,
		dstPort:    443,
		ipProtocol: netV1.IPProtocol_IP_PROTOCOL_TCP,
	}
	v := flowstatval{
		source: endpointMetadata{
			identity:    1001,
			clusterName: "cluster-a",
			namespace:   "client-ns",
			podName:     "client-pod",
		},
		destination: endpointMetadata{
			identity:    1002,
			clusterName: "cluster-a",
			namespace:   "server-ns",
			podName:     "server-pod",
		},
		forwarded: 1,
		dropped:   1,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = flowstatToConnection(k, v)
	}
}

func formatTestSingleConnection(t *testing.T, db *connLogDB) *graphV1.Connection {
	t.Helper()

	store := db.reset()
	require.Len(t, store, 1)
	for k, v := range store {
		conn := flowstatToConnection(k, v)
		require.NotNil(t, conn)
		return conn
	}
	return nil
}

func formatTestPodEndpoint(identity uint32, cluster, namespace, pod string) *flowpb.Endpoint {
	return &flowpb.Endpoint{
		Identity:    identity,
		ClusterName: cluster,
		Namespace:   namespace,
		PodName:     pod,
	}
}

func formatTestFlow(
	source, destination *flowpb.Endpoint,
	sourceIP, destinationIP string,
	sourcePort, destinationPort uint32,
	verdict flowpb.Verdict,
) *flowpb.Flow {
	return &flowpb.Flow{
		Verdict: verdict,
		IP: &flowpb.IP{
			Source:      sourceIP,
			Destination: destinationIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      sourcePort,
					DestinationPort: destinationPort,
				},
			},
		},
		Source:      source,
		Destination: destination,
	}
}

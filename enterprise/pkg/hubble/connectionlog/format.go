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
	typeV1 "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	netV1 "github.com/isovalent/ipa/common/net/v1alpha"
	commonV1 "github.com/isovalent/ipa/common/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

var (
	// emitterName holds the name reported in the ConnectionLog's Emitter field.
	emitterName string = "Hubble"
	// emitterVersion holds the version string reported in the ConnectionLog's
	// Emitter field.
	emitterVersion string
)

func init() {
	ciliumVersion := version.GetCiliumVersion()
	emitterVersion = ciliumVersion.Version
}

// flowstatToConnection convert a flowstats val into a graphV1 Connection.
func flowstatToConnection(k flowstatkey, v flowstatval) *graphV1.Connection {
	src, dst := flowToVertices(k, v)
	if src == nil || dst == nil {
		return nil
	}
	link := flowstatvalEdge(v)
	return &graphV1.Connection{
		Source:      src,
		Destination: dst,
		Links:       []*graphV1.Edge{link},
	}
}

// flowToVertices extract a pair of graphV1 Vertices source and destination
// from a flowstatval.
func flowToVertices(k flowstatkey, v flowstatval) (src, dst *graphV1.Vertex) {
	src = endpointToVertex(
		v.source,
		k.srcIP,
		k.srcPort,
		k.ipProtocol,
	)
	dst = endpointToVertex(
		v.destination,
		k.dstIP,
		k.dstPort,
		k.ipProtocol,
	)
	return
}

// flowstatvalEdge extract a graphV1 Edge from a flowstatval.
func flowstatvalEdge(v flowstatval) *graphV1.Edge {
	return &graphV1.Edge{
		Type: &graphV1.Edge_RoutingTelemetry{
			RoutingTelemetry: &graphV1.EdgeTypeRoutingTelemetry{
				RoutingForwardedTotal:  v.forwarded,
				RoutingDroppedTotal:    v.dropped,
				RoutingErrorTotal:      v.errored,
				RoutingAuditTotal:      v.audited,
				RoutingRedirectedTotal: v.redirected,
				RoutingTracedTotal:     v.traced,
				RoutingTranslatedTotal: v.translated,
			},
		},
	}
}

// may return nil if the given endpoint should be ignored.
func endpointToVertex(ep endpointMetadata, addr string, port uint32, protocol netV1.IPProtocol) *graphV1.Vertex {
	id := identity.NumericIdentity(ep.identity)
	// Handle world specifically since it has a dedicated type representation
	// at the in the graphV1 API.
	switch id {
	case identity.ReservedIdentityWorld,
		identity.ReservedIdentityWorldIPv4,
		identity.ReservedIdentityWorldIPv6:
		return &graphV1.Vertex{
			Family: &graphV1.Vertex_WorldEntity{
				WorldEntity: &graphV1.VertexFamilyWorldEntity{
					DnsName:    ep.dnsName,
					Ip:         addr,
					Port:       port,
					IpProtocol: protocol,
				},
			},
		}
	}

	// Initialize a Kubernetes vertex with all the info shared between reserved
	// identites and Pods.
	k8s := &graphV1.VertexFamilyKubernetes{
		// Don't fill in k8s Resource related stuff besides
		// ResourceKind nor NodeName and ContainerName as the info are
		// missing from Hubble flows. endpointManager could provide
		// them but at an additional overhead cost.
		ClusterName: ep.clusterName,
		Namespace:   ep.namespace,
		PodName:     ep.podName,
		Ip:          addr,
		Port:        port,
		IpProtocol:  protocol,
	}

	// NOTE: world identites have already been handled earlier.
	switch id {
	// TODO: figure out which other reserved identities we wish to handle as
	// exception, if any. If we choose to ignore e.g. ReservedIdentityUnmanaged
	// or else maybe it would make sense to filter them out earlier at the
	// connLogger level.
	case identity.ReservedIdentityHost:
		// the only case where we're sure to know the node name.
		k8s.NodeName = ep.nodeName
	default: // non-reserved identity handling.
		if ep.podName == "" {
			// Not a Pod, maybe a health-check etc. not filtered by the
			// connLogger. Ignore it since we cannot represent it meaningfully
			// in the graphV1 API.
			// TODO: have some kind of metrics for the ignored vertices?
			return nil
		}
		// NOTE: should we try ep.GetWorkloads() and adapt k8s.WorkloadKind
		// accordingly?
		k8s.ResourceName = ep.podName
		k8s.WorkloadKind = typeV1.WorkloadKind_WORKLOAD_KIND_POD
		k8s.ResourceKind = typeV1.ResourceKind_RESOURCE_KIND_WORKLOAD
	}

	return &graphV1.Vertex{
		Family: &graphV1.Vertex_Kubernetes{
			Kubernetes: k8s,
		},
	}
}

func connectionLog(from, to time.Time, connections []*graphV1.Connection) *graphV1.ConnectionLog {
	return &graphV1.ConnectionLog{
		Emitter: &commonV1.Emitter{
			Name:    emitterName,
			Version: emitterVersion,
		},
		WindowStart: timestamppb.New(from),
		WindowEnd:   timestamppb.New(to),
		Connections: connections,
	}
}

# Graph API documentation and overall concepts

## Overview

The graph API is a protobuf based API that enables data sources to export
connection events that a client can query to render arbitrary graphs.

The graph API is the spiritual successor to the Hubble v1 API for using
networking data to draw graph representations of networking concepts. Although
the initial use cases revolve around networking, the API is extensible and
adapts to any kind of connection as new `Edge` and `Vertex` types are added.
This extensibility allows rendering almost arbitrary graphs, as long as the
underlying data is available.

### Relationship to Hubble Flow

The graph API is complementary to the Hubble Flow API. Both APIs serve different
purposes and work together:

#### Comparison table

| Aspect | Hubble Flow API | Graph API (Connection Logs) |
|--------|-----------------|----------------------------|
| **Purpose** | Individual flow observability and troubleshooting | Aggregated graph visualization and analysis |
| **Granularity** | Discrete events at a specific point in time | Time-windowed aggregations of connections between endpoints |
| **Data model** | Rich, detailed `Flow` message tightly coupled to networking concepts found in Cilium (L2/L3/L4/L7 details, verdict, drop reasons, policy matching, trace information) | `Connection` with separate `Vertex` (endpoint properties) and `Edge` (aggregatable telemetry data) |
| **Use cases** | Real-time monitoring, troubleshooting connectivity issues, policy troubleshooting | Service dependency mapping, traffic patterns visualization, capacity planning, network policy coverage analysis, high-level observability |
| **Output** | Stream of individual flow events as they happen | Periodic connection logs with pre-aggregated metrics |
| **Event model** | Individual flow events | Aggregated connection summaries |
| **Timestamp** | Single point in time | Time window (start/end) |
| **Metrics** | Instantaneous values | Aggregated telemetry data |
| **Volume** | High (one event per flow) | Low (one event per vertex pair per window) |
| **Aggregation** | Limited (connection or identity) | Built-in at source and query time |
| **Extensibility** | Fixed schema | Extensible vertex/edge types |

#### Why a new event type?

Connection logs were created to address specific limitations when using Hubble
Flow for graph visualization:

1. **Volume reduction**: Hubble Flow can generate millions of events per second.
   For graph visualization, this needs to be aggregated. The graph API
   aggregates at the source, which reduces the load on the network as well as
   when storing and processing data.

2. **Graph-optimized structure**: Separating vertex properties from edge
   telemetry enables flexible client-side grouping and aggregation without
   re-parsing complex flow structures.

3. **Extensibility**: Developers can add new vertex families and edge types without
   breaking existing clients. Hubble Flow's schema is more tightly coupled to
   networking concepts found in Cilium.

4. **Storage efficiency**: Aggregated connection logs require significantly less
   storage than raw flow events for long-term retention.

#### Using both together

The APIs are complementary:
- Use **Hubble Flow** for real-time troubleshooting, policy verification, and
  detailed flow inspection
- Use **Graph API** for visualizing service maps, analyzing traffic patterns,
  and understanding system topology over time
- Emitters like Hubble can generate both Flow events and Connection logs from
  the same observations

## Core concepts

### Data model

The graph API consists of four main components:

1. **ConnectionLog**: A time-windowed message emitted by a data source
2. **Connection**: A directed graph with source vertex → destination vertex
   linked by edges
3. **Vertex**: Properties of a connection endpoint (source or destination)
4. **Edge**: Aggregatable telemetry properties of the connection

#### Complete example: Kubernetes pod-to-pod connection

Here's a complete example of a ConnectionLog containing a single connection
between two Kubernetes pods with multiple edge types:

```json5
{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "emitter": {
    "name": "Hubble",
    "version": "1.16.0",
    // source_identifier is optional; set it to distinguish between multiple
    // instances of the same emitter (e.g., Cilium agents on different nodes,
    // or a smart switch serial number).
    "source_identifier": "node-us-west-1a"
  },
  "window_start": "2026-03-26T10:00:00Z",
  "window_end": "2026-03-26T10:00:10Z",
  "connections": [{
    "source": {
      "kubernetes": {
        "cluster_name": "prod-us-west",
        "namespace": "frontend",
        "pod_name": "web-server-abc123",
        "resource_kind": "RESOURCE_KIND_WORKLOAD",
        "resource_name": "web-server-abc123",
        "ip": "10.0.1.50",
        "port": 8080,
        "ip_protocol": "IP_PROTOCOL_TCP"
      }
    },
    "destination": {
      "kubernetes": {
        "cluster_name": "prod-us-west",
        "namespace": "backend",
        "pod_name": "api-service-def456",
        "resource_kind": "RESOURCE_KIND_WORKLOAD",
        "resource_name": "api-service-def456",
        "ip": "10.0.2.100",
        "port": 9090,
        "ip_protocol": "IP_PROTOCOL_TCP"
      }
    },
    "links": [
      {
        "network_telemetry": {
          "network_transmit_packets_total": 1250,
          "network_transmit_bytes_total": 523400,
          "network_transmit_drop_total": 0,
          "network_receive_packets_total": 1180,
          "network_receive_bytes_total": 89200
        }
      },
      {
        "l4_telemetry": {
          "tcp_retransmits_total": 3,
          "tcp_zero_window_total": 0,
          "tcp_resets_total": 0
        }
      },
      {
        "l7_telemetry": {
          "http_requests_total": 450,
          "http_server_errors_total": 2,
          "http_client_errors_total": 15
        }
      }
    ]
  }]
}
```

This example shows:
- A 10-second observation window
- Network-level metrics (packets, bytes)
- Transport-level metrics (TCP retransmits)
- Application-level metrics (HTTP requests and errors)

All metrics are aggregated over the time window for this specific
source/destination pair.

#### Example: network device connection

The graph API also supports network devices as vertices:

```json5
{
  "source": {
    "network_device": {
      "name": "switch-01",
      "ip": "192.168.1.1",
      "interface_name": "eth0",
      "vlan_name": "production",
      "vlan_id": 100
    }
  },
  "destination": {
    "network_device": {
      "name": "router-02",
      "ip": "192.168.1.254",
      "interface_name": "eth1",
      "vlan_name": "production",
      "vlan_id": 100
    }
  },
  "links": [{
    "routing_telemetry": {
      "routing_forwarded_total": 125000,
      "routing_dropped_total": 45,
      "routing_dropped_policy_total": 12
    }
  }]
}
```

#### Example: Kubernetes service to external endpoint

Connections can span different vertex families:

```json5
{
  "source": {
    "kubernetes": {
      "cluster_name": "prod-us-west",
      "namespace": "backend",
      "resource_kind": "RESOURCE_KIND_SERVICE",
      "resource_name": "api-gateway",
      "service_kind": "SERVICE_KIND_CLUSTER_IP",
      "ip": "10.96.0.50",
      "port": 443,
      "ip_protocol": "IP_PROTOCOL_TCP"
    }
  },
  "destination": {
    "world_entity": {
      "dns_name": "api.external-service.com",
      "ip": "203.0.113.45",
      "port": 443,
      "ip_protocol": "IP_PROTOCOL_TCP"
    }
  },
  "links": [{
    "l7_telemetry": {
      "http_requests_total": 89,
      "http_server_errors_total": 0,
      "http_client_errors_total": 4
    }
  }]
}
```

### Data aggregation

One of the core concepts of the graph API is data aggregation. With the concept
of a time window, data aggregates at the source that emits connection
events and also at query time to cover different time windows. Aggregation
drastically reduces the number of connection log messages to process. To enable
this property, all of the metadata on the edge of a connection must support
aggregation by some function, typically `SUM`.

#### How aggregation works

Design all edge properties to support aggregation using an appropriate function.
The aggregation function depends on the type of telemetry data:

- **Counters** (most common): aggregated using `SUM`
  - Examples: packet counts, byte counts, request counts, error counts
  - `total_packets = sum(packets_window1, packets_window2, ...)`

- **Histograms**: aggregated by summing bucket counts
  - Example: `EdgeTypeMulticastTelemetry.FeederReceiverDelayHistogram`
  - Each bucket count is summed independently across time windows

- **Future telemetry types** could use other aggregation functions:
  - `MAX`: for maximum latency observed
  - `MIN`: for minimum throughput observed
  - `AVG`: for average values (requires storing sum + count)
  - Percentiles or other statistical aggregates

The current API primarily uses counter-based telemetry (aggregated via `SUM`),
but the design supports extending to other aggregatable property types as new
edge types are added.

#### Source-time aggregation

At the source (emitter), connections are aggregated within a time window.
Instead of emitting a separate event for each individual observation, the
emitter aggregates all observations for the same vertex pair during the time
window into a single `Connection` with aggregated edge properties.

For example, if a data emitter observes HTTP traffic between Pod A and Pod B
during a 10-second window:

**Before aggregation (individual observations):**
```
t=0s:  Pod A → Pod B: 50 HTTP requests, 2 errors (4xx)
t=3s:  Pod A → Pod B: 30 HTTP requests, 0 errors
t=6s:  Pod A → Pod B: 45 HTTP requests, 1 error (5xx)
t=9s:  Pod A → Pod B: 25 HTTP requests, 3 errors (4xx)
```

**After source-time aggregation (single ConnectionLog):**
```json5
{
  "window_start": "t=0s",
  "window_end": "t=10s",
  "connections": [{
    "source": "Pod A",
    "destination": "Pod B",
    "links": [{
      "l7_telemetry": {
        "http_requests_total": 150,         // SUM: 50 + 30 + 45 + 25
        "http_client_errors_total": 5,      // SUM: 2 + 0 + 0 + 3
        "http_server_errors_total": 1       // SUM: 0 + 0 + 1 + 0
      }
    }]
  }]
}
```

This approach drastically reduces the number of events that need to be
transmitted, stored, and processed.

#### Query-time aggregation

At query time, clients can aggregate across multiple time windows or across
multiple connections by grouping vertices differently.

**Aggregating across time windows:**

Two `ConnectionLog` messages for the same vertex pair with consecutive time
windows can be aggregated to show totals over a longer period:

```
Window 1 (0-10s): Pod A → Pod B, 150 HTTP requests, 5 client errors
Window 2 (10-20s): Pod A → Pod B, 180 HTTP requests, 8 client errors
---
Aggregated (0-20s): Pod A → Pod B, 330 HTTP requests, 13 client errors
```

**Aggregating by grouping vertices:**

Clients can group connections by higher-level vertex attributes. For example,
instead of viewing pod-to-pod connections, group by namespace.

Before grouping (pod-level granularity):
```json5
// Connection 1
{
  "source": {"kubernetes": {"namespace": "frontend", "pod_name": "web-abc"}},
  "destination": {"kubernetes": {"namespace": "backend", "pod_name": "api-xyz"}},
  "links": [{"l7_telemetry": {"http_requests_total": 150}}]
}

// Connection 2
{
  "source": {"kubernetes": {"namespace": "frontend", "pod_name": "web-def"}},
  "destination": {"kubernetes": {"namespace": "backend", "pod_name": "api-xyz"}},
  "links": [{"l7_telemetry": {"http_requests_total": 120}}]
}

// Connection 3
{
  "source": {"kubernetes": {"namespace": "frontend", "pod_name": "web-abc"}},
  "destination": {"kubernetes": {"namespace": "backend", "pod_name": "db-mno"}},
  "links": [{"l7_telemetry": {"http_requests_total": 80}}]
}
```

After grouping by namespace (namespace-level granularity):
```json5
{
  "source": {"kubernetes": {"namespace": "frontend"}},
  "destination": {"kubernetes": {"namespace": "backend"}},
  "links": [{"l7_telemetry": {"http_requests_total": 350}}]  // SUM: 150 + 120 + 80
}
```

The client created a new aggregated vertex by selecting only the `namespace`
attribute and dropping pod-specific attributes like `pod_name`. All connections
sharing the same grouped source and destination are combined using the
aggregation function.

This is why all edge properties must support aggregation—it enables flexible
aggregation at any level without losing data fidelity. When adding new edge
types, ensure all properties have a well-defined aggregation function.

### Generic querying

Another core concept of the graph API is that while the source of connection
data may be very specific, which allows for database optimizations, the querying
facility is generic and flexible. In other words, clients can query for various
types of connections using the same query concepts. This property allows clients
to render graphs that represent varying data using the same rendering engine and code.

## Requirements for data emitters

### Emitting connection data with multiple edge types

Data emitters such as Hubble and Tetragon MUST include all applicable edge types
for a given connection within a single `Connection` message. Each connection is
defined by a unique pair of source and destination vertices, and the `links`
field contains all edge types that apply to that connection during the time
window.

For example, a TCP connection between Pod A and Pod B that carries HTTP traffic
requires emitting a **single** `Connection` per time window with:
- `source`: Pod A vertex properties
- `destination`: Pod B vertex properties
- `links`: array containing **multiple** edge types:
  - `EdgeTypeNetworkTelemetry` (packet counts, bytes, drops)
  - `EdgeTypeL4Telemetry` (TCP retransmits, resets, zero windows)
  - `EdgeTypeL7Telemetry` (HTTP request counts, error rates)

#### Correct approach
```json5
{
  "window_start": "2026-03-26T10:00:00Z",
  "window_end": "2026-03-26T10:00:10Z",
  "connections": [{
    "source": {
      "kubernetes": {
        "namespace": "frontend",
        "pod_name": "pod-a",
        "ip": "10.0.1.10",
        "port": 8080
      }
    },
    "destination": {
      "kubernetes": {
        "namespace": "backend",
        "pod_name": "pod-b",
        "ip": "10.0.2.20",
        "port": 9090
      }
    },
    "links": [
      {
        "network_telemetry": {
          "network_transmit_packets_total": 1500,
          "network_transmit_bytes_total": 750000
        }
      },
      {
        "l4_telemetry": {
          "tcp_retransmits_total": 2,
          "tcp_resets_total": 0
        }
      },
      {
        "l7_telemetry": {
          "http_requests_total": 350,
          "http_client_errors_total": 5
        }
      }
    ]
  }]
}
```

#### Incorrect approach (DO NOT DO THIS)
```json5
{
  // Don't emit separate connections for the same vertex pair
  "connections": [
    {
      "source": {"kubernetes": {"pod_name": "pod-a"}},
      "destination": {"kubernetes": {"pod_name": "pod-b"}},
      "links": [{"network_telemetry": {"network_transmit_packets_total": 1500}}]
    },
    {
      "source": {"kubernetes": {"pod_name": "pod-a"}},
      "destination": {"kubernetes": {"pod_name": "pod-b"}},
      "links": [{"l4_telemetry": {"tcp_retransmits_total": 2}}]
    },
    {
      "source": {"kubernetes": {"pod_name": "pod-a"}},
      "destination": {"kubernetes": {"pod_name": "pod-b"}},
      "links": [{"l7_telemetry": {"http_requests_total": 350}}]
    }
  ]
}
```

**Why this is incorrect**

This approach creates three separate `Connection` messages for the same vertex
pair (pod-a → pod-b), with each connection containing only one edge type. This
violates the data model: three connection objects consume more memory, bandwidth,
and storage than a single connection with three edges.

Instead, combine all edge types into a single `Connection` with multiple entries
in the `links` array, as shown in the correct example above.

Each edge type in the `links` array MUST be different. A connection cannot
include two `EdgeTypeNetworkTelemetry` edges, but can include one of each
available edge type that is relevant to the connection.

### Vertex property constraints

Vertex properties MUST be scalar values, not collections or complex types. This
constraint exists because clients create arbitrary vertices by grouping one or
more source and destination vertex attributes. Non-scalar properties require
unrolling or flattening. However, showing too much information in a graph
provides little value. Add unique identifiers to vertex properties so clients
can query other data sources to obtain more information about a given vertex.

#### Why scalar properties only?

When clients aggregate connections by grouping vertices, they select specific
vertex attributes to group by. This only works if properties are scalar values
that can be used as grouping keys.

For example, grouping by namespace works because namespace is a scalar string:
```
Group by: source.kubernetes.namespace
Result: All pods in "frontend" namespace are treated as one vertex
```

If properties were collections (arrays, maps), grouping becomes ambiguous:
- How does grouping work with an array of labels?
- Which element of the array defines the group?
- How do vertices with different array lengths get handled?

#### Best practices

1. **Keep it minimal**: Only include vertex properties that are useful for
   grouping and graph visualization. Graphs become cluttered with too much
   information.

2. **Use identifiers**: For complex metadata, store a UID in the vertex and let
   clients query external systems (Kubernetes API, Timescape, etc.) for details.

3. **Connection-specific values**: Vertex properties should reflect the values
   relevant to that specific connection. If a pod has multiple IPs, use the IP
   actually involved in the connection.

4. **Think about grouping**: Ask "would someone want to group by this property?"
   If no, consider whether it belongs in the vertex at all.

## Validation rules

This section documents all the mandatory (MUST/MUST NOT) and recommended
(SHOULD/SHOULD NOT) constraints for implementing and using the graph API.

### ConnectionLog constraints

**MUST:**
- Each `ConnectionLog` MUST have a unique `uuid` to identify the event
- `window_start` MUST be before `window_end`
- The `connections` array MUST contain at least one `Connection` if the
  ConnectionLog is emitted (emitters MAY choose not to emit if no connections
  were observed)

**SHOULD NOT:**
- Emitters SHOULD NOT re-emit the same `ConnectionLog` events (identified by
  `uuid`)
- `ConnectionLog` events SHOULD NOT have overlapping time windows for the same
  vertex pairs from the same emitter

### Connection constraints

**MUST:**
- Each `Connection` MUST have exactly one `source` vertex
- Each `Connection` MUST have exactly one `destination` vertex
- The `links` array MUST contain at least one `Edge`
- If multiple edges are provided in `links`, each edge type MUST be different
  (e.g., a connection cannot have two `EdgeTypeNetworkTelemetry` edges in the
  same connection)

**MUST NOT:**
- Do NOT emit multiple separate `Connection` messages for the same source and
  destination vertex pair within the same time window. Instead, combine all edge
  types into a single `Connection` with multiple entries in the `links` array.

### Vertex constraints

**MUST:**
- All vertex properties MUST be scalar values (strings, numbers, enums)
- Each vertex MUST belong to exactly one vertex family (e.g., `kubernetes`,
  `network_device`, or `world_entity`)
- Vertex properties MUST represent values relevant to the specific connection
  being described

**MUST NOT:**
- Vertex properties MUST NOT be collections (arrays, maps) or complex nested
  objects
- Vertex properties MUST NOT contain non-scalar data without flattening it first

### Edge constraints

**MUST:**
- All edge properties MUST be aggregatable using a well-defined function
  (typically `SUM` for counters, bucket summation for histograms)
- Edge property names for counters SHOULD use the `_total` suffix to indicate
  they are cumulative values over the time window
- Each edge MUST belong to exactly one edge type (e.g., `network_telemetry`,
  `l4_telemetry`, `l7_telemetry`, etc.)

### Data emitter requirements

**MUST:**
- Emitters MUST include all applicable edge types for a connection in a single
  `Connection` message
- Emitters MUST aggregate observations within their time window before emitting
- Emitters MUST set both `window_start` and `window_end` to define the
  aggregation period
- Emitters MUST populate the `emitter` field to identify the source of the data

**SHOULD:**
- Emitters SHOULD use non-overlapping time windows for better query-time
  aggregation
- Emitters SHOULD emit ConnectionLog events at regular intervals
- Time windows SHOULD be aligned to regular boundaries (e.g., every 10 seconds
  starting at :00, :10, :20, etc.)
- Emitters SHOULD populate `source_identifier` when multiple instances of the
  same emitter can run concurrently (e.g., one Cilium agent per node, or an HA
  pair of smart switches) to allow consumers to deduplicate or attribute events
  to a specific instance

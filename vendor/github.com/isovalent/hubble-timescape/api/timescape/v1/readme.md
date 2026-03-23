# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [timescape/v1/file_source.proto](#timescape_v1_file_source-proto)
    - [FileSource](#timescape-v1-FileSource)
  
    - [Compression](#timescape-v1-Compression)
    - [ObjectType](#timescape-v1-ObjectType)
  
- [timescape/v1/coordinator.proto](#timescape_v1_coordinator-proto)
    - [GetFileSourceURIsRequest](#timescape-v1-GetFileSourceURIsRequest)
    - [GetFileSourceURIsResponse](#timescape-v1-GetFileSourceURIsResponse)
  
    - [CoordinatorService](#timescape-v1-CoordinatorService)
  
- [timescape/v1/flowmask.proto](#timescape_v1_flowmask-proto)
    - [FlowMask](#timescape-v1-FlowMask)
  
- [timescape/v1/time_filter.proto](#timescape_v1_time_filter-proto)
    - [TimeFilter](#timescape-v1-TimeFilter)
  
- [timescape/v1/flow.proto](#timescape_v1_flow-proto)
    - [FlowCount](#timescape-v1-FlowCount)
    - [GetFlowCountRequest](#timescape-v1-GetFlowCountRequest)
    - [GetFlowCountResponse](#timescape-v1-GetFlowCountResponse)
    - [GetFlowRequest](#timescape-v1-GetFlowRequest)
    - [GetFlowResponse](#timescape-v1-GetFlowResponse)
    - [GetFlowsSummaryRequest](#timescape-v1-GetFlowsSummaryRequest)
    - [GetFlowsSummaryResponse](#timescape-v1-GetFlowsSummaryResponse)
    - [GetNamespacesRequest](#timescape-v1-GetNamespacesRequest)
    - [GetNamespacesResponse](#timescape-v1-GetNamespacesResponse)
    - [Namespace](#timescape-v1-Namespace)
    - [TSFlow](#timescape-v1-TSFlow)
  
    - [FlowService](#timescape-v1-FlowService)
  
- [timescape/v1/k8s_events.proto](#timescape_v1_k8s_events-proto)
    - [GetActiveK8sResourcesFilter](#timescape-v1-GetActiveK8sResourcesFilter)
    - [GetActiveK8sResourcesRequest](#timescape-v1-GetActiveK8sResourcesRequest)
    - [GetActiveK8sResourcesResponse](#timescape-v1-GetActiveK8sResourcesResponse)
    - [GetK8sEventsRequest](#timescape-v1-GetK8sEventsRequest)
    - [GetK8sEventsResponse](#timescape-v1-GetK8sEventsResponse)
    - [GetK8sLatestEventsRequest](#timescape-v1-GetK8sLatestEventsRequest)
    - [GetK8sLatestEventsResponse](#timescape-v1-GetK8sLatestEventsResponse)
    - [K8sEventFilter](#timescape-v1-K8sEventFilter)
    - [K8sLatestEventFilter](#timescape-v1-K8sLatestEventFilter)
    - [K8sResource](#timescape-v1-K8sResource)
  
    - [EventField](#timescape-v1-EventField)
    - [GetK8sEventsRequest.ResultsOrder](#timescape-v1-GetK8sEventsRequest-ResultsOrder)
    - [GetK8sLatestEventsRequest.ResultsOrder](#timescape-v1-GetK8sLatestEventsRequest-ResultsOrder)
  
    - [K8sEventService](#timescape-v1-K8sEventService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="timescape_v1_file_source-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1/file_source.proto



<a name="timescape-v1-FileSource"></a>

### FileSource
FileSource contains metadata about files in object storage or on disk.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uri | [string](#string) |  | uri is the URL of the file that was ingested. It is used to uniquely identify the file, so that we can keep track of the files already fully or partially ingested. It includes the bucket name. |
| compression | [Compression](#timescape-v1-Compression) |  | compression is the type of compression for the source_uri. |
| object_type | [ObjectType](#timescape-v1-ObjectType) |  | object_type defines the type of objects in the file. |
| mod_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | mod_time is the files mod time |
| size | [int64](#int64) |  | size is the file size in bytes |





 


<a name="timescape-v1-Compression"></a>

### Compression
Compression is an enum defining compression types.

| Name | Number | Description |
| ---- | ------ | ----------- |
| COMPRESSION_UNSPECIFIED | 0 | COMPRESSION_UNSPECIFIED means the type of compression of the file is unknown. |
| COMPRESSION_NONE | 1 | COMPRESSION_NONE means that the object is uncompressed. |
| COMPRESSION_GZIP | 2 | COMPRESSION_UNCOMPRESSED means that the object is compressed with gzip. |



<a name="timescape-v1-ObjectType"></a>

### ObjectType
ObjectType is the type of objects in a file

| Name | Number | Description |
| ---- | ------ | ----------- |
| OBJECT_TYPE_UNSPECIFIED | 0 | OBJECT_TYPE_UNSPECIFIED means the type of objects in the file is unknown. |
| OBJECT_TYPE_FLOW | 1 | OBJECT_TYPE_FLOW means the type of objects in the file are flows. |
| OBJECT_TYPE_TETRAGON_EVENT | 2 | OBJECT_TYPE_TETRAGON_EVENT means the type of objects in the file are FGS events. |
| OBJECT_TYPE_K8S_EVENT | 3 | OBJECT_TYPE_K8S_EVENT means the type of objects in the file are K8s events. |
| OBJECT_TYPE_SYSTEM_STATUS_EVENT | 4 | OBJECT_TYPE_SYSTEM_STATUS_EVENT marks the objects as system status events. |
| OBJECT_TYPE_CONNECTIONLOG_EVENT | 5 | OBJECT_TYPE_CONNECTIONLOG_EVENT means the type of objects in the file are graph API&#39;s ConnectionLog events. |
| OBJECT_TYPE_PROCESS_TREE_APP_MODEL_EVENT | 6 | OBJECT_TYPE_PROCESS_TREE_APP_MODEL_EVENT means the type of objects in the file are process tree application model events. |


 

 

 



<a name="timescape_v1_coordinator-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1/coordinator.proto



<a name="timescape-v1-GetFileSourceURIsRequest"></a>

### GetFileSourceURIsRequest
GetFileSourceURIsRequest is the request parameter for the GetFileSourceURIs
RPC.






<a name="timescape-v1-GetFileSourceURIsResponse"></a>

### GetFileSourceURIsResponse
GetFileSourceURIsResponse contains a response from the GetFileSourceURIs RPC
endpoint.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source | [FileSource](#timescape-v1-FileSource) |  | Source contains the metadata of the file to ingest. TODO: Should this be a list of FileSource, so we can send batches of files to ingesters, instead of sending one file at a time? |





 

 

 


<a name="timescape-v1-CoordinatorService"></a>

### CoordinatorService
CoordinatorService is a service that enables coordination amongst multiple
ingester replicas.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetFileSourceURIs | [GetFileSourceURIsRequest](#timescape-v1-GetFileSourceURIsRequest) | [GetFileSourceURIsResponse](#timescape-v1-GetFileSourceURIsResponse) stream | GetFileSourceURIs returns a stream of URIs to ingest. |

 



<a name="timescape_v1_flowmask-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1/flowmask.proto



<a name="timescape-v1-FlowMask"></a>

### FlowMask



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uuid | [bool](#bool) |  |  |
| emitter | [bool](#bool) |  |  |
| verdict | [bool](#bool) |  |  |
| drop_reason | [bool](#bool) |  |  |
| auth_type | [bool](#bool) |  |  |
| ethernet | [bool](#bool) |  |  |
| IP | [bool](#bool) |  |  |
| l4 | [bool](#bool) |  |  |
| tunnel | [bool](#bool) |  |  |
| source | [bool](#bool) |  |  |
| destination | [bool](#bool) |  |  |
| Type | [bool](#bool) |  |  |
| node_name | [bool](#bool) |  |  |
| node_labels | [bool](#bool) |  |  |
| source_names | [bool](#bool) |  |  |
| destination_names | [bool](#bool) |  |  |
| l7 | [bool](#bool) |  |  |
| reply | [bool](#bool) |  |  |
| event_type | [bool](#bool) |  |  |
| source_service | [bool](#bool) |  |  |
| destination_service | [bool](#bool) |  |  |
| traffic_direction | [bool](#bool) |  |  |
| policy_match_type | [bool](#bool) |  |  |
| trace_observation_point | [bool](#bool) |  |  |
| trace_reason | [bool](#bool) |  |  |
| file | [bool](#bool) |  |  |
| ip_trace_id | [bool](#bool) |  |  |
| drop_reason_desc | [bool](#bool) |  |  |
| is_reply | [bool](#bool) |  |  |
| debug_capture_point | [bool](#bool) |  |  |
| interface | [bool](#bool) |  |  |
| proxy_port | [bool](#bool) |  |  |
| trace_context | [bool](#bool) |  |  |
| sock_xlate_point | [bool](#bool) |  |  |
| socket_cookie | [bool](#bool) |  |  |
| cgroup_id | [bool](#bool) |  |  |
| Summary | [bool](#bool) |  |  |
| extensions | [bool](#bool) |  |  |
| egress_allowed_by | [bool](#bool) |  |  |
| ingress_allowed_by | [bool](#bool) |  |  |
| egress_denied_by | [bool](#bool) |  |  |
| ingress_denied_by | [bool](#bool) |  |  |
| policy_log | [bool](#bool) |  |  |
| aggregate | [bool](#bool) |  |  |





 

 

 

 



<a name="timescape_v1_time_filter-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1/time_filter.proto



<a name="timescape-v1-TimeFilter"></a>

### TimeFilter
TimeFilter is a filter that allows to specify a starting time, ending time
or time range.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| since | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | since defines the starting time for the filter (inclusive). |
| until | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | until defines the ending time for the filter (inclusive). |





 

 

 

 



<a name="timescape_v1_flow-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1/flow.proto



<a name="timescape-v1-FlowCount"></a>

### FlowCount
FlowCount is the result of a FlowCount operation.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| start | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Start is the time at which the time window starts. |
| count | [uint64](#uint64) |  | Count is the number of flows in the time window. |






<a name="timescape-v1-GetFlowCountRequest"></a>

### GetFlowCountRequest
GetFlowCountRequest for the GetFlowCount rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| limit | [uint64](#uint64) |  | Limit is the maximum number of results to return. |
| time_filter | [TimeFilter](#timescape-v1-TimeFilter) |  | Since and Until can be used to specify a time interval. |
| window | [uint64](#uint64) |  | If the duration window is not provided, the results are not aggregated by window. |
| include | [flow.FlowFilter](#flow-FlowFilter) | repeated | Include are filters that flows must match. |
| exclude | [flow.FlowFilter](#flow-FlowFilter) | repeated | Exclude are filters that flows must not match. |






<a name="timescape-v1-GetFlowCountResponse"></a>

### GetFlowCountResponse
GetFlowCountResponse for the GetFlowCount rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow_count | [FlowCount](#timescape-v1-FlowCount) |  | FlowCount returns the number of flows matching the query |






<a name="timescape-v1-GetFlowRequest"></a>

### GetFlowRequest
GetFlowRequest for the GetFlow rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | id of the flow as seen in the timescape data store |






<a name="timescape-v1-GetFlowResponse"></a>

### GetFlowResponse
GetFlowResponse for the GetFlow rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [flow.Flow](#flow-Flow) |  | flow information |






<a name="timescape-v1-GetFlowsSummaryRequest"></a>

### GetFlowsSummaryRequest
GetFlowsSummaryRequest for the GetFlows rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| limit | [uint64](#uint64) |  | Limit is the maximum number of results to return. Note that when aggregation is enabled limit is strictly an upper bound: if 10 results are returned when a limit of 100 was requested, there could be more aggregated flows than 10 matching the request. This is currently a limitation of the current implementation needed for performance reasons. |
| time_filter | [TimeFilter](#timescape-v1-TimeFilter) |  | Since and Until can be used to specify a time interval. |
| include | [flow.FlowFilter](#flow-FlowFilter) | repeated | Include are filters that flows must match. |
| exclude | [flow.FlowFilter](#flow-FlowFilter) | repeated | Exclude are filters that flows must not match. |
| mask | [FlowMask](#timescape-v1-FlowMask) |  | FlowMask controls which fields to inflate for each Flow in the response.

This gives control to the caller for how much information about each flow they would like returned back.

Omitting this field from the request will default to populating all fields of a Flow in response. |
| aggregation | [isovalent.flow.aggregation.Aggregation](#isovalent-flow-aggregation-Aggregation) |  | Aggregation is an aggregator configuration. |






<a name="timescape-v1-GetFlowsSummaryResponse"></a>

### GetFlowsSummaryResponse
GetFlowsSummaryResponse for the GetFlows rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [TSFlow](#timescape-v1-TSFlow) |  | Flow matching the request parameters. |






<a name="timescape-v1-GetNamespacesRequest"></a>

### GetNamespacesRequest
GetNamespacesRequest for the GetNamespaces rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time_filter | [TimeFilter](#timescape-v1-TimeFilter) |  | Since and Until can be used to specify a time interval. |






<a name="timescape-v1-GetNamespacesResponse"></a>

### GetNamespacesResponse
GetNamespacesResponse for the GetNamespaces rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [Namespace](#timescape-v1-Namespace) | repeated | Namespaces list |






<a name="timescape-v1-Namespace"></a>

### Namespace
Namespace represents a namespace.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name is the name of the namespace. |
| cluster | [string](#string) |  | Cluster is the cluster of the namespace. |






<a name="timescape-v1-TSFlow"></a>

### TSFlow
TSFlow wraps Hubble&#39;s flow.Flow definition with additional metadata.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | A unique identifier for the embedded flow. |
| flow | [flow.Flow](#flow-Flow) |  | Flow as created defined by the Hubble observer. |





 

 

 


<a name="timescape-v1-FlowService"></a>

### FlowService
FlowService is a service that offers network flow related information.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetFlow | [GetFlowRequest](#timescape-v1-GetFlowRequest) | [GetFlowResponse](#timescape-v1-GetFlowResponse) | GetFlow returns the flow that corresponds to the unique identifier. |
| GetFlowCount | [GetFlowCountRequest](#timescape-v1-GetFlowCountRequest) | [GetFlowCountResponse](#timescape-v1-GetFlowCountResponse) stream | GetFlowCount returns the flow count per time window. If the duration of the time window is 0, results are not aggregated by window. The filter parameter can be used to limit the scope to flows that match the filter (e.g. time range). |
| GetNamespaces | [GetNamespacesRequest](#timescape-v1-GetNamespacesRequest) | [GetNamespacesResponse](#timescape-v1-GetNamespacesResponse) | GetNamespaces returns a unique list of namespaces seen in flows or Kubernetes namespace events. |
| GetFlowsSummary | [GetFlowsSummaryRequest](#timescape-v1-GetFlowsSummaryRequest) | [GetFlowsSummaryResponse](#timescape-v1-GetFlowsSummaryResponse) stream | GetFlowsSummary allows retrieval of multiple flows at the same time. |

 



<a name="timescape_v1_k8s_events-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1/k8s_events.proto



<a name="timescape-v1-GetActiveK8sResourcesFilter"></a>

### GetActiveK8sResourcesFilter
GetActiveK8sResourcesFilter is a filter to be used in the GetActiveK8sResources include/exclude fields.
All fields are optional. If multiple fields are set, then all fields must
match for the filter to match.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| api_version | [string](#string) | repeated | api_version is the k8s apiVersion of the resource. |
| kind | [k8sevent.v1.Kind](#k8sevent-v1-Kind) | repeated | Filter by the k8s resource kind. |
| name | [string](#string) | repeated | Filter by the name of the k8s event. |
| namespace | [string](#string) | repeated | Filter by the k8s resource namespace. |
| cluster | [string](#string) | repeated | Filter by the k8s resource cluster. |






<a name="timescape-v1-GetActiveK8sResourcesRequest"></a>

### GetActiveK8sResourcesRequest
GetActiveK8sResourcesRequest for the GetActiveK8sResources rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| when | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | when is the point in time to check for active resources. |
| include | [GetActiveK8sResourcesFilter](#timescape-v1-GetActiveK8sResourcesFilter) | repeated | Include are filters that events must match. If multiple include filters are specified, only one of them has to match for a resource to be included. |
| exclude | [GetActiveK8sResourcesFilter](#timescape-v1-GetActiveK8sResourcesFilter) | repeated | Exclude are filters that events must not match. If multiple excluded filters are specified, only one of them has to match for a resource to be excluded. |
| field_mask | [google.protobuf.FieldMask](#google-protobuf-FieldMask) |  | FieldMask allows clients to limit event fields that will be returned. |






<a name="timescape-v1-GetActiveK8sResourcesResponse"></a>

### GetActiveK8sResourcesResponse
GetActiveK8sResourcesResponse for the GetActiveK8sResources rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| resource | [K8sResource](#timescape-v1-K8sResource) |  | resoruce is the k8s resource. |






<a name="timescape-v1-GetK8sEventsRequest"></a>

### GetK8sEventsRequest
GetK8sEventsRequest for the GetK8sEvents rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time_filter | [TimeFilter](#timescape-v1-TimeFilter) |  | TimeFilter is a filter that allows to specify a time interval. |
| include | [K8sEventFilter](#timescape-v1-K8sEventFilter) | repeated | Include are filters that events must match. If multiple include filters are specified, only one of them has to match for a flow to be included. |
| exclude | [K8sEventFilter](#timescape-v1-K8sEventFilter) | repeated | Exclude are filters that events must not match. If multiple excluded filters are specified, only one of them has to match for a flow to be excluded. |
| field_mask | [google.protobuf.FieldMask](#google-protobuf-FieldMask) |  | FieldMask allows clients to limit event fields that will be returned. |
| limit | [uint64](#uint64) |  | Limit is the maximum number of events to return. Defaults to the most recent (last) events, unless `first` is true, then it will return the earliest events. |
| distinct_on | [EventField](#timescape-v1-EventField) | repeated | Event fields to distinct by. Defaults to returning the most recent (last) distinct occurrence, unless `first` is true, then it will return the earliest occurrence. |
| first | [bool](#bool) |  | First specifies if we should look at the earliest (first) events or the most recent (last) events for both `limit` and `distinct_on`. |
| results_order | [GetK8sEventsRequest.ResultsOrder](#timescape-v1-GetK8sEventsRequest-ResultsOrder) |  | results_order specifies the expected order of the results. |






<a name="timescape-v1-GetK8sEventsResponse"></a>

### GetK8sEventsResponse
GetK8sEventsResponse for the GetK8sEvents rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event | [k8sevent.v1.Event](#k8sevent-v1-Event) |  | Event is the event information. |






<a name="timescape-v1-GetK8sLatestEventsRequest"></a>

### GetK8sLatestEventsRequest
GetK8sLatestEventsRequest for the GetK8sLatestEvents rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time_filter | [TimeFilter](#timescape-v1-TimeFilter) |  | TimeFilter is a filter that allows to specify a time interval. |
| include | [K8sLatestEventFilter](#timescape-v1-K8sLatestEventFilter) | repeated | Include are filters that events must match. If multiple include filters are specified, only one of them has to match for a flow to be included. |
| exclude | [K8sLatestEventFilter](#timescape-v1-K8sLatestEventFilter) | repeated | Exclude are filters that events must not match. If multiple excluded filters are specified, only one of them has to match for a flow to be excluded. |
| field_mask | [google.protobuf.FieldMask](#google-protobuf-FieldMask) |  | FieldMask allows clients to limit event fields that will be returned. |
| results_order | [GetK8sLatestEventsRequest.ResultsOrder](#timescape-v1-GetK8sLatestEventsRequest-ResultsOrder) |  | results_order specifies the expected order of the results. |






<a name="timescape-v1-GetK8sLatestEventsResponse"></a>

### GetK8sLatestEventsResponse
GetK8sLatestEventsResponse for the GetK8sLatestEvents rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event | [k8sevent.v1.Event](#k8sevent-v1-Event) |  | Event is the event information. |






<a name="timescape-v1-K8sEventFilter"></a>

### K8sEventFilter
K8sEventFilter is a filter to be used in the GetK8sEventsRequest include/exclude fields.
All fields are optional. If multiple fields are set, then all fields must
match for the filter to match.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | repeated | Filter by the name of the k8s event. |
| namespace | [string](#string) | repeated | Filter by the k8s resource namespace. |
| resource_uuid | [string](#string) | repeated | Filter by the k8s resource uuid. |
| event_type | [k8sevent.v1.EventType](#k8sevent-v1-EventType) | repeated | Filter by the event type. |
| kind | [k8sevent.v1.Kind](#k8sevent-v1-Kind) | repeated | Filter by the k8s resource kind. |
| cluster | [string](#string) | repeated | Filter by the k8s resource cluster. |






<a name="timescape-v1-K8sLatestEventFilter"></a>

### K8sLatestEventFilter
K8sLatestEventFilter is a filter to be used in the GetK8sLatestEventsRequest
include/exclude fields.
All fields are optional. If multiple fields are set, then all fields must
match for the filter to match.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) | repeated | Filter by the k8s resource namespace. |
| kind | [k8sevent.v1.Kind](#k8sevent-v1-Kind) | repeated | Filter by the k8s resource kind. |
| cluster | [string](#string) | repeated | Filter by the k8s resource cluster. |






<a name="timescape-v1-K8sResource"></a>

### K8sResource
K8sResource represents a Kubernetes resource.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Time is the time the resource was created or modified. |
| api_version | [string](#string) |  | api_version is the k8s apiVersion of the resource. |
| kind | [k8sevent.v1.Kind](#k8sevent-v1-Kind) |  | kind is the k8s kind of the resource. |
| cluster | [string](#string) |  | cluster is the name of the cluster this event was recorded on. |
| namespace | [string](#string) |  | namespace is the namespace of the Kubernetes resource resource the event was about. |
| name | [string](#string) |  | name is the name of the Kubernetes resource resource the event was about. |
| resource_uuid | [string](#string) |  | resource_uuid is the k8s resource uuid. |
| object | [string](#string) |  | object is the full object stored as JSON. |





 


<a name="timescape-v1-EventField"></a>

### EventField
Subset of the fields from k8sevent.v1.Event.

Some indices are skipped to make sure they match the indexes on message
Event upstream.

| Name | Number | Description |
| ---- | ------ | ----------- |
| EVENT_FIELD_UNSPECIFIED | 0 | Unknown field |
| EVENT_FIELD_EVENT_TYPE | 2 | Event type |
| EVENT_FIELD_RESOURCE_VERSION | 3 | Kubernetes resource version. |
| EVENT_FIELD_RESOURCE_UUID | 4 | Resource UUID; |
| EVENT_FIELD_API_VERSION | 5 | API version of the resource. |
| EVENT_FIELD_KIND | 6 | Kubernetes kind of the resource. |
| EVENT_FIELD_NAME | 7 | Name is the name of the Kubernetes resource resource the event was about. |
| EVENT_FIELD_NAMESPACE | 8 | Namespace of the Kubernetes resource resource the event was about. |
| EVENT_FIELD_CLUSTER | 12 | Cluster name where Kubernetes event occurred. |



<a name="timescape-v1-GetK8sEventsRequest-ResultsOrder"></a>

### GetK8sEventsRequest.ResultsOrder
ResultsOrder is an enum that defines result ordering.

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESULTS_ORDER_UNSPECIFIED | 0 | RESULTS_ORDER_UNSPECIFIED means that no particular order should be assumed. |
| RESULTS_ORDER_EVENT_TIME_ASCENDING | 1 | RESULTS_ORDER_EVENT_TIME_ASCENDING means that results are sorted by event time in ascending order. |
| RESULTS_ORDER_EVENT_TIME_DESCENDING | 2 | RESULTS_ORDER_EVENT_TIME_DESCENDING means that results are sorted by event time in descending order. |



<a name="timescape-v1-GetK8sLatestEventsRequest-ResultsOrder"></a>

### GetK8sLatestEventsRequest.ResultsOrder
ResultsOrder is an enum that defines result ordering.

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESULTS_ORDER_UNSPECIFIED | 0 | RESULTS_ORDER_UNSPECIFIED means that no particular order should be assumed. |
| RESULTS_ORDER_EVENT_TIME_ASCENDING | 1 | RESULTS_ORDER_EVENT_TIME_ASCENDING means that results are sorted by event time in ascending order. |
| RESULTS_ORDER_EVENT_TIME_DESCENDING | 2 | RESULTS_ORDER_EVENT_TIME_DESCENDING means that results are sorted by event time in descending order. |


 

 


<a name="timescape-v1-K8sEventService"></a>

### K8sEventService
K8sEventService is a service that allows for querying events about
Kubernetes resources.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetK8sEvents | [GetK8sEventsRequest](#timescape-v1-GetK8sEventsRequest) | [GetK8sEventsResponse](#timescape-v1-GetK8sEventsResponse) stream | GetK8sEvents streams events about Kubernetes resources. |
| GetK8sLatestEvents | [GetK8sLatestEventsRequest](#timescape-v1-GetK8sLatestEventsRequest) | [GetK8sLatestEventsResponse](#timescape-v1-GetK8sLatestEventsResponse) stream | GetK8sLatestEvents streams the latest kubernetes events available for each (cluster_name, namespace, name and kind). |
| GetActiveK8sResources | [GetActiveK8sResourcesRequest](#timescape-v1-GetActiveK8sResourcesRequest) | [GetActiveK8sResourcesResponse](#timescape-v1-GetActiveK8sResourcesResponse) stream | GetActiveK8sResources streams the currently active Kubernetes resources. A resource is considered active if there is at least one event for it with no DELETED event type after it. |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |


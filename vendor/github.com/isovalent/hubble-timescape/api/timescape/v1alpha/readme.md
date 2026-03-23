# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [timescape/v1alpha/ingester.proto](#timescape_v1alpha_ingester-proto)
    - [IngestRequest](#timescape-v1alpha-IngestRequest)
    - [IngestResponse](#timescape-v1alpha-IngestResponse)
  
    - [IngesterService](#timescape-v1alpha-IngesterService)
  
- [timescape/v1alpha/system_status.proto](#timescape_v1alpha_system_status-proto)
    - [ExtraData](#timescape-v1alpha-ExtraData)
    - [ExtraData.DataEntry](#timescape-v1alpha-ExtraData-DataEntry)
    - [FailingCondition](#timescape-v1alpha-FailingCondition)
    - [GetDetailRequest](#timescape-v1alpha-GetDetailRequest)
    - [GetDetailResponse](#timescape-v1alpha-GetDetailResponse)
    - [GetExtraDataRequest](#timescape-v1alpha-GetExtraDataRequest)
    - [GetExtraDataResponse](#timescape-v1alpha-GetExtraDataResponse)
    - [GetLatestPolicyStatusRequest](#timescape-v1alpha-GetLatestPolicyStatusRequest)
    - [GetLatestPolicyStatusResponse](#timescape-v1alpha-GetLatestPolicyStatusResponse)
    - [GetSummaryRequest](#timescape-v1alpha-GetSummaryRequest)
    - [GetSummaryResponse](#timescape-v1alpha-GetSummaryResponse)
    - [GetTimelineRequest](#timescape-v1alpha-GetTimelineRequest)
    - [GetTimelineResponse](#timescape-v1alpha-GetTimelineResponse)
    - [NodeFailingCondition](#timescape-v1alpha-NodeFailingCondition)
    - [QualifiedConditionID](#timescape-v1alpha-QualifiedConditionID)
    - [SystemPolicyStatus](#timescape-v1alpha-SystemPolicyStatus)
    - [TimelineSample](#timescape-v1alpha-TimelineSample)
  
    - [SystemStatusService](#timescape-v1alpha-SystemStatusService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="timescape_v1alpha_ingester-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1alpha/ingester.proto



<a name="timescape-v1alpha-IngestRequest"></a>

### IngestRequest
IngestRequest is the request message for the Ingest rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [flow.Flow](#flow-Flow) |  | Flow is the flow data to be ingested. |






<a name="timescape-v1alpha-IngestResponse"></a>

### IngestResponse
IngestResponse is the response message for the Ingest rpc call.





 

 

 


<a name="timescape-v1alpha-IngesterService"></a>

### IngesterService
IngesterService is a service that allows for ingestion of external data
for Timescape.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Ingest | [IngestRequest](#timescape-v1alpha-IngestRequest) stream | [IngestResponse](#timescape-v1alpha-IngestResponse) | Ingest ingests data into Timescape. |

 



<a name="timescape_v1alpha_system_status-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## timescape/v1alpha/system_status.proto



<a name="timescape-v1alpha-ExtraData"></a>

### ExtraData
Extra data for a specific node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster | [string](#string) |  | The cluster of the node. |
| node | [string](#string) |  | The node |
| timestamp | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Time at which the extra data was received. |
| data | [ExtraData.DataEntry](#timescape-v1alpha-ExtraData-DataEntry) | repeated | The extra data for this node. |






<a name="timescape-v1alpha-ExtraData-DataEntry"></a>

### ExtraData.DataEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="timescape-v1alpha-FailingCondition"></a>

### FailingCondition
A failing condition


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| condition_id | [QualifiedConditionID](#timescape-v1alpha-QualifiedConditionID) |  | The qualified condition id. |
| severity | [string](#string) |  | Condition severity. |
| affected_nodes_count | [uint32](#uint32) |  | Number of affected nodes. |
| last_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Latest time it occurred. |






<a name="timescape-v1alpha-GetDetailRequest"></a>

### GetDetailRequest
Request of GetDetail rpc call


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster | [string](#string) |  | Optional cluster to filter the results |
| time_filter | [timescape.v1.TimeFilter](#timescape-v1-TimeFilter) |  | Since and Until can be used to specify a time interval. |
| qid | [QualifiedConditionID](#timescape-v1alpha-QualifiedConditionID) |  | The condition we&#39;re requesting. |






<a name="timescape-v1alpha-GetDetailResponse"></a>

### GetDetailResponse
Response of GetDetail rpc call contains the list of nodes
on which the given condition is failing along with the
failing condition message from each node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| metadata | [system_status.v1alpha.ConditionMetadata](#system_status-v1alpha-ConditionMetadata) |  | Metadata associated with the condition |
| nodes | [NodeFailingCondition](#timescape-v1alpha-NodeFailingCondition) | repeated | The nodes for which this condition is failing on. |






<a name="timescape-v1alpha-GetExtraDataRequest"></a>

### GetExtraDataRequest
Request for the GetExtraData rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster | [string](#string) |  | Optional cluster to filter the results |
| system | [system_status.v1alpha.SystemID](#system_status-v1alpha-SystemID) |  | The required system name and version. |






<a name="timescape-v1alpha-GetExtraDataResponse"></a>

### GetExtraDataResponse
Response for the GetExtraData rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [ExtraData](#timescape-v1alpha-ExtraData) | repeated | The extra data for each node for the requested system. |






<a name="timescape-v1alpha-GetLatestPolicyStatusRequest"></a>

### GetLatestPolicyStatusRequest
Request for GetLatestPolicyStatus rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster | [string](#string) |  | Optional cluster to filter the results |
| node_names | [string](#string) | repeated | The nodes for which to get the current policy status. If empty, returns the policy status for all systems. |






<a name="timescape-v1alpha-GetLatestPolicyStatusResponse"></a>

### GetLatestPolicyStatusResponse
Response for GetLatestPolicyStatus rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| statuses | [SystemPolicyStatus](#timescape-v1alpha-SystemPolicyStatus) | repeated | The list of policy statuses for the requested node. |






<a name="timescape-v1alpha-GetSummaryRequest"></a>

### GetSummaryRequest
Request of GetSummary rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster | [string](#string) |  | Optional cluster to filter the results |
| time_filter | [timescape.v1.TimeFilter](#timescape-v1-TimeFilter) |  | Since and Until can be used to specify a time interval. |






<a name="timescape-v1alpha-GetSummaryResponse"></a>

### GetSummaryResponse
Response of GetSummary rpc call.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| failing_conditions | [FailingCondition](#timescape-v1alpha-FailingCondition) | repeated | The currently failing conditions. |






<a name="timescape-v1alpha-GetTimelineRequest"></a>

### GetTimelineRequest
Request of GetTimeline rpc call


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| condition_id | [QualifiedConditionID](#timescape-v1alpha-QualifiedConditionID) |  | Optional condition ID to show the timeline for. If unset all conditions are included. |
| cluster | [string](#string) |  | Optional cluster to filter the results. |
| time_filter | [timescape.v1.TimeFilter](#timescape-v1-TimeFilter) |  | Since and Until can be used to specify a time interval. If not set defaults to last 24 hours. |
| window_size | [google.protobuf.Duration](#google-protobuf-Duration) |  | Optional window size for samples. Defaults to 1 hour. |






<a name="timescape-v1alpha-GetTimelineResponse"></a>

### GetTimelineResponse
Response of GetTimeline rpc call


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| samples | [TimelineSample](#timescape-v1alpha-TimelineSample) | repeated | Samples of failing and succeeding conditions in buckets specified by &#39;window_size&#39; in the time range specified by &#39;time_filter&#39;. |






<a name="timescape-v1alpha-NodeFailingCondition"></a>

### NodeFailingCondition
Details of a failing condition on a specific node


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster | [string](#string) |  | The cluster for the node. |
| node | [string](#string) |  | The node on which the condition is failing. |
| message | [string](#string) |  | The failing condition message giving more details on why it is failing. |
| severity | [system_status.v1alpha.Severity](#system_status-v1alpha-Severity) |  | Severity of the failure. |






<a name="timescape-v1alpha-QualifiedConditionID"></a>

### QualifiedConditionID
QualifiedConditionID uniquely identifies the condition to a specific system.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| system | [system_status.v1alpha.SystemID](#system_status-v1alpha-SystemID) |  | The system name and version. |
| condition_id | [string](#string) |  | Condition identifier. |






<a name="timescape-v1alpha-SystemPolicyStatus"></a>

### SystemPolicyStatus
SystemPolicyStatus represents the policy status of a system at a specific time.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| timestamp | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The time at which the policy status was recorded. |
| policy_status | [system_status.v1alpha.PolicyStatusUpdate](#system_status-v1alpha-PolicyStatusUpdate) |  | The current policy status. |






<a name="timescape-v1alpha-TimelineSample"></a>

### TimelineSample
A timeline sample


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| timestamp | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Time of the sample |
| success_count | [uint32](#uint32) |  | Number of succeeding conditions across all nodes. |
| fail_count | [uint32](#uint32) |  | Number of failing conditions across all nodes. |
| node_success_count | [uint32](#uint32) |  | Number of nodes without any failing conditions. |
| node_fail_count | [uint32](#uint32) |  | Number of nodes with at least one failing condition. |





 

 

 


<a name="timescape-v1alpha-SystemStatusService"></a>

### SystemStatusService
SystemStatusService for querying the system status.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetSummary | [GetSummaryRequest](#timescape-v1alpha-GetSummaryRequest) | [GetSummaryResponse](#timescape-v1alpha-GetSummaryResponse) | GetSummary returns a summary of failing conditions. |
| GetDetail | [GetDetailRequest](#timescape-v1alpha-GetDetailRequest) | [GetDetailResponse](#timescape-v1alpha-GetDetailResponse) | GetDetail returns details about a specific condition. |
| GetTimeline | [GetTimelineRequest](#timescape-v1alpha-GetTimelineRequest) | [GetTimelineResponse](#timescape-v1alpha-GetTimelineResponse) | GetTimeline returns a timeline of counts of succeeding and failing conditions. |
| GetExtraData | [GetExtraDataRequest](#timescape-v1alpha-GetExtraDataRequest) | [GetExtraDataResponse](#timescape-v1alpha-GetExtraDataResponse) | GetExtraData returns the latest extra data from each node for a specific system. |
| GetLatestPolicyStatus | [GetLatestPolicyStatusRequest](#timescape-v1alpha-GetLatestPolicyStatusRequest) | [GetLatestPolicyStatusResponse](#timescape-v1alpha-GetLatestPolicyStatusResponse) | GetLatestPolicyStatus returns the latest policy status for the specified systems. |

 



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


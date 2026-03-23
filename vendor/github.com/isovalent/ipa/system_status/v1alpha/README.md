# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [system_status/v1alpha/system_status.proto](#system_status_v1alpha_system_status-proto)
    - [ConditionMetadata](#system_status-v1alpha-ConditionMetadata)
    - [FailingCondition](#system_status-v1alpha-FailingCondition)
    - [PolicyStatus](#system_status-v1alpha-PolicyStatus)
    - [PolicyStatus.ExtraDataEntry](#system_status-v1alpha-PolicyStatus-ExtraDataEntry)
    - [PolicyStatusUpdate](#system_status-v1alpha-PolicyStatusUpdate)
    - [SystemID](#system_status-v1alpha-SystemID)
    - [SystemMetadataUpdate](#system_status-v1alpha-SystemMetadataUpdate)
    - [SystemStatusEvent](#system_status-v1alpha-SystemStatusEvent)
    - [SystemStatusUpdate](#system_status-v1alpha-SystemStatusUpdate)
    - [SystemStatusUpdate.ExtraDataEntry](#system_status-v1alpha-SystemStatusUpdate-ExtraDataEntry)
  
    - [PolicyType](#system_status-v1alpha-PolicyType)
    - [Severity](#system_status-v1alpha-Severity)
  
- [Scalar Value Types](#scalar-value-types)



<a name="system_status_v1alpha_system_status-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## system_status/v1alpha/system_status.proto



<a name="system_status-v1alpha-ConditionMetadata"></a>

### ConditionMetadata



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| condition_id | [string](#string) |  | The identifier for the condition within a system |
| subsystem | [string](#string) |  | The sub-system that is impacted by the condition. This should be fairly high-level and user should be able to easily infer what functionality is being impacted. |
| description | [string](#string) |  | A detailed description about the condition |
| resolution | [string](#string) |  | An optional description on how to either mitigate or resolve the condition |






<a name="system_status-v1alpha-FailingCondition"></a>

### FailingCondition



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| condition_id | [string](#string) |  | Identifier to identify a condition within a system. For a globally unique identifier this must be paired with [SystemID]. |
| severity | [Severity](#system_status-v1alpha-Severity) |  | Severity of the failure |
| message | [string](#string) |  | Optional details on why the condition is failing |






<a name="system_status-v1alpha-PolicyStatus"></a>

### PolicyStatus
PolicyStatus represents the status of a single policy on a node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [PolicyType](#system_status-v1alpha-PolicyType) |  | Type of the policy. |
| id | [string](#string) |  | ID of the policy. |
| name | [string](#string) |  | Name of the policy. |
| namespace | [string](#string) |  | Namespace of the policy. |
| version | [string](#string) |  | Version of the policy. |
| failing_conditions | [FailingCondition](#system_status-v1alpha-FailingCondition) | repeated | Conditions that are currently preventing the policy to be enforced. If empty, the policy is being enforced. |
| extra_data | [PolicyStatus.ExtraDataEntry](#system_status-v1alpha-PolicyStatus-ExtraDataEntry) | repeated | Extra data that allows the SmartSwitch client to include additional information or data that needs to be presented to the end-user or consumer of this data. |






<a name="system_status-v1alpha-PolicyStatus-ExtraDataEntry"></a>

### PolicyStatus.ExtraDataEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="system_status-v1alpha-PolicyStatusUpdate"></a>

### PolicyStatusUpdate
PolicyStatusUpdate contains the current statuses of all the policies on a
node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster_name | [string](#string) |  | Cluster for which the status is being updated |
| node_name | [string](#string) |  | The name of the node that&#39;s reporting the policy statuses. |
| statuses | [PolicyStatus](#system_status-v1alpha-PolicyStatus) | repeated | The statuses of all the policies on the node. |






<a name="system_status-v1alpha-SystemID"></a>

### SystemID
System identifier


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | The name of the system. This is usually the name of the process reporting the status, e.g. cilium-agent or cilium-operator. |
| version | [string](#string) |  | Version of the system, e.g. v1.18.0-cee.1. |






<a name="system_status-v1alpha-SystemMetadataUpdate"></a>

### SystemMetadataUpdate
Update of the metadata associated with system&#39;s known conditions.
The metadata is separated from conditions to reduce the size of the
update payload and to allow updating the metadata after a system has
been released.

Metadata updates for the same system are combined together allowing
e.g. the Cilium Agent and Cilium Operator to upload their metadata
separately even though they&#39;re part of the same system.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| system | [SystemID](#system_status-v1alpha-SystemID) |  | The system the metadata is associated with |
| conditions | [ConditionMetadata](#system_status-v1alpha-ConditionMetadata) | repeated | Metadata for each condition |






<a name="system_status-v1alpha-SystemStatusEvent"></a>

### SystemStatusEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Time at which the event was produced |
| status | [SystemStatusUpdate](#system_status-v1alpha-SystemStatusUpdate) |  |  |
| metadata | [SystemMetadataUpdate](#system_status-v1alpha-SystemMetadataUpdate) |  |  |
| policy | [PolicyStatusUpdate](#system_status-v1alpha-PolicyStatusUpdate) |  |  |






<a name="system_status-v1alpha-SystemStatusUpdate"></a>

### SystemStatusUpdate
An update describing the current state of a system running
on a particular node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster_name | [string](#string) |  | Cluster for which the status is being updated |
| node_name | [string](#string) |  | Node for which the status is being updated. If empty the status is for the whole cluster. |
| system | [SystemID](#system_status-v1alpha-SystemID) |  | The system whose status is being updated |
| started_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The local node time at which this system was started |
| total_conditions | [uint32](#uint32) |  | The total number of evaluated diagnostic conditions |
| failing_conditions | [FailingCondition](#system_status-v1alpha-FailingCondition) | repeated | The currently failing conditions |
| extra_data | [SystemStatusUpdate.ExtraDataEntry](#system_status-v1alpha-SystemStatusUpdate-ExtraDataEntry) | repeated | Extra unstructured data to include in the status update. Each system may use this field to send arbitrary key value pairs as a part of the status update. It is up to each consumer of the status update to interpret or ignore this field. |






<a name="system_status-v1alpha-SystemStatusUpdate-ExtraDataEntry"></a>

### SystemStatusUpdate.ExtraDataEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |





 


<a name="system_status-v1alpha-PolicyType"></a>

### PolicyType
PolicyType represents the type of a policy.

| Name | Number | Description |
| ---- | ------ | ----------- |
| POLICY_TYPE_UNSPECIFIED | 0 |  |
| POLICY_TYPE_TETRAGON_NETWORK_POLICY | 1 |  |
| POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY | 2 |  |



<a name="system_status-v1alpha-Severity"></a>

### Severity


| Name | Number | Description |
| ---- | ------ | ----------- |
| SEVERITY_UNSPECIFIED | 0 |  |
| SEVERITY_DEBUG | 1 | Debug severity is for failures that are not by default shown to the user, but can aid with debugging issues |
| SEVERITY_MINOR | 2 | Minor severity is for failures that are noteworthy, but have limited impact to the system. |
| SEVERITY_MAJOR | 3 | Major severity is for failures that have a clear impact to the functioning of the system. |
| SEVERITY_CRITICAL | 4 | Critical severity is for failures that have significant impact to the whole cluster. |


 

 

 



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


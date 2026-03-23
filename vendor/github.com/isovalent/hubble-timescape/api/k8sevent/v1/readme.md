# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [k8sevent/v1/event.proto](#k8sevent_v1_event-proto)
    - [Event](#k8sevent-v1-Event)
    - [Event.LabelsEntry](#k8sevent-v1-Event-LabelsEntry)
    - [ExportEvent](#k8sevent-v1-ExportEvent)
  
    - [EventType](#k8sevent-v1-EventType)
    - [Kind](#k8sevent-v1-Kind)
  
- [Scalar Value Types](#scalar-value-types)



<a name="k8sevent_v1_event-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## k8sevent/v1/event.proto



<a name="k8sevent-v1-Event"></a>

### Event
Event represents an event occurring on a Kubernetes resource.

#### Experimental

Notice: This type is EXPERIMENTAL and may be changed or removed in a
later release.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Time is the time when the event happened. |
| event_type | [EventType](#k8sevent-v1-EventType) |  | event_type is the event type. |
| resource_version | [string](#string) |  | resource_version is the K8s resource version. |
| resource_uuid | [string](#string) |  | resource_uuid is the k8s resource uuid. |
| api_version | [string](#string) |  | api_version is the k8s apiVersion of the resource. |
| kind | [Kind](#k8sevent-v1-Kind) |  | kind is the k8s kind of the resource. |
| name | [string](#string) |  | name is the name of the Kubernetes resource resource the event was about. |
| namespace | [string](#string) |  | namespace is the namespace of the Kubernetes resource resource the event was about. |
| labels | [Event.LabelsEntry](#k8sevent-v1-Event-LabelsEntry) | repeated | labels are the labels on the resource when the event happened. |
| object | [string](#string) |  | object is the full object stored as JSON. |
| old_object | [string](#string) |  | old_object is the instance of the object before the update, stored as JSON. |
| cluster | [string](#string) |  | cluster is the name of the cluster this event was recorded on. |
| generation | [int64](#int64) |  | generation is the k8s resource generation. It is a sequence number representing a specific generation of the desired state of the resource. |
| creation_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Time is the time when the event was created, taken from the Kubernetes metadata.creationTimestamp field. |






<a name="k8sevent-v1-Event-LabelsEntry"></a>

### Event.LabelsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="k8sevent-v1-ExportEvent"></a>

### ExportEvent
ExportEvent represents an exported event.

#### Experimental

Notice: This type is EXPERIMENTAL and may be changed or removed in a
later release.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | time is the time when the event happened. |
| k8s_event | [Event](#k8sevent-v1-Event) |  | event is the underlying event. |





 


<a name="k8sevent-v1-EventType"></a>

### EventType
EventType represents the type of event that occurred.

#### Experimental

Notice: This type is EXPERIMENTAL and may be changed or removed in a
later release.

| Name | Number | Description |
| ---- | ------ | ----------- |
| EVENT_TYPE_UNSPECIFIED | 0 | The event type wasn&#39;t specified. This is an error. |
| EVENT_TYPE_CREATED | 1 | The resource was created. The event.object contains the object created. |
| EVENT_TYPE_UPDATED | 2 | The resource was updated. The event.object contains the new version and event.old_object contains the version before it was updated. |
| EVENT_TYPE_DELETED | 3 | The resource was deleted. The event.old_object contains the object that was deleted. |



<a name="k8sevent-v1-Kind"></a>

### Kind
Kind represents the Kubernetes resource Kind

#### Experimental

Notice: This type is EXPERIMENTAL and may be changed or removed in a
later release.

| Name | Number | Description |
| ---- | ------ | ----------- |
| KIND_UNSPECIFIED | 0 | The kind of the object was unspecified. This is an error. |
| KIND_CILIUM_NETWORK_POLICY | 1 | The kind of the object was CiliumNetworkPolicy. |
| KIND_CILIUM_CLUSTERWIDE_NETWORK_POLICY | 2 | The kind of the object was CiliumClusterwideNetworkPolicy. |
| KIND_KUBERNETES_NETWORK_POLICY | 3 | The kind of the object was the upstream Kubernetes NetworkPolicy. |
| KIND_KUBERNETES_ENDPOINT | 4 | The kind of the object was the upstream Kubernetes Endpoint. |
| KIND_CILIUM_ENDPOINT | 5 | The kind of the object was CiliumEndpoint. |
| KIND_CILIUM_IDENTITY | 6 | The kind of the object was CiliumIdentity. |
| KIND_TETRAGON_NETWORK_POLICY | 7 | The kind of the object was TetragonNetworkPolicy. |
| KIND_CILIUM_NODE | 8 | The kind of the object was CiliumNode. |
| KIND_TETRAGON_NETWORK_POLICY_NAMESPACED | 9 | The kind of the object was TetragonNetworkPolicyNamespaced. |
| KIND_TETRAGON_NODE | 10 | The kind of the object was TetragonNode. |
| KIND_SMART_SWITCH | 11 | The kind of the object was SmartSwitch. |
| KIND_SMART_SWITCH_NETWORK_POLICY | 12 | The kind of the object was SmartSwitchNetworkPolicy. |
| KIND_ISOVALENT_NETWORK_POLICY | 13 | The kind of the object was IsovalentNetworkPolicy. |
| KIND_ISOVALENT_CLUSTERWIDE_NETWORK_POLICY | 14 | The kind of the object was IsovalentClusterwideNetworkPolicy. |
| KIND_KUBERNETES_NAMESPACE | 15 | The kind of the object was the upstream Kubernetes Namespace. |


 

 

 



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


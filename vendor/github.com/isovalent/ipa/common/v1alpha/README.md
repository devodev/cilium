# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [common/v1alpha/emitter.proto](#common_v1alpha_emitter-proto)
    - [Emitter](#common-v1alpha-Emitter)
  
- [Scalar Value Types](#scalar-value-types)



<a name="common_v1alpha_emitter-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## common/v1alpha/emitter.proto



<a name="common-v1alpha-Emitter"></a>

### Emitter
Emitter identifies the source that emits some data.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | name identifies the emitter. The name should be capitalized (&#34;Hubble&#34;, not &#34;hubble&#34; nor &#34;HUBBLE&#34;). |
| version | [string](#string) |  | version identifies the emitter version. The version should not contain a &#39;v&#39; prefix as sometimes seen (&#34;1.19.0&#34;, not &#34;v1.19.0&#34;). |
| source_identifier | [string](#string) |  | source_identifier uniquely identifies the specific instance of the emitter that produced the data. While name and version describe the emitter software itself, source_identifier pinpoints where it ran, which makes it possible to distinguish between multiple emitters of the same kind -- for example, to deduplicate events from an HA pair of smart switches, or to attribute a connection log to a specific Cilium agent.

Typical values are the Kubernetes node name or pod hostname of a Cilium agent, or the serial number of a smart switch. The field is optional and may be left unset by emitters that cannot meaningfully identify themselves (e.g. single-instance deployments).

The upper bound of 253 matches the maximum length of a DNS name (RFC 1035), which also bounds Kubernetes object names and pod hostnames, and comfortably fits a typical hardware serial number. |





 

 

 

 



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


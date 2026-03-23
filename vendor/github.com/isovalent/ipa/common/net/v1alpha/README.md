# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [common/net/v1alpha/protocol.proto](#common_net_v1alpha_protocol-proto)
    - [IPProtocol](#common-net-v1alpha-IPProtocol)
  
- [Scalar Value Types](#scalar-value-types)



<a name="common_net_v1alpha_protocol-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## common/net/v1alpha/protocol.proto


 


<a name="common-net-v1alpha-IPProtocol"></a>

### IPProtocol
IPProtocol is a list of IP protocols.

Field numbers match IANA&#39;s assigned protocol numbers.
See the URL below for reference:
https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

| Name | Number | Description |
| ---- | ------ | ----------- |
| IP_PROTOCOL_UNSPECIFIED | 0 | IP_PROTOCOL_UNSPECIFIED is to be used when the protocol is not specified. |
| IP_PROTOCOL_ICMP | 1 | IP_PROTOCOL_ICMP is the Internet Control Message protocol. |
| IP_PROTOCOL_IGMP | 2 | IP_PROTOCOL_IGMP is the Internet Group management protocol. |
| IP_PROTOCOL_TCP | 6 | IP_PROTOCOL_TCP is the Transmission Control protocol. |
| IP_PROTOCOL_UDP | 17 | IP_PROTOCOL_UDP is the User Datagram protocol. |
| IP_PROTOCOL_DCCP | 33 | IP_PROTOCOL_DCCP is the Datagram Congestion Control protocol. |
| IP_PROTOCOL_ICMPV6 | 58 | IP_PROTOCOL_ICMPV6 is ICMP for IPv6. |
| IP_PROTOCOL_MTP | 92 | IP_PROTOCOL_MTP is the Multicast Transport Protocol. |
| IP_PROTOCOL_SCTP | 132 | IP_PROTOCOL_SCTP is the Stream Control Transmission protocol. |
| IP_PROTOCOL_UDPLITE | 136 | IP_PROTOCOL_UDPLITE is the Lightweight User Datagram protocol. |


 

 

 



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


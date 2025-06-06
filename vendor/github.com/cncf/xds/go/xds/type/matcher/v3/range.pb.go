// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.29.1
// source: xds/type/matcher/v3/range.proto

package v3

import (
	v3 "github.com/cncf/xds/go/xds/type/v3"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Int64RangeMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RangeMatchers []*Int64RangeMatcher_RangeMatcher `protobuf:"bytes,1,rep,name=range_matchers,json=rangeMatchers,proto3" json:"range_matchers,omitempty"`
}

func (x *Int64RangeMatcher) Reset() {
	*x = Int64RangeMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xds_type_matcher_v3_range_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Int64RangeMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Int64RangeMatcher) ProtoMessage() {}

func (x *Int64RangeMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_xds_type_matcher_v3_range_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Int64RangeMatcher.ProtoReflect.Descriptor instead.
func (*Int64RangeMatcher) Descriptor() ([]byte, []int) {
	return file_xds_type_matcher_v3_range_proto_rawDescGZIP(), []int{0}
}

func (x *Int64RangeMatcher) GetRangeMatchers() []*Int64RangeMatcher_RangeMatcher {
	if x != nil {
		return x.RangeMatchers
	}
	return nil
}

type Int32RangeMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RangeMatchers []*Int32RangeMatcher_RangeMatcher `protobuf:"bytes,1,rep,name=range_matchers,json=rangeMatchers,proto3" json:"range_matchers,omitempty"`
}

func (x *Int32RangeMatcher) Reset() {
	*x = Int32RangeMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xds_type_matcher_v3_range_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Int32RangeMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Int32RangeMatcher) ProtoMessage() {}

func (x *Int32RangeMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_xds_type_matcher_v3_range_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Int32RangeMatcher.ProtoReflect.Descriptor instead.
func (*Int32RangeMatcher) Descriptor() ([]byte, []int) {
	return file_xds_type_matcher_v3_range_proto_rawDescGZIP(), []int{1}
}

func (x *Int32RangeMatcher) GetRangeMatchers() []*Int32RangeMatcher_RangeMatcher {
	if x != nil {
		return x.RangeMatchers
	}
	return nil
}

type DoubleRangeMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RangeMatchers []*DoubleRangeMatcher_RangeMatcher `protobuf:"bytes,1,rep,name=range_matchers,json=rangeMatchers,proto3" json:"range_matchers,omitempty"`
}

func (x *DoubleRangeMatcher) Reset() {
	*x = DoubleRangeMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xds_type_matcher_v3_range_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DoubleRangeMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DoubleRangeMatcher) ProtoMessage() {}

func (x *DoubleRangeMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_xds_type_matcher_v3_range_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DoubleRangeMatcher.ProtoReflect.Descriptor instead.
func (*DoubleRangeMatcher) Descriptor() ([]byte, []int) {
	return file_xds_type_matcher_v3_range_proto_rawDescGZIP(), []int{2}
}

func (x *DoubleRangeMatcher) GetRangeMatchers() []*DoubleRangeMatcher_RangeMatcher {
	if x != nil {
		return x.RangeMatchers
	}
	return nil
}

type Int64RangeMatcher_RangeMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ranges  []*v3.Int64Range `protobuf:"bytes,1,rep,name=ranges,proto3" json:"ranges,omitempty"`
	OnMatch *Matcher_OnMatch `protobuf:"bytes,2,opt,name=on_match,json=onMatch,proto3" json:"on_match,omitempty"`
}

func (x *Int64RangeMatcher_RangeMatcher) Reset() {
	*x = Int64RangeMatcher_RangeMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xds_type_matcher_v3_range_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Int64RangeMatcher_RangeMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Int64RangeMatcher_RangeMatcher) ProtoMessage() {}

func (x *Int64RangeMatcher_RangeMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_xds_type_matcher_v3_range_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Int64RangeMatcher_RangeMatcher.ProtoReflect.Descriptor instead.
func (*Int64RangeMatcher_RangeMatcher) Descriptor() ([]byte, []int) {
	return file_xds_type_matcher_v3_range_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Int64RangeMatcher_RangeMatcher) GetRanges() []*v3.Int64Range {
	if x != nil {
		return x.Ranges
	}
	return nil
}

func (x *Int64RangeMatcher_RangeMatcher) GetOnMatch() *Matcher_OnMatch {
	if x != nil {
		return x.OnMatch
	}
	return nil
}

type Int32RangeMatcher_RangeMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ranges  []*v3.Int32Range `protobuf:"bytes,1,rep,name=ranges,proto3" json:"ranges,omitempty"`
	OnMatch *Matcher_OnMatch `protobuf:"bytes,2,opt,name=on_match,json=onMatch,proto3" json:"on_match,omitempty"`
}

func (x *Int32RangeMatcher_RangeMatcher) Reset() {
	*x = Int32RangeMatcher_RangeMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xds_type_matcher_v3_range_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Int32RangeMatcher_RangeMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Int32RangeMatcher_RangeMatcher) ProtoMessage() {}

func (x *Int32RangeMatcher_RangeMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_xds_type_matcher_v3_range_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Int32RangeMatcher_RangeMatcher.ProtoReflect.Descriptor instead.
func (*Int32RangeMatcher_RangeMatcher) Descriptor() ([]byte, []int) {
	return file_xds_type_matcher_v3_range_proto_rawDescGZIP(), []int{1, 0}
}

func (x *Int32RangeMatcher_RangeMatcher) GetRanges() []*v3.Int32Range {
	if x != nil {
		return x.Ranges
	}
	return nil
}

func (x *Int32RangeMatcher_RangeMatcher) GetOnMatch() *Matcher_OnMatch {
	if x != nil {
		return x.OnMatch
	}
	return nil
}

type DoubleRangeMatcher_RangeMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ranges  []*v3.DoubleRange `protobuf:"bytes,1,rep,name=ranges,proto3" json:"ranges,omitempty"`
	OnMatch *Matcher_OnMatch  `protobuf:"bytes,2,opt,name=on_match,json=onMatch,proto3" json:"on_match,omitempty"`
}

func (x *DoubleRangeMatcher_RangeMatcher) Reset() {
	*x = DoubleRangeMatcher_RangeMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_xds_type_matcher_v3_range_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DoubleRangeMatcher_RangeMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DoubleRangeMatcher_RangeMatcher) ProtoMessage() {}

func (x *DoubleRangeMatcher_RangeMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_xds_type_matcher_v3_range_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DoubleRangeMatcher_RangeMatcher.ProtoReflect.Descriptor instead.
func (*DoubleRangeMatcher_RangeMatcher) Descriptor() ([]byte, []int) {
	return file_xds_type_matcher_v3_range_proto_rawDescGZIP(), []int{2, 0}
}

func (x *DoubleRangeMatcher_RangeMatcher) GetRanges() []*v3.DoubleRange {
	if x != nil {
		return x.Ranges
	}
	return nil
}

func (x *DoubleRangeMatcher_RangeMatcher) GetOnMatch() *Matcher_OnMatch {
	if x != nil {
		return x.OnMatch
	}
	return nil
}

var File_xds_type_matcher_v3_range_proto protoreflect.FileDescriptor

var file_xds_type_matcher_v3_range_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x78, 0x64, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x65, 0x72, 0x2f, 0x76, 0x33, 0x2f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x13, 0x78, 0x64, 0x73, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x1a, 0x17, 0x78, 0x64, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65,
	0x2f, 0x76, 0x33, 0x2f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x21, 0x78, 0x64, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x72, 0x2f, 0x76, 0x33, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xfc, 0x01, 0x0a, 0x11,
	0x49, 0x6e, 0x74, 0x36, 0x34, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x72, 0x12, 0x5a, 0x0a, 0x0e, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x33, 0x2e, 0x78, 0x64, 0x73, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e,
	0x49, 0x6e, 0x74, 0x36, 0x34, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x72, 0x2e, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x52, 0x0d,
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x73, 0x1a, 0x8a, 0x01,
	0x0a, 0x0c, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12, 0x39,
	0x0a, 0x06, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x78, 0x64, 0x73, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x49, 0x6e, 0x74,
	0x36, 0x34, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x92, 0x01, 0x02, 0x08,
	0x01, 0x52, 0x06, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x12, 0x3f, 0x0a, 0x08, 0x6f, 0x6e, 0x5f,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x78, 0x64,
	0x73, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76,
	0x33, 0x2e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x4f, 0x6e, 0x4d, 0x61, 0x74, 0x63,
	0x68, 0x52, 0x07, 0x6f, 0x6e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x22, 0xfc, 0x01, 0x0a, 0x11, 0x49,
	0x6e, 0x74, 0x33, 0x32, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72,
	0x12, 0x5a, 0x0a, 0x0e, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x33, 0x2e, 0x78, 0x64, 0x73, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x49,
	0x6e, 0x74, 0x33, 0x32, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72,
	0x2e, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x52, 0x0d, 0x72,
	0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x73, 0x1a, 0x8a, 0x01, 0x0a,
	0x0c, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12, 0x39, 0x0a,
	0x06, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x78, 0x64, 0x73, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x49, 0x6e, 0x74, 0x33,
	0x32, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x92, 0x01, 0x02, 0x08, 0x01,
	0x52, 0x06, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x12, 0x3f, 0x0a, 0x08, 0x6f, 0x6e, 0x5f, 0x6d,
	0x61, 0x74, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x78, 0x64, 0x73,
	0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33,
	0x2e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x4f, 0x6e, 0x4d, 0x61, 0x74, 0x63, 0x68,
	0x52, 0x07, 0x6f, 0x6e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x22, 0xff, 0x01, 0x0a, 0x12, 0x44, 0x6f,
	0x75, 0x62, 0x6c, 0x65, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72,
	0x12, 0x5b, 0x0a, 0x0e, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x34, 0x2e, 0x78, 0x64, 0x73, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x44,
	0x6f, 0x75, 0x62, 0x6c, 0x65, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x72, 0x2e, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x52, 0x0d,
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x73, 0x1a, 0x8b, 0x01,
	0x0a, 0x0c, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12, 0x3a,
	0x0a, 0x06, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x78, 0x64, 0x73, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x44, 0x6f, 0x75,
	0x62, 0x6c, 0x65, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x92, 0x01, 0x02,
	0x08, 0x01, 0x52, 0x06, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x12, 0x3f, 0x0a, 0x08, 0x6f, 0x6e,
	0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x78,
	0x64, 0x73, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e,
	0x76, 0x33, 0x2e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x4f, 0x6e, 0x4d, 0x61, 0x74,
	0x63, 0x68, 0x52, 0x07, 0x6f, 0x6e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x42, 0x5a, 0x0a, 0x1e, 0x63,
	0x6f, 0x6d, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x78, 0x64, 0x73, 0x2e, 0x74, 0x79,
	0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x42, 0x0a, 0x52,
	0x61, 0x6e, 0x67, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2a, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6e, 0x63, 0x66, 0x2f, 0x78, 0x64, 0x73,
	0x2f, 0x67, 0x6f, 0x2f, 0x78, 0x64, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_xds_type_matcher_v3_range_proto_rawDescOnce sync.Once
	file_xds_type_matcher_v3_range_proto_rawDescData = file_xds_type_matcher_v3_range_proto_rawDesc
)

func file_xds_type_matcher_v3_range_proto_rawDescGZIP() []byte {
	file_xds_type_matcher_v3_range_proto_rawDescOnce.Do(func() {
		file_xds_type_matcher_v3_range_proto_rawDescData = protoimpl.X.CompressGZIP(file_xds_type_matcher_v3_range_proto_rawDescData)
	})
	return file_xds_type_matcher_v3_range_proto_rawDescData
}

var file_xds_type_matcher_v3_range_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_xds_type_matcher_v3_range_proto_goTypes = []interface{}{
	(*Int64RangeMatcher)(nil),               // 0: xds.type.matcher.v3.Int64RangeMatcher
	(*Int32RangeMatcher)(nil),               // 1: xds.type.matcher.v3.Int32RangeMatcher
	(*DoubleRangeMatcher)(nil),              // 2: xds.type.matcher.v3.DoubleRangeMatcher
	(*Int64RangeMatcher_RangeMatcher)(nil),  // 3: xds.type.matcher.v3.Int64RangeMatcher.RangeMatcher
	(*Int32RangeMatcher_RangeMatcher)(nil),  // 4: xds.type.matcher.v3.Int32RangeMatcher.RangeMatcher
	(*DoubleRangeMatcher_RangeMatcher)(nil), // 5: xds.type.matcher.v3.DoubleRangeMatcher.RangeMatcher
	(*v3.Int64Range)(nil),                   // 6: xds.type.v3.Int64Range
	(*Matcher_OnMatch)(nil),                 // 7: xds.type.matcher.v3.Matcher.OnMatch
	(*v3.Int32Range)(nil),                   // 8: xds.type.v3.Int32Range
	(*v3.DoubleRange)(nil),                  // 9: xds.type.v3.DoubleRange
}
var file_xds_type_matcher_v3_range_proto_depIdxs = []int32{
	3, // 0: xds.type.matcher.v3.Int64RangeMatcher.range_matchers:type_name -> xds.type.matcher.v3.Int64RangeMatcher.RangeMatcher
	4, // 1: xds.type.matcher.v3.Int32RangeMatcher.range_matchers:type_name -> xds.type.matcher.v3.Int32RangeMatcher.RangeMatcher
	5, // 2: xds.type.matcher.v3.DoubleRangeMatcher.range_matchers:type_name -> xds.type.matcher.v3.DoubleRangeMatcher.RangeMatcher
	6, // 3: xds.type.matcher.v3.Int64RangeMatcher.RangeMatcher.ranges:type_name -> xds.type.v3.Int64Range
	7, // 4: xds.type.matcher.v3.Int64RangeMatcher.RangeMatcher.on_match:type_name -> xds.type.matcher.v3.Matcher.OnMatch
	8, // 5: xds.type.matcher.v3.Int32RangeMatcher.RangeMatcher.ranges:type_name -> xds.type.v3.Int32Range
	7, // 6: xds.type.matcher.v3.Int32RangeMatcher.RangeMatcher.on_match:type_name -> xds.type.matcher.v3.Matcher.OnMatch
	9, // 7: xds.type.matcher.v3.DoubleRangeMatcher.RangeMatcher.ranges:type_name -> xds.type.v3.DoubleRange
	7, // 8: xds.type.matcher.v3.DoubleRangeMatcher.RangeMatcher.on_match:type_name -> xds.type.matcher.v3.Matcher.OnMatch
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_xds_type_matcher_v3_range_proto_init() }
func file_xds_type_matcher_v3_range_proto_init() {
	if File_xds_type_matcher_v3_range_proto != nil {
		return
	}
	file_xds_type_matcher_v3_matcher_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_xds_type_matcher_v3_range_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Int64RangeMatcher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_xds_type_matcher_v3_range_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Int32RangeMatcher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_xds_type_matcher_v3_range_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DoubleRangeMatcher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_xds_type_matcher_v3_range_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Int64RangeMatcher_RangeMatcher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_xds_type_matcher_v3_range_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Int32RangeMatcher_RangeMatcher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_xds_type_matcher_v3_range_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DoubleRangeMatcher_RangeMatcher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_xds_type_matcher_v3_range_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_xds_type_matcher_v3_range_proto_goTypes,
		DependencyIndexes: file_xds_type_matcher_v3_range_proto_depIdxs,
		MessageInfos:      file_xds_type_matcher_v3_range_proto_msgTypes,
	}.Build()
	File_xds_type_matcher_v3_range_proto = out.File
	file_xds_type_matcher_v3_range_proto_rawDesc = nil
	file_xds_type_matcher_v3_range_proto_goTypes = nil
	file_xds_type_matcher_v3_range_proto_depIdxs = nil
}

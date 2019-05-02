// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/errors/distinct_error.proto

package errors // import "google.golang.org/genproto/googleapis/ads/googleads/v1/errors"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Enum describing possible distinct errors.
type DistinctErrorEnum_DistinctError int32

const (
	// Enum unspecified.
	DistinctErrorEnum_UNSPECIFIED DistinctErrorEnum_DistinctError = 0
	// The received error code is not known in this version.
	DistinctErrorEnum_UNKNOWN DistinctErrorEnum_DistinctError = 1
	// Duplicate element.
	DistinctErrorEnum_DUPLICATE_ELEMENT DistinctErrorEnum_DistinctError = 2
	// Duplicate type.
	DistinctErrorEnum_DUPLICATE_TYPE DistinctErrorEnum_DistinctError = 3
)

var DistinctErrorEnum_DistinctError_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "DUPLICATE_ELEMENT",
	3: "DUPLICATE_TYPE",
}
var DistinctErrorEnum_DistinctError_value = map[string]int32{
	"UNSPECIFIED":       0,
	"UNKNOWN":           1,
	"DUPLICATE_ELEMENT": 2,
	"DUPLICATE_TYPE":    3,
}

func (x DistinctErrorEnum_DistinctError) String() string {
	return proto.EnumName(DistinctErrorEnum_DistinctError_name, int32(x))
}
func (DistinctErrorEnum_DistinctError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_distinct_error_ce2809863c4e9fa7, []int{0, 0}
}

// Container for enum describing possible distinct errors.
type DistinctErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DistinctErrorEnum) Reset()         { *m = DistinctErrorEnum{} }
func (m *DistinctErrorEnum) String() string { return proto.CompactTextString(m) }
func (*DistinctErrorEnum) ProtoMessage()    {}
func (*DistinctErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_distinct_error_ce2809863c4e9fa7, []int{0}
}
func (m *DistinctErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DistinctErrorEnum.Unmarshal(m, b)
}
func (m *DistinctErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DistinctErrorEnum.Marshal(b, m, deterministic)
}
func (dst *DistinctErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DistinctErrorEnum.Merge(dst, src)
}
func (m *DistinctErrorEnum) XXX_Size() int {
	return xxx_messageInfo_DistinctErrorEnum.Size(m)
}
func (m *DistinctErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_DistinctErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_DistinctErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*DistinctErrorEnum)(nil), "google.ads.googleads.v1.errors.DistinctErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.errors.DistinctErrorEnum_DistinctError", DistinctErrorEnum_DistinctError_name, DistinctErrorEnum_DistinctError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/errors/distinct_error.proto", fileDescriptor_distinct_error_ce2809863c4e9fa7)
}

var fileDescriptor_distinct_error_ce2809863c4e9fa7 = []byte{
	// 307 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0xdf, 0x4a, 0xc3, 0x30,
	0x18, 0xc5, 0x5d, 0x07, 0x0a, 0x19, 0x6a, 0x17, 0xf0, 0x46, 0x64, 0x17, 0x7d, 0x80, 0x84, 0xb2,
	0xbb, 0x78, 0x95, 0xad, 0x71, 0x0c, 0x67, 0x2d, 0xd8, 0xd6, 0x3f, 0x14, 0x46, 0x5d, 0x4a, 0x28,
	0xac, 0x49, 0x69, 0xea, 0x1e, 0xc8, 0x4b, 0x1f, 0xc5, 0x47, 0x11, 0x7c, 0x07, 0x69, 0xb3, 0x56,
	0x76, 0xa1, 0x57, 0x3d, 0xfd, 0xf8, 0x9d, 0xf3, 0x9d, 0x7c, 0x60, 0x2a, 0x94, 0x12, 0xdb, 0x0c,
	0xa7, 0x5c, 0x63, 0x23, 0x1b, 0xb5, 0x73, 0x71, 0x56, 0x55, 0xaa, 0xd2, 0x98, 0xe7, 0xba, 0xce,
	0xe5, 0xa6, 0x5e, 0xb7, 0xff, 0xa8, 0xac, 0x54, 0xad, 0xe0, 0xc4, 0x90, 0x28, 0xe5, 0x1a, 0xf5,
	0x26, 0xb4, 0x73, 0x91, 0x31, 0x5d, 0x5e, 0x75, 0xa1, 0x65, 0x8e, 0x53, 0x29, 0x55, 0x9d, 0xd6,
	0xb9, 0x92, 0xda, 0xb8, 0x9d, 0x02, 0x8c, 0xbd, 0x7d, 0x2a, 0x6b, 0x78, 0x26, 0xdf, 0x0a, 0xe7,
	0x09, 0x9c, 0x1e, 0x0c, 0xe1, 0x39, 0x18, 0x45, 0xfe, 0x43, 0xc0, 0xe6, 0xcb, 0x9b, 0x25, 0xf3,
	0xec, 0x23, 0x38, 0x02, 0x27, 0x91, 0x7f, 0xeb, 0xdf, 0x3f, 0xfa, 0xf6, 0x00, 0x5e, 0x80, 0xb1,
	0x17, 0x05, 0xab, 0xe5, 0x9c, 0x86, 0x6c, 0xcd, 0x56, 0xec, 0x8e, 0xf9, 0xa1, 0x6d, 0x41, 0x08,
	0xce, 0x7e, 0xc7, 0xe1, 0x73, 0xc0, 0xec, 0xe1, 0xec, 0x7b, 0x00, 0x9c, 0x8d, 0x2a, 0xd0, 0xff,
	0x9d, 0x67, 0xf0, 0x60, 0x7d, 0xd0, 0x34, 0x0d, 0x06, 0x2f, 0xde, 0xde, 0x25, 0xd4, 0x36, 0x95,
	0x02, 0xa9, 0x4a, 0x60, 0x91, 0xc9, 0xf6, 0x1d, 0xdd, 0xb9, 0xca, 0x5c, 0xff, 0x75, 0xbd, 0x6b,
	0xf3, 0x79, 0xb7, 0x86, 0x0b, 0x4a, 0x3f, 0xac, 0xc9, 0xc2, 0x84, 0x51, 0xae, 0x91, 0x91, 0x8d,
	0x8a, 0x5d, 0xd4, 0xae, 0xd4, 0x9f, 0x1d, 0x90, 0x50, 0xae, 0x93, 0x1e, 0x48, 0x62, 0x37, 0x31,
	0xc0, 0x97, 0xe5, 0x98, 0x29, 0x21, 0x94, 0x6b, 0x42, 0x7a, 0x84, 0x90, 0xd8, 0x25, 0xc4, 0x40,
	0xaf, 0xc7, 0x6d, 0xbb, 0xe9, 0x4f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5f, 0xfb, 0x24, 0x56, 0xda,
	0x01, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/shared_set_type.proto

package enums // import "google.golang.org/genproto/googleapis/ads/googleads/v1/enums"

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

// Enum listing the possible shared set types.
type SharedSetTypeEnum_SharedSetType int32

const (
	// Not specified.
	SharedSetTypeEnum_UNSPECIFIED SharedSetTypeEnum_SharedSetType = 0
	// Used for return value only. Represents value unknown in this version.
	SharedSetTypeEnum_UNKNOWN SharedSetTypeEnum_SharedSetType = 1
	// A set of keywords that can be excluded from targeting.
	SharedSetTypeEnum_NEGATIVE_KEYWORDS SharedSetTypeEnum_SharedSetType = 2
	// A set of placements that can be excluded from targeting.
	SharedSetTypeEnum_NEGATIVE_PLACEMENTS SharedSetTypeEnum_SharedSetType = 3
)

var SharedSetTypeEnum_SharedSetType_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "NEGATIVE_KEYWORDS",
	3: "NEGATIVE_PLACEMENTS",
}
var SharedSetTypeEnum_SharedSetType_value = map[string]int32{
	"UNSPECIFIED":         0,
	"UNKNOWN":             1,
	"NEGATIVE_KEYWORDS":   2,
	"NEGATIVE_PLACEMENTS": 3,
}

func (x SharedSetTypeEnum_SharedSetType) String() string {
	return proto.EnumName(SharedSetTypeEnum_SharedSetType_name, int32(x))
}
func (SharedSetTypeEnum_SharedSetType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_shared_set_type_6bb2efaed389b7a6, []int{0, 0}
}

// Container for enum describing types of shared sets.
type SharedSetTypeEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SharedSetTypeEnum) Reset()         { *m = SharedSetTypeEnum{} }
func (m *SharedSetTypeEnum) String() string { return proto.CompactTextString(m) }
func (*SharedSetTypeEnum) ProtoMessage()    {}
func (*SharedSetTypeEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_shared_set_type_6bb2efaed389b7a6, []int{0}
}
func (m *SharedSetTypeEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SharedSetTypeEnum.Unmarshal(m, b)
}
func (m *SharedSetTypeEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SharedSetTypeEnum.Marshal(b, m, deterministic)
}
func (dst *SharedSetTypeEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SharedSetTypeEnum.Merge(dst, src)
}
func (m *SharedSetTypeEnum) XXX_Size() int {
	return xxx_messageInfo_SharedSetTypeEnum.Size(m)
}
func (m *SharedSetTypeEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_SharedSetTypeEnum.DiscardUnknown(m)
}

var xxx_messageInfo_SharedSetTypeEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*SharedSetTypeEnum)(nil), "google.ads.googleads.v1.enums.SharedSetTypeEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.SharedSetTypeEnum_SharedSetType", SharedSetTypeEnum_SharedSetType_name, SharedSetTypeEnum_SharedSetType_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/shared_set_type.proto", fileDescriptor_shared_set_type_6bb2efaed389b7a6)
}

var fileDescriptor_shared_set_type_6bb2efaed389b7a6 = []byte{
	// 318 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x50, 0xcf, 0x4a, 0xc3, 0x30,
	0x1c, 0x76, 0x1d, 0x28, 0x64, 0x88, 0x5d, 0x45, 0x04, 0x71, 0x87, 0xed, 0x01, 0x52, 0xca, 0x6e,
	0xf1, 0x94, 0x6d, 0x71, 0x8c, 0x69, 0x57, 0xec, 0xd6, 0xa1, 0x54, 0x46, 0x35, 0x21, 0x0e, 0xb6,
	0xa4, 0x34, 0xd9, 0x60, 0xaf, 0xe3, 0xd1, 0x47, 0xf1, 0x45, 0x04, 0x9f, 0x42, 0x9a, 0xb8, 0xc2,
	0x0e, 0x7a, 0x09, 0x1f, 0xbf, 0xef, 0x0f, 0x5f, 0x3e, 0xd0, 0xe5, 0x52, 0xf2, 0x15, 0xf3, 0x33,
	0xaa, 0x7c, 0x0b, 0x4b, 0xb4, 0x0d, 0x7c, 0x26, 0x36, 0x6b, 0xe5, 0xab, 0xb7, 0xac, 0x60, 0x74,
	0xa1, 0x98, 0x5e, 0xe8, 0x5d, 0xce, 0x60, 0x5e, 0x48, 0x2d, 0xbd, 0x96, 0x55, 0xc2, 0x8c, 0x2a,
	0x58, 0x99, 0xe0, 0x36, 0x80, 0xc6, 0x74, 0x75, 0xbd, 0xcf, 0xcc, 0x97, 0x7e, 0x26, 0x84, 0xd4,
	0x99, 0x5e, 0x4a, 0xa1, 0xac, 0xb9, 0x53, 0x80, 0x66, 0x6c, 0x52, 0x63, 0xa6, 0xa7, 0xbb, 0x9c,
	0x11, 0xb1, 0x59, 0x77, 0x9e, 0xc1, 0xe9, 0xc1, 0xd1, 0x3b, 0x03, 0x8d, 0x59, 0x18, 0x47, 0xa4,
	0x3f, 0xba, 0x1d, 0x91, 0x81, 0x7b, 0xe4, 0x35, 0xc0, 0xc9, 0x2c, 0x1c, 0x87, 0x93, 0x79, 0xe8,
	0xd6, 0xbc, 0x0b, 0xd0, 0x0c, 0xc9, 0x10, 0x4f, 0x47, 0x09, 0x59, 0x8c, 0xc9, 0xe3, 0x7c, 0xf2,
	0x30, 0x88, 0x5d, 0xc7, 0xbb, 0x04, 0xe7, 0xd5, 0x39, 0xba, 0xc3, 0x7d, 0x72, 0x4f, 0xc2, 0x69,
	0xec, 0xd6, 0x7b, 0x5f, 0x35, 0xd0, 0x7e, 0x95, 0x6b, 0xf8, 0x6f, 0xef, 0x9e, 0x77, 0x50, 0x21,
	0x2a, 0xdb, 0x46, 0xb5, 0xa7, 0xde, 0xaf, 0x89, 0xcb, 0x55, 0x26, 0x38, 0x94, 0x05, 0xf7, 0x39,
	0x13, 0xe6, 0x2f, 0xfb, 0xc5, 0xf2, 0xa5, 0xfa, 0x63, 0xc0, 0x1b, 0xf3, 0xbe, 0x3b, 0xf5, 0x21,
	0xc6, 0x1f, 0x4e, 0x6b, 0x68, 0xa3, 0x30, 0x55, 0xd0, 0xc2, 0x12, 0x25, 0x01, 0x2c, 0x37, 0x50,
	0x9f, 0x7b, 0x3e, 0xc5, 0x54, 0xa5, 0x15, 0x9f, 0x26, 0x41, 0x6a, 0xf8, 0x6f, 0xa7, 0x6d, 0x8f,
	0x08, 0x61, 0xaa, 0x10, 0xaa, 0x14, 0x08, 0x25, 0x01, 0x42, 0x46, 0xf3, 0x72, 0x6c, 0x8a, 0x75,
	0x7f, 0x02, 0x00, 0x00, 0xff, 0xff, 0x62, 0x76, 0xf7, 0xc4, 0xd8, 0x01, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/frequency_cap_time_unit.proto

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

// Unit of time the cap is defined at (e.g. day, week).
type FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit int32

const (
	// Not specified.
	FrequencyCapTimeUnitEnum_UNSPECIFIED FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit = 0
	// Used for return value only. Represents value unknown in this version.
	FrequencyCapTimeUnitEnum_UNKNOWN FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit = 1
	// The cap would define limit per one day.
	FrequencyCapTimeUnitEnum_DAY FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit = 2
	// The cap would define limit per one week.
	FrequencyCapTimeUnitEnum_WEEK FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit = 3
	// The cap would define limit per one month.
	FrequencyCapTimeUnitEnum_MONTH FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit = 4
)

var FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "DAY",
	3: "WEEK",
	4: "MONTH",
}
var FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"DAY":         2,
	"WEEK":        3,
	"MONTH":       4,
}

func (x FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit) String() string {
	return proto.EnumName(FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit_name, int32(x))
}
func (FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_frequency_cap_time_unit_d8858482f1696885, []int{0, 0}
}

// Container for enum describing the unit of time the cap is defined at.
type FrequencyCapTimeUnitEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FrequencyCapTimeUnitEnum) Reset()         { *m = FrequencyCapTimeUnitEnum{} }
func (m *FrequencyCapTimeUnitEnum) String() string { return proto.CompactTextString(m) }
func (*FrequencyCapTimeUnitEnum) ProtoMessage()    {}
func (*FrequencyCapTimeUnitEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_frequency_cap_time_unit_d8858482f1696885, []int{0}
}
func (m *FrequencyCapTimeUnitEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FrequencyCapTimeUnitEnum.Unmarshal(m, b)
}
func (m *FrequencyCapTimeUnitEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FrequencyCapTimeUnitEnum.Marshal(b, m, deterministic)
}
func (dst *FrequencyCapTimeUnitEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FrequencyCapTimeUnitEnum.Merge(dst, src)
}
func (m *FrequencyCapTimeUnitEnum) XXX_Size() int {
	return xxx_messageInfo_FrequencyCapTimeUnitEnum.Size(m)
}
func (m *FrequencyCapTimeUnitEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_FrequencyCapTimeUnitEnum.DiscardUnknown(m)
}

var xxx_messageInfo_FrequencyCapTimeUnitEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*FrequencyCapTimeUnitEnum)(nil), "google.ads.googleads.v1.enums.FrequencyCapTimeUnitEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit", FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit_name, FrequencyCapTimeUnitEnum_FrequencyCapTimeUnit_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/frequency_cap_time_unit.proto", fileDescriptor_frequency_cap_time_unit_d8858482f1696885)
}

var fileDescriptor_frequency_cap_time_unit_d8858482f1696885 = []byte{
	// 324 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0xcf, 0x4e, 0xf2, 0x40,
	0x14, 0xc5, 0x3f, 0x0a, 0x9f, 0xe8, 0xb0, 0xb0, 0x69, 0x5c, 0xa8, 0x91, 0x05, 0x3c, 0xc0, 0x34,
	0x8d, 0xbb, 0x61, 0x35, 0x40, 0x41, 0x42, 0x2c, 0x44, 0xf9, 0x13, 0x4d, 0x13, 0x32, 0xd2, 0x71,
	0x32, 0x09, 0x9d, 0xa9, 0xcc, 0x94, 0xc4, 0xd7, 0x71, 0xe9, 0xa3, 0xf8, 0x28, 0x2e, 0x7c, 0x06,
	0xd3, 0x19, 0xcb, 0x0a, 0xdd, 0x34, 0x27, 0x3d, 0xf7, 0x77, 0xe6, 0xdc, 0x0b, 0x3a, 0x4c, 0x4a,
	0xb6, 0xa1, 0x3e, 0x49, 0x94, 0x6f, 0x65, 0xa1, 0x76, 0x81, 0x4f, 0x45, 0x9e, 0x2a, 0xff, 0x79,
	0x4b, 0x5f, 0x72, 0x2a, 0xd6, 0xaf, 0xab, 0x35, 0xc9, 0x56, 0x9a, 0xa7, 0x74, 0x95, 0x0b, 0xae,
	0x61, 0xb6, 0x95, 0x5a, 0x7a, 0x4d, 0x4b, 0x40, 0x92, 0x28, 0xb8, 0x87, 0xe1, 0x2e, 0x80, 0x06,
	0xbe, 0xbc, 0x2a, 0xb3, 0x33, 0xee, 0x13, 0x21, 0xa4, 0x26, 0x9a, 0x4b, 0xa1, 0x2c, 0xdc, 0x16,
	0xe0, 0x7c, 0x50, 0xa6, 0xf7, 0x48, 0x36, 0xe3, 0x29, 0x9d, 0x0b, 0xae, 0x43, 0x91, 0xa7, 0xed,
	0x3b, 0x70, 0x76, 0xc8, 0xf3, 0x4e, 0x41, 0x63, 0x1e, 0xdd, 0x4f, 0xc3, 0xde, 0x68, 0x30, 0x0a,
	0xfb, 0xee, 0x3f, 0xaf, 0x01, 0xea, 0xf3, 0x68, 0x1c, 0x4d, 0x96, 0x91, 0x5b, 0xf1, 0xea, 0xa0,
	0xda, 0xc7, 0x0f, 0xae, 0xe3, 0x1d, 0x83, 0xda, 0x32, 0x0c, 0xc7, 0x6e, 0xd5, 0x3b, 0x01, 0xff,
	0x6f, 0x27, 0xd1, 0xec, 0xc6, 0xad, 0x75, 0xbf, 0x2a, 0xa0, 0xb5, 0x96, 0x29, 0xfc, 0xb3, 0x73,
	0xf7, 0xe2, 0xd0, 0xbb, 0xd3, 0xa2, 0xf0, 0xb4, 0xf2, 0xd8, 0xfd, 0x61, 0x99, 0xdc, 0x10, 0xc1,
	0xa0, 0xdc, 0x32, 0x9f, 0x51, 0x61, 0xd6, 0x29, 0x8f, 0x97, 0x71, 0xf5, 0xcb, 0x2d, 0x3b, 0xe6,
	0xfb, 0xe6, 0x54, 0x87, 0x18, 0xbf, 0x3b, 0xcd, 0xa1, 0x8d, 0xc2, 0x89, 0x82, 0x56, 0x16, 0x6a,
	0x11, 0xc0, 0x62, 0x7f, 0xf5, 0x51, 0xfa, 0x31, 0x4e, 0x54, 0xbc, 0xf7, 0xe3, 0x45, 0x10, 0x1b,
	0xff, 0xd3, 0x69, 0xd9, 0x9f, 0x08, 0xe1, 0x44, 0x21, 0xb4, 0x9f, 0x40, 0x68, 0x11, 0x20, 0x64,
	0x66, 0x9e, 0x8e, 0x4c, 0xb1, 0xeb, 0xef, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7c, 0x8d, 0xe0, 0xdf,
	0xe3, 0x01, 0x00, 0x00,
}

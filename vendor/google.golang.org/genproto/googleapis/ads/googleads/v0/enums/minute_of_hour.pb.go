// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/enums/minute_of_hour.proto

package enums // import "google.golang.org/genproto/googleapis/ads/googleads/v0/enums"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Enumerates of quarter-hours. E.g. "FIFTEEN"
type MinuteOfHourEnum_MinuteOfHour int32

const (
	// Not specified.
	MinuteOfHourEnum_UNSPECIFIED MinuteOfHourEnum_MinuteOfHour = 0
	// The value is unknown in this version.
	MinuteOfHourEnum_UNKNOWN MinuteOfHourEnum_MinuteOfHour = 1
	// Zero minutes past the hour.
	MinuteOfHourEnum_ZERO MinuteOfHourEnum_MinuteOfHour = 2
	// Fifteen minutes past the hour.
	MinuteOfHourEnum_FIFTEEN MinuteOfHourEnum_MinuteOfHour = 3
	// Thirty minutes past the hour.
	MinuteOfHourEnum_THIRTY MinuteOfHourEnum_MinuteOfHour = 4
	// Forty-five minutes past the hour.
	MinuteOfHourEnum_FORTY_FIVE MinuteOfHourEnum_MinuteOfHour = 5
)

var MinuteOfHourEnum_MinuteOfHour_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "ZERO",
	3: "FIFTEEN",
	4: "THIRTY",
	5: "FORTY_FIVE",
}
var MinuteOfHourEnum_MinuteOfHour_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"ZERO":        2,
	"FIFTEEN":     3,
	"THIRTY":      4,
	"FORTY_FIVE":  5,
}

func (x MinuteOfHourEnum_MinuteOfHour) String() string {
	return proto.EnumName(MinuteOfHourEnum_MinuteOfHour_name, int32(x))
}
func (MinuteOfHourEnum_MinuteOfHour) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_minute_of_hour_7b7d8b5307e8d14c, []int{0, 0}
}

// Container for enumeration of quarter-hours.
type MinuteOfHourEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MinuteOfHourEnum) Reset()         { *m = MinuteOfHourEnum{} }
func (m *MinuteOfHourEnum) String() string { return proto.CompactTextString(m) }
func (*MinuteOfHourEnum) ProtoMessage()    {}
func (*MinuteOfHourEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_minute_of_hour_7b7d8b5307e8d14c, []int{0}
}
func (m *MinuteOfHourEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MinuteOfHourEnum.Unmarshal(m, b)
}
func (m *MinuteOfHourEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MinuteOfHourEnum.Marshal(b, m, deterministic)
}
func (dst *MinuteOfHourEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MinuteOfHourEnum.Merge(dst, src)
}
func (m *MinuteOfHourEnum) XXX_Size() int {
	return xxx_messageInfo_MinuteOfHourEnum.Size(m)
}
func (m *MinuteOfHourEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_MinuteOfHourEnum.DiscardUnknown(m)
}

var xxx_messageInfo_MinuteOfHourEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*MinuteOfHourEnum)(nil), "google.ads.googleads.v0.enums.MinuteOfHourEnum")
	proto.RegisterEnum("google.ads.googleads.v0.enums.MinuteOfHourEnum_MinuteOfHour", MinuteOfHourEnum_MinuteOfHour_name, MinuteOfHourEnum_MinuteOfHour_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/enums/minute_of_hour.proto", fileDescriptor_minute_of_hour_7b7d8b5307e8d14c)
}

var fileDescriptor_minute_of_hour_7b7d8b5307e8d14c = []byte{
	// 305 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x50, 0x4f, 0x4e, 0xb3, 0x40,
	0x1c, 0xfd, 0x4a, 0xfb, 0x55, 0xf3, 0xab, 0xd1, 0x71, 0xf6, 0x5d, 0xb4, 0x07, 0x18, 0x88, 0xee,
	0xc6, 0x15, 0xd5, 0xa1, 0x25, 0x46, 0x20, 0x48, 0x31, 0x6d, 0x48, 0x08, 0x0a, 0x1d, 0x9b, 0x14,
	0xa6, 0x61, 0x4a, 0x0f, 0xe4, 0xd2, 0xa3, 0x78, 0x10, 0x17, 0x9e, 0xc2, 0x30, 0x58, 0xd2, 0x8d,
	0x6e, 0x26, 0x2f, 0xef, 0xcf, 0xe4, 0xfd, 0x1e, 0x5c, 0x71, 0x21, 0xf8, 0x26, 0xd3, 0x93, 0x54,
	0xea, 0x0d, 0xac, 0xd1, 0xde, 0xd0, 0xb3, 0xa2, 0xca, 0xa5, 0x9e, 0xaf, 0x8b, 0x6a, 0x97, 0xc5,
	0x62, 0x15, 0xbf, 0x8a, 0xaa, 0x24, 0xdb, 0x52, 0xec, 0x04, 0x1e, 0x36, 0x46, 0x92, 0xa4, 0x92,
	0xb4, 0x19, 0xb2, 0x37, 0x88, 0xca, 0x8c, 0x25, 0xa0, 0x07, 0x15, 0x73, 0x57, 0x33, 0x51, 0x95,
	0xac, 0xa8, 0xf2, 0x71, 0x0c, 0x67, 0xc7, 0x1c, 0xbe, 0x80, 0xc1, 0xdc, 0x79, 0xf4, 0xd8, 0xad,
	0x6d, 0xd9, 0xec, 0x0e, 0xfd, 0xc3, 0x03, 0x38, 0x99, 0x3b, 0xf7, 0x8e, 0xfb, 0xe4, 0xa0, 0x0e,
	0x3e, 0x85, 0xde, 0x92, 0xf9, 0x2e, 0xd2, 0x6a, 0xda, 0xb2, 0xad, 0x80, 0x31, 0x07, 0x75, 0x31,
	0x40, 0x3f, 0x98, 0xd9, 0x7e, 0xb0, 0x40, 0x3d, 0x7c, 0x0e, 0x60, 0xb9, 0x7e, 0xb0, 0x88, 0x2d,
	0x3b, 0x64, 0xe8, 0xff, 0xe4, 0xb3, 0x03, 0xa3, 0x17, 0x91, 0x93, 0x3f, 0xab, 0x4d, 0x2e, 0x8f,
	0x4b, 0x78, 0xf5, 0x31, 0x5e, 0x67, 0x39, 0xf9, 0xc9, 0x70, 0xb1, 0x49, 0x0a, 0x4e, 0x44, 0xc9,
	0x75, 0x9e, 0x15, 0xea, 0xd4, 0xc3, 0x24, 0xdb, 0xb5, 0xfc, 0x65, 0xa1, 0x1b, 0xf5, 0xbe, 0x69,
	0xdd, 0xa9, 0x69, 0xbe, 0x6b, 0xc3, 0x69, 0xf3, 0x95, 0x99, 0x4a, 0xd2, 0xc0, 0x1a, 0x85, 0x06,
	0xa9, 0x47, 0x90, 0x1f, 0x07, 0x3d, 0x32, 0x53, 0x19, 0xb5, 0x7a, 0x14, 0x1a, 0x91, 0xd2, 0xbf,
	0xb4, 0x51, 0x43, 0x52, 0x6a, 0xa6, 0x92, 0xd2, 0xd6, 0x41, 0x69, 0x68, 0x50, 0xaa, 0x3c, 0xcf,
	0x7d, 0x55, 0xec, 0xfa, 0x3b, 0x00, 0x00, 0xff, 0xff, 0x87, 0x73, 0x9e, 0xc7, 0xb9, 0x01, 0x00,
	0x00,
}

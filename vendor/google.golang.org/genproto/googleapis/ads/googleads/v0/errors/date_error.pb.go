// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/errors/date_error.proto

package errors // import "google.golang.org/genproto/googleapis/ads/googleads/v0/errors"

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

// Enum describing possible date errors.
type DateErrorEnum_DateError int32

const (
	// Enum unspecified.
	DateErrorEnum_UNSPECIFIED DateErrorEnum_DateError = 0
	// The received error code is not known in this version.
	DateErrorEnum_UNKNOWN DateErrorEnum_DateError = 1
	// Given field values do not correspond to a valid date.
	DateErrorEnum_INVALID_FIELD_VALUES_IN_DATE DateErrorEnum_DateError = 2
	// Given field values do not correspond to a valid date time.
	DateErrorEnum_INVALID_FIELD_VALUES_IN_DATE_TIME DateErrorEnum_DateError = 3
	// The string date's format should be yyyy-mm-dd.
	DateErrorEnum_INVALID_STRING_DATE DateErrorEnum_DateError = 4
	// The string date time's format should be yyyy-mm-dd hh:mm:ss.ssssss.
	DateErrorEnum_INVALID_STRING_DATE_TIME_MICROS DateErrorEnum_DateError = 6
	// The string date time's format should be yyyy-mm-dd hh:mm:ss.
	DateErrorEnum_INVALID_STRING_DATE_TIME_SECONDS DateErrorEnum_DateError = 11
	// Date is before allowed minimum.
	DateErrorEnum_EARLIER_THAN_MINIMUM_DATE DateErrorEnum_DateError = 7
	// Date is after allowed maximum.
	DateErrorEnum_LATER_THAN_MAXIMUM_DATE DateErrorEnum_DateError = 8
	// Date range bounds are not in order.
	DateErrorEnum_DATE_RANGE_MINIMUM_DATE_LATER_THAN_MAXIMUM_DATE DateErrorEnum_DateError = 9
	// Both dates in range are null.
	DateErrorEnum_DATE_RANGE_MINIMUM_AND_MAXIMUM_DATES_BOTH_NULL DateErrorEnum_DateError = 10
)

var DateErrorEnum_DateError_name = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "UNKNOWN",
	2:  "INVALID_FIELD_VALUES_IN_DATE",
	3:  "INVALID_FIELD_VALUES_IN_DATE_TIME",
	4:  "INVALID_STRING_DATE",
	6:  "INVALID_STRING_DATE_TIME_MICROS",
	11: "INVALID_STRING_DATE_TIME_SECONDS",
	7:  "EARLIER_THAN_MINIMUM_DATE",
	8:  "LATER_THAN_MAXIMUM_DATE",
	9:  "DATE_RANGE_MINIMUM_DATE_LATER_THAN_MAXIMUM_DATE",
	10: "DATE_RANGE_MINIMUM_AND_MAXIMUM_DATES_BOTH_NULL",
}
var DateErrorEnum_DateError_value = map[string]int32{
	"UNSPECIFIED":                                     0,
	"UNKNOWN":                                         1,
	"INVALID_FIELD_VALUES_IN_DATE":                    2,
	"INVALID_FIELD_VALUES_IN_DATE_TIME":               3,
	"INVALID_STRING_DATE":                             4,
	"INVALID_STRING_DATE_TIME_MICROS":                 6,
	"INVALID_STRING_DATE_TIME_SECONDS":                11,
	"EARLIER_THAN_MINIMUM_DATE":                       7,
	"LATER_THAN_MAXIMUM_DATE":                         8,
	"DATE_RANGE_MINIMUM_DATE_LATER_THAN_MAXIMUM_DATE": 9,
	"DATE_RANGE_MINIMUM_AND_MAXIMUM_DATES_BOTH_NULL":  10,
}

func (x DateErrorEnum_DateError) String() string {
	return proto.EnumName(DateErrorEnum_DateError_name, int32(x))
}
func (DateErrorEnum_DateError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_date_error_04d689f0bf984a6b, []int{0, 0}
}

// Container for enum describing possible date errors.
type DateErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DateErrorEnum) Reset()         { *m = DateErrorEnum{} }
func (m *DateErrorEnum) String() string { return proto.CompactTextString(m) }
func (*DateErrorEnum) ProtoMessage()    {}
func (*DateErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_date_error_04d689f0bf984a6b, []int{0}
}
func (m *DateErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DateErrorEnum.Unmarshal(m, b)
}
func (m *DateErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DateErrorEnum.Marshal(b, m, deterministic)
}
func (dst *DateErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DateErrorEnum.Merge(dst, src)
}
func (m *DateErrorEnum) XXX_Size() int {
	return xxx_messageInfo_DateErrorEnum.Size(m)
}
func (m *DateErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_DateErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_DateErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*DateErrorEnum)(nil), "google.ads.googleads.v0.errors.DateErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v0.errors.DateErrorEnum_DateError", DateErrorEnum_DateError_name, DateErrorEnum_DateError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/errors/date_error.proto", fileDescriptor_date_error_04d689f0bf984a6b)
}

var fileDescriptor_date_error_04d689f0bf984a6b = []byte{
	// 413 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xdf, 0x6e, 0xd3, 0x30,
	0x14, 0x87, 0x69, 0x8a, 0x36, 0x76, 0x2a, 0x20, 0x32, 0x17, 0x13, 0x02, 0xc6, 0x28, 0x70, 0xeb,
	0x44, 0xec, 0xce, 0x5c, 0xb9, 0xb5, 0xd7, 0x59, 0x24, 0x4e, 0x95, 0x7f, 0x20, 0x14, 0xc9, 0x0a,
	0x24, 0x8a, 0x90, 0xb6, 0x7a, 0x8a, 0xcb, 0xde, 0x82, 0x97, 0xe0, 0x92, 0x47, 0xe1, 0x4d, 0xe0,
	0x15, 0xb8, 0x41, 0x89, 0xd7, 0x4c, 0x93, 0xd6, 0x5e, 0xe5, 0x17, 0x9f, 0xef, 0xf3, 0xb1, 0x74,
	0x0e, 0x78, 0x8d, 0xd6, 0xcd, 0x79, 0xed, 0x95, 0x95, 0xb9, 0x8e, 0x5d, 0xba, 0xf2, 0xbd, 0xba,
	0x6d, 0x75, 0x6b, 0xbc, 0xaa, 0x5c, 0xd7, 0xaa, 0xcf, 0xf8, 0xb2, 0xd5, 0x6b, 0x8d, 0x8e, 0x2c,
	0x85, 0xcb, 0xca, 0xe0, 0x41, 0xc0, 0x57, 0x3e, 0xb6, 0xc2, 0xf4, 0xc7, 0x18, 0x1e, 0xb2, 0x72,
	0x5d, 0xf3, 0xee, 0x97, 0xaf, 0xbe, 0x5f, 0x4c, 0xff, 0x39, 0x70, 0x30, 0x9c, 0xa0, 0xc7, 0x30,
	0xc9, 0x64, 0xb2, 0xe4, 0x73, 0x71, 0x2a, 0x38, 0x73, 0xef, 0xa1, 0x09, 0xec, 0x67, 0xf2, 0x83,
	0x8c, 0x3e, 0x4a, 0x77, 0x84, 0x8e, 0xe1, 0xb9, 0x90, 0x39, 0x0d, 0x04, 0x53, 0xa7, 0x82, 0x07,
	0x4c, 0xe5, 0x34, 0xc8, 0x78, 0xa2, 0x84, 0x54, 0x8c, 0xa6, 0xdc, 0x75, 0xd0, 0x5b, 0x78, 0xb5,
	0x8b, 0x50, 0xa9, 0x08, 0xb9, 0x3b, 0x46, 0x87, 0xf0, 0x64, 0x83, 0x25, 0x69, 0x2c, 0xe4, 0xc2,
	0xfa, 0xf7, 0xd1, 0x6b, 0x78, 0x79, 0x47, 0xa1, 0xd7, 0x54, 0x28, 0xe6, 0x71, 0x94, 0xb8, 0x7b,
	0xe8, 0x0d, 0x1c, 0x6f, 0x85, 0x12, 0x3e, 0x8f, 0x24, 0x4b, 0xdc, 0x09, 0x7a, 0x01, 0x4f, 0x39,
	0x8d, 0x03, 0xc1, 0x63, 0x95, 0x9e, 0x51, 0xa9, 0x42, 0x21, 0x45, 0x98, 0x85, 0xb6, 0xd3, 0x3e,
	0x7a, 0x06, 0x87, 0x01, 0x4d, 0x87, 0x22, 0xfd, 0x74, 0x53, 0x7c, 0x80, 0x4e, 0xc0, 0xeb, 0xaf,
	0x8c, 0xa9, 0x5c, 0xf0, 0x5b, 0xa6, 0xda, 0x26, 0x1d, 0xa0, 0x77, 0x80, 0xef, 0x90, 0xa8, 0x64,
	0xb7, 0xc0, 0x44, 0xcd, 0xa2, 0xf4, 0x4c, 0xc9, 0x2c, 0x08, 0x5c, 0x98, 0xfd, 0x19, 0xc1, 0xf4,
	0xab, 0xbe, 0xc0, 0xbb, 0xc7, 0x36, 0x7b, 0x34, 0x4c, 0x68, 0xd9, 0x8d, 0x79, 0x39, 0xfa, 0xcc,
	0xae, 0x8d, 0x46, 0x9f, 0x97, 0xab, 0x06, 0xeb, 0xb6, 0xf1, 0x9a, 0x7a, 0xd5, 0x2f, 0xc1, 0x66,
	0x53, 0x2e, 0xbf, 0x99, 0x6d, 0x8b, 0xf3, 0xde, 0x7e, 0x7e, 0x3a, 0xe3, 0x05, 0xa5, 0xbf, 0x9c,
	0xa3, 0x85, 0xbd, 0x8c, 0x56, 0x06, 0xdb, 0xd8, 0xa5, 0xdc, 0xc7, 0x7d, 0x4b, 0xf3, 0x7b, 0x03,
	0x14, 0xb4, 0x32, 0xc5, 0x00, 0x14, 0xb9, 0x5f, 0x58, 0xe0, 0xaf, 0x33, 0xb5, 0xa7, 0x84, 0xd0,
	0xca, 0x10, 0x32, 0x20, 0x84, 0xe4, 0x3e, 0x21, 0x16, 0xfa, 0xb2, 0xd7, 0xbf, 0xee, 0xe4, 0x7f,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xcf, 0xe7, 0x23, 0x23, 0xd5, 0x02, 0x00, 0x00,
}

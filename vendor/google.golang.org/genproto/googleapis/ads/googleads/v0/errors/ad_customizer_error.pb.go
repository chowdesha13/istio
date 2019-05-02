// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/errors/ad_customizer_error.proto

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

// Enum describing possible ad customizer errors.
type AdCustomizerErrorEnum_AdCustomizerError int32

const (
	// Enum unspecified.
	AdCustomizerErrorEnum_UNSPECIFIED AdCustomizerErrorEnum_AdCustomizerError = 0
	// The received error code is not known in this version.
	AdCustomizerErrorEnum_UNKNOWN AdCustomizerErrorEnum_AdCustomizerError = 1
	// Invalid date argument in countdown function.
	AdCustomizerErrorEnum_COUNTDOWN_INVALID_DATE_FORMAT AdCustomizerErrorEnum_AdCustomizerError = 2
	// Countdown end date is in the past.
	AdCustomizerErrorEnum_COUNTDOWN_DATE_IN_PAST AdCustomizerErrorEnum_AdCustomizerError = 3
	// Invalid locale string in countdown function.
	AdCustomizerErrorEnum_COUNTDOWN_INVALID_LOCALE AdCustomizerErrorEnum_AdCustomizerError = 4
	// Days-before argument to countdown function is not positive.
	AdCustomizerErrorEnum_COUNTDOWN_INVALID_START_DAYS_BEFORE AdCustomizerErrorEnum_AdCustomizerError = 5
	// A user list referenced in an IF function does not exist.
	AdCustomizerErrorEnum_UNKNOWN_USER_LIST AdCustomizerErrorEnum_AdCustomizerError = 6
)

var AdCustomizerErrorEnum_AdCustomizerError_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "COUNTDOWN_INVALID_DATE_FORMAT",
	3: "COUNTDOWN_DATE_IN_PAST",
	4: "COUNTDOWN_INVALID_LOCALE",
	5: "COUNTDOWN_INVALID_START_DAYS_BEFORE",
	6: "UNKNOWN_USER_LIST",
}
var AdCustomizerErrorEnum_AdCustomizerError_value = map[string]int32{
	"UNSPECIFIED":                         0,
	"UNKNOWN":                             1,
	"COUNTDOWN_INVALID_DATE_FORMAT":       2,
	"COUNTDOWN_DATE_IN_PAST":              3,
	"COUNTDOWN_INVALID_LOCALE":            4,
	"COUNTDOWN_INVALID_START_DAYS_BEFORE": 5,
	"UNKNOWN_USER_LIST":                   6,
}

func (x AdCustomizerErrorEnum_AdCustomizerError) String() string {
	return proto.EnumName(AdCustomizerErrorEnum_AdCustomizerError_name, int32(x))
}
func (AdCustomizerErrorEnum_AdCustomizerError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ad_customizer_error_8e31a87aead61c95, []int{0, 0}
}

// Container for enum describing possible ad customizer errors.
type AdCustomizerErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AdCustomizerErrorEnum) Reset()         { *m = AdCustomizerErrorEnum{} }
func (m *AdCustomizerErrorEnum) String() string { return proto.CompactTextString(m) }
func (*AdCustomizerErrorEnum) ProtoMessage()    {}
func (*AdCustomizerErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_ad_customizer_error_8e31a87aead61c95, []int{0}
}
func (m *AdCustomizerErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AdCustomizerErrorEnum.Unmarshal(m, b)
}
func (m *AdCustomizerErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AdCustomizerErrorEnum.Marshal(b, m, deterministic)
}
func (dst *AdCustomizerErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdCustomizerErrorEnum.Merge(dst, src)
}
func (m *AdCustomizerErrorEnum) XXX_Size() int {
	return xxx_messageInfo_AdCustomizerErrorEnum.Size(m)
}
func (m *AdCustomizerErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_AdCustomizerErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_AdCustomizerErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*AdCustomizerErrorEnum)(nil), "google.ads.googleads.v0.errors.AdCustomizerErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v0.errors.AdCustomizerErrorEnum_AdCustomizerError", AdCustomizerErrorEnum_AdCustomizerError_name, AdCustomizerErrorEnum_AdCustomizerError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/errors/ad_customizer_error.proto", fileDescriptor_ad_customizer_error_8e31a87aead61c95)
}

var fileDescriptor_ad_customizer_error_8e31a87aead61c95 = []byte{
	// 366 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0x4f, 0x0b, 0xd3, 0x30,
	0x18, 0xc6, 0x6d, 0xa7, 0x13, 0xb2, 0x83, 0x5d, 0x60, 0x43, 0x44, 0x07, 0xd6, 0x83, 0xb7, 0xb4,
	0xe0, 0x45, 0xe2, 0x29, 0x6b, 0xb3, 0x51, 0xac, 0x69, 0xe9, 0xbf, 0xa1, 0x14, 0x42, 0x5d, 0x4b,
	0x19, 0x6c, 0xcb, 0x68, 0xb6, 0x1d, 0xfc, 0x38, 0x1e, 0xfd, 0x28, 0x1e, 0xfc, 0x1c, 0xe2, 0xcd,
	0x6f, 0x20, 0x6d, 0xb6, 0x7a, 0x28, 0x7a, 0xca, 0xc3, 0xfb, 0xfe, 0x9e, 0xe4, 0xcd, 0xf3, 0x82,
	0xb7, 0xb5, 0x10, 0xf5, 0xbe, 0xb2, 0x8a, 0x52, 0x5a, 0x4a, 0xb6, 0xea, 0x6a, 0x5b, 0x55, 0xd3,
	0x88, 0x46, 0x5a, 0x45, 0xc9, 0xb7, 0x17, 0x79, 0x16, 0x87, 0xdd, 0x97, 0xaa, 0xe1, 0x5d, 0x11,
	0x9d, 0x1a, 0x71, 0x16, 0x70, 0xa1, 0x70, 0x54, 0x94, 0x12, 0xf5, 0x4e, 0x74, 0xb5, 0x91, 0x72,
	0x9a, 0x3f, 0x35, 0x30, 0x23, 0xa5, 0xd3, 0x9b, 0x69, 0x5b, 0xa6, 0xc7, 0xcb, 0xc1, 0xfc, 0xa1,
	0x81, 0xe9, 0xa0, 0x03, 0x9f, 0x80, 0x49, 0xca, 0xe2, 0x90, 0x3a, 0xde, 0xca, 0xa3, 0xae, 0xf1,
	0x00, 0x4e, 0xc0, 0xe3, 0x94, 0xbd, 0x67, 0xc1, 0x86, 0x19, 0x1a, 0x7c, 0x09, 0x5e, 0x38, 0x41,
	0xca, 0x12, 0x37, 0xd8, 0x30, 0xee, 0xb1, 0x8c, 0xf8, 0x9e, 0xcb, 0x5d, 0x92, 0x50, 0xbe, 0x0a,
	0xa2, 0x0f, 0x24, 0x31, 0x74, 0xf8, 0x0c, 0xcc, 0xff, 0x22, 0x5d, 0xcb, 0x63, 0x3c, 0x24, 0x71,
	0x62, 0x8c, 0xe0, 0x73, 0xf0, 0x74, 0x68, 0xf7, 0x03, 0x87, 0xf8, 0xd4, 0x78, 0x08, 0x5f, 0x83,
	0x57, 0xc3, 0x6e, 0x9c, 0x90, 0x28, 0xe1, 0x2e, 0xf9, 0x18, 0xf3, 0x25, 0x5d, 0x05, 0x11, 0x35,
	0x1e, 0xc1, 0x19, 0x98, 0xde, 0x46, 0xe2, 0x69, 0x4c, 0x23, 0xee, 0x7b, 0x71, 0x62, 0x8c, 0x97,
	0xbf, 0x35, 0x60, 0x6e, 0xc5, 0x01, 0xfd, 0x3f, 0x91, 0xe5, 0x7c, 0xf0, 0xe9, 0xb0, 0x4d, 0x32,
	0xd4, 0x3e, 0xb9, 0x37, 0x67, 0x2d, 0xf6, 0xc5, 0xb1, 0x46, 0xa2, 0xa9, 0xad, 0xba, 0x3a, 0x76,
	0x39, 0xdf, 0xb7, 0x72, 0xda, 0xc9, 0x7f, 0x2d, 0xe9, 0x9d, 0x3a, 0xbe, 0xea, 0xa3, 0x35, 0x21,
	0xdf, 0xf4, 0xc5, 0x5a, 0x5d, 0x46, 0x4a, 0x89, 0x94, 0x6c, 0x55, 0x66, 0xa3, 0xee, 0x49, 0xf9,
	0xfd, 0x0e, 0xe4, 0xa4, 0x94, 0x79, 0x0f, 0xe4, 0x99, 0x9d, 0x2b, 0xe0, 0x97, 0x6e, 0xaa, 0x2a,
	0xc6, 0xa4, 0x94, 0x18, 0xf7, 0x08, 0xc6, 0x99, 0x8d, 0xb1, 0x82, 0x3e, 0x8f, 0xbb, 0xe9, 0xde,
	0xfc, 0x09, 0x00, 0x00, 0xff, 0xff, 0x84, 0x06, 0x70, 0x25, 0x41, 0x02, 0x00, 0x00,
}

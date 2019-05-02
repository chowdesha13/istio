// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/errors/conversion_action_error.proto

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

// Enum describing possible conversion action errors.
type ConversionActionErrorEnum_ConversionActionError int32

const (
	// Enum unspecified.
	ConversionActionErrorEnum_UNSPECIFIED ConversionActionErrorEnum_ConversionActionError = 0
	// The received error code is not known in this version.
	ConversionActionErrorEnum_UNKNOWN ConversionActionErrorEnum_ConversionActionError = 1
	// The specified conversion action name already exists.
	ConversionActionErrorEnum_DUPLICATE_NAME ConversionActionErrorEnum_ConversionActionError = 2
	// Another conversion action with the specified app id already exists.
	ConversionActionErrorEnum_DUPLICATE_APP_ID ConversionActionErrorEnum_ConversionActionError = 3
	// Android first open action conflicts with Google play codeless download
	// action tracking the same app.
	ConversionActionErrorEnum_TWO_CONVERSION_ACTIONS_BIDDING_ON_SAME_APP_DOWNLOAD ConversionActionErrorEnum_ConversionActionError = 4
	// Android first open action conflicts with Google play codeless download
	// action tracking the same app.
	ConversionActionErrorEnum_BIDDING_ON_SAME_APP_DOWNLOAD_AS_GLOBAL_ACTION ConversionActionErrorEnum_ConversionActionError = 5
	// The attribution model cannot be set to DATA_DRIVEN because a data-driven
	// model has never been generated.
	ConversionActionErrorEnum_DATA_DRIVEN_MODEL_WAS_NEVER_GENERATED ConversionActionErrorEnum_ConversionActionError = 6
	// The attribution model cannot be set to DATA_DRIVEN because the
	// data-driven model is expired.
	ConversionActionErrorEnum_DATA_DRIVEN_MODEL_EXPIRED ConversionActionErrorEnum_ConversionActionError = 7
	// The attribution model cannot be set to DATA_DRIVEN because the
	// data-driven model is stale.
	ConversionActionErrorEnum_DATA_DRIVEN_MODEL_STALE ConversionActionErrorEnum_ConversionActionError = 8
	// The attribution model cannot be set to DATA_DRIVEN because the
	// data-driven model is unavailable or the conversion action was newly
	// added.
	ConversionActionErrorEnum_DATA_DRIVEN_MODEL_UNKNOWN ConversionActionErrorEnum_ConversionActionError = 9
)

var ConversionActionErrorEnum_ConversionActionError_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "DUPLICATE_NAME",
	3: "DUPLICATE_APP_ID",
	4: "TWO_CONVERSION_ACTIONS_BIDDING_ON_SAME_APP_DOWNLOAD",
	5: "BIDDING_ON_SAME_APP_DOWNLOAD_AS_GLOBAL_ACTION",
	6: "DATA_DRIVEN_MODEL_WAS_NEVER_GENERATED",
	7: "DATA_DRIVEN_MODEL_EXPIRED",
	8: "DATA_DRIVEN_MODEL_STALE",
	9: "DATA_DRIVEN_MODEL_UNKNOWN",
}
var ConversionActionErrorEnum_ConversionActionError_value = map[string]int32{
	"UNSPECIFIED":      0,
	"UNKNOWN":          1,
	"DUPLICATE_NAME":   2,
	"DUPLICATE_APP_ID": 3,
	"TWO_CONVERSION_ACTIONS_BIDDING_ON_SAME_APP_DOWNLOAD": 4,
	"BIDDING_ON_SAME_APP_DOWNLOAD_AS_GLOBAL_ACTION":       5,
	"DATA_DRIVEN_MODEL_WAS_NEVER_GENERATED":               6,
	"DATA_DRIVEN_MODEL_EXPIRED":                           7,
	"DATA_DRIVEN_MODEL_STALE":                             8,
	"DATA_DRIVEN_MODEL_UNKNOWN":                           9,
}

func (x ConversionActionErrorEnum_ConversionActionError) String() string {
	return proto.EnumName(ConversionActionErrorEnum_ConversionActionError_name, int32(x))
}
func (ConversionActionErrorEnum_ConversionActionError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_conversion_action_error_055aa1a3ebd90275, []int{0, 0}
}

// Container for enum describing possible conversion action errors.
type ConversionActionErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ConversionActionErrorEnum) Reset()         { *m = ConversionActionErrorEnum{} }
func (m *ConversionActionErrorEnum) String() string { return proto.CompactTextString(m) }
func (*ConversionActionErrorEnum) ProtoMessage()    {}
func (*ConversionActionErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_conversion_action_error_055aa1a3ebd90275, []int{0}
}
func (m *ConversionActionErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConversionActionErrorEnum.Unmarshal(m, b)
}
func (m *ConversionActionErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConversionActionErrorEnum.Marshal(b, m, deterministic)
}
func (dst *ConversionActionErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConversionActionErrorEnum.Merge(dst, src)
}
func (m *ConversionActionErrorEnum) XXX_Size() int {
	return xxx_messageInfo_ConversionActionErrorEnum.Size(m)
}
func (m *ConversionActionErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_ConversionActionErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_ConversionActionErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ConversionActionErrorEnum)(nil), "google.ads.googleads.v0.errors.ConversionActionErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v0.errors.ConversionActionErrorEnum_ConversionActionError", ConversionActionErrorEnum_ConversionActionError_name, ConversionActionErrorEnum_ConversionActionError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/errors/conversion_action_error.proto", fileDescriptor_conversion_action_error_055aa1a3ebd90275)
}

var fileDescriptor_conversion_action_error_055aa1a3ebd90275 = []byte{
	// 427 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x52, 0x4f, 0x8b, 0xd4, 0x30,
	0x14, 0x77, 0xba, 0xba, 0xab, 0x59, 0xd0, 0x10, 0x14, 0x59, 0xc5, 0x3d, 0x0c, 0x78, 0xf0, 0x60,
	0x5a, 0xd9, 0x83, 0x50, 0xbd, 0xbc, 0x69, 0x62, 0x09, 0x76, 0x92, 0xd2, 0x76, 0x3a, 0x22, 0x03,
	0x61, 0x9c, 0x0e, 0x65, 0x61, 0xb7, 0x59, 0x9a, 0x75, 0x3e, 0x90, 0x47, 0x3f, 0x8a, 0x37, 0xbf,
	0x86, 0x17, 0x4f, 0xde, 0xa5, 0xcd, 0x4e, 0x3d, 0xec, 0x38, 0xa7, 0xf7, 0xe3, 0xfd, 0xfe, 0x24,
	0xbc, 0xf7, 0xd0, 0xfb, 0xda, 0x98, 0xfa, 0x62, 0xed, 0x2f, 0x2b, 0xeb, 0x3b, 0xd8, 0xa1, 0x4d,
	0xe0, 0xaf, 0xdb, 0xd6, 0xb4, 0xd6, 0x5f, 0x99, 0x66, 0xb3, 0x6e, 0xed, 0xb9, 0x69, 0xf4, 0x72,
	0x75, 0xdd, 0x95, 0x9e, 0xa0, 0x57, 0xad, 0xb9, 0x36, 0xe4, 0xd4, 0x59, 0xe8, 0xb2, 0xb2, 0x74,
	0x70, 0xd3, 0x4d, 0x40, 0x9d, 0x7b, 0xfc, 0xdb, 0x43, 0x27, 0xd1, 0x90, 0x00, 0x7d, 0x00, 0xef,
	0x28, 0xde, 0x7c, 0xbd, 0x1c, 0xff, 0xf4, 0xd0, 0x93, 0x9d, 0x2c, 0x79, 0x84, 0x8e, 0x67, 0x32,
	0x4f, 0x79, 0x24, 0x3e, 0x08, 0xce, 0xf0, 0x1d, 0x72, 0x8c, 0x8e, 0x66, 0xf2, 0xa3, 0x54, 0x73,
	0x89, 0x47, 0x84, 0xa0, 0x87, 0x6c, 0x96, 0x26, 0x22, 0x82, 0x82, 0x6b, 0x09, 0x53, 0x8e, 0x3d,
	0xf2, 0x18, 0xe1, 0x7f, 0x3d, 0x48, 0x53, 0x2d, 0x18, 0x3e, 0x20, 0x6f, 0xd1, 0x59, 0x31, 0x57,
	0x3a, 0x52, 0xb2, 0xe4, 0x59, 0x2e, 0x94, 0xd4, 0x10, 0x15, 0x42, 0xc9, 0x5c, 0x4f, 0x04, 0x63,
	0x42, 0xc6, 0x5a, 0x49, 0x9d, 0xc3, 0xd4, 0x59, 0x98, 0x9a, 0xcb, 0x44, 0x01, 0xc3, 0x77, 0xc9,
	0x1b, 0xf4, 0x7a, 0x9f, 0x42, 0x43, 0xae, 0xe3, 0x44, 0x4d, 0x20, 0xb9, 0x09, 0xc4, 0xf7, 0xc8,
	0x2b, 0xf4, 0x92, 0x41, 0x01, 0x9a, 0x65, 0xa2, 0xe4, 0x52, 0x4f, 0x15, 0xe3, 0x89, 0x9e, 0x43,
	0xae, 0x25, 0x2f, 0x79, 0xa6, 0x63, 0x2e, 0x79, 0x06, 0x05, 0x67, 0xf8, 0x90, 0xbc, 0x40, 0x27,
	0xb7, 0xa5, 0xfc, 0x53, 0x2a, 0x32, 0xce, 0xf0, 0x11, 0x79, 0x8e, 0x9e, 0xde, 0xa6, 0xf3, 0x02,
	0x12, 0x8e, 0xef, 0xef, 0xf6, 0x6e, 0x67, 0xf3, 0x60, 0xf2, 0x67, 0x84, 0xc6, 0x2b, 0x73, 0x49,
	0xf7, 0x2f, 0x66, 0xf2, 0x6c, 0xe7, 0xdc, 0xd3, 0x6e, 0xa9, 0xe9, 0xe8, 0x33, 0xbb, 0x71, 0xd7,
	0xe6, 0x62, 0xd9, 0xd4, 0xd4, 0xb4, 0xb5, 0x5f, 0xaf, 0x9b, 0x7e, 0xe5, 0xdb, 0x23, 0xb9, 0x3a,
	0xb7, 0xff, 0xbb, 0x99, 0x77, 0xae, 0x7c, 0xf3, 0x0e, 0x62, 0x80, 0xef, 0xde, 0x69, 0xec, 0xc2,
	0xa0, 0xb2, 0xd4, 0xc1, 0x0e, 0x95, 0x01, 0xed, 0x9f, 0xb4, 0x3f, 0xb6, 0x82, 0x05, 0x54, 0x76,
	0x31, 0x08, 0x16, 0x65, 0xb0, 0x70, 0x82, 0x5f, 0xde, 0xd8, 0x75, 0xc3, 0x10, 0x2a, 0x1b, 0x86,
	0x83, 0x24, 0x0c, 0xcb, 0x20, 0x0c, 0x9d, 0xe8, 0xcb, 0x61, 0xff, 0xbb, 0xb3, 0xbf, 0x01, 0x00,
	0x00, 0xff, 0xff, 0x20, 0xf8, 0xe9, 0xf3, 0xd0, 0x02, 0x00, 0x00,
}

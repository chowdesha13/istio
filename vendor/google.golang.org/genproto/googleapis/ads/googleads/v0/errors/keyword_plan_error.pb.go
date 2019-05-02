// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/errors/keyword_plan_error.proto

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

// Enum describing possible errors from applying a keyword plan.
type KeywordPlanErrorEnum_KeywordPlanError int32

const (
	// Enum unspecified.
	KeywordPlanErrorEnum_UNSPECIFIED KeywordPlanErrorEnum_KeywordPlanError = 0
	// The received error code is not known in this version.
	KeywordPlanErrorEnum_UNKNOWN KeywordPlanErrorEnum_KeywordPlanError = 1
	// The plan's bid multiplier value is outside the valid range.
	KeywordPlanErrorEnum_BID_MULTIPLIER_OUT_OF_RANGE KeywordPlanErrorEnum_KeywordPlanError = 2
	// The plan's bid value is too high.
	KeywordPlanErrorEnum_BID_TOO_HIGH KeywordPlanErrorEnum_KeywordPlanError = 3
	// The plan's bid value is too low.
	KeywordPlanErrorEnum_BID_TOO_LOW KeywordPlanErrorEnum_KeywordPlanError = 4
	// The plan's cpc bid is not a multiple of the minimum billable unit.
	KeywordPlanErrorEnum_BID_TOO_MANY_FRACTIONAL_DIGITS KeywordPlanErrorEnum_KeywordPlanError = 5
	// The plan's daily budget value is too low.
	KeywordPlanErrorEnum_DAILY_BUDGET_TOO_LOW KeywordPlanErrorEnum_KeywordPlanError = 6
	// The plan's daily budget is not a multiple of the minimum billable unit.
	KeywordPlanErrorEnum_DAILY_BUDGET_TOO_MANY_FRACTIONAL_DIGITS KeywordPlanErrorEnum_KeywordPlanError = 7
	// The input has an invalid value.
	KeywordPlanErrorEnum_INVALID_VALUE KeywordPlanErrorEnum_KeywordPlanError = 8
	// The plan has no keyword.
	KeywordPlanErrorEnum_KEYWORD_PLAN_HAS_NO_KEYWORDS KeywordPlanErrorEnum_KeywordPlanError = 9
	// The plan is not enabled and API cannot provide mutation, forecast or
	// stats.
	KeywordPlanErrorEnum_KEYWORD_PLAN_NOT_ENABLED KeywordPlanErrorEnum_KeywordPlanError = 10
	// The requested plan cannot be found for providing forecast or stats.
	KeywordPlanErrorEnum_KEYWORD_PLAN_NOT_FOUND KeywordPlanErrorEnum_KeywordPlanError = 11
	// The plan is missing a cpc bid.
	KeywordPlanErrorEnum_MISSING_BID KeywordPlanErrorEnum_KeywordPlanError = 13
	// The plan is missing required forecast_period field.
	KeywordPlanErrorEnum_MISSING_FORECAST_PERIOD KeywordPlanErrorEnum_KeywordPlanError = 14
	// The plan's forecast_period has invalid forecast date range.
	KeywordPlanErrorEnum_INVALID_FORECAST_DATE_RANGE KeywordPlanErrorEnum_KeywordPlanError = 15
	// The plan's name is invalid.
	KeywordPlanErrorEnum_INVALID_NAME KeywordPlanErrorEnum_KeywordPlanError = 16
)

var KeywordPlanErrorEnum_KeywordPlanError_name = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "UNKNOWN",
	2:  "BID_MULTIPLIER_OUT_OF_RANGE",
	3:  "BID_TOO_HIGH",
	4:  "BID_TOO_LOW",
	5:  "BID_TOO_MANY_FRACTIONAL_DIGITS",
	6:  "DAILY_BUDGET_TOO_LOW",
	7:  "DAILY_BUDGET_TOO_MANY_FRACTIONAL_DIGITS",
	8:  "INVALID_VALUE",
	9:  "KEYWORD_PLAN_HAS_NO_KEYWORDS",
	10: "KEYWORD_PLAN_NOT_ENABLED",
	11: "KEYWORD_PLAN_NOT_FOUND",
	13: "MISSING_BID",
	14: "MISSING_FORECAST_PERIOD",
	15: "INVALID_FORECAST_DATE_RANGE",
	16: "INVALID_NAME",
}
var KeywordPlanErrorEnum_KeywordPlanError_value = map[string]int32{
	"UNSPECIFIED":                             0,
	"UNKNOWN":                                 1,
	"BID_MULTIPLIER_OUT_OF_RANGE":             2,
	"BID_TOO_HIGH":                            3,
	"BID_TOO_LOW":                             4,
	"BID_TOO_MANY_FRACTIONAL_DIGITS":          5,
	"DAILY_BUDGET_TOO_LOW":                    6,
	"DAILY_BUDGET_TOO_MANY_FRACTIONAL_DIGITS": 7,
	"INVALID_VALUE":                           8,
	"KEYWORD_PLAN_HAS_NO_KEYWORDS":            9,
	"KEYWORD_PLAN_NOT_ENABLED":                10,
	"KEYWORD_PLAN_NOT_FOUND":                  11,
	"MISSING_BID":                             13,
	"MISSING_FORECAST_PERIOD":                 14,
	"INVALID_FORECAST_DATE_RANGE":             15,
	"INVALID_NAME":                            16,
}

func (x KeywordPlanErrorEnum_KeywordPlanError) String() string {
	return proto.EnumName(KeywordPlanErrorEnum_KeywordPlanError_name, int32(x))
}
func (KeywordPlanErrorEnum_KeywordPlanError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_keyword_plan_error_d7df061126d84594, []int{0, 0}
}

// Container for enum describing possible errors from applying a keyword plan
// resource (keyword plan, keyword plan campaign, keyword plan ad group or
// keyword plan keyword) or KeywordPlanService RPC.
type KeywordPlanErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KeywordPlanErrorEnum) Reset()         { *m = KeywordPlanErrorEnum{} }
func (m *KeywordPlanErrorEnum) String() string { return proto.CompactTextString(m) }
func (*KeywordPlanErrorEnum) ProtoMessage()    {}
func (*KeywordPlanErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_keyword_plan_error_d7df061126d84594, []int{0}
}
func (m *KeywordPlanErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeywordPlanErrorEnum.Unmarshal(m, b)
}
func (m *KeywordPlanErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeywordPlanErrorEnum.Marshal(b, m, deterministic)
}
func (dst *KeywordPlanErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeywordPlanErrorEnum.Merge(dst, src)
}
func (m *KeywordPlanErrorEnum) XXX_Size() int {
	return xxx_messageInfo_KeywordPlanErrorEnum.Size(m)
}
func (m *KeywordPlanErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_KeywordPlanErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_KeywordPlanErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*KeywordPlanErrorEnum)(nil), "google.ads.googleads.v0.errors.KeywordPlanErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v0.errors.KeywordPlanErrorEnum_KeywordPlanError", KeywordPlanErrorEnum_KeywordPlanError_name, KeywordPlanErrorEnum_KeywordPlanError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/errors/keyword_plan_error.proto", fileDescriptor_keyword_plan_error_d7df061126d84594)
}

var fileDescriptor_keyword_plan_error_d7df061126d84594 = []byte{
	// 489 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0x4f, 0x8b, 0xd3, 0x40,
	0x18, 0xc6, 0x6d, 0xab, 0xbb, 0x3a, 0x75, 0xdd, 0x71, 0x58, 0x75, 0x71, 0x97, 0x2a, 0xbd, 0x78,
	0x10, 0x92, 0x80, 0x07, 0x21, 0x9e, 0x26, 0x9d, 0x49, 0x3a, 0x34, 0x9d, 0x09, 0xf9, 0x57, 0x2a,
	0x85, 0x21, 0x9a, 0x12, 0xc4, 0x6e, 0x52, 0x12, 0x5d, 0xf1, 0xeb, 0x78, 0xf4, 0xe2, 0xd7, 0x10,
	0x3f, 0x8a, 0x27, 0x3f, 0x82, 0x4c, 0xa7, 0x09, 0xb8, 0xcb, 0x7a, 0xca, 0xcb, 0xf3, 0xfe, 0x9e,
	0x37, 0x33, 0xef, 0x3c, 0xe0, 0x75, 0x51, 0x55, 0xc5, 0x66, 0x6d, 0x66, 0x79, 0x63, 0xea, 0x52,
	0x55, 0x97, 0x96, 0xb9, 0xae, 0xeb, 0xaa, 0x6e, 0xcc, 0x8f, 0xeb, 0xaf, 0x5f, 0xaa, 0x3a, 0x97,
	0xdb, 0x4d, 0x56, 0xca, 0x9d, 0x66, 0x6c, 0xeb, 0xea, 0x53, 0x85, 0x46, 0x9a, 0x36, 0xb2, 0xbc,
	0x31, 0x3a, 0xa3, 0x71, 0x69, 0x19, 0xda, 0x38, 0xfe, 0x39, 0x00, 0x27, 0x33, 0x6d, 0x0e, 0x36,
	0x59, 0x49, 0x95, 0x4a, 0xcb, 0xcf, 0x17, 0xe3, 0x1f, 0x03, 0x00, 0xaf, 0x36, 0xd0, 0x31, 0x18,
	0x26, 0x3c, 0x0a, 0xe8, 0x84, 0xb9, 0x8c, 0x12, 0x78, 0x0b, 0x0d, 0xc1, 0x61, 0xc2, 0x67, 0x5c,
	0x2c, 0x38, 0xec, 0xa1, 0x67, 0xe0, 0xcc, 0x61, 0x44, 0xce, 0x13, 0x3f, 0x66, 0x81, 0xcf, 0x68,
	0x28, 0x45, 0x12, 0x4b, 0xe1, 0xca, 0x10, 0x73, 0x8f, 0xc2, 0x3e, 0x82, 0xe0, 0xbe, 0x02, 0x62,
	0x21, 0xe4, 0x94, 0x79, 0x53, 0x38, 0x50, 0x03, 0x5b, 0xc5, 0x17, 0x0b, 0x78, 0x1b, 0x8d, 0xc1,
	0xa8, 0x15, 0xe6, 0x98, 0x2f, 0xa5, 0x1b, 0xe2, 0x49, 0xcc, 0x04, 0xc7, 0xbe, 0x24, 0xcc, 0x63,
	0x71, 0x04, 0xef, 0xa0, 0x53, 0x70, 0x42, 0x30, 0xf3, 0x97, 0xd2, 0x49, 0x88, 0x47, 0xe3, 0xce,
	0x7d, 0x80, 0x5e, 0x82, 0x17, 0xd7, 0x3a, 0x37, 0x8c, 0x39, 0x44, 0x0f, 0xc1, 0x11, 0xe3, 0x29,
	0xf6, 0x19, 0x91, 0x29, 0xf6, 0x13, 0x0a, 0xef, 0xa2, 0xe7, 0xe0, 0x7c, 0x46, 0x97, 0x0b, 0x11,
	0x12, 0x19, 0xf8, 0x98, 0xcb, 0x29, 0x8e, 0x24, 0x17, 0x72, 0xaf, 0x45, 0xf0, 0x1e, 0x3a, 0x07,
	0xa7, 0xff, 0x10, 0x5c, 0xc4, 0x92, 0x72, 0xec, 0xf8, 0x94, 0x40, 0x80, 0x9e, 0x82, 0xc7, 0xd7,
	0xba, 0xae, 0x48, 0x38, 0x81, 0x43, 0x75, 0xd5, 0x39, 0x8b, 0x22, 0xc6, 0x3d, 0xe9, 0x30, 0x02,
	0x8f, 0xd0, 0x19, 0x78, 0xd2, 0x0a, 0xae, 0x08, 0xe9, 0x04, 0x47, 0xb1, 0x0c, 0x68, 0xc8, 0x04,
	0x81, 0x0f, 0xd4, 0x2e, 0xdb, 0xc3, 0x75, 0x4d, 0x82, 0x63, 0xba, 0xdf, 0xe5, 0xb1, 0xda, 0x65,
	0x0b, 0x70, 0x3c, 0xa7, 0x10, 0x3a, 0x7f, 0x7a, 0x60, 0xfc, 0xbe, 0xba, 0x30, 0xfe, 0xff, 0xe2,
	0xce, 0xa3, 0xab, 0xaf, 0x1a, 0xa8, 0xa0, 0x04, 0xbd, 0xb7, 0x64, 0x6f, 0x2c, 0xaa, 0x4d, 0x56,
	0x16, 0x46, 0x55, 0x17, 0x66, 0xb1, 0x2e, 0x77, 0x31, 0x6a, 0x33, 0xb7, 0xfd, 0xd0, 0xdc, 0x14,
	0xc1, 0x37, 0xfa, 0xf3, 0xad, 0x3f, 0xf0, 0x30, 0xfe, 0xde, 0x1f, 0x79, 0x7a, 0x18, 0xce, 0x1b,
	0x43, 0x97, 0xaa, 0x4a, 0x2d, 0x63, 0xf7, 0xcb, 0xe6, 0x57, 0x0b, 0xac, 0x70, 0xde, 0xac, 0x3a,
	0x60, 0x95, 0x5a, 0x2b, 0x0d, 0xfc, 0xee, 0x8f, 0xb5, 0x6a, 0xdb, 0x38, 0x6f, 0x6c, 0xbb, 0x43,
	0x6c, 0x3b, 0xb5, 0x6c, 0x5b, 0x43, 0xef, 0x0e, 0x76, 0xa7, 0x7b, 0xf5, 0x37, 0x00, 0x00, 0xff,
	0xff, 0x9e, 0xf7, 0xd3, 0x36, 0x1f, 0x03, 0x00, 0x00,
}

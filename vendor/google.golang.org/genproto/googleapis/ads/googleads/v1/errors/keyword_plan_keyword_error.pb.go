// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/errors/keyword_plan_keyword_error.proto

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

// Enum describing possible errors from applying a keyword plan keyword.
type KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError int32

const (
	// Enum unspecified.
	KeywordPlanKeywordErrorEnum_UNSPECIFIED KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 0
	// The received error code is not known in this version.
	KeywordPlanKeywordErrorEnum_UNKNOWN KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 1
	// A keyword or negative keyword has invalid match type.
	KeywordPlanKeywordErrorEnum_INVALID_KEYWORD_MATCH_TYPE KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 2
	// A keyword or negative keyword with same text and match type already
	// exists.
	KeywordPlanKeywordErrorEnum_DUPLICATE_KEYWORD KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 3
	// Keyword or negative keyword text exceeds the allowed limit.
	KeywordPlanKeywordErrorEnum_KEYWORD_TEXT_TOO_LONG KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 4
	// Keyword or negative keyword text has invalid characters or symbols.
	KeywordPlanKeywordErrorEnum_KEYWORD_HAS_INVALID_CHARS KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 5
	// Keyword or negative keyword text has too many words.
	KeywordPlanKeywordErrorEnum_KEYWORD_HAS_TOO_MANY_WORDS KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 6
	// Keyword or negative keyword has invalid text.
	KeywordPlanKeywordErrorEnum_INVALID_KEYWORD_TEXT KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError = 7
)

var KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "INVALID_KEYWORD_MATCH_TYPE",
	3: "DUPLICATE_KEYWORD",
	4: "KEYWORD_TEXT_TOO_LONG",
	5: "KEYWORD_HAS_INVALID_CHARS",
	6: "KEYWORD_HAS_TOO_MANY_WORDS",
	7: "INVALID_KEYWORD_TEXT",
}
var KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError_value = map[string]int32{
	"UNSPECIFIED":                0,
	"UNKNOWN":                    1,
	"INVALID_KEYWORD_MATCH_TYPE": 2,
	"DUPLICATE_KEYWORD":          3,
	"KEYWORD_TEXT_TOO_LONG":      4,
	"KEYWORD_HAS_INVALID_CHARS":  5,
	"KEYWORD_HAS_TOO_MANY_WORDS": 6,
	"INVALID_KEYWORD_TEXT":       7,
}

func (x KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError) String() string {
	return proto.EnumName(KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError_name, int32(x))
}
func (KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_keyword_plan_keyword_error_827b5a9192749835, []int{0, 0}
}

// Container for enum describing possible errors from applying a keyword or a
// negative keyword from a keyword plan.
type KeywordPlanKeywordErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KeywordPlanKeywordErrorEnum) Reset()         { *m = KeywordPlanKeywordErrorEnum{} }
func (m *KeywordPlanKeywordErrorEnum) String() string { return proto.CompactTextString(m) }
func (*KeywordPlanKeywordErrorEnum) ProtoMessage()    {}
func (*KeywordPlanKeywordErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_keyword_plan_keyword_error_827b5a9192749835, []int{0}
}
func (m *KeywordPlanKeywordErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeywordPlanKeywordErrorEnum.Unmarshal(m, b)
}
func (m *KeywordPlanKeywordErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeywordPlanKeywordErrorEnum.Marshal(b, m, deterministic)
}
func (dst *KeywordPlanKeywordErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeywordPlanKeywordErrorEnum.Merge(dst, src)
}
func (m *KeywordPlanKeywordErrorEnum) XXX_Size() int {
	return xxx_messageInfo_KeywordPlanKeywordErrorEnum.Size(m)
}
func (m *KeywordPlanKeywordErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_KeywordPlanKeywordErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_KeywordPlanKeywordErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*KeywordPlanKeywordErrorEnum)(nil), "google.ads.googleads.v1.errors.KeywordPlanKeywordErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.errors.KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError", KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError_name, KeywordPlanKeywordErrorEnum_KeywordPlanKeywordError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/errors/keyword_plan_keyword_error.proto", fileDescriptor_keyword_plan_keyword_error_827b5a9192749835)
}

var fileDescriptor_keyword_plan_keyword_error_827b5a9192749835 = []byte{
	// 395 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x51, 0xcd, 0x6e, 0xd3, 0x30,
	0x00, 0xa6, 0x19, 0x6c, 0x92, 0x77, 0xc0, 0x58, 0x4c, 0xb0, 0x31, 0x7a, 0xc8, 0x03, 0x38, 0x8a,
	0xb8, 0x99, 0x03, 0xf2, 0x12, 0xd3, 0x46, 0xed, 0x92, 0x68, 0x49, 0x33, 0x8a, 0x22, 0x59, 0x81,
	0x44, 0x51, 0x45, 0x66, 0x47, 0x71, 0x19, 0xe2, 0xca, 0xa3, 0x70, 0xe4, 0x51, 0x78, 0x0c, 0x8e,
	0xbc, 0x00, 0x57, 0xe4, 0x78, 0xae, 0x10, 0x52, 0x77, 0xca, 0x17, 0x7f, 0x7f, 0xd6, 0x67, 0xf0,
	0xa6, 0x95, 0xb2, 0xed, 0x1a, 0xaf, 0xaa, 0x95, 0x67, 0xa0, 0x46, 0xb7, 0xbe, 0xd7, 0x0c, 0x83,
	0x1c, 0x94, 0xf7, 0xa9, 0xf9, 0xfa, 0x45, 0x0e, 0x35, 0xef, 0xbb, 0x4a, 0x70, 0xfb, 0x33, 0x72,
	0xb8, 0x1f, 0xe4, 0x56, 0xa2, 0xa9, 0x71, 0xe1, 0xaa, 0x56, 0x78, 0x17, 0x80, 0x6f, 0x7d, 0x6c,
	0x02, 0xce, 0xce, 0x6d, 0x41, 0xbf, 0xf1, 0x2a, 0x21, 0xe4, 0xb6, 0xda, 0x6e, 0xa4, 0x50, 0xc6,
	0xed, 0x7e, 0x73, 0xc0, 0x8b, 0x85, 0x49, 0x4d, 0xbb, 0x4a, 0xdc, 0x41, 0xa6, 0xad, 0x4c, 0x7c,
	0xbe, 0x71, 0x7f, 0x4d, 0xc0, 0xb3, 0x3d, 0x3c, 0x7a, 0x0c, 0x8e, 0x57, 0x71, 0x96, 0xb2, 0x20,
	0x7a, 0x1b, 0xb1, 0x10, 0x3e, 0x40, 0xc7, 0xe0, 0x68, 0x15, 0x2f, 0xe2, 0xe4, 0x3a, 0x86, 0x13,
	0x34, 0x05, 0x67, 0x51, 0x5c, 0xd0, 0x65, 0x14, 0xf2, 0x05, 0x5b, 0x5f, 0x27, 0x57, 0x21, 0xbf,
	0xa4, 0x79, 0x30, 0xe7, 0xf9, 0x3a, 0x65, 0xd0, 0x41, 0x27, 0xe0, 0x49, 0xb8, 0x4a, 0x97, 0x51,
	0x40, 0x73, 0x66, 0x15, 0xf0, 0x00, 0x9d, 0x82, 0x13, 0x2b, 0xcf, 0xd9, 0xbb, 0x9c, 0xe7, 0x49,
	0xc2, 0x97, 0x49, 0x3c, 0x83, 0x0f, 0xd1, 0x4b, 0x70, 0x6a, 0xa9, 0x39, 0xcd, 0xb8, 0x4d, 0x0f,
	0xe6, 0xf4, 0x2a, 0x83, 0x8f, 0x74, 0xe1, 0xbf, 0xb4, 0x36, 0x5e, 0xd2, 0x78, 0xcd, 0xf5, 0x49,
	0x06, 0x0f, 0xd1, 0x73, 0xf0, 0xf4, 0xff, 0x0b, 0xe9, 0x06, 0x78, 0x74, 0xf1, 0x67, 0x02, 0xdc,
	0x8f, 0xf2, 0x06, 0xdf, 0xbf, 0xe4, 0xc5, 0xf9, 0x9e, 0x21, 0x52, 0xbd, 0x64, 0x3a, 0x79, 0x1f,
	0xde, 0xf9, 0x5b, 0xd9, 0x55, 0xa2, 0xc5, 0x72, 0x68, 0xbd, 0xb6, 0x11, 0xe3, 0xce, 0xf6, 0x69,
	0xfb, 0x8d, 0xda, 0xf7, 0xd2, 0xaf, 0xcd, 0xe7, 0xbb, 0x73, 0x30, 0xa3, 0xf4, 0x87, 0x33, 0x9d,
	0x99, 0x30, 0x5a, 0x2b, 0x6c, 0xa0, 0x46, 0x85, 0x8f, 0xc7, 0x4a, 0xf5, 0xd3, 0x0a, 0x4a, 0x5a,
	0xab, 0x72, 0x27, 0x28, 0x0b, 0xbf, 0x34, 0x82, 0xdf, 0x8e, 0x6b, 0x4e, 0x09, 0xa1, 0xb5, 0x22,
	0x64, 0x27, 0x21, 0xa4, 0xf0, 0x09, 0x31, 0xa2, 0x0f, 0x87, 0xe3, 0xed, 0x5e, 0xfd, 0x0d, 0x00,
	0x00, 0xff, 0xff, 0xcd, 0x4e, 0x24, 0x72, 0x86, 0x02, 0x00, 0x00,
}

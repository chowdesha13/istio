// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/errors/ad_group_bid_modifier_error.proto

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

// Enum describing possible ad group bid modifier errors.
type AdGroupBidModifierErrorEnum_AdGroupBidModifierError int32

const (
	// Enum unspecified.
	AdGroupBidModifierErrorEnum_UNSPECIFIED AdGroupBidModifierErrorEnum_AdGroupBidModifierError = 0
	// The received error code is not known in this version.
	AdGroupBidModifierErrorEnum_UNKNOWN AdGroupBidModifierErrorEnum_AdGroupBidModifierError = 1
	// The criterion ID does not support bid modification.
	AdGroupBidModifierErrorEnum_CRITERION_ID_NOT_SUPPORTED AdGroupBidModifierErrorEnum_AdGroupBidModifierError = 2
	// Cannot override the bid modifier for the given criterion ID if the parent
	// campaign is opted out of the same criterion.
	AdGroupBidModifierErrorEnum_CANNOT_OVERRIDE_OPTED_OUT_CAMPAIGN_CRITERION_BID_MODIFIER AdGroupBidModifierErrorEnum_AdGroupBidModifierError = 3
)

var AdGroupBidModifierErrorEnum_AdGroupBidModifierError_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "CRITERION_ID_NOT_SUPPORTED",
	3: "CANNOT_OVERRIDE_OPTED_OUT_CAMPAIGN_CRITERION_BID_MODIFIER",
}
var AdGroupBidModifierErrorEnum_AdGroupBidModifierError_value = map[string]int32{
	"UNSPECIFIED":                0,
	"UNKNOWN":                    1,
	"CRITERION_ID_NOT_SUPPORTED": 2,
	"CANNOT_OVERRIDE_OPTED_OUT_CAMPAIGN_CRITERION_BID_MODIFIER": 3,
}

func (x AdGroupBidModifierErrorEnum_AdGroupBidModifierError) String() string {
	return proto.EnumName(AdGroupBidModifierErrorEnum_AdGroupBidModifierError_name, int32(x))
}
func (AdGroupBidModifierErrorEnum_AdGroupBidModifierError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ad_group_bid_modifier_error_c7cd17cf84154d84, []int{0, 0}
}

// Container for enum describing possible ad group bid modifier errors.
type AdGroupBidModifierErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AdGroupBidModifierErrorEnum) Reset()         { *m = AdGroupBidModifierErrorEnum{} }
func (m *AdGroupBidModifierErrorEnum) String() string { return proto.CompactTextString(m) }
func (*AdGroupBidModifierErrorEnum) ProtoMessage()    {}
func (*AdGroupBidModifierErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_ad_group_bid_modifier_error_c7cd17cf84154d84, []int{0}
}
func (m *AdGroupBidModifierErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AdGroupBidModifierErrorEnum.Unmarshal(m, b)
}
func (m *AdGroupBidModifierErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AdGroupBidModifierErrorEnum.Marshal(b, m, deterministic)
}
func (dst *AdGroupBidModifierErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdGroupBidModifierErrorEnum.Merge(dst, src)
}
func (m *AdGroupBidModifierErrorEnum) XXX_Size() int {
	return xxx_messageInfo_AdGroupBidModifierErrorEnum.Size(m)
}
func (m *AdGroupBidModifierErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_AdGroupBidModifierErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_AdGroupBidModifierErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*AdGroupBidModifierErrorEnum)(nil), "google.ads.googleads.v1.errors.AdGroupBidModifierErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.errors.AdGroupBidModifierErrorEnum_AdGroupBidModifierError", AdGroupBidModifierErrorEnum_AdGroupBidModifierError_name, AdGroupBidModifierErrorEnum_AdGroupBidModifierError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/errors/ad_group_bid_modifier_error.proto", fileDescriptor_ad_group_bid_modifier_error_c7cd17cf84154d84)
}

var fileDescriptor_ad_group_bid_modifier_error_c7cd17cf84154d84 = []byte{
	// 368 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x51, 0xcd, 0xaa, 0xd4, 0x30,
	0x14, 0xb6, 0xbd, 0xa0, 0x90, 0xbb, 0xb0, 0x74, 0x23, 0x5c, 0x2f, 0xb3, 0xe8, 0x03, 0xa4, 0x14,
	0x57, 0x46, 0x04, 0xd3, 0x26, 0x96, 0x20, 0x93, 0x94, 0x4e, 0x5b, 0x41, 0x0a, 0xa1, 0x63, 0x6a,
	0x29, 0xcc, 0x34, 0xa5, 0x99, 0x99, 0x47, 0xf1, 0x01, 0x5c, 0xfa, 0x00, 0x3e, 0x84, 0x8f, 0xe2,
	0x0b, 0xb8, 0x95, 0x36, 0x33, 0xe3, 0x6a, 0xee, 0x2a, 0x1f, 0xe7, 0x7c, 0x3f, 0xe7, 0xe4, 0x80,
	0x0f, 0x9d, 0xd6, 0xdd, 0xae, 0x0d, 0x1b, 0x65, 0x42, 0x0b, 0x67, 0x74, 0x8a, 0xc2, 0x76, 0x9a,
	0xf4, 0x64, 0xc2, 0x46, 0xc9, 0x6e, 0xd2, 0xc7, 0x51, 0x6e, 0x7b, 0x25, 0xf7, 0x5a, 0xf5, 0xdf,
	0xfa, 0x76, 0x92, 0x4b, 0x13, 0x8e, 0x93, 0x3e, 0x68, 0x7f, 0x65, 0x65, 0xb0, 0x51, 0x06, 0x5e,
	0x1d, 0xe0, 0x29, 0x82, 0xd6, 0xe1, 0xe1, 0xf1, 0x92, 0x30, 0xf6, 0x61, 0x33, 0x0c, 0xfa, 0xd0,
	0x1c, 0x7a, 0x3d, 0x18, 0xab, 0x0e, 0x7e, 0x39, 0xe0, 0x35, 0x56, 0xe9, 0x1c, 0x11, 0xf7, 0x6a,
	0x7d, 0x0e, 0xa0, 0xb3, 0x94, 0x0e, 0xc7, 0x7d, 0xf0, 0xdd, 0x01, 0xaf, 0x6e, 0xf4, 0xfd, 0x97,
	0xe0, 0xbe, 0xe4, 0x9b, 0x8c, 0x26, 0xec, 0x23, 0xa3, 0xc4, 0x7b, 0xe6, 0xdf, 0x83, 0x17, 0x25,
	0xff, 0xc4, 0xc5, 0x67, 0xee, 0x39, 0xfe, 0x0a, 0x3c, 0x24, 0x39, 0x2b, 0x68, 0xce, 0x04, 0x97,
	0x8c, 0x48, 0x2e, 0x0a, 0xb9, 0x29, 0xb3, 0x4c, 0xe4, 0x05, 0x25, 0x9e, 0xeb, 0xbf, 0x07, 0x6f,
	0x13, 0xcc, 0xe7, 0xaa, 0xa8, 0x68, 0x9e, 0x33, 0x42, 0xa5, 0xc8, 0x0a, 0x4a, 0xa4, 0x28, 0x0b,
	0x99, 0xe0, 0x75, 0x86, 0x59, 0xca, 0xe5, 0x7f, 0x8b, 0x98, 0x11, 0xb9, 0x16, 0x64, 0xce, 0xca,
	0xbd, 0xbb, 0xf8, 0xaf, 0x03, 0x82, 0xaf, 0x7a, 0x0f, 0x9f, 0xde, 0x3e, 0x7e, 0xbc, 0x31, 0x7c,
	0x36, 0x6f, 0x9f, 0x39, 0x5f, 0xc8, 0x59, 0xdf, 0xe9, 0x5d, 0x33, 0x74, 0x50, 0x4f, 0x5d, 0xd8,
	0xb5, 0xc3, 0xf2, 0x37, 0x97, 0x7b, 0x8c, 0xbd, 0xb9, 0x75, 0x9e, 0x77, 0xf6, 0xf9, 0xe1, 0xde,
	0xa5, 0x18, 0xff, 0x74, 0x57, 0xa9, 0x35, 0xc3, 0xca, 0x40, 0x0b, 0x67, 0x54, 0x45, 0x70, 0x89,
	0x34, 0xbf, 0x2f, 0x84, 0x1a, 0x2b, 0x53, 0x5f, 0x09, 0x75, 0x15, 0xd5, 0x96, 0xf0, 0xc7, 0x0d,
	0x6c, 0x15, 0x21, 0xac, 0x0c, 0x42, 0x57, 0x0a, 0x42, 0x55, 0x84, 0x90, 0x25, 0x6d, 0x9f, 0x2f,
	0xd3, 0xbd, 0xf9, 0x17, 0x00, 0x00, 0xff, 0xff, 0x43, 0x72, 0x94, 0x76, 0x3b, 0x02, 0x00, 0x00,
}

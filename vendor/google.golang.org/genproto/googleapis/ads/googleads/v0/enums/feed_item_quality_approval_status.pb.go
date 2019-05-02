// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/enums/feed_item_quality_approval_status.proto

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

// The possible quality evaluation approval statuses of a feed item.
type FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus int32

const (
	// No value has been specified.
	FeedItemQualityApprovalStatusEnum_UNSPECIFIED FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus = 0
	// Used for return value only. Represents value unknown in this version.
	FeedItemQualityApprovalStatusEnum_UNKNOWN FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus = 1
	// Meets all quality expectations.
	FeedItemQualityApprovalStatusEnum_APPROVED FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus = 2
	// Does not meet some quality expectations. The specific reason is found in
	// the quality_disapproval_reasons field.
	FeedItemQualityApprovalStatusEnum_DISAPPROVED FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus = 3
)

var FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "APPROVED",
	3: "DISAPPROVED",
}
var FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"APPROVED":    2,
	"DISAPPROVED": 3,
}

func (x FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus) String() string {
	return proto.EnumName(FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus_name, int32(x))
}
func (FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_feed_item_quality_approval_status_6ed9af1832badd62, []int{0, 0}
}

// Container for enum describing possible quality evaluation approval statuses
// of a feed item.
type FeedItemQualityApprovalStatusEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FeedItemQualityApprovalStatusEnum) Reset()         { *m = FeedItemQualityApprovalStatusEnum{} }
func (m *FeedItemQualityApprovalStatusEnum) String() string { return proto.CompactTextString(m) }
func (*FeedItemQualityApprovalStatusEnum) ProtoMessage()    {}
func (*FeedItemQualityApprovalStatusEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_feed_item_quality_approval_status_6ed9af1832badd62, []int{0}
}
func (m *FeedItemQualityApprovalStatusEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FeedItemQualityApprovalStatusEnum.Unmarshal(m, b)
}
func (m *FeedItemQualityApprovalStatusEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FeedItemQualityApprovalStatusEnum.Marshal(b, m, deterministic)
}
func (dst *FeedItemQualityApprovalStatusEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FeedItemQualityApprovalStatusEnum.Merge(dst, src)
}
func (m *FeedItemQualityApprovalStatusEnum) XXX_Size() int {
	return xxx_messageInfo_FeedItemQualityApprovalStatusEnum.Size(m)
}
func (m *FeedItemQualityApprovalStatusEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_FeedItemQualityApprovalStatusEnum.DiscardUnknown(m)
}

var xxx_messageInfo_FeedItemQualityApprovalStatusEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*FeedItemQualityApprovalStatusEnum)(nil), "google.ads.googleads.v0.enums.FeedItemQualityApprovalStatusEnum")
	proto.RegisterEnum("google.ads.googleads.v0.enums.FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus", FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus_name, FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/enums/feed_item_quality_approval_status.proto", fileDescriptor_feed_item_quality_approval_status_6ed9af1832badd62)
}

var fileDescriptor_feed_item_quality_approval_status_6ed9af1832badd62 = []byte{
	// 307 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0x41, 0x6a, 0xb4, 0x30,
	0x1c, 0xc5, 0x3f, 0x1d, 0xf8, 0x5a, 0x32, 0x85, 0x0e, 0xee, 0x67, 0x31, 0x73, 0x80, 0x28, 0x74,
	0x97, 0xae, 0x32, 0xd5, 0x19, 0xa4, 0xe0, 0xd8, 0xca, 0x58, 0x28, 0x82, 0xa4, 0x4d, 0x1a, 0x04,
	0x35, 0xd6, 0x44, 0xa1, 0xcb, 0x5e, 0xa5, 0xcb, 0x1e, 0xa5, 0x47, 0xe9, 0x05, 0xba, 0x2d, 0x26,
	0x33, 0xee, 0xea, 0x46, 0x1e, 0xff, 0xf7, 0xfc, 0xf1, 0xf2, 0x40, 0xc0, 0x85, 0xe0, 0x25, 0x73,
	0x09, 0x95, 0xae, 0x91, 0x83, 0xea, 0x3d, 0x97, 0xd5, 0x5d, 0x25, 0xdd, 0x17, 0xc6, 0x68, 0x5e,
	0x28, 0x56, 0xe5, 0xaf, 0x1d, 0x29, 0x0b, 0xf5, 0x96, 0x93, 0xa6, 0x69, 0x45, 0x4f, 0xca, 0x5c,
	0x2a, 0xa2, 0x3a, 0x09, 0x9b, 0x56, 0x28, 0xe1, 0x2c, 0xcd, 0xbf, 0x90, 0x50, 0x09, 0x47, 0x0c,
	0xec, 0x3d, 0xa8, 0x31, 0xeb, 0x77, 0x0b, 0xac, 0xb6, 0x8c, 0xd1, 0x50, 0xb1, 0xea, 0xce, 0x80,
	0xf0, 0x91, 0x93, 0x68, 0x4c, 0x50, 0x77, 0xd5, 0x3a, 0x03, 0xcb, 0xc9, 0x90, 0x73, 0x09, 0xe6,
	0x87, 0x28, 0x89, 0x83, 0x9b, 0x70, 0x1b, 0x06, 0xfe, 0xe2, 0x9f, 0x33, 0x07, 0x67, 0x87, 0xe8,
	0x36, 0xda, 0x3f, 0x44, 0x0b, 0xcb, 0xb9, 0x00, 0xe7, 0x38, 0x8e, 0xef, 0xf7, 0x69, 0xe0, 0x2f,
	0xec, 0x21, 0xeb, 0x87, 0xc9, 0x78, 0x98, 0x6d, 0x7e, 0x2c, 0xb0, 0x7a, 0x16, 0x15, 0x9c, 0x6c,
	0xba, 0x59, 0x4f, 0x36, 0x88, 0x87, 0xc7, 0xc6, 0xd6, 0xe3, 0xe6, 0x08, 0xe1, 0xa2, 0x24, 0x35,
	0x87, 0xa2, 0xe5, 0x2e, 0x67, 0xb5, 0x9e, 0xe2, 0xb4, 0x62, 0x53, 0xc8, 0x3f, 0x46, 0xbd, 0xd6,
	0xdf, 0x0f, 0x7b, 0xb6, 0xc3, 0xf8, 0xd3, 0x5e, 0xee, 0x0c, 0x0a, 0x53, 0x09, 0x8d, 0x1c, 0x54,
	0xea, 0xc1, 0x61, 0x12, 0xf9, 0x75, 0xf2, 0x33, 0x4c, 0x65, 0x36, 0xfa, 0x59, 0xea, 0x65, 0xda,
	0xff, 0xb6, 0x57, 0xe6, 0x88, 0x10, 0xa6, 0x12, 0xa1, 0x31, 0x81, 0x50, 0xea, 0x21, 0xa4, 0x33,
	0x4f, 0xff, 0x75, 0xb1, 0xab, 0xdf, 0x00, 0x00, 0x00, 0xff, 0xff, 0xec, 0xb2, 0x07, 0xd1, 0xec,
	0x01, 0x00, 0x00,
}

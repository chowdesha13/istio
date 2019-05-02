// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/enums/ad_group_status.proto

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

// The possible statuses of an ad group.
type AdGroupStatusEnum_AdGroupStatus int32

const (
	// The status has not been specified.
	AdGroupStatusEnum_UNSPECIFIED AdGroupStatusEnum_AdGroupStatus = 0
	// The received value is not known in this version.
	//
	// This is a response-only value.
	AdGroupStatusEnum_UNKNOWN AdGroupStatusEnum_AdGroupStatus = 1
	// The ad group is enabled.
	AdGroupStatusEnum_ENABLED AdGroupStatusEnum_AdGroupStatus = 2
	// The ad group is paused.
	AdGroupStatusEnum_PAUSED AdGroupStatusEnum_AdGroupStatus = 3
	// The ad group is removed.
	AdGroupStatusEnum_REMOVED AdGroupStatusEnum_AdGroupStatus = 4
)

var AdGroupStatusEnum_AdGroupStatus_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "ENABLED",
	3: "PAUSED",
	4: "REMOVED",
}
var AdGroupStatusEnum_AdGroupStatus_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"ENABLED":     2,
	"PAUSED":      3,
	"REMOVED":     4,
}

func (x AdGroupStatusEnum_AdGroupStatus) String() string {
	return proto.EnumName(AdGroupStatusEnum_AdGroupStatus_name, int32(x))
}
func (AdGroupStatusEnum_AdGroupStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ad_group_status_96bd7a2e646a31b3, []int{0, 0}
}

// Container for enum describing possible statuses of an ad group.
type AdGroupStatusEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AdGroupStatusEnum) Reset()         { *m = AdGroupStatusEnum{} }
func (m *AdGroupStatusEnum) String() string { return proto.CompactTextString(m) }
func (*AdGroupStatusEnum) ProtoMessage()    {}
func (*AdGroupStatusEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_ad_group_status_96bd7a2e646a31b3, []int{0}
}
func (m *AdGroupStatusEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AdGroupStatusEnum.Unmarshal(m, b)
}
func (m *AdGroupStatusEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AdGroupStatusEnum.Marshal(b, m, deterministic)
}
func (dst *AdGroupStatusEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdGroupStatusEnum.Merge(dst, src)
}
func (m *AdGroupStatusEnum) XXX_Size() int {
	return xxx_messageInfo_AdGroupStatusEnum.Size(m)
}
func (m *AdGroupStatusEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_AdGroupStatusEnum.DiscardUnknown(m)
}

var xxx_messageInfo_AdGroupStatusEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*AdGroupStatusEnum)(nil), "google.ads.googleads.v0.enums.AdGroupStatusEnum")
	proto.RegisterEnum("google.ads.googleads.v0.enums.AdGroupStatusEnum_AdGroupStatus", AdGroupStatusEnum_AdGroupStatus_name, AdGroupStatusEnum_AdGroupStatus_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/enums/ad_group_status.proto", fileDescriptor_ad_group_status_96bd7a2e646a31b3)
}

var fileDescriptor_ad_group_status_96bd7a2e646a31b3 = []byte{
	// 291 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0xd1, 0x4a, 0xc3, 0x30,
	0x14, 0x86, 0x6d, 0x27, 0x13, 0x32, 0xc4, 0xda, 0xfb, 0x5d, 0x6c, 0x0f, 0x90, 0x16, 0x76, 0x17,
	0xaf, 0x52, 0x1b, 0xcb, 0x50, 0xbb, 0x62, 0x69, 0x05, 0x29, 0x8c, 0x6a, 0x4a, 0x14, 0xd6, 0xa6,
	0xf4, 0xb4, 0x7b, 0x20, 0x2f, 0x7d, 0x14, 0x5f, 0x44, 0xf0, 0x29, 0x24, 0x89, 0x2b, 0xec, 0x42,
	0x6f, 0xc2, 0x9f, 0xf3, 0x9f, 0x2f, 0x39, 0xff, 0x41, 0x2b, 0x21, 0xa5, 0xd8, 0x55, 0x5e, 0xc9,
	0xc1, 0x33, 0x52, 0xa9, 0xbd, 0xef, 0x55, 0xcd, 0x50, 0x83, 0x57, 0xf2, 0xad, 0xe8, 0xe4, 0xd0,
	0x6e, 0xa1, 0x2f, 0xfb, 0x01, 0x70, 0xdb, 0xc9, 0x5e, 0xba, 0x73, 0xd3, 0x89, 0x4b, 0x0e, 0x78,
	0x84, 0xf0, 0xde, 0xc7, 0x1a, 0x5a, 0xbe, 0xa2, 0x4b, 0xca, 0x23, 0x85, 0xa5, 0x9a, 0x62, 0xcd,
	0x50, 0x2f, 0x53, 0x74, 0x7e, 0x54, 0x74, 0x2f, 0xd0, 0x2c, 0x8b, 0xd3, 0x84, 0x5d, 0xaf, 0x6f,
	0xd6, 0x2c, 0x74, 0x4e, 0xdc, 0x19, 0x3a, 0xcb, 0xe2, 0xdb, 0x78, 0xf3, 0x18, 0x3b, 0x96, 0xba,
	0xb0, 0x98, 0x06, 0x77, 0x2c, 0x74, 0x6c, 0x17, 0xa1, 0x69, 0x42, 0xb3, 0x94, 0x85, 0xce, 0x44,
	0x19, 0x0f, 0xec, 0x7e, 0x93, 0xb3, 0xd0, 0x39, 0x0d, 0xbe, 0x2c, 0xb4, 0x78, 0x91, 0x35, 0xfe,
	0x77, 0x9e, 0xc0, 0x3d, 0xfa, 0x38, 0x51, 0x11, 0x12, 0xeb, 0x29, 0xf8, 0x85, 0x84, 0xdc, 0x95,
	0x8d, 0xc0, 0xb2, 0x13, 0x9e, 0xa8, 0x1a, 0x1d, 0xf0, 0xb0, 0x89, 0xf6, 0x0d, 0xfe, 0x58, 0xcc,
	0x95, 0x3e, 0xdf, 0xed, 0x49, 0x44, 0xe9, 0x87, 0x3d, 0x8f, 0xcc, 0x53, 0x94, 0x03, 0x36, 0x52,
	0xa9, 0xdc, 0xc7, 0x2a, 0x39, 0x7c, 0x1e, 0xfc, 0x82, 0x72, 0x28, 0x46, 0xbf, 0xc8, 0xfd, 0x42,
	0xfb, 0xdf, 0xf6, 0xc2, 0x14, 0x09, 0xa1, 0x1c, 0x08, 0x19, 0x3b, 0x08, 0xc9, 0x7d, 0x42, 0x74,
	0xcf, 0xf3, 0x54, 0x0f, 0xb6, 0xfa, 0x09, 0x00, 0x00, 0xff, 0xff, 0xc1, 0x77, 0xa6, 0xa9, 0xb0,
	0x01, 0x00, 0x00,
}

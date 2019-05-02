// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/ad_network_type.proto

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

// Enumerates Google Ads network types.
type AdNetworkTypeEnum_AdNetworkType int32

const (
	// Not specified.
	AdNetworkTypeEnum_UNSPECIFIED AdNetworkTypeEnum_AdNetworkType = 0
	// The value is unknown in this version.
	AdNetworkTypeEnum_UNKNOWN AdNetworkTypeEnum_AdNetworkType = 1
	// Google search.
	AdNetworkTypeEnum_SEARCH AdNetworkTypeEnum_AdNetworkType = 2
	// Search partners.
	AdNetworkTypeEnum_SEARCH_PARTNERS AdNetworkTypeEnum_AdNetworkType = 3
	// Display Network.
	AdNetworkTypeEnum_CONTENT AdNetworkTypeEnum_AdNetworkType = 4
	// YouTube Search.
	AdNetworkTypeEnum_YOUTUBE_SEARCH AdNetworkTypeEnum_AdNetworkType = 5
	// YouTube Videos
	AdNetworkTypeEnum_YOUTUBE_WATCH AdNetworkTypeEnum_AdNetworkType = 6
	// Cross-network.
	AdNetworkTypeEnum_MIXED AdNetworkTypeEnum_AdNetworkType = 7
)

var AdNetworkTypeEnum_AdNetworkType_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "SEARCH",
	3: "SEARCH_PARTNERS",
	4: "CONTENT",
	5: "YOUTUBE_SEARCH",
	6: "YOUTUBE_WATCH",
	7: "MIXED",
}
var AdNetworkTypeEnum_AdNetworkType_value = map[string]int32{
	"UNSPECIFIED":     0,
	"UNKNOWN":         1,
	"SEARCH":          2,
	"SEARCH_PARTNERS": 3,
	"CONTENT":         4,
	"YOUTUBE_SEARCH":  5,
	"YOUTUBE_WATCH":   6,
	"MIXED":           7,
}

func (x AdNetworkTypeEnum_AdNetworkType) String() string {
	return proto.EnumName(AdNetworkTypeEnum_AdNetworkType_name, int32(x))
}
func (AdNetworkTypeEnum_AdNetworkType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ad_network_type_ef7be46207dccd14, []int{0, 0}
}

// Container for enumeration of Google Ads network types.
type AdNetworkTypeEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AdNetworkTypeEnum) Reset()         { *m = AdNetworkTypeEnum{} }
func (m *AdNetworkTypeEnum) String() string { return proto.CompactTextString(m) }
func (*AdNetworkTypeEnum) ProtoMessage()    {}
func (*AdNetworkTypeEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_ad_network_type_ef7be46207dccd14, []int{0}
}
func (m *AdNetworkTypeEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AdNetworkTypeEnum.Unmarshal(m, b)
}
func (m *AdNetworkTypeEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AdNetworkTypeEnum.Marshal(b, m, deterministic)
}
func (dst *AdNetworkTypeEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdNetworkTypeEnum.Merge(dst, src)
}
func (m *AdNetworkTypeEnum) XXX_Size() int {
	return xxx_messageInfo_AdNetworkTypeEnum.Size(m)
}
func (m *AdNetworkTypeEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_AdNetworkTypeEnum.DiscardUnknown(m)
}

var xxx_messageInfo_AdNetworkTypeEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*AdNetworkTypeEnum)(nil), "google.ads.googleads.v1.enums.AdNetworkTypeEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.AdNetworkTypeEnum_AdNetworkType", AdNetworkTypeEnum_AdNetworkType_name, AdNetworkTypeEnum_AdNetworkType_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/ad_network_type.proto", fileDescriptor_ad_network_type_ef7be46207dccd14)
}

var fileDescriptor_ad_network_type_ef7be46207dccd14 = []byte{
	// 356 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x50, 0xcf, 0x6a, 0xe2, 0x40,
	0x1c, 0xde, 0xc4, 0x55, 0xd9, 0x11, 0xd7, 0x38, 0x7b, 0x5b, 0xd6, 0x83, 0x3e, 0xc0, 0x84, 0xe0,
	0x6d, 0xf6, 0x34, 0x89, 0xb3, 0x2a, 0xcb, 0x8e, 0x41, 0x13, 0xdd, 0x96, 0x40, 0x48, 0x9b, 0x10,
	0xa4, 0x3a, 0x13, 0x9c, 0x68, 0xf1, 0x21, 0xfa, 0x12, 0xed, 0xad, 0x8f, 0xd2, 0x17, 0x29, 0xf4,
	0x29, 0x4a, 0x32, 0x46, 0xf0, 0xd0, 0x5e, 0x86, 0x8f, 0xdf, 0xf7, 0x87, 0xf9, 0x3e, 0x30, 0x4c,
	0x85, 0x48, 0x37, 0x89, 0x19, 0xc5, 0xd2, 0x54, 0xb0, 0x40, 0x07, 0xcb, 0x4c, 0xf8, 0x7e, 0x2b,
	0xcd, 0x28, 0x0e, 0x79, 0x92, 0xdf, 0x8b, 0xdd, 0x5d, 0x98, 0x1f, 0xb3, 0x04, 0x65, 0x3b, 0x91,
	0x0b, 0xd8, 0x53, 0x4a, 0x14, 0xc5, 0x12, 0x9d, 0x4d, 0xe8, 0x60, 0xa1, 0xd2, 0xf4, 0xf3, 0x57,
	0x95, 0x99, 0xad, 0xcd, 0x88, 0x73, 0x91, 0x47, 0xf9, 0x5a, 0x70, 0xa9, 0xcc, 0x83, 0x27, 0x0d,
	0x74, 0x49, 0xcc, 0x54, 0xaa, 0x77, 0xcc, 0x12, 0xca, 0xf7, 0xdb, 0xc1, 0x83, 0x06, 0xda, 0x17,
	0x57, 0xd8, 0x01, 0x2d, 0x9f, 0x2d, 0x5c, 0xea, 0x4c, 0xff, 0x4c, 0xe9, 0xc8, 0xf8, 0x02, 0x5b,
	0xa0, 0xe9, 0xb3, 0xbf, 0x6c, 0xb6, 0x62, 0x86, 0x06, 0x01, 0x68, 0x2c, 0x28, 0x99, 0x3b, 0x13,
	0x43, 0x87, 0x3f, 0x40, 0x47, 0xe1, 0xd0, 0x25, 0x73, 0x8f, 0xd1, 0xf9, 0xc2, 0xa8, 0x15, 0x6a,
	0x67, 0xc6, 0x3c, 0xca, 0x3c, 0xe3, 0x2b, 0x84, 0xe0, 0xfb, 0xd5, 0xcc, 0xf7, 0x7c, 0x9b, 0x86,
	0x27, 0x57, 0x1d, 0x76, 0x41, 0xbb, 0xba, 0xad, 0x88, 0xe7, 0x4c, 0x8c, 0x06, 0xfc, 0x06, 0xea,
	0xff, 0xa6, 0xff, 0xe9, 0xc8, 0x68, 0xda, 0xaf, 0x1a, 0xe8, 0xdf, 0x8a, 0x2d, 0xfa, 0xb4, 0xa9,
	0x0d, 0x2f, 0xbe, 0xec, 0x16, 0xfd, 0x5c, 0xed, 0xda, 0x3e, 0x99, 0x52, 0xb1, 0x89, 0x78, 0x8a,
	0xc4, 0x2e, 0x35, 0xd3, 0x84, 0x97, 0xed, 0xab, 0x8d, 0xb3, 0xb5, 0xfc, 0x60, 0xf2, 0xdf, 0xe5,
	0xfb, 0xa8, 0xd7, 0xc6, 0x84, 0x3c, 0xeb, 0xbd, 0xb1, 0x8a, 0x22, 0xb1, 0x44, 0x0a, 0x16, 0x68,
	0x69, 0xa1, 0x62, 0x34, 0xf9, 0x52, 0xf1, 0x01, 0x89, 0x65, 0x70, 0xe6, 0x83, 0xa5, 0x15, 0x94,
	0xfc, 0x9b, 0xde, 0x57, 0x47, 0x8c, 0x49, 0x2c, 0x31, 0x3e, 0x2b, 0x30, 0x5e, 0x5a, 0x18, 0x97,
	0x9a, 0x9b, 0x46, 0xf9, 0xb1, 0xe1, 0x7b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x16, 0xfc, 0x47, 0xc5,
	0x0a, 0x02, 0x00, 0x00,
}

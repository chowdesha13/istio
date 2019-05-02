// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/ad_type.proto

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

// The possible types of an ad.
type AdTypeEnum_AdType int32

const (
	// No value has been specified.
	AdTypeEnum_UNSPECIFIED AdTypeEnum_AdType = 0
	// The received value is not known in this version.
	//
	// This is a response-only value.
	AdTypeEnum_UNKNOWN AdTypeEnum_AdType = 1
	// The ad is a text ad.
	AdTypeEnum_TEXT_AD AdTypeEnum_AdType = 2
	// The ad is an expanded text ad.
	AdTypeEnum_EXPANDED_TEXT_AD AdTypeEnum_AdType = 3
	// The ad is a call only ad.
	AdTypeEnum_CALL_ONLY_AD AdTypeEnum_AdType = 6
	// The ad is an expanded dynamic search ad.
	AdTypeEnum_EXPANDED_DYNAMIC_SEARCH_AD AdTypeEnum_AdType = 7
	// The ad is a hotel ad.
	AdTypeEnum_HOTEL_AD AdTypeEnum_AdType = 8
	// The ad is a Smart Shopping ad.
	AdTypeEnum_SHOPPING_SMART_AD AdTypeEnum_AdType = 9
	// The ad is a standard Shopping ad.
	AdTypeEnum_SHOPPING_PRODUCT_AD AdTypeEnum_AdType = 10
	// The ad is a video ad.
	AdTypeEnum_VIDEO_AD AdTypeEnum_AdType = 12
	// This ad is a Gmail ad.
	AdTypeEnum_GMAIL_AD AdTypeEnum_AdType = 13
	// This ad is an Image ad.
	AdTypeEnum_IMAGE_AD AdTypeEnum_AdType = 14
	// The ad is a responsive search ad.
	AdTypeEnum_RESPONSIVE_SEARCH_AD AdTypeEnum_AdType = 15
	// The ad is a legacy responsive display ad.
	AdTypeEnum_LEGACY_RESPONSIVE_DISPLAY_AD AdTypeEnum_AdType = 16
	// The ad is an app ad.
	AdTypeEnum_APP_AD AdTypeEnum_AdType = 17
	// The ad is a legacy app install ad.
	AdTypeEnum_LEGACY_APP_INSTALL_AD AdTypeEnum_AdType = 18
	// The ad is a responsive display ad.
	AdTypeEnum_RESPONSIVE_DISPLAY_AD AdTypeEnum_AdType = 19
)

var AdTypeEnum_AdType_name = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "UNKNOWN",
	2:  "TEXT_AD",
	3:  "EXPANDED_TEXT_AD",
	6:  "CALL_ONLY_AD",
	7:  "EXPANDED_DYNAMIC_SEARCH_AD",
	8:  "HOTEL_AD",
	9:  "SHOPPING_SMART_AD",
	10: "SHOPPING_PRODUCT_AD",
	12: "VIDEO_AD",
	13: "GMAIL_AD",
	14: "IMAGE_AD",
	15: "RESPONSIVE_SEARCH_AD",
	16: "LEGACY_RESPONSIVE_DISPLAY_AD",
	17: "APP_AD",
	18: "LEGACY_APP_INSTALL_AD",
	19: "RESPONSIVE_DISPLAY_AD",
}
var AdTypeEnum_AdType_value = map[string]int32{
	"UNSPECIFIED":                  0,
	"UNKNOWN":                      1,
	"TEXT_AD":                      2,
	"EXPANDED_TEXT_AD":             3,
	"CALL_ONLY_AD":                 6,
	"EXPANDED_DYNAMIC_SEARCH_AD":   7,
	"HOTEL_AD":                     8,
	"SHOPPING_SMART_AD":            9,
	"SHOPPING_PRODUCT_AD":          10,
	"VIDEO_AD":                     12,
	"GMAIL_AD":                     13,
	"IMAGE_AD":                     14,
	"RESPONSIVE_SEARCH_AD":         15,
	"LEGACY_RESPONSIVE_DISPLAY_AD": 16,
	"APP_AD":                       17,
	"LEGACY_APP_INSTALL_AD":        18,
	"RESPONSIVE_DISPLAY_AD":        19,
}

func (x AdTypeEnum_AdType) String() string {
	return proto.EnumName(AdTypeEnum_AdType_name, int32(x))
}
func (AdTypeEnum_AdType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ad_type_a9a274bf62e2c41f, []int{0, 0}
}

// Container for enum describing possible types of an ad.
type AdTypeEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AdTypeEnum) Reset()         { *m = AdTypeEnum{} }
func (m *AdTypeEnum) String() string { return proto.CompactTextString(m) }
func (*AdTypeEnum) ProtoMessage()    {}
func (*AdTypeEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_ad_type_a9a274bf62e2c41f, []int{0}
}
func (m *AdTypeEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AdTypeEnum.Unmarshal(m, b)
}
func (m *AdTypeEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AdTypeEnum.Marshal(b, m, deterministic)
}
func (dst *AdTypeEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdTypeEnum.Merge(dst, src)
}
func (m *AdTypeEnum) XXX_Size() int {
	return xxx_messageInfo_AdTypeEnum.Size(m)
}
func (m *AdTypeEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_AdTypeEnum.DiscardUnknown(m)
}

var xxx_messageInfo_AdTypeEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*AdTypeEnum)(nil), "google.ads.googleads.v1.enums.AdTypeEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.AdTypeEnum_AdType", AdTypeEnum_AdType_name, AdTypeEnum_AdType_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/ad_type.proto", fileDescriptor_ad_type_a9a274bf62e2c41f)
}

var fileDescriptor_ad_type_a9a274bf62e2c41f = []byte{
	// 457 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x52, 0xcf, 0x6e, 0xd3, 0x30,
	0x18, 0xa7, 0x99, 0xd4, 0x8d, 0xaf, 0x85, 0x65, 0xde, 0x26, 0x60, 0xda, 0x10, 0xdb, 0x15, 0x29,
	0x51, 0xc5, 0x2d, 0x9c, 0xbe, 0x26, 0x26, 0xb5, 0x48, 0x1d, 0xab, 0x49, 0xc3, 0x8a, 0x2a, 0x45,
	0x81, 0x44, 0x51, 0xa5, 0x35, 0x89, 0xe6, 0x6e, 0xd2, 0x5e, 0x87, 0x23, 0x8f, 0xc2, 0x53, 0xc0,
	0x95, 0x13, 0x8f, 0x80, 0xec, 0xac, 0xd1, 0x0e, 0xb0, 0x8b, 0xf5, 0xfb, 0xe7, 0x9f, 0x6c, 0x7d,
	0x1f, 0xbc, 0x2d, 0xeb, 0xba, 0xbc, 0x2a, 0xec, 0x2c, 0x97, 0x76, 0x0b, 0x15, 0xba, 0x1d, 0xd9,
	0x45, 0x75, 0xb3, 0x96, 0x76, 0x96, 0xa7, 0x9b, 0xbb, 0xa6, 0xb0, 0x9a, 0xeb, 0x7a, 0x53, 0x93,
	0xb3, 0x36, 0x61, 0x65, 0xb9, 0xb4, 0xba, 0xb0, 0x75, 0x3b, 0xb2, 0x74, 0xf8, 0xe4, 0x74, 0xdb,
	0xd5, 0xac, 0xec, 0xac, 0xaa, 0xea, 0x4d, 0xb6, 0x59, 0xd5, 0x95, 0x6c, 0x2f, 0x5f, 0xfc, 0x31,
	0x00, 0x30, 0x8f, 0xef, 0x9a, 0x82, 0x56, 0x37, 0xeb, 0x8b, 0x5f, 0x06, 0xf4, 0x5b, 0x4a, 0xf6,
	0x61, 0x30, 0xe7, 0x91, 0xa0, 0x2e, 0xfb, 0xc0, 0xa8, 0x67, 0x3e, 0x21, 0x03, 0xd8, 0x9d, 0xf3,
	0x8f, 0x3c, 0xfc, 0xc4, 0xcd, 0x9e, 0x22, 0x31, 0xbd, 0x8c, 0x53, 0xf4, 0x4c, 0x83, 0x1c, 0x81,
	0x49, 0x2f, 0x05, 0x72, 0x8f, 0x7a, 0xe9, 0x56, 0xdd, 0x21, 0x26, 0x0c, 0x5d, 0x0c, 0x82, 0x34,
	0xe4, 0xc1, 0x42, 0x29, 0x7d, 0xf2, 0x1a, 0x4e, 0xba, 0x9c, 0xb7, 0xe0, 0x38, 0x65, 0x6e, 0x1a,
	0x51, 0x9c, 0xb9, 0x13, 0xe5, 0xef, 0x92, 0x21, 0xec, 0x4d, 0xc2, 0x98, 0x06, 0x8a, 0xed, 0x91,
	0x63, 0x38, 0x88, 0x26, 0xa1, 0x10, 0x8c, 0xfb, 0x69, 0x34, 0xc5, 0x99, 0xae, 0x7d, 0x4a, 0x5e,
	0xc0, 0x61, 0x27, 0x8b, 0x59, 0xe8, 0xcd, 0x5d, 0x6d, 0x80, 0xba, 0x9d, 0x30, 0x8f, 0x86, 0x8a,
	0x0d, 0x15, 0xf3, 0xa7, 0xc8, 0x74, 0xd7, 0x33, 0xc5, 0xd8, 0x14, 0x7d, 0xaa, 0xd8, 0x73, 0xf2,
	0x12, 0x8e, 0x66, 0x34, 0x12, 0x21, 0x8f, 0x58, 0x42, 0x1f, 0xbc, 0x60, 0x9f, 0xbc, 0x81, 0xd3,
	0x80, 0xfa, 0xe8, 0x2e, 0xd2, 0x07, 0x01, 0x8f, 0x45, 0x22, 0x40, 0xfd, 0x07, 0x93, 0x00, 0xf4,
	0x51, 0x08, 0x85, 0x0f, 0xc8, 0x2b, 0x38, 0xbe, 0x4f, 0x2b, 0x89, 0xf1, 0x28, 0x56, 0xff, 0x45,
	0xcf, 0x24, 0xca, 0xfa, 0x77, 0xc3, 0xe1, 0xf8, 0x67, 0x0f, 0xce, 0xbf, 0xd6, 0x6b, 0xeb, 0xd1,
	0xb1, 0x8d, 0x07, 0xed, 0x18, 0x84, 0x9a, 0x92, 0xe8, 0x7d, 0x1e, 0xdf, 0xa7, 0xcb, 0xfa, 0x2a,
	0xab, 0x4a, 0xab, 0xbe, 0x2e, 0xed, 0xb2, 0xa8, 0xf4, 0x0c, 0xb7, 0x1b, 0xd2, 0xac, 0xe4, 0x7f,
	0x16, 0xe6, 0xbd, 0x3e, 0xbf, 0x19, 0x3b, 0x3e, 0xe2, 0x77, 0xe3, 0xcc, 0x6f, 0xab, 0x30, 0x97,
	0x56, 0x0b, 0x15, 0x4a, 0x46, 0x96, 0xda, 0x00, 0xf9, 0x63, 0xeb, 0x2f, 0x31, 0x97, 0xcb, 0xce,
	0x5f, 0x26, 0xa3, 0xa5, 0xf6, 0x7f, 0x1b, 0xe7, 0xad, 0xe8, 0x38, 0x98, 0x4b, 0xc7, 0xe9, 0x12,
	0x8e, 0x93, 0x8c, 0x1c, 0x47, 0x67, 0xbe, 0xf4, 0xf5, 0xc3, 0xde, 0xfd, 0x0d, 0x00, 0x00, 0xff,
	0xff, 0x35, 0xb8, 0x1c, 0x20, 0xc8, 0x02, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/sitelink_placeholder_field.proto

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

// Possible values for Sitelink placeholder fields.
type SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField int32

const (
	// Not specified.
	SitelinkPlaceholderFieldEnum_UNSPECIFIED SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 0
	// Used for return value only. Represents value unknown in this version.
	SitelinkPlaceholderFieldEnum_UNKNOWN SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 1
	// Data Type: STRING. The link text for your sitelink.
	SitelinkPlaceholderFieldEnum_TEXT SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 2
	// Data Type: STRING. First line of the sitelink description.
	SitelinkPlaceholderFieldEnum_LINE_1 SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 3
	// Data Type: STRING. Second line of the sitelink description.
	SitelinkPlaceholderFieldEnum_LINE_2 SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 4
	// Data Type: URL_LIST. Final URLs for the sitelink when using Upgraded
	// URLs.
	SitelinkPlaceholderFieldEnum_FINAL_URLS SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 5
	// Data Type: URL_LIST. Final Mobile URLs for the sitelink when using
	// Upgraded URLs.
	SitelinkPlaceholderFieldEnum_FINAL_MOBILE_URLS SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 6
	// Data Type: URL. Tracking template for the sitelink when using Upgraded
	// URLs.
	SitelinkPlaceholderFieldEnum_TRACKING_URL SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 7
	// Data Type: STRING. Final URL suffix for sitelink when using parallel
	// tracking.
	SitelinkPlaceholderFieldEnum_FINAL_URL_SUFFIX SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField = 8
)

var SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "TEXT",
	3: "LINE_1",
	4: "LINE_2",
	5: "FINAL_URLS",
	6: "FINAL_MOBILE_URLS",
	7: "TRACKING_URL",
	8: "FINAL_URL_SUFFIX",
}
var SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField_value = map[string]int32{
	"UNSPECIFIED":       0,
	"UNKNOWN":           1,
	"TEXT":              2,
	"LINE_1":            3,
	"LINE_2":            4,
	"FINAL_URLS":        5,
	"FINAL_MOBILE_URLS": 6,
	"TRACKING_URL":      7,
	"FINAL_URL_SUFFIX":  8,
}

func (x SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField) String() string {
	return proto.EnumName(SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField_name, int32(x))
}
func (SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_sitelink_placeholder_field_f4c9f90eceb5bd6f, []int{0, 0}
}

// Values for Sitelink placeholder fields.
type SitelinkPlaceholderFieldEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SitelinkPlaceholderFieldEnum) Reset()         { *m = SitelinkPlaceholderFieldEnum{} }
func (m *SitelinkPlaceholderFieldEnum) String() string { return proto.CompactTextString(m) }
func (*SitelinkPlaceholderFieldEnum) ProtoMessage()    {}
func (*SitelinkPlaceholderFieldEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_sitelink_placeholder_field_f4c9f90eceb5bd6f, []int{0}
}
func (m *SitelinkPlaceholderFieldEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SitelinkPlaceholderFieldEnum.Unmarshal(m, b)
}
func (m *SitelinkPlaceholderFieldEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SitelinkPlaceholderFieldEnum.Marshal(b, m, deterministic)
}
func (dst *SitelinkPlaceholderFieldEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SitelinkPlaceholderFieldEnum.Merge(dst, src)
}
func (m *SitelinkPlaceholderFieldEnum) XXX_Size() int {
	return xxx_messageInfo_SitelinkPlaceholderFieldEnum.Size(m)
}
func (m *SitelinkPlaceholderFieldEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_SitelinkPlaceholderFieldEnum.DiscardUnknown(m)
}

var xxx_messageInfo_SitelinkPlaceholderFieldEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*SitelinkPlaceholderFieldEnum)(nil), "google.ads.googleads.v1.enums.SitelinkPlaceholderFieldEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField", SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField_name, SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/sitelink_placeholder_field.proto", fileDescriptor_sitelink_placeholder_field_f4c9f90eceb5bd6f)
}

var fileDescriptor_sitelink_placeholder_field_f4c9f90eceb5bd6f = []byte{
	// 377 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0xd1, 0x8e, 0x9a, 0x40,
	0x14, 0x86, 0x0b, 0x5a, 0x35, 0x63, 0xd3, 0x4e, 0x27, 0x6d, 0xd2, 0x34, 0x7a, 0xa1, 0x0f, 0x30,
	0x84, 0xf6, 0x6e, 0x9a, 0x34, 0x01, 0x0b, 0x86, 0x48, 0x91, 0x88, 0xb8, 0x66, 0x43, 0x42, 0x58,
	0x61, 0x59, 0xb2, 0x38, 0x43, 0x1c, 0xf4, 0x81, 0xf6, 0x6e, 0xf7, 0x51, 0x7c, 0x94, 0xbd, 0xdc,
	0x27, 0xd8, 0xc0, 0x28, 0x7b, 0xe5, 0xde, 0x4c, 0xfe, 0x39, 0xe7, 0x7c, 0xe7, 0xcc, 0xfc, 0x07,
	0xfc, 0x4d, 0x19, 0x4b, 0xf3, 0x44, 0x89, 0x62, 0xae, 0x08, 0x59, 0xa9, 0x83, 0xaa, 0x24, 0x74,
	0xbf, 0xe5, 0x0a, 0xcf, 0xca, 0x24, 0xcf, 0xe8, 0x7d, 0x58, 0xe4, 0xd1, 0x26, 0xb9, 0x63, 0x79,
	0x9c, 0xec, 0xc2, 0xdb, 0x2c, 0xc9, 0x63, 0x5c, 0xec, 0x58, 0xc9, 0xd0, 0x50, 0x40, 0x38, 0x8a,
	0x39, 0x6e, 0x78, 0x7c, 0x50, 0x71, 0xcd, 0xff, 0x1c, 0x9c, 0xdb, 0x17, 0x99, 0x12, 0x51, 0xca,
	0xca, 0xa8, 0xcc, 0x18, 0xe5, 0x02, 0x1e, 0x1f, 0x25, 0x30, 0xf0, 0x4e, 0x13, 0xdc, 0xb7, 0x01,
	0x66, 0xd5, 0xdf, 0xa0, 0xfb, 0xed, 0xf8, 0x51, 0x02, 0x3f, 0x2e, 0x15, 0xa0, 0x2f, 0xa0, 0xef,
	0x3b, 0x9e, 0x6b, 0x4c, 0x2c, 0xd3, 0x32, 0xfe, 0xc1, 0x0f, 0xa8, 0x0f, 0xba, 0xbe, 0x33, 0x73,
	0xe6, 0x57, 0x0e, 0x94, 0x50, 0x0f, 0xb4, 0x97, 0xc6, 0x7a, 0x09, 0x65, 0x04, 0x40, 0xc7, 0xb6,
	0x1c, 0x23, 0x54, 0x61, 0xab, 0xd1, 0xbf, 0x60, 0x1b, 0x7d, 0x06, 0xc0, 0xb4, 0x1c, 0xcd, 0x0e,
	0xfd, 0x85, 0xed, 0xc1, 0x8f, 0xe8, 0x3b, 0xf8, 0x2a, 0xee, 0xff, 0xe7, 0xba, 0x65, 0x1b, 0x22,
	0xdc, 0x41, 0x10, 0x7c, 0x5a, 0x2e, 0xb4, 0xc9, 0xcc, 0x72, 0xa6, 0x55, 0x08, 0x76, 0xd1, 0x37,
	0x00, 0x1b, 0x30, 0xf4, 0x7c, 0xd3, 0xb4, 0xd6, 0xb0, 0xa7, 0xbf, 0x48, 0x60, 0xb4, 0x61, 0x5b,
	0xfc, 0xae, 0x21, 0xfa, 0xf0, 0xd2, 0x77, 0xdc, 0xca, 0x11, 0x57, 0xba, 0xd6, 0x4f, 0x7c, 0xca,
	0xf2, 0x88, 0xa6, 0x98, 0xed, 0x52, 0x25, 0x4d, 0x68, 0xed, 0xd7, 0x79, 0x41, 0x45, 0xc6, 0x2f,
	0xec, 0xeb, 0x4f, 0x7d, 0x3e, 0xc8, 0xad, 0xa9, 0xa6, 0x3d, 0xc9, 0xc3, 0xa9, 0x68, 0xa5, 0xc5,
	0x1c, 0x0b, 0x59, 0xa9, 0x95, 0x8a, 0x2b, 0x6f, 0xf9, 0xf1, 0x9c, 0x0f, 0xb4, 0x98, 0x07, 0x4d,
	0x3e, 0x58, 0xa9, 0x41, 0x9d, 0x7f, 0x96, 0x47, 0x22, 0x48, 0x88, 0x16, 0x73, 0x42, 0x9a, 0x0a,
	0x42, 0x56, 0x2a, 0x21, 0x75, 0xcd, 0x4d, 0xa7, 0x7e, 0xd8, 0xef, 0xd7, 0x00, 0x00, 0x00, 0xff,
	0xff, 0xd0, 0xf6, 0xda, 0x64, 0x47, 0x02, 0x00, 0x00,
}

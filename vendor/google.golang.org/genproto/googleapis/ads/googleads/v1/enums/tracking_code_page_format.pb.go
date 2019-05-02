// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/tracking_code_page_format.proto

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

// The format of the web page where the tracking tag and snippet will be
// installed.
type TrackingCodePageFormatEnum_TrackingCodePageFormat int32

const (
	// Not specified.
	TrackingCodePageFormatEnum_UNSPECIFIED TrackingCodePageFormatEnum_TrackingCodePageFormat = 0
	// Used for return value only. Represents value unknown in this version.
	TrackingCodePageFormatEnum_UNKNOWN TrackingCodePageFormatEnum_TrackingCodePageFormat = 1
	// Standard HTML page format.
	TrackingCodePageFormatEnum_HTML TrackingCodePageFormatEnum_TrackingCodePageFormat = 2
	// Google AMP page format.
	TrackingCodePageFormatEnum_AMP TrackingCodePageFormatEnum_TrackingCodePageFormat = 3
)

var TrackingCodePageFormatEnum_TrackingCodePageFormat_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "HTML",
	3: "AMP",
}
var TrackingCodePageFormatEnum_TrackingCodePageFormat_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"HTML":        2,
	"AMP":         3,
}

func (x TrackingCodePageFormatEnum_TrackingCodePageFormat) String() string {
	return proto.EnumName(TrackingCodePageFormatEnum_TrackingCodePageFormat_name, int32(x))
}
func (TrackingCodePageFormatEnum_TrackingCodePageFormat) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_tracking_code_page_format_964e87d685b6ede5, []int{0, 0}
}

// Container for enum describing the format of the web page where the tracking
// tag and snippet will be installed.
type TrackingCodePageFormatEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TrackingCodePageFormatEnum) Reset()         { *m = TrackingCodePageFormatEnum{} }
func (m *TrackingCodePageFormatEnum) String() string { return proto.CompactTextString(m) }
func (*TrackingCodePageFormatEnum) ProtoMessage()    {}
func (*TrackingCodePageFormatEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_tracking_code_page_format_964e87d685b6ede5, []int{0}
}
func (m *TrackingCodePageFormatEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TrackingCodePageFormatEnum.Unmarshal(m, b)
}
func (m *TrackingCodePageFormatEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TrackingCodePageFormatEnum.Marshal(b, m, deterministic)
}
func (dst *TrackingCodePageFormatEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TrackingCodePageFormatEnum.Merge(dst, src)
}
func (m *TrackingCodePageFormatEnum) XXX_Size() int {
	return xxx_messageInfo_TrackingCodePageFormatEnum.Size(m)
}
func (m *TrackingCodePageFormatEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_TrackingCodePageFormatEnum.DiscardUnknown(m)
}

var xxx_messageInfo_TrackingCodePageFormatEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*TrackingCodePageFormatEnum)(nil), "google.ads.googleads.v1.enums.TrackingCodePageFormatEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.TrackingCodePageFormatEnum_TrackingCodePageFormat", TrackingCodePageFormatEnum_TrackingCodePageFormat_name, TrackingCodePageFormatEnum_TrackingCodePageFormat_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/tracking_code_page_format.proto", fileDescriptor_tracking_code_page_format_964e87d685b6ede5)
}

var fileDescriptor_tracking_code_page_format_964e87d685b6ede5 = []byte{
	// 312 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0xc1, 0x4e, 0xc2, 0x30,
	0x18, 0xc7, 0x65, 0x18, 0x31, 0xe5, 0xe0, 0xb2, 0x83, 0x07, 0x94, 0x03, 0x3c, 0x40, 0x9b, 0xc5,
	0x5b, 0x8d, 0x87, 0x82, 0x80, 0x44, 0x99, 0x4b, 0x04, 0x4c, 0xcc, 0x12, 0x52, 0x69, 0x6d, 0x16,
	0x59, 0xbf, 0x65, 0x1d, 0x3c, 0x90, 0x47, 0x1f, 0xc5, 0x47, 0xf1, 0xe4, 0x23, 0x98, 0xb5, 0xc0,
	0x09, 0xbd, 0x2c, 0xff, 0xec, 0xff, 0xfd, 0xfe, 0xfd, 0x7f, 0x1f, 0xba, 0x51, 0x00, 0x6a, 0x25,
	0x09, 0x17, 0x86, 0x38, 0x59, 0xa9, 0x4d, 0x48, 0xa4, 0x5e, 0x67, 0x86, 0x94, 0x05, 0x5f, 0xbe,
	0xa7, 0x5a, 0x2d, 0x96, 0x20, 0xe4, 0x22, 0xe7, 0x4a, 0x2e, 0xde, 0xa0, 0xc8, 0x78, 0x89, 0xf3,
	0x02, 0x4a, 0x08, 0xda, 0x8e, 0xc1, 0x5c, 0x18, 0xbc, 0xc7, 0xf1, 0x26, 0xc4, 0x16, 0x6f, 0x5d,
	0xee, 0xd2, 0xf3, 0x94, 0x70, 0xad, 0xa1, 0xe4, 0x65, 0x0a, 0xda, 0x38, 0xb8, 0xab, 0x50, 0x6b,
	0xba, 0xcd, 0xef, 0x83, 0x90, 0x31, 0x57, 0x72, 0x68, 0xc3, 0x07, 0x7a, 0x9d, 0x75, 0xc7, 0xe8,
	0xfc, 0xb0, 0x1b, 0x9c, 0xa1, 0xe6, 0x2c, 0x7a, 0x8a, 0x07, 0xfd, 0xf1, 0x70, 0x3c, 0xb8, 0xf5,
	0x8f, 0x82, 0x26, 0x6a, 0xcc, 0xa2, 0xfb, 0xe8, 0xf1, 0x39, 0xf2, 0x6b, 0xc1, 0x29, 0x3a, 0xbe,
	0x9b, 0x4e, 0x1e, 0x7c, 0x2f, 0x68, 0xa0, 0x3a, 0x9b, 0xc4, 0x7e, 0xbd, 0xf7, 0x53, 0x43, 0x9d,
	0x25, 0x64, 0xf8, 0xdf, 0xb2, 0xbd, 0x8b, 0xc3, 0xcf, 0xc5, 0x55, 0xd7, 0xb8, 0xf6, 0xd2, 0xdb,
	0xd2, 0x0a, 0x56, 0x5c, 0x2b, 0x0c, 0x85, 0x22, 0x4a, 0x6a, 0xbb, 0xc9, 0xee, 0x72, 0x79, 0x6a,
	0xfe, 0x38, 0xe4, 0xb5, 0xfd, 0x7e, 0x78, 0xf5, 0x11, 0x63, 0x9f, 0x5e, 0x7b, 0xe4, 0xa2, 0x98,
	0x30, 0xd8, 0xc9, 0x4a, 0xcd, 0x43, 0x5c, 0x2d, 0x6e, 0xbe, 0x76, 0x7e, 0xc2, 0x84, 0x49, 0xf6,
	0x7e, 0x32, 0x0f, 0x13, 0xeb, 0x7f, 0x7b, 0x1d, 0xf7, 0x93, 0x52, 0x26, 0x0c, 0xa5, 0xfb, 0x09,
	0x4a, 0xe7, 0x21, 0xa5, 0x76, 0xe6, 0xf5, 0xc4, 0x16, 0xbb, 0xfa, 0x0d, 0x00, 0x00, 0xff, 0xff,
	0x30, 0x63, 0x0b, 0x36, 0xe0, 0x01, 0x00, 0x00,
}

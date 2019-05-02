// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/dsa_page_feed_criterion_field.proto

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

// Possible values for Dynamic Search Ad Page Feed criterion fields.
type DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField int32

const (
	// Not specified.
	DsaPageFeedCriterionFieldEnum_UNSPECIFIED DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField = 0
	// Used for return value only. Represents value unknown in this version.
	DsaPageFeedCriterionFieldEnum_UNKNOWN DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField = 1
	// Data Type: URL or URL_LIST. URL of the web page you want to target.
	DsaPageFeedCriterionFieldEnum_PAGE_URL DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField = 2
	// Data Type: STRING_LIST. The labels that will help you target ads within
	// your page feed.
	DsaPageFeedCriterionFieldEnum_LABEL DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField = 3
)

var DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "PAGE_URL",
	3: "LABEL",
}
var DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"PAGE_URL":    2,
	"LABEL":       3,
}

func (x DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField) String() string {
	return proto.EnumName(DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField_name, int32(x))
}
func (DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_dsa_page_feed_criterion_field_e9797bc759a46566, []int{0, 0}
}

// Values for Dynamic Search Ad Page Feed criterion fields.
type DsaPageFeedCriterionFieldEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DsaPageFeedCriterionFieldEnum) Reset()         { *m = DsaPageFeedCriterionFieldEnum{} }
func (m *DsaPageFeedCriterionFieldEnum) String() string { return proto.CompactTextString(m) }
func (*DsaPageFeedCriterionFieldEnum) ProtoMessage()    {}
func (*DsaPageFeedCriterionFieldEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_dsa_page_feed_criterion_field_e9797bc759a46566, []int{0}
}
func (m *DsaPageFeedCriterionFieldEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DsaPageFeedCriterionFieldEnum.Unmarshal(m, b)
}
func (m *DsaPageFeedCriterionFieldEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DsaPageFeedCriterionFieldEnum.Marshal(b, m, deterministic)
}
func (dst *DsaPageFeedCriterionFieldEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DsaPageFeedCriterionFieldEnum.Merge(dst, src)
}
func (m *DsaPageFeedCriterionFieldEnum) XXX_Size() int {
	return xxx_messageInfo_DsaPageFeedCriterionFieldEnum.Size(m)
}
func (m *DsaPageFeedCriterionFieldEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_DsaPageFeedCriterionFieldEnum.DiscardUnknown(m)
}

var xxx_messageInfo_DsaPageFeedCriterionFieldEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*DsaPageFeedCriterionFieldEnum)(nil), "google.ads.googleads.v1.enums.DsaPageFeedCriterionFieldEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField", DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField_name, DsaPageFeedCriterionFieldEnum_DsaPageFeedCriterionField_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/dsa_page_feed_criterion_field.proto", fileDescriptor_dsa_page_feed_criterion_field_e9797bc759a46566)
}

var fileDescriptor_dsa_page_feed_criterion_field_e9797bc759a46566 = []byte{
	// 318 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x50, 0xcd, 0x4a, 0xc3, 0x40,
	0x18, 0xb4, 0x29, 0xfe, 0x6d, 0x05, 0x43, 0x6e, 0x8a, 0x15, 0xda, 0x07, 0xd8, 0x10, 0xbc, 0xad,
	0xa7, 0x4d, 0x9b, 0x96, 0x62, 0x89, 0xa1, 0xd2, 0x0a, 0x12, 0x08, 0x6b, 0x77, 0xbb, 0x04, 0xda,
	0xdd, 0x90, 0x2f, 0xed, 0x03, 0x79, 0xf4, 0x51, 0x7c, 0x14, 0xaf, 0xbe, 0x80, 0x64, 0xd7, 0xf4,
	0x16, 0x2f, 0x61, 0xc8, 0xcc, 0x37, 0x33, 0x3b, 0x88, 0x4a, 0xad, 0xe5, 0x56, 0xf8, 0x8c, 0x83,
	0x6f, 0x61, 0x8d, 0x0e, 0x81, 0x2f, 0xd4, 0x7e, 0x07, 0x3e, 0x07, 0x96, 0x15, 0x4c, 0x8a, 0x6c,
	0x23, 0x04, 0xcf, 0xd6, 0x65, 0x5e, 0x89, 0x32, 0xd7, 0x2a, 0xdb, 0xe4, 0x62, 0xcb, 0x71, 0x51,
	0xea, 0x4a, 0x7b, 0x7d, 0x7b, 0x87, 0x19, 0x07, 0x7c, 0xb4, 0xc0, 0x87, 0x00, 0x1b, 0x8b, 0xdb,
	0xbb, 0x26, 0xa1, 0xc8, 0x7d, 0xa6, 0x94, 0xae, 0x58, 0x95, 0x6b, 0x05, 0xf6, 0x78, 0x08, 0xa8,
	0x3f, 0x06, 0x96, 0x30, 0x29, 0x26, 0x42, 0xf0, 0x51, 0x13, 0x30, 0xa9, 0xfd, 0x23, 0xb5, 0xdf,
	0x0d, 0x17, 0xe8, 0xa6, 0x55, 0xe0, 0x5d, 0xa3, 0xde, 0x32, 0x7e, 0x49, 0xa2, 0xd1, 0x6c, 0x32,
	0x8b, 0xc6, 0xee, 0x89, 0xd7, 0x43, 0xe7, 0xcb, 0xf8, 0x29, 0x7e, 0x7e, 0x8d, 0xdd, 0x8e, 0x77,
	0x85, 0x2e, 0x12, 0x3a, 0x8d, 0xb2, 0xe5, 0x62, 0xee, 0x3a, 0xde, 0x25, 0x3a, 0x9d, 0xd3, 0x30,
	0x9a, 0xbb, 0xdd, 0xf0, 0xa7, 0x83, 0x06, 0x6b, 0xbd, 0xc3, 0xff, 0x16, 0x0f, 0xef, 0x5b, 0x73,
	0x93, 0xba, 0x7a, 0xd2, 0x79, 0x0b, 0xff, 0x0c, 0xa4, 0xde, 0x32, 0x25, 0xb1, 0x2e, 0xa5, 0x2f,
	0x85, 0x32, 0x0f, 0x6b, 0xc6, 0x2c, 0x72, 0x68, 0xd9, 0xf6, 0xd1, 0x7c, 0x3f, 0x9c, 0xee, 0x94,
	0xd2, 0x4f, 0xa7, 0x3f, 0xb5, 0x56, 0x94, 0x03, 0xb6, 0xb0, 0x46, 0xab, 0x00, 0xd7, 0x23, 0xc0,
	0x57, 0xc3, 0xa7, 0x94, 0x43, 0x7a, 0xe4, 0xd3, 0x55, 0x90, 0x1a, 0xfe, 0xdb, 0x19, 0xd8, 0x9f,
	0x84, 0x50, 0x0e, 0x84, 0x1c, 0x15, 0x84, 0xac, 0x02, 0x42, 0x8c, 0xe6, 0xfd, 0xcc, 0x14, 0x7b,
	0xf8, 0x0d, 0x00, 0x00, 0xff, 0xff, 0x3c, 0xf4, 0x41, 0xe5, 0xf3, 0x01, 0x00, 0x00,
}

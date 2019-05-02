// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/price_extension_price_qualifier.proto

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

// Enums of price extension price qualifier.
type PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier int32

const (
	// Not specified.
	PriceExtensionPriceQualifierEnum_UNSPECIFIED PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier = 0
	// Used for return value only. Represents value unknown in this version.
	PriceExtensionPriceQualifierEnum_UNKNOWN PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier = 1
	// 'From' qualifier for the price.
	PriceExtensionPriceQualifierEnum_FROM PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier = 2
	// 'Up to' qualifier for the price.
	PriceExtensionPriceQualifierEnum_UP_TO PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier = 3
	// 'Average' qualifier for the price.
	PriceExtensionPriceQualifierEnum_AVERAGE PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier = 4
)

var PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "FROM",
	3: "UP_TO",
	4: "AVERAGE",
}
var PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"FROM":        2,
	"UP_TO":       3,
	"AVERAGE":     4,
}

func (x PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier) String() string {
	return proto.EnumName(PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier_name, int32(x))
}
func (PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_price_extension_price_qualifier_b151df2520862de8, []int{0, 0}
}

// Container for enum describing a price extension price qualifier.
type PriceExtensionPriceQualifierEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PriceExtensionPriceQualifierEnum) Reset()         { *m = PriceExtensionPriceQualifierEnum{} }
func (m *PriceExtensionPriceQualifierEnum) String() string { return proto.CompactTextString(m) }
func (*PriceExtensionPriceQualifierEnum) ProtoMessage()    {}
func (*PriceExtensionPriceQualifierEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_price_extension_price_qualifier_b151df2520862de8, []int{0}
}
func (m *PriceExtensionPriceQualifierEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PriceExtensionPriceQualifierEnum.Unmarshal(m, b)
}
func (m *PriceExtensionPriceQualifierEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PriceExtensionPriceQualifierEnum.Marshal(b, m, deterministic)
}
func (dst *PriceExtensionPriceQualifierEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PriceExtensionPriceQualifierEnum.Merge(dst, src)
}
func (m *PriceExtensionPriceQualifierEnum) XXX_Size() int {
	return xxx_messageInfo_PriceExtensionPriceQualifierEnum.Size(m)
}
func (m *PriceExtensionPriceQualifierEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_PriceExtensionPriceQualifierEnum.DiscardUnknown(m)
}

var xxx_messageInfo_PriceExtensionPriceQualifierEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*PriceExtensionPriceQualifierEnum)(nil), "google.ads.googleads.v1.enums.PriceExtensionPriceQualifierEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier", PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier_name, PriceExtensionPriceQualifierEnum_PriceExtensionPriceQualifier_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/price_extension_price_qualifier.proto", fileDescriptor_price_extension_price_qualifier_b151df2520862de8)
}

var fileDescriptor_price_extension_price_qualifier_b151df2520862de8 = []byte{
	// 326 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x50, 0x4d, 0x4e, 0xf3, 0x30,
	0x10, 0xfd, 0x92, 0xf6, 0xe3, 0xc7, 0x5d, 0x10, 0x65, 0x89, 0x5a, 0x89, 0xf6, 0x00, 0x8e, 0x22,
	0x76, 0x66, 0xe5, 0x96, 0xb4, 0xaa, 0x10, 0x69, 0x28, 0x34, 0x48, 0x28, 0xa2, 0x32, 0x8d, 0xb1,
	0x2c, 0xb5, 0x76, 0x88, 0xd3, 0x8a, 0x35, 0x47, 0x61, 0xc9, 0x51, 0x38, 0x0a, 0x07, 0x60, 0x8d,
	0x6c, 0x93, 0xee, 0xc8, 0xc6, 0x7a, 0xe3, 0x79, 0xf3, 0x66, 0xde, 0x03, 0x23, 0x26, 0x25, 0x5b,
	0xd3, 0x80, 0xe4, 0x2a, 0xb0, 0x50, 0xa3, 0x5d, 0x18, 0x50, 0xb1, 0xdd, 0xa8, 0xa0, 0x28, 0xf9,
	0x8a, 0x2e, 0xe9, 0x6b, 0x45, 0x85, 0xe2, 0x52, 0x2c, 0x6d, 0xfd, 0xb2, 0x25, 0x6b, 0xfe, 0xcc,
	0x69, 0x09, 0x8b, 0x52, 0x56, 0xd2, 0xef, 0xd9, 0x49, 0x48, 0x72, 0x05, 0xf7, 0x22, 0x70, 0x17,
	0x42, 0x23, 0x72, 0xda, 0xad, 0x77, 0x14, 0x3c, 0x20, 0x42, 0xc8, 0x8a, 0x54, 0x5c, 0x0a, 0x65,
	0x87, 0x07, 0x6f, 0x0e, 0x38, 0x4b, 0xb4, 0x6c, 0x54, 0x6f, 0x31, 0xd5, 0x4d, 0xbd, 0x23, 0x12,
	0xdb, 0xcd, 0xe0, 0x11, 0x74, 0x9b, 0x38, 0xfe, 0x09, 0xe8, 0x2c, 0xe2, 0xdb, 0x24, 0x1a, 0x4d,
	0xc7, 0xd3, 0xe8, 0xd2, 0xfb, 0xe7, 0x77, 0xc0, 0xe1, 0x22, 0xbe, 0x8a, 0x67, 0xf7, 0xb1, 0xe7,
	0xf8, 0x47, 0xa0, 0x3d, 0x9e, 0xcf, 0xae, 0x3d, 0xd7, 0x3f, 0x06, 0xff, 0x17, 0xc9, 0xf2, 0x6e,
	0xe6, 0xb5, 0x34, 0x03, 0xa7, 0xd1, 0x1c, 0x4f, 0x22, 0xaf, 0x3d, 0xfc, 0x76, 0x40, 0x7f, 0x25,
	0x37, 0xb0, 0xd1, 0xc8, 0xb0, 0xdf, 0x74, 0x43, 0xa2, 0xdd, 0x24, 0xce, 0xc3, 0xf0, 0x57, 0x83,
	0xc9, 0x35, 0x11, 0x0c, 0xca, 0x92, 0x05, 0x8c, 0x0a, 0xe3, 0xb5, 0x4e, 0xb8, 0xe0, 0xea, 0x8f,
	0xc0, 0x2f, 0xcc, 0xfb, 0xee, 0xb6, 0x26, 0x18, 0x7f, 0xb8, 0xbd, 0x89, 0x95, 0xc2, 0xb9, 0x82,
	0x16, 0x6a, 0x94, 0x86, 0x50, 0x67, 0xa2, 0x3e, 0xeb, 0x7e, 0x86, 0x73, 0x95, 0xed, 0xfb, 0x59,
	0x1a, 0x66, 0xa6, 0xff, 0xe5, 0xf6, 0xed, 0x27, 0x42, 0x38, 0x57, 0x08, 0xed, 0x19, 0x08, 0xa5,
	0x21, 0x42, 0x86, 0xf3, 0x74, 0x60, 0x0e, 0x3b, 0xff, 0x09, 0x00, 0x00, 0xff, 0xff, 0x21, 0x8d,
	0x8b, 0x8d, 0x08, 0x02, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/budget_delivery_method.proto

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

// Possible delivery methods of a Budget.
type BudgetDeliveryMethodEnum_BudgetDeliveryMethod int32

const (
	// Not specified.
	BudgetDeliveryMethodEnum_UNSPECIFIED BudgetDeliveryMethodEnum_BudgetDeliveryMethod = 0
	// Used for return value only. Represents value unknown in this version.
	BudgetDeliveryMethodEnum_UNKNOWN BudgetDeliveryMethodEnum_BudgetDeliveryMethod = 1
	// The budget server will throttle serving evenly across
	// the entire time period.
	BudgetDeliveryMethodEnum_STANDARD BudgetDeliveryMethodEnum_BudgetDeliveryMethod = 2
	// The budget server will not throttle serving,
	// and ads will serve as fast as possible.
	BudgetDeliveryMethodEnum_ACCELERATED BudgetDeliveryMethodEnum_BudgetDeliveryMethod = 3
)

var BudgetDeliveryMethodEnum_BudgetDeliveryMethod_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "STANDARD",
	3: "ACCELERATED",
}
var BudgetDeliveryMethodEnum_BudgetDeliveryMethod_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"STANDARD":    2,
	"ACCELERATED": 3,
}

func (x BudgetDeliveryMethodEnum_BudgetDeliveryMethod) String() string {
	return proto.EnumName(BudgetDeliveryMethodEnum_BudgetDeliveryMethod_name, int32(x))
}
func (BudgetDeliveryMethodEnum_BudgetDeliveryMethod) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_budget_delivery_method_9bb695e482492a3b, []int{0, 0}
}

// Message describing Budget delivery methods. A delivery method determines the
// rate at which the Budget is spent.
type BudgetDeliveryMethodEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BudgetDeliveryMethodEnum) Reset()         { *m = BudgetDeliveryMethodEnum{} }
func (m *BudgetDeliveryMethodEnum) String() string { return proto.CompactTextString(m) }
func (*BudgetDeliveryMethodEnum) ProtoMessage()    {}
func (*BudgetDeliveryMethodEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_budget_delivery_method_9bb695e482492a3b, []int{0}
}
func (m *BudgetDeliveryMethodEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BudgetDeliveryMethodEnum.Unmarshal(m, b)
}
func (m *BudgetDeliveryMethodEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BudgetDeliveryMethodEnum.Marshal(b, m, deterministic)
}
func (dst *BudgetDeliveryMethodEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BudgetDeliveryMethodEnum.Merge(dst, src)
}
func (m *BudgetDeliveryMethodEnum) XXX_Size() int {
	return xxx_messageInfo_BudgetDeliveryMethodEnum.Size(m)
}
func (m *BudgetDeliveryMethodEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_BudgetDeliveryMethodEnum.DiscardUnknown(m)
}

var xxx_messageInfo_BudgetDeliveryMethodEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*BudgetDeliveryMethodEnum)(nil), "google.ads.googleads.v1.enums.BudgetDeliveryMethodEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.BudgetDeliveryMethodEnum_BudgetDeliveryMethod", BudgetDeliveryMethodEnum_BudgetDeliveryMethod_name, BudgetDeliveryMethodEnum_BudgetDeliveryMethod_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/budget_delivery_method.proto", fileDescriptor_budget_delivery_method_9bb695e482492a3b)
}

var fileDescriptor_budget_delivery_method_9bb695e482492a3b = []byte{
	// 313 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x50, 0xcf, 0x4a, 0xfb, 0x30,
	0x00, 0xfe, 0xad, 0x83, 0x9f, 0x92, 0x09, 0x96, 0xe2, 0x41, 0xc5, 0x1d, 0xb6, 0x07, 0x48, 0x28,
	0xde, 0xe2, 0x29, 0x5d, 0xe3, 0x18, 0x6a, 0x1d, 0xfb, 0x27, 0x48, 0x61, 0x74, 0x26, 0xc4, 0xc2,
	0x9a, 0x8c, 0xa6, 0x2d, 0xf8, 0x3a, 0x1e, 0x7d, 0x14, 0x1f, 0xc5, 0x83, 0xcf, 0x20, 0x4d, 0xd6,
	0x9e, 0xa6, 0x97, 0xf0, 0x91, 0xef, 0x4f, 0xbe, 0x7c, 0x00, 0x0b, 0xa5, 0xc4, 0x96, 0xa3, 0x84,
	0x69, 0x64, 0x61, 0x8d, 0x2a, 0x1f, 0x71, 0x59, 0x66, 0x1a, 0x6d, 0x4a, 0x26, 0x78, 0xb1, 0x66,
	0x7c, 0x9b, 0x56, 0x3c, 0x7f, 0x5b, 0x67, 0xbc, 0x78, 0x55, 0x0c, 0xee, 0x72, 0x55, 0x28, 0xaf,
	0x6f, 0x0d, 0x30, 0x61, 0x1a, 0xb6, 0x5e, 0x58, 0xf9, 0xd0, 0x78, 0x2f, 0xaf, 0x9a, 0xe8, 0x5d,
	0x8a, 0x12, 0x29, 0x55, 0x91, 0x14, 0xa9, 0x92, 0xda, 0x9a, 0x87, 0x0a, 0x9c, 0x07, 0x26, 0x3c,
	0xdc, 0x67, 0x3f, 0x98, 0x68, 0x2a, 0xcb, 0x6c, 0x38, 0x07, 0x67, 0x87, 0x38, 0xef, 0x14, 0xf4,
	0x96, 0xd1, 0x7c, 0x4a, 0x47, 0x93, 0xdb, 0x09, 0x0d, 0xdd, 0x7f, 0x5e, 0x0f, 0x1c, 0x2d, 0xa3,
	0xbb, 0xe8, 0xf1, 0x29, 0x72, 0x3b, 0xde, 0x09, 0x38, 0x9e, 0x2f, 0x48, 0x14, 0x92, 0x59, 0xe8,
	0x3a, 0xb5, 0x96, 0x8c, 0x46, 0xf4, 0x9e, 0xce, 0xc8, 0x82, 0x86, 0x6e, 0x37, 0xf8, 0xee, 0x80,
	0xc1, 0x8b, 0xca, 0xe0, 0x9f, 0xa5, 0x83, 0x8b, 0x43, 0x0f, 0x4f, 0xeb, 0xc6, 0xd3, 0xce, 0x73,
	0xb0, 0xf7, 0x0a, 0xb5, 0x4d, 0xa4, 0x80, 0x2a, 0x17, 0x48, 0x70, 0x69, 0xfe, 0xd3, 0x8c, 0xb7,
	0x4b, 0xf5, 0x2f, 0x5b, 0xde, 0x98, 0xf3, 0xdd, 0xe9, 0x8e, 0x09, 0xf9, 0x70, 0xfa, 0x63, 0x1b,
	0x45, 0x98, 0x86, 0x16, 0xd6, 0x68, 0xe5, 0xc3, 0x7a, 0x00, 0xfd, 0xd9, 0xf0, 0x31, 0x61, 0x3a,
	0x6e, 0xf9, 0x78, 0xe5, 0xc7, 0x86, 0xff, 0x72, 0x06, 0xf6, 0x12, 0x63, 0xc2, 0x34, 0xc6, 0xad,
	0x02, 0xe3, 0x95, 0x8f, 0xb1, 0xd1, 0x6c, 0xfe, 0x9b, 0x62, 0xd7, 0x3f, 0x01, 0x00, 0x00, 0xff,
	0xff, 0x11, 0x07, 0xf6, 0x4b, 0xe3, 0x01, 0x00, 0x00,
}

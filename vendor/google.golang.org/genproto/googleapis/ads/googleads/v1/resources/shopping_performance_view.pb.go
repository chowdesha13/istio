// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/resources/shopping_performance_view.proto

package resources // import "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"

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

// Shopping performance view.
// Provides Shopping campaign statistics aggregated at several product dimension
// levels. Product dimension values from Merchant Center such as brand,
// category, custom attributes, product condition and product type will reflect
// the state of each dimension as of the date and time when the corresponding
// event was recorded.
type ShoppingPerformanceView struct {
	// The resource name of the Shopping performance view.
	// Shopping performance view resource names have the form:
	// `customers/{customer_id}/shoppingPerformanceView`
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ShoppingPerformanceView) Reset()         { *m = ShoppingPerformanceView{} }
func (m *ShoppingPerformanceView) String() string { return proto.CompactTextString(m) }
func (*ShoppingPerformanceView) ProtoMessage()    {}
func (*ShoppingPerformanceView) Descriptor() ([]byte, []int) {
	return fileDescriptor_shopping_performance_view_e974dd982cd67dd4, []int{0}
}
func (m *ShoppingPerformanceView) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ShoppingPerformanceView.Unmarshal(m, b)
}
func (m *ShoppingPerformanceView) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ShoppingPerformanceView.Marshal(b, m, deterministic)
}
func (dst *ShoppingPerformanceView) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ShoppingPerformanceView.Merge(dst, src)
}
func (m *ShoppingPerformanceView) XXX_Size() int {
	return xxx_messageInfo_ShoppingPerformanceView.Size(m)
}
func (m *ShoppingPerformanceView) XXX_DiscardUnknown() {
	xxx_messageInfo_ShoppingPerformanceView.DiscardUnknown(m)
}

var xxx_messageInfo_ShoppingPerformanceView proto.InternalMessageInfo

func (m *ShoppingPerformanceView) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*ShoppingPerformanceView)(nil), "google.ads.googleads.v1.resources.ShoppingPerformanceView")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/resources/shopping_performance_view.proto", fileDescriptor_shopping_performance_view_e974dd982cd67dd4)
}

var fileDescriptor_shopping_performance_view_e974dd982cd67dd4 = []byte{
	// 278 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x90, 0x41, 0x4a, 0xc4, 0x30,
	0x14, 0x86, 0x69, 0x05, 0xc1, 0xa2, 0x9b, 0xd9, 0x28, 0x32, 0x0b, 0x47, 0x19, 0x70, 0x95, 0x50,
	0xdc, 0x45, 0x10, 0x32, 0x9b, 0x01, 0x17, 0x52, 0x46, 0xe8, 0x42, 0x0a, 0x25, 0xb6, 0x31, 0x06,
	0xa6, 0x79, 0x21, 0xaf, 0x76, 0xce, 0xe0, 0x35, 0x5c, 0x7a, 0x14, 0x8f, 0xe2, 0x29, 0xa4, 0x93,
	0x49, 0x5c, 0xe9, 0xec, 0x7e, 0xda, 0x2f, 0xdf, 0xff, 0xf3, 0x32, 0xae, 0x00, 0xd4, 0x5a, 0x52,
	0xd1, 0x22, 0xf5, 0x71, 0x4c, 0x43, 0x4e, 0x9d, 0x44, 0x78, 0x73, 0x8d, 0x44, 0x8a, 0xaf, 0x60,
	0xad, 0x36, 0xaa, 0xb6, 0xd2, 0xbd, 0x80, 0xeb, 0x84, 0x69, 0x64, 0x3d, 0x68, 0xb9, 0x21, 0xd6,
	0x41, 0x0f, 0x93, 0x99, 0x7f, 0x47, 0x44, 0x8b, 0x24, 0x2a, 0xc8, 0x90, 0x93, 0xa8, 0x38, 0x9f,
	0x86, 0x16, 0xab, 0xa9, 0x30, 0x06, 0x7a, 0xd1, 0x6b, 0x30, 0xe8, 0x05, 0x97, 0x77, 0xd9, 0xe9,
	0xe3, 0xae, 0xa3, 0xf8, 0xad, 0x28, 0xb5, 0xdc, 0x4c, 0xae, 0xb2, 0x93, 0x60, 0xa9, 0x8d, 0xe8,
	0xe4, 0x59, 0x72, 0x91, 0x5c, 0x1f, 0xad, 0x8e, 0xc3, 0xc7, 0x07, 0xd1, 0xc9, 0xc5, 0x7b, 0x9a,
	0xcd, 0x1b, 0xe8, 0xc8, 0xde, 0x1d, 0x8b, 0xe9, 0x1f, 0x3d, 0xc5, 0xb8, 0xa3, 0x48, 0x9e, 0xee,
	0x77, 0x0a, 0x05, 0x6b, 0x61, 0x14, 0x01, 0xa7, 0xa8, 0x92, 0x66, 0xbb, 0x32, 0x5c, 0xc7, 0x6a,
	0xfc, 0xe7, 0x58, 0xb7, 0x31, 0x7d, 0xa4, 0x07, 0x4b, 0xce, 0x3f, 0xd3, 0xd9, 0xd2, 0x2b, 0x79,
	0x8b, 0xc4, 0xc7, 0x31, 0x95, 0x39, 0x59, 0x05, 0xf2, 0x2b, 0x30, 0x15, 0x6f, 0xb1, 0x8a, 0x4c,
	0x55, 0xe6, 0x55, 0x64, 0xbe, 0xd3, 0xb9, 0xff, 0xc1, 0x18, 0x6f, 0x91, 0xb1, 0x48, 0x31, 0x56,
	0xe6, 0x8c, 0x45, 0xee, 0xf9, 0x70, 0x3b, 0xf6, 0xe6, 0x27, 0x00, 0x00, 0xff, 0xff, 0x97, 0x2e,
	0xb3, 0x88, 0xd8, 0x01, 0x00, 0x00,
}

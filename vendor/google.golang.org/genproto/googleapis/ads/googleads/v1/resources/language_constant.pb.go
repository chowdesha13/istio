// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/resources/language_constant.proto

package resources // import "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import wrappers "github.com/golang/protobuf/ptypes/wrappers"
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

// A language.
type LanguageConstant struct {
	// The resource name of the language constant.
	// Language constant resource names have the form:
	//
	// `languageConstants/{criterion_id}`
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	// The ID of the language constant.
	Id *wrappers.Int64Value `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	// The language code, e.g. "en_US", "en_AU", "es", "fr", etc.
	Code *wrappers.StringValue `protobuf:"bytes,3,opt,name=code,proto3" json:"code,omitempty"`
	// The full name of the language in English, e.g., "English (US)", "Spanish",
	// etc.
	Name *wrappers.StringValue `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	// Whether the language is targetable.
	Targetable           *wrappers.BoolValue `protobuf:"bytes,5,opt,name=targetable,proto3" json:"targetable,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *LanguageConstant) Reset()         { *m = LanguageConstant{} }
func (m *LanguageConstant) String() string { return proto.CompactTextString(m) }
func (*LanguageConstant) ProtoMessage()    {}
func (*LanguageConstant) Descriptor() ([]byte, []int) {
	return fileDescriptor_language_constant_43a2ca18ad5b792d, []int{0}
}
func (m *LanguageConstant) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LanguageConstant.Unmarshal(m, b)
}
func (m *LanguageConstant) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LanguageConstant.Marshal(b, m, deterministic)
}
func (dst *LanguageConstant) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LanguageConstant.Merge(dst, src)
}
func (m *LanguageConstant) XXX_Size() int {
	return xxx_messageInfo_LanguageConstant.Size(m)
}
func (m *LanguageConstant) XXX_DiscardUnknown() {
	xxx_messageInfo_LanguageConstant.DiscardUnknown(m)
}

var xxx_messageInfo_LanguageConstant proto.InternalMessageInfo

func (m *LanguageConstant) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *LanguageConstant) GetId() *wrappers.Int64Value {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *LanguageConstant) GetCode() *wrappers.StringValue {
	if m != nil {
		return m.Code
	}
	return nil
}

func (m *LanguageConstant) GetName() *wrappers.StringValue {
	if m != nil {
		return m.Name
	}
	return nil
}

func (m *LanguageConstant) GetTargetable() *wrappers.BoolValue {
	if m != nil {
		return m.Targetable
	}
	return nil
}

func init() {
	proto.RegisterType((*LanguageConstant)(nil), "google.ads.googleads.v1.resources.LanguageConstant")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/resources/language_constant.proto", fileDescriptor_language_constant_43a2ca18ad5b792d)
}

var fileDescriptor_language_constant_43a2ca18ad5b792d = []byte{
	// 371 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0xd1, 0x4a, 0xeb, 0x30,
	0x18, 0xc7, 0x69, 0xb6, 0x73, 0xe0, 0xe4, 0x9c, 0x03, 0x52, 0x10, 0xca, 0x1c, 0xb2, 0x29, 0x83,
	0x81, 0x90, 0x5a, 0x15, 0xc1, 0x78, 0xd5, 0x79, 0x31, 0x14, 0x91, 0x31, 0xa1, 0x17, 0x52, 0x18,
	0x59, 0x13, 0x43, 0xa1, 0x4b, 0x4a, 0x92, 0xce, 0x7b, 0xf1, 0x49, 0xbc, 0xf4, 0x51, 0x7c, 0x14,
	0x9f, 0x42, 0xda, 0xb4, 0x45, 0x1c, 0xa8, 0x77, 0x1f, 0xcd, 0xef, 0xf7, 0xff, 0x7f, 0x24, 0x85,
	0x67, 0x5c, 0x4a, 0x9e, 0x31, 0x9f, 0x50, 0xed, 0xdb, 0xb1, 0x9c, 0xd6, 0x81, 0xaf, 0x98, 0x96,
	0x85, 0x4a, 0x98, 0xf6, 0x33, 0x22, 0x78, 0x41, 0x38, 0x5b, 0x24, 0x52, 0x68, 0x43, 0x84, 0x41,
	0xb9, 0x92, 0x46, 0xba, 0x43, 0xcb, 0x23, 0x42, 0x35, 0x6a, 0x55, 0xb4, 0x0e, 0x50, 0xab, 0xf6,
	0x76, 0xeb, 0xf4, 0x4a, 0x58, 0x16, 0xf7, 0xfe, 0x83, 0x22, 0x79, 0xce, 0x94, 0xb6, 0x11, 0xbd,
	0x7e, 0xd3, 0x9e, 0xa7, 0x3e, 0x11, 0x42, 0x1a, 0x62, 0x52, 0x29, 0xea, 0xd3, 0xbd, 0x27, 0x00,
	0xb7, 0xae, 0xeb, 0xf2, 0x8b, 0xba, 0xdb, 0xdd, 0x87, 0xff, 0x9b, 0xfc, 0x85, 0x20, 0x2b, 0xe6,
	0x39, 0x03, 0x67, 0xfc, 0x67, 0xfe, 0xaf, 0xf9, 0x78, 0x43, 0x56, 0xcc, 0x3d, 0x80, 0x20, 0xa5,
	0x1e, 0x18, 0x38, 0xe3, 0xbf, 0x47, 0x3b, 0xf5, 0x72, 0xa8, 0x59, 0x02, 0x5d, 0x0a, 0x73, 0x7a,
	0x12, 0x91, 0xac, 0x60, 0x73, 0x90, 0x52, 0xf7, 0x10, 0x76, 0x13, 0x49, 0x99, 0xd7, 0xa9, 0xf0,
	0xfe, 0x06, 0x7e, 0x6b, 0x54, 0x2a, 0xb8, 0xe5, 0x2b, 0xb2, 0x34, 0xaa, 0xea, 0xee, 0x4f, 0x8c,
	0x92, 0x74, 0x31, 0x84, 0x86, 0x28, 0xce, 0x0c, 0x59, 0x66, 0xcc, 0xfb, 0x55, 0x79, 0xbd, 0x0d,
	0x6f, 0x22, 0x65, 0x66, 0xad, 0x0f, 0xf4, 0xe4, 0x11, 0xc0, 0x51, 0x22, 0x57, 0xe8, 0xdb, 0xeb,
	0x9e, 0x6c, 0x7f, 0xbe, 0xad, 0x59, 0x99, 0x3c, 0x73, 0xee, 0xae, 0x6a, 0x97, 0xcb, 0xf2, 0x31,
	0x91, 0x54, 0xdc, 0xe7, 0x4c, 0x54, 0xbd, 0xcd, 0xab, 0xe7, 0xa9, 0xfe, 0xe2, 0x27, 0x38, 0x6f,
	0xa7, 0x67, 0xd0, 0x99, 0x86, 0xe1, 0x0b, 0x18, 0x4e, 0x6d, 0x64, 0x48, 0x35, 0xb2, 0x63, 0x39,
	0x45, 0x01, 0x9a, 0x37, 0xe4, 0x6b, 0xc3, 0xc4, 0x21, 0xd5, 0x71, 0xcb, 0xc4, 0x51, 0x10, 0xb7,
	0xcc, 0x1b, 0x18, 0xd9, 0x03, 0x8c, 0x43, 0xaa, 0x31, 0x6e, 0x29, 0x8c, 0xa3, 0x00, 0xe3, 0x96,
	0x5b, 0xfe, 0xae, 0x96, 0x3d, 0x7e, 0x0f, 0x00, 0x00, 0xff, 0xff, 0x54, 0x30, 0x09, 0x79, 0xb0,
	0x02, 0x00, 0x00,
}

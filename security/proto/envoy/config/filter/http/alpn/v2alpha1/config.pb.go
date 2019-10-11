// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/filter/http/alpn/v2alpha1/config.proto

package v2alpha1

import (
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// FilterConfig is the config for ALPN filter.
type FilterConfig struct {
	// A list of ALPN that will override the ALPN for upstream TLS connections.
	AlpnOverride         []string `protobuf:"bytes,1,rep,name=alpn_override,json=alpnOverride,proto3" json:"alpn_override,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FilterConfig) Reset()         { *m = FilterConfig{} }
func (m *FilterConfig) String() string { return proto.CompactTextString(m) }
func (*FilterConfig) ProtoMessage()    {}
func (*FilterConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_9dd199870dce382a, []int{0}
}

func (m *FilterConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FilterConfig.Unmarshal(m, b)
}
func (m *FilterConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FilterConfig.Marshal(b, m, deterministic)
}
func (m *FilterConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FilterConfig.Merge(m, src)
}
func (m *FilterConfig) XXX_Size() int {
	return xxx_messageInfo_FilterConfig.Size(m)
}
func (m *FilterConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_FilterConfig.DiscardUnknown(m)
}

var xxx_messageInfo_FilterConfig proto.InternalMessageInfo

func (m *FilterConfig) GetAlpnOverride() []string {
	if m != nil {
		return m.AlpnOverride
	}
	return nil
}

func init() {
	proto.RegisterType((*FilterConfig)(nil), "istio.envoy.config.filter.http.alpn.v2alpha1.FilterConfig")
}

func init() {
	proto.RegisterFile("envoy/config/filter/http/alpn/v2alpha1/config.proto", fileDescriptor_9dd199870dce382a)
}

var fileDescriptor_9dd199870dce382a = []byte{
	// 155 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x32, 0x4e, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0x4f, 0xcb, 0xcc, 0x29, 0x49, 0x2d, 0xd2,
	0xcf, 0x28, 0x29, 0x29, 0xd0, 0x4f, 0xcc, 0x29, 0xc8, 0xd3, 0x2f, 0x33, 0x4a, 0xcc, 0x29, 0xc8,
	0x48, 0x34, 0x84, 0x2a, 0xd0, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xd2, 0xc9, 0x2c, 0x2e, 0xc9,
	0xcc, 0xd7, 0x03, 0x6b, 0xd5, 0x83, 0xca, 0x40, 0xb4, 0xea, 0x81, 0xb4, 0xea, 0x81, 0xb4, 0xea,
	0xc1, 0xb4, 0x2a, 0x19, 0x73, 0xf1, 0xb8, 0x81, 0x25, 0x9d, 0xc1, 0x2a, 0x85, 0x94, 0xb9, 0x78,
	0x41, 0x0a, 0xe2, 0xf3, 0xcb, 0x52, 0x8b, 0x8a, 0x32, 0x53, 0x52, 0x25, 0x18, 0x15, 0x98, 0x35,
	0x38, 0x83, 0x78, 0x40, 0x82, 0xfe, 0x50, 0x31, 0x27, 0xd3, 0x28, 0x63, 0x88, 0x25, 0x99, 0xf9,
	0xfa, 0x89, 0x05, 0x99, 0xfa, 0xc4, 0x39, 0x33, 0x89, 0x0d, 0xec, 0x40, 0x63, 0x40, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x34, 0xf8, 0x0a, 0x00, 0xd7, 0x00, 0x00, 0x00,
}

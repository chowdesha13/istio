// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pkg/dns/proto/nds.proto

package istio_networking_nds_v1

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
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

// Table of hostnames and their IPs to br used for DNS resolution at the agent
// Sent by istiod to istio agents via xds
type NameTable struct {
	// Map of hostname to resolution attributes.
	Table                map[string]*NameTable_NameInfo `protobuf:"bytes,1,rep,name=table,proto3" json:"table,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}                       `json:"-"`
	XXX_unrecognized     []byte                         `json:"-"`
	XXX_sizecache        int32                          `json:"-"`
}

func (m *NameTable) Reset()         { *m = NameTable{} }
func (m *NameTable) String() string { return proto.CompactTextString(m) }
func (*NameTable) ProtoMessage()    {}
func (*NameTable) Descriptor() ([]byte, []int) {
	return fileDescriptor_a3d88f15c0af915b, []int{0}
}

func (m *NameTable) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NameTable.Unmarshal(m, b)
}
func (m *NameTable) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NameTable.Marshal(b, m, deterministic)
}
func (m *NameTable) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NameTable.Merge(m, src)
}
func (m *NameTable) XXX_Size() int {
	return xxx_messageInfo_NameTable.Size(m)
}
func (m *NameTable) XXX_DiscardUnknown() {
	xxx_messageInfo_NameTable.DiscardUnknown(m)
}

var xxx_messageInfo_NameTable proto.InternalMessageInfo

func (m *NameTable) GetTable() map[string]*NameTable_NameInfo {
	if m != nil {
		return m.Table
	}
	return nil
}

type NameTable_NameInfo struct {
	// List of IPs for the host.
	Ips []string `protobuf:"bytes,1,rep,name=ips,proto3" json:"ips,omitempty"`
	// The name of the service registry containing the service (e.g. 'Kubernetes').
	Registry string `protobuf:"bytes,2,opt,name=registry,proto3" json:"registry,omitempty"`
	// The k8s service name. Only applies when registry=`Kubernetes`
	Shortname string `protobuf:"bytes,3,opt,name=shortname,proto3" json:"shortname,omitempty"`
	// The k8s namespace for the service. Only applies when registry=`Kubernetes`
	Namespace string `protobuf:"bytes,4,opt,name=namespace,proto3" json:"namespace,omitempty"`
	// List of alternate hosts to map to the IPs.
	// Only applies when registry=`Kubernetes`
	AltHosts             []string `protobuf:"bytes,5,rep,name=alt_hosts,json=altHosts,proto3" json:"alt_hosts,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NameTable_NameInfo) Reset()         { *m = NameTable_NameInfo{} }
func (m *NameTable_NameInfo) String() string { return proto.CompactTextString(m) }
func (*NameTable_NameInfo) ProtoMessage()    {}
func (*NameTable_NameInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_a3d88f15c0af915b, []int{0, 0}
}

func (m *NameTable_NameInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NameTable_NameInfo.Unmarshal(m, b)
}
func (m *NameTable_NameInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NameTable_NameInfo.Marshal(b, m, deterministic)
}
func (m *NameTable_NameInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NameTable_NameInfo.Merge(m, src)
}
func (m *NameTable_NameInfo) XXX_Size() int {
	return xxx_messageInfo_NameTable_NameInfo.Size(m)
}
func (m *NameTable_NameInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_NameTable_NameInfo.DiscardUnknown(m)
}

var xxx_messageInfo_NameTable_NameInfo proto.InternalMessageInfo

func (m *NameTable_NameInfo) GetIps() []string {
	if m != nil {
		return m.Ips
	}
	return nil
}

func (m *NameTable_NameInfo) GetRegistry() string {
	if m != nil {
		return m.Registry
	}
	return ""
}

func (m *NameTable_NameInfo) GetShortname() string {
	if m != nil {
		return m.Shortname
	}
	return ""
}

func (m *NameTable_NameInfo) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *NameTable_NameInfo) GetAltHosts() []string {
	if m != nil {
		return m.AltHosts
	}
	return nil
}

func init() {
	proto.RegisterType((*NameTable)(nil), "istio.networking.nds.v1.NameTable")
	proto.RegisterMapType((map[string]*NameTable_NameInfo)(nil), "istio.networking.nds.v1.NameTable.TableEntry")
	proto.RegisterType((*NameTable_NameInfo)(nil), "istio.networking.nds.v1.NameTable.NameInfo")
}

func init() {
	proto.RegisterFile("pkg/dns/proto/nds.proto", fileDescriptor_a3d88f15c0af915b)
}

var fileDescriptor_a3d88f15c0af915b = []byte{
	// 261 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0xc1, 0x4a, 0xc4, 0x30,
	0x10, 0x86, 0x69, 0x6b, 0xa5, 0x99, 0xbd, 0x48, 0x2e, 0x1b, 0xaa, 0x87, 0xc5, 0xd3, 0x82, 0x98,
	0xe2, 0x7a, 0x11, 0x6f, 0x22, 0x82, 0x5e, 0x3c, 0x14, 0xef, 0x92, 0x75, 0x63, 0x37, 0xb4, 0x9b,
	0x94, 0x64, 0x5c, 0xe9, 0x63, 0xf8, 0x5c, 0xbe, 0x94, 0x4c, 0x8a, 0xdd, 0x93, 0xe0, 0x25, 0xf9,
	0x67, 0x3e, 0xfe, 0xc9, 0x3f, 0x81, 0x79, 0xdf, 0x36, 0xd5, 0xc6, 0x86, 0xaa, 0xf7, 0x0e, 0x5d,
	0x65, 0x37, 0x41, 0x46, 0xc5, 0xe7, 0x26, 0xa0, 0x71, 0xd2, 0x6a, 0xfc, 0x74, 0xbe, 0x35, 0xb6,
	0x91, 0xc4, 0xf6, 0x57, 0xe7, 0xdf, 0x29, 0xb0, 0x67, 0xb5, 0xd3, 0x2f, 0x6a, 0xdd, 0x69, 0x7e,
	0x0f, 0x39, 0x92, 0x10, 0xc9, 0x22, 0x5b, 0xce, 0x56, 0x97, 0xf2, 0x0f, 0x9b, 0x9c, 0x2c, 0x32,
	0x9e, 0x0f, 0x16, 0xfd, 0x50, 0x8f, 0xde, 0xf2, 0x2b, 0x81, 0x82, 0xf8, 0x93, 0x7d, 0x77, 0xfc,
	0x04, 0x32, 0xd3, 0x87, 0x38, 0x8f, 0xd5, 0x24, 0x79, 0x09, 0x85, 0xd7, 0x8d, 0x09, 0xe8, 0x07,
	0x91, 0x2e, 0x92, 0x25, 0xab, 0xa7, 0x9a, 0x9f, 0x01, 0x0b, 0x5b, 0xe7, 0xd1, 0xaa, 0x9d, 0x16,
	0x59, 0x84, 0x87, 0x06, 0x51, 0xba, 0x43, 0xaf, 0xde, 0xb4, 0x38, 0x1a, 0xe9, 0xd4, 0xe0, 0xa7,
	0xc0, 0x54, 0x87, 0xaf, 0x5b, 0x17, 0x30, 0x88, 0x3c, 0xbe, 0x57, 0xa8, 0x0e, 0x1f, 0xa9, 0x2e,
	0x35, 0xc0, 0x21, 0x28, 0x85, 0x6a, 0xf5, 0x20, 0x92, 0x38, 0x82, 0x24, 0xbf, 0x83, 0x7c, 0xaf,
	0xba, 0x0f, 0x1d, 0x13, 0xcd, 0x56, 0x17, 0xff, 0x58, 0xfc, 0x77, 0xc5, 0x7a, 0x74, 0xde, 0xa6,
	0x37, 0xc9, 0xfa, 0x38, 0xfe, 0xf6, 0xf5, 0x4f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x75, 0x64,
	0x75, 0x88, 0x01, 0x00, 0x00,
}

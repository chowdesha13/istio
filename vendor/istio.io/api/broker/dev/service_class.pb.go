// Code generated by protoc-gen-go. DO NOT EDIT.
// source: broker/dev/service_class.proto

package dev // import "istio.io/api/broker/dev"

/*
This package defines service broker configurations.
*/

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// $hide_from_docs
// ServiceClass defines a service that are exposed to Istio service consumers.
// The service is linked into one or more ServicePlan.
type ServiceClass struct {
	// Required. Istio deployment spec for the service class.
	Deployment *Deployment `protobuf:"bytes,1,opt,name=deployment,proto3" json:"deployment,omitempty"`
	// Required. Listing information for the public catalog.
	Entry                *CatalogEntry `protobuf:"bytes,2,opt,name=entry,proto3" json:"entry,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *ServiceClass) Reset()         { *m = ServiceClass{} }
func (m *ServiceClass) String() string { return proto.CompactTextString(m) }
func (*ServiceClass) ProtoMessage()    {}
func (*ServiceClass) Descriptor() ([]byte, []int) {
	return fileDescriptor_service_class_66454733304d50ab, []int{0}
}
func (m *ServiceClass) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServiceClass.Unmarshal(m, b)
}
func (m *ServiceClass) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServiceClass.Marshal(b, m, deterministic)
}
func (dst *ServiceClass) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServiceClass.Merge(dst, src)
}
func (m *ServiceClass) XXX_Size() int {
	return xxx_messageInfo_ServiceClass.Size(m)
}
func (m *ServiceClass) XXX_DiscardUnknown() {
	xxx_messageInfo_ServiceClass.DiscardUnknown(m)
}

var xxx_messageInfo_ServiceClass proto.InternalMessageInfo

func (m *ServiceClass) GetDeployment() *Deployment {
	if m != nil {
		return m.Deployment
	}
	return nil
}

func (m *ServiceClass) GetEntry() *CatalogEntry {
	if m != nil {
		return m.Entry
	}
	return nil
}

// $hide_from_docs
// Deployment defines how the service instances are deployed.
type Deployment struct {
	// For truely multi-tenant service, the deployed service instance name.
	Instance             string   `protobuf:"bytes,1,opt,name=instance,proto3" json:"instance,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Deployment) Reset()         { *m = Deployment{} }
func (m *Deployment) String() string { return proto.CompactTextString(m) }
func (*Deployment) ProtoMessage()    {}
func (*Deployment) Descriptor() ([]byte, []int) {
	return fileDescriptor_service_class_66454733304d50ab, []int{1}
}
func (m *Deployment) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Deployment.Unmarshal(m, b)
}
func (m *Deployment) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Deployment.Marshal(b, m, deterministic)
}
func (dst *Deployment) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Deployment.Merge(dst, src)
}
func (m *Deployment) XXX_Size() int {
	return xxx_messageInfo_Deployment.Size(m)
}
func (m *Deployment) XXX_DiscardUnknown() {
	xxx_messageInfo_Deployment.DiscardUnknown(m)
}

var xxx_messageInfo_Deployment proto.InternalMessageInfo

func (m *Deployment) GetInstance() string {
	if m != nil {
		return m.Instance
	}
	return ""
}

// $hide_from_docs
// CatalogEntry defines listing information for this service within the exposed
// catalog.  The message is a subset of OSBI service fields defined in
// https://github.com/openservicebrokerapi
type CatalogEntry struct {
	// Required. Public service name.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Required. Public unique service guid.
	Id string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	// Required. Public short service description.
	Description          string   `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CatalogEntry) Reset()         { *m = CatalogEntry{} }
func (m *CatalogEntry) String() string { return proto.CompactTextString(m) }
func (*CatalogEntry) ProtoMessage()    {}
func (*CatalogEntry) Descriptor() ([]byte, []int) {
	return fileDescriptor_service_class_66454733304d50ab, []int{2}
}
func (m *CatalogEntry) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CatalogEntry.Unmarshal(m, b)
}
func (m *CatalogEntry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CatalogEntry.Marshal(b, m, deterministic)
}
func (dst *CatalogEntry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CatalogEntry.Merge(dst, src)
}
func (m *CatalogEntry) XXX_Size() int {
	return xxx_messageInfo_CatalogEntry.Size(m)
}
func (m *CatalogEntry) XXX_DiscardUnknown() {
	xxx_messageInfo_CatalogEntry.DiscardUnknown(m)
}

var xxx_messageInfo_CatalogEntry proto.InternalMessageInfo

func (m *CatalogEntry) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *CatalogEntry) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *CatalogEntry) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func init() {
	proto.RegisterType((*ServiceClass)(nil), "istio.broker.dev.ServiceClass")
	proto.RegisterType((*Deployment)(nil), "istio.broker.dev.Deployment")
	proto.RegisterType((*CatalogEntry)(nil), "istio.broker.dev.CatalogEntry")
}

func init() {
	proto.RegisterFile("broker/dev/service_class.proto", fileDescriptor_service_class_66454733304d50ab)
}

var fileDescriptor_service_class_66454733304d50ab = []byte{
	// 233 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0xd0, 0xcd, 0x4a, 0x03, 0x31,
	0x10, 0x07, 0x70, 0x76, 0xfd, 0xc0, 0x4e, 0x8b, 0xc8, 0x5c, 0x5c, 0x45, 0x4a, 0xd9, 0x53, 0x4f,
	0x59, 0x50, 0x8f, 0x9e, 0xac, 0xbe, 0xc0, 0xea, 0xc9, 0x8b, 0xa4, 0x9b, 0x41, 0x06, 0xb7, 0x99,
	0x90, 0x84, 0x85, 0x5e, 0x7d, 0x72, 0x69, 0x82, 0xed, 0x62, 0x6f, 0xf9, 0xf8, 0xfd, 0x67, 0x86,
	0x81, 0xf9, 0xda, 0xcb, 0x37, 0xf9, 0xc6, 0xd0, 0xd0, 0x04, 0xf2, 0x03, 0x77, 0xf4, 0xd9, 0xf5,
	0x3a, 0x04, 0xe5, 0xbc, 0x44, 0xc1, 0x2b, 0x0e, 0x91, 0x45, 0x65, 0xa5, 0x0c, 0x0d, 0xf5, 0x4f,
	0x01, 0xb3, 0xb7, 0x2c, 0x57, 0x3b, 0x88, 0x4f, 0x00, 0x86, 0x5c, 0x2f, 0xdb, 0x0d, 0xd9, 0x58,
	0x15, 0x8b, 0x62, 0x39, 0xbd, 0xbf, 0x53, 0xff, 0x73, 0xea, 0x65, 0x6f, 0xda, 0x91, 0xc7, 0x47,
	0x38, 0x23, 0x1b, 0xfd, 0xb6, 0x2a, 0x53, 0x70, 0x7e, 0x1c, 0x5c, 0xe9, 0xa8, 0x7b, 0xf9, 0x7a,
	0xdd, 0xa9, 0x36, 0xe3, 0x7a, 0x09, 0x70, 0xa8, 0x87, 0xb7, 0x70, 0xc1, 0x36, 0x44, 0x6d, 0x3b,
	0x4a, 0xfd, 0x27, 0xed, 0xfe, 0x5e, 0xbf, 0xc3, 0x6c, 0x5c, 0x00, 0x11, 0x4e, 0xad, 0xde, 0xfc,
	0xb9, 0x74, 0xc6, 0x4b, 0x28, 0xd9, 0xa4, 0x01, 0x26, 0x6d, 0xc9, 0x06, 0x17, 0x30, 0x35, 0x14,
	0x3a, 0xcf, 0x2e, 0xb2, 0xd8, 0xea, 0x24, 0x7d, 0x8c, 0x9f, 0x9e, 0x6f, 0x3e, 0xae, 0xf3, 0x9c,
	0x2c, 0x8d, 0x76, 0xdc, 0x1c, 0xb6, 0xb8, 0x3e, 0x4f, 0x8b, 0x7b, 0xf8, 0x0d, 0x00, 0x00, 0xff,
	0xff, 0xb4, 0xba, 0x2a, 0xff, 0x5a, 0x01, 0x00, 0x00,
}

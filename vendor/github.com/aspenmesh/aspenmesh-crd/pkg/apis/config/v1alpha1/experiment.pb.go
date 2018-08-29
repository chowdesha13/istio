// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pkg/apis/config/v1alpha1/experiment.proto

package v1alpha1 // import "github.com/aspenmesh/aspenmesh-crd/pkg/apis/config/v1alpha1"

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

// ExperimentSpec is the specification of Experiment resource
type ExperimentSpec struct {
	// Experiment name. Chosen by user.
	Id string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	// Token used to route traffic to experiment.
	Token string `protobuf:"bytes,2,opt,name=token" json:"token,omitempty"`
	// Specification of services in the experiment
	Spec                 *ServiceSpec `protobuf:"bytes,3,opt,name=spec" json:"spec,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *ExperimentSpec) Reset()         { *m = ExperimentSpec{} }
func (m *ExperimentSpec) String() string { return proto.CompactTextString(m) }
func (*ExperimentSpec) ProtoMessage()    {}
func (*ExperimentSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_experiment_2a26293f4c767c79, []int{0}
}
func (m *ExperimentSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExperimentSpec.Unmarshal(m, b)
}
func (m *ExperimentSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExperimentSpec.Marshal(b, m, deterministic)
}
func (dst *ExperimentSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExperimentSpec.Merge(dst, src)
}
func (m *ExperimentSpec) XXX_Size() int {
	return xxx_messageInfo_ExperimentSpec.Size(m)
}
func (m *ExperimentSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_ExperimentSpec.DiscardUnknown(m)
}

var xxx_messageInfo_ExperimentSpec proto.InternalMessageInfo

func (m *ExperimentSpec) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *ExperimentSpec) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *ExperimentSpec) GetSpec() *ServiceSpec {
	if m != nil {
		return m.Spec
	}
	return nil
}

// Represents a service as viewed by istio
type Service struct {
	// IstioService name
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// IstioService namespace
	Namespace            string   `protobuf:"bytes,2,opt,name=namespace" json:"namespace,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Service) Reset()         { *m = Service{} }
func (m *Service) String() string { return proto.CompactTextString(m) }
func (*Service) ProtoMessage()    {}
func (*Service) Descriptor() ([]byte, []int) {
	return fileDescriptor_experiment_2a26293f4c767c79, []int{1}
}
func (m *Service) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Service.Unmarshal(m, b)
}
func (m *Service) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Service.Marshal(b, m, deterministic)
}
func (dst *Service) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Service.Merge(dst, src)
}
func (m *Service) XXX_Size() int {
	return xxx_messageInfo_Service.Size(m)
}
func (m *Service) XXX_DiscardUnknown() {
	xxx_messageInfo_Service.DiscardUnknown(m)
}

var xxx_messageInfo_Service proto.InternalMessageInfo

func (m *Service) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Service) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

// ServiceSelector specifies the original and experiment version of services
type ServiceSelector struct {
	// Original service whose traffic should be affected
	Original *Service `protobuf:"bytes,1,opt,name=original" json:"original,omitempty"`
	// Experimental version of that service.
	Experiment *Service `protobuf:"bytes,2,opt,name=experiment" json:"experiment,omitempty"`
	// Percent of all production traffic the experimental service should receive.
	ProdTrafficLoad      float32  `protobuf:"fixed32,3,opt,name=prod_traffic_load,json=prodTrafficLoad" json:"prod_traffic_load,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ServiceSelector) Reset()         { *m = ServiceSelector{} }
func (m *ServiceSelector) String() string { return proto.CompactTextString(m) }
func (*ServiceSelector) ProtoMessage()    {}
func (*ServiceSelector) Descriptor() ([]byte, []int) {
	return fileDescriptor_experiment_2a26293f4c767c79, []int{2}
}
func (m *ServiceSelector) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServiceSelector.Unmarshal(m, b)
}
func (m *ServiceSelector) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServiceSelector.Marshal(b, m, deterministic)
}
func (dst *ServiceSelector) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServiceSelector.Merge(dst, src)
}
func (m *ServiceSelector) XXX_Size() int {
	return xxx_messageInfo_ServiceSelector.Size(m)
}
func (m *ServiceSelector) XXX_DiscardUnknown() {
	xxx_messageInfo_ServiceSelector.DiscardUnknown(m)
}

var xxx_messageInfo_ServiceSelector proto.InternalMessageInfo

func (m *ServiceSelector) GetOriginal() *Service {
	if m != nil {
		return m.Original
	}
	return nil
}

func (m *ServiceSelector) GetExperiment() *Service {
	if m != nil {
		return m.Experiment
	}
	return nil
}

func (m *ServiceSelector) GetProdTrafficLoad() float32 {
	if m != nil {
		return m.ProdTrafficLoad
	}
	return 0
}

// ServiceSpec defines the services in the experiment
type ServiceSpec struct {
	Services             []*ServiceSelector `protobuf:"bytes,1,rep,name=services" json:"services,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *ServiceSpec) Reset()         { *m = ServiceSpec{} }
func (m *ServiceSpec) String() string { return proto.CompactTextString(m) }
func (*ServiceSpec) ProtoMessage()    {}
func (*ServiceSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_experiment_2a26293f4c767c79, []int{3}
}
func (m *ServiceSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServiceSpec.Unmarshal(m, b)
}
func (m *ServiceSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServiceSpec.Marshal(b, m, deterministic)
}
func (dst *ServiceSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServiceSpec.Merge(dst, src)
}
func (m *ServiceSpec) XXX_Size() int {
	return xxx_messageInfo_ServiceSpec.Size(m)
}
func (m *ServiceSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_ServiceSpec.DiscardUnknown(m)
}

var xxx_messageInfo_ServiceSpec proto.InternalMessageInfo

func (m *ServiceSpec) GetServices() []*ServiceSelector {
	if m != nil {
		return m.Services
	}
	return nil
}

func init() {
	proto.RegisterType((*ExperimentSpec)(nil), "aspenmesh.config.v1alpha1.ExperimentSpec")
	proto.RegisterType((*Service)(nil), "aspenmesh.config.v1alpha1.Service")
	proto.RegisterType((*ServiceSelector)(nil), "aspenmesh.config.v1alpha1.ServiceSelector")
	proto.RegisterType((*ServiceSpec)(nil), "aspenmesh.config.v1alpha1.ServiceSpec")
}

func init() {
	proto.RegisterFile("pkg/apis/config/v1alpha1/experiment.proto", fileDescriptor_experiment_2a26293f4c767c79)
}

var fileDescriptor_experiment_2a26293f4c767c79 = []byte{
	// 322 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x31, 0x6f, 0xf2, 0x30,
	0x10, 0x55, 0x02, 0xdf, 0x57, 0xb8, 0x48, 0xa0, 0x5a, 0x1d, 0x52, 0xa9, 0x03, 0xca, 0x50, 0x51,
	0xa4, 0x26, 0x82, 0x6e, 0x45, 0xed, 0x80, 0xd4, 0x4e, 0x9d, 0x42, 0xbb, 0x74, 0x41, 0xc6, 0x39,
	0x82, 0x45, 0x62, 0x5b, 0xb6, 0x8b, 0xfa, 0xf7, 0xfa, 0xcf, 0x2a, 0x9c, 0x10, 0x58, 0x50, 0x99,
	0x7c, 0xf7, 0x7c, 0xef, 0x3d, 0xfb, 0xe9, 0xe0, 0x4e, 0x6d, 0xf2, 0x84, 0x2a, 0x6e, 0x12, 0x26,
	0xc5, 0x8a, 0xe7, 0xc9, 0x76, 0x4c, 0x0b, 0xb5, 0xa6, 0xe3, 0x04, 0xbf, 0x15, 0x6a, 0x5e, 0xa2,
	0xb0, 0xb1, 0xd2, 0xd2, 0x4a, 0x72, 0x4d, 0x8d, 0x42, 0x51, 0xa2, 0x59, 0xc7, 0xd5, 0x6c, 0xbc,
	0x9f, 0x8d, 0x34, 0xf4, 0x5e, 0x9a, 0xf1, 0xb9, 0x42, 0x46, 0x7a, 0xe0, 0xf3, 0x2c, 0xf4, 0x06,
	0xde, 0xb0, 0x9b, 0xfa, 0x3c, 0x23, 0x57, 0xf0, 0xcf, 0xca, 0x0d, 0x8a, 0xd0, 0x77, 0x50, 0xd5,
	0x90, 0x47, 0x68, 0x1b, 0x85, 0x2c, 0x6c, 0x0d, 0xbc, 0x61, 0x30, 0xb9, 0x8d, 0x4f, 0x3a, 0xc4,
	0x73, 0xd4, 0x5b, 0xce, 0x70, 0xa7, 0x9d, 0x3a, 0x4e, 0x34, 0x85, 0x8b, 0x1a, 0x24, 0x04, 0xda,
	0x82, 0x96, 0x58, 0xdb, 0xb9, 0x9a, 0xdc, 0x40, 0x77, 0x77, 0x1a, 0x45, 0x19, 0xd6, 0xa6, 0x07,
	0x20, 0xfa, 0xf1, 0xa0, 0xbf, 0x97, 0xc4, 0x02, 0x99, 0x95, 0x9a, 0x3c, 0x43, 0x47, 0x6a, 0x9e,
	0x73, 0x41, 0x0b, 0xa7, 0x14, 0x4c, 0xa2, 0xbf, 0x1f, 0x94, 0x36, 0x1c, 0x32, 0x03, 0x38, 0x64,
	0xe6, 0x2c, 0xcf, 0x53, 0x38, 0x62, 0x91, 0x11, 0x5c, 0x2a, 0x2d, 0xb3, 0x85, 0xd5, 0x74, 0xb5,
	0xe2, 0x6c, 0x51, 0x48, 0x9a, 0xb9, 0x74, 0xfc, 0xb4, 0xbf, 0xbb, 0x78, 0xaf, 0xf0, 0x37, 0x49,
	0xb3, 0xe8, 0x03, 0x82, 0xa3, 0x54, 0xc8, 0x2b, 0x74, 0x4c, 0xd5, 0x9a, 0xd0, 0x1b, 0xb4, 0x86,
	0xc1, 0x64, 0x74, 0x46, 0x9e, 0xf5, 0xe7, 0xd3, 0x86, 0x3b, 0x7b, 0xfa, 0x9c, 0xe6, 0xdc, 0xae,
	0xbf, 0x96, 0x31, 0x93, 0x65, 0xd2, 0x28, 0x1c, 0xaa, 0x7b, 0xa6, 0xb3, 0xe4, 0xd4, 0xda, 0x2c,
	0xff, 0xbb, 0x65, 0x79, 0xf8, 0x0d, 0x00, 0x00, 0xff, 0xff, 0x84, 0xc4, 0xd1, 0x82, 0x59, 0x02,
	0x00, 0x00,
}

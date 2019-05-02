// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/services/customer_client_service.proto

package services // import "google.golang.org/genproto/googleapis/ads/googleads/v1/services"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import resources "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"
import _ "google.golang.org/genproto/googleapis/api/annotations"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Request message for [CustomerClientService.GetCustomerClient][google.ads.googleads.v1.services.CustomerClientService.GetCustomerClient].
type GetCustomerClientRequest struct {
	// The resource name of the client to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetCustomerClientRequest) Reset()         { *m = GetCustomerClientRequest{} }
func (m *GetCustomerClientRequest) String() string { return proto.CompactTextString(m) }
func (*GetCustomerClientRequest) ProtoMessage()    {}
func (*GetCustomerClientRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_customer_client_service_19dc04d99b6c1854, []int{0}
}
func (m *GetCustomerClientRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetCustomerClientRequest.Unmarshal(m, b)
}
func (m *GetCustomerClientRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetCustomerClientRequest.Marshal(b, m, deterministic)
}
func (dst *GetCustomerClientRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetCustomerClientRequest.Merge(dst, src)
}
func (m *GetCustomerClientRequest) XXX_Size() int {
	return xxx_messageInfo_GetCustomerClientRequest.Size(m)
}
func (m *GetCustomerClientRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetCustomerClientRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetCustomerClientRequest proto.InternalMessageInfo

func (m *GetCustomerClientRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetCustomerClientRequest)(nil), "google.ads.googleads.v1.services.GetCustomerClientRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// CustomerClientServiceClient is the client API for CustomerClientService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CustomerClientServiceClient interface {
	// Returns the requested client in full detail.
	GetCustomerClient(ctx context.Context, in *GetCustomerClientRequest, opts ...grpc.CallOption) (*resources.CustomerClient, error)
}

type customerClientServiceClient struct {
	cc *grpc.ClientConn
}

func NewCustomerClientServiceClient(cc *grpc.ClientConn) CustomerClientServiceClient {
	return &customerClientServiceClient{cc}
}

func (c *customerClientServiceClient) GetCustomerClient(ctx context.Context, in *GetCustomerClientRequest, opts ...grpc.CallOption) (*resources.CustomerClient, error) {
	out := new(resources.CustomerClient)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.CustomerClientService/GetCustomerClient", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CustomerClientServiceServer is the server API for CustomerClientService service.
type CustomerClientServiceServer interface {
	// Returns the requested client in full detail.
	GetCustomerClient(context.Context, *GetCustomerClientRequest) (*resources.CustomerClient, error)
}

func RegisterCustomerClientServiceServer(s *grpc.Server, srv CustomerClientServiceServer) {
	s.RegisterService(&_CustomerClientService_serviceDesc, srv)
}

func _CustomerClientService_GetCustomerClient_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCustomerClientRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CustomerClientServiceServer).GetCustomerClient(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.CustomerClientService/GetCustomerClient",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CustomerClientServiceServer).GetCustomerClient(ctx, req.(*GetCustomerClientRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _CustomerClientService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v1.services.CustomerClientService",
	HandlerType: (*CustomerClientServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCustomerClient",
			Handler:    _CustomerClientService_GetCustomerClient_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v1/services/customer_client_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/services/customer_client_service.proto", fileDescriptor_customer_client_service_19dc04d99b6c1854)
}

var fileDescriptor_customer_client_service_19dc04d99b6c1854 = []byte{
	// 360 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xbf, 0x4a, 0xc3, 0x40,
	0x1c, 0xc7, 0x49, 0x04, 0xc1, 0xa0, 0x83, 0x01, 0xa1, 0x04, 0x87, 0x52, 0x3b, 0x48, 0x87, 0x3b,
	0xce, 0x0e, 0xe2, 0x89, 0x4a, 0xda, 0xa1, 0x4e, 0x52, 0x2a, 0x74, 0x90, 0x40, 0x39, 0x93, 0x23,
	0x04, 0x9a, 0xbb, 0x7a, 0xbf, 0x6b, 0x17, 0x71, 0xd0, 0x57, 0xf0, 0x0d, 0x1c, 0x7d, 0x07, 0x5f,
	0xc0, 0xd5, 0xc1, 0x17, 0x70, 0xf2, 0x29, 0x24, 0xbd, 0x5c, 0xa0, 0xd8, 0xd0, 0xed, 0xcb, 0xfd,
	0xbe, 0x9f, 0xdf, 0x9f, 0x6f, 0xe2, 0x5d, 0xa6, 0x52, 0xa6, 0x53, 0x8e, 0x59, 0x02, 0xd8, 0xc8,
	0x42, 0x2d, 0x08, 0x06, 0xae, 0x16, 0x59, 0xcc, 0x01, 0xc7, 0x73, 0xd0, 0x32, 0xe7, 0x6a, 0x12,
	0x4f, 0x33, 0x2e, 0xf4, 0xa4, 0x2c, 0xa0, 0x99, 0x92, 0x5a, 0xfa, 0x4d, 0x03, 0x21, 0x96, 0x00,
	0xaa, 0x78, 0xb4, 0x20, 0xc8, 0xf2, 0xc1, 0x69, 0xdd, 0x04, 0xc5, 0x41, 0xce, 0xd5, 0x9a, 0x11,
	0xa6, 0x75, 0x70, 0x68, 0xc1, 0x59, 0x86, 0x99, 0x10, 0x52, 0x33, 0x9d, 0x49, 0x01, 0xa6, 0xda,
	0xba, 0xf2, 0x1a, 0x03, 0xae, 0xfb, 0x25, 0xd9, 0x5f, 0x82, 0x23, 0xfe, 0x30, 0xe7, 0xa0, 0xfd,
	0x23, 0x6f, 0xcf, 0x36, 0x9f, 0x08, 0x96, 0xf3, 0x86, 0xd3, 0x74, 0x8e, 0x77, 0x46, 0xbb, 0xf6,
	0xf1, 0x86, 0xe5, 0xfc, 0xe4, 0xdb, 0xf1, 0x0e, 0x56, 0xf1, 0x5b, 0xb3, 0xb2, 0xff, 0xe1, 0x78,
	0xfb, 0xff, 0x7a, 0xfb, 0x14, 0x6d, 0x3a, 0x15, 0xd5, 0x2d, 0x14, 0x90, 0x5a, 0xb6, 0x0a, 0x01,
	0xad, 0x92, 0xad, 0xb3, 0x97, 0xaf, 0x9f, 0x57, 0xb7, 0xeb, 0x93, 0x22, 0xaa, 0xc7, 0x95, 0x73,
	0x2e, 0x6c, 0x5e, 0x80, 0x3b, 0x55, 0x76, 0x06, 0x03, 0xdc, 0x79, 0xea, 0x3d, 0xbb, 0x5e, 0x3b,
	0x96, 0xf9, 0xc6, 0x7d, 0x7b, 0xc1, 0xda, 0xfb, 0x87, 0x45, 0xbe, 0x43, 0xe7, 0xee, 0xba, 0xe4,
	0x53, 0x39, 0x65, 0x22, 0x45, 0x52, 0xa5, 0x38, 0xe5, 0x62, 0x99, 0xbe, 0xfd, 0x90, 0xb3, 0x0c,
	0xea, 0xff, 0x9c, 0x73, 0x2b, 0xde, 0xdc, 0xad, 0x41, 0x18, 0xbe, 0xbb, 0xcd, 0x81, 0x69, 0x18,
	0x26, 0x80, 0x8c, 0x2c, 0xd4, 0x98, 0xa0, 0x72, 0x30, 0x7c, 0x5a, 0x4b, 0x14, 0x26, 0x10, 0x55,
	0x96, 0x68, 0x4c, 0x22, 0x6b, 0xf9, 0x75, 0xdb, 0xe6, 0x9d, 0xd2, 0x30, 0x01, 0x4a, 0x2b, 0x13,
	0xa5, 0x63, 0x42, 0xa9, 0xb5, 0xdd, 0x6f, 0x2f, 0xf7, 0xec, 0xfe, 0x05, 0x00, 0x00, 0xff, 0xff,
	0x14, 0x0f, 0x26, 0x19, 0xe0, 0x02, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/services/location_view_service.proto

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

// Request message for [LocationViewService.GetLocationView][google.ads.googleads.v1.services.LocationViewService.GetLocationView].
type GetLocationViewRequest struct {
	// The resource name of the location view to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetLocationViewRequest) Reset()         { *m = GetLocationViewRequest{} }
func (m *GetLocationViewRequest) String() string { return proto.CompactTextString(m) }
func (*GetLocationViewRequest) ProtoMessage()    {}
func (*GetLocationViewRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_location_view_service_1678e91aea592293, []int{0}
}
func (m *GetLocationViewRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetLocationViewRequest.Unmarshal(m, b)
}
func (m *GetLocationViewRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetLocationViewRequest.Marshal(b, m, deterministic)
}
func (dst *GetLocationViewRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetLocationViewRequest.Merge(dst, src)
}
func (m *GetLocationViewRequest) XXX_Size() int {
	return xxx_messageInfo_GetLocationViewRequest.Size(m)
}
func (m *GetLocationViewRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetLocationViewRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetLocationViewRequest proto.InternalMessageInfo

func (m *GetLocationViewRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetLocationViewRequest)(nil), "google.ads.googleads.v1.services.GetLocationViewRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// LocationViewServiceClient is the client API for LocationViewService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type LocationViewServiceClient interface {
	// Returns the requested location view in full detail.
	GetLocationView(ctx context.Context, in *GetLocationViewRequest, opts ...grpc.CallOption) (*resources.LocationView, error)
}

type locationViewServiceClient struct {
	cc *grpc.ClientConn
}

func NewLocationViewServiceClient(cc *grpc.ClientConn) LocationViewServiceClient {
	return &locationViewServiceClient{cc}
}

func (c *locationViewServiceClient) GetLocationView(ctx context.Context, in *GetLocationViewRequest, opts ...grpc.CallOption) (*resources.LocationView, error) {
	out := new(resources.LocationView)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.LocationViewService/GetLocationView", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LocationViewServiceServer is the server API for LocationViewService service.
type LocationViewServiceServer interface {
	// Returns the requested location view in full detail.
	GetLocationView(context.Context, *GetLocationViewRequest) (*resources.LocationView, error)
}

func RegisterLocationViewServiceServer(s *grpc.Server, srv LocationViewServiceServer) {
	s.RegisterService(&_LocationViewService_serviceDesc, srv)
}

func _LocationViewService_GetLocationView_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetLocationViewRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LocationViewServiceServer).GetLocationView(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.LocationViewService/GetLocationView",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LocationViewServiceServer).GetLocationView(ctx, req.(*GetLocationViewRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _LocationViewService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v1.services.LocationViewService",
	HandlerType: (*LocationViewServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetLocationView",
			Handler:    _LocationViewService_GetLocationView_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v1/services/location_view_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/services/location_view_service.proto", fileDescriptor_location_view_service_1678e91aea592293)
}

var fileDescriptor_location_view_service_1678e91aea592293 = []byte{
	// 362 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0x3f, 0x4b, 0xc3, 0x40,
	0x18, 0xc6, 0x49, 0x04, 0xc1, 0xa0, 0x08, 0x11, 0xa4, 0x14, 0x87, 0x52, 0x3b, 0x48, 0x87, 0x3b,
	0xa2, 0x88, 0x72, 0xda, 0x21, 0x5d, 0xea, 0x20, 0x52, 0x2a, 0x64, 0x90, 0x40, 0x39, 0x93, 0x97,
	0x10, 0x68, 0x72, 0x35, 0xef, 0x35, 0x1d, 0xc4, 0xc5, 0xaf, 0xe0, 0x37, 0x70, 0x74, 0xf7, 0x4b,
	0x08, 0x4e, 0x7e, 0x05, 0x27, 0xbf, 0x84, 0x92, 0x5e, 0x2e, 0x54, 0x6d, 0xe9, 0xf6, 0xf0, 0xe6,
	0xf9, 0x3d, 0xef, 0x9f, 0x9c, 0x75, 0x1e, 0x09, 0x11, 0x8d, 0x80, 0xf2, 0x10, 0xa9, 0x92, 0x85,
	0xca, 0x1d, 0x8a, 0x90, 0xe5, 0x71, 0x00, 0x48, 0x47, 0x22, 0xe0, 0x32, 0x16, 0xe9, 0x30, 0x8f,
	0x61, 0x3a, 0x2c, 0xcb, 0x64, 0x9c, 0x09, 0x29, 0xec, 0x86, 0x42, 0x08, 0x0f, 0x91, 0x54, 0x34,
	0xc9, 0x1d, 0xa2, 0xe9, 0xfa, 0xf1, 0xb2, 0xfc, 0x0c, 0x50, 0x4c, 0xb2, 0x7f, 0x0d, 0x54, 0x70,
	0x7d, 0x4f, 0x63, 0xe3, 0x98, 0xf2, 0x34, 0x15, 0x72, 0xe6, 0x40, 0xf5, 0xb5, 0xd9, 0xb1, 0x76,
	0x7b, 0x20, 0x2f, 0x4b, 0xce, 0x8b, 0x61, 0x3a, 0x80, 0xbb, 0x09, 0xa0, 0xb4, 0xf7, 0xad, 0x2d,
	0x1d, 0x3c, 0x4c, 0x79, 0x02, 0x35, 0xa3, 0x61, 0x1c, 0x6c, 0x0c, 0x36, 0x75, 0xf1, 0x8a, 0x27,
	0x70, 0xf8, 0x6e, 0x58, 0x3b, 0xf3, 0xf0, 0xb5, 0x1a, 0xd6, 0x7e, 0x35, 0xac, 0xed, 0x3f, 0xb9,
	0xf6, 0x29, 0x59, 0xb5, 0x22, 0x59, 0x3c, 0x4a, 0x9d, 0x2e, 0x25, 0xab, 0xd5, 0xc9, 0x3c, 0xd7,
	0x3c, 0x79, 0xfc, 0xf8, 0x7c, 0x32, 0x1d, 0x9b, 0x16, 0xe7, 0xb9, 0xff, 0xb5, 0x46, 0x27, 0x98,
	0xa0, 0x14, 0x09, 0x64, 0x48, 0xdb, 0xd5, 0xbd, 0x0a, 0x08, 0x69, 0xfb, 0xa1, 0xfb, 0x6d, 0x58,
	0xad, 0x40, 0x24, 0x2b, 0x27, 0xed, 0xd6, 0x16, 0x6c, 0xdd, 0x2f, 0x2e, 0xda, 0x37, 0x6e, 0x2e,
	0x4a, 0x3a, 0x12, 0x23, 0x9e, 0x46, 0x44, 0x64, 0x11, 0x8d, 0x20, 0x9d, 0xdd, 0x5b, 0xff, 0xb8,
	0x71, 0x8c, 0xcb, 0xdf, 0xc9, 0x99, 0x16, 0xcf, 0xe6, 0x5a, 0xcf, 0x75, 0x5f, 0xcc, 0x46, 0x4f,
	0x05, 0xba, 0x21, 0x12, 0x25, 0x0b, 0xe5, 0x39, 0xa4, 0x6c, 0x8c, 0x6f, 0xda, 0xe2, 0xbb, 0x21,
	0xfa, 0x95, 0xc5, 0xf7, 0x1c, 0x5f, 0x5b, 0xbe, 0xcc, 0x96, 0xaa, 0x33, 0xe6, 0x86, 0xc8, 0x58,
	0x65, 0x62, 0xcc, 0x73, 0x18, 0xd3, 0xb6, 0xdb, 0xf5, 0xd9, 0x9c, 0x47, 0x3f, 0x01, 0x00, 0x00,
	0xff, 0xff, 0x91, 0x8a, 0x03, 0x21, 0xce, 0x02, 0x00, 0x00,
}

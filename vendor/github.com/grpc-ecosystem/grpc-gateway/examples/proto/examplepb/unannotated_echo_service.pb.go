// Code generated by protoc-gen-go. DO NOT EDIT.
// source: examples/proto/examplepb/unannotated_echo_service.proto

package examplepb

/*
Unannotated Echo Service
Similar to echo_service.proto but without annotations. See
unannotated_echo_service.yaml for the equivalent of the annotations in
gRPC API configuration format.

Echo Service API consists of a single service which returns
a message.
*/

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import duration "github.com/golang/protobuf/ptypes/duration"

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

// UnannotatedSimpleMessage represents a simple message sent to the unannotated Echo service.
type UnannotatedSimpleMessage struct {
	// Id represents the message identifier.
	Id                   string             `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Num                  int64              `protobuf:"varint,2,opt,name=num,proto3" json:"num,omitempty"`
	Duration             *duration.Duration `protobuf:"bytes,3,opt,name=duration,proto3" json:"duration,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *UnannotatedSimpleMessage) Reset()         { *m = UnannotatedSimpleMessage{} }
func (m *UnannotatedSimpleMessage) String() string { return proto.CompactTextString(m) }
func (*UnannotatedSimpleMessage) ProtoMessage()    {}
func (*UnannotatedSimpleMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_unannotated_echo_service_ca2b904682e29806, []int{0}
}
func (m *UnannotatedSimpleMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UnannotatedSimpleMessage.Unmarshal(m, b)
}
func (m *UnannotatedSimpleMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UnannotatedSimpleMessage.Marshal(b, m, deterministic)
}
func (dst *UnannotatedSimpleMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UnannotatedSimpleMessage.Merge(dst, src)
}
func (m *UnannotatedSimpleMessage) XXX_Size() int {
	return xxx_messageInfo_UnannotatedSimpleMessage.Size(m)
}
func (m *UnannotatedSimpleMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_UnannotatedSimpleMessage.DiscardUnknown(m)
}

var xxx_messageInfo_UnannotatedSimpleMessage proto.InternalMessageInfo

func (m *UnannotatedSimpleMessage) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *UnannotatedSimpleMessage) GetNum() int64 {
	if m != nil {
		return m.Num
	}
	return 0
}

func (m *UnannotatedSimpleMessage) GetDuration() *duration.Duration {
	if m != nil {
		return m.Duration
	}
	return nil
}

func init() {
	proto.RegisterType((*UnannotatedSimpleMessage)(nil), "grpc.gateway.examples.examplepb.UnannotatedSimpleMessage")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// UnannotatedEchoServiceClient is the client API for UnannotatedEchoService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type UnannotatedEchoServiceClient interface {
	// Echo method receives a simple message and returns it.
	//
	// The message posted as the id parameter will also be
	// returned.
	Echo(ctx context.Context, in *UnannotatedSimpleMessage, opts ...grpc.CallOption) (*UnannotatedSimpleMessage, error)
	// EchoBody method receives a simple message and returns it.
	EchoBody(ctx context.Context, in *UnannotatedSimpleMessage, opts ...grpc.CallOption) (*UnannotatedSimpleMessage, error)
	// EchoDelete method receives a simple message and returns it.
	EchoDelete(ctx context.Context, in *UnannotatedSimpleMessage, opts ...grpc.CallOption) (*UnannotatedSimpleMessage, error)
}

type unannotatedEchoServiceClient struct {
	cc *grpc.ClientConn
}

func NewUnannotatedEchoServiceClient(cc *grpc.ClientConn) UnannotatedEchoServiceClient {
	return &unannotatedEchoServiceClient{cc}
}

func (c *unannotatedEchoServiceClient) Echo(ctx context.Context, in *UnannotatedSimpleMessage, opts ...grpc.CallOption) (*UnannotatedSimpleMessage, error) {
	out := new(UnannotatedSimpleMessage)
	err := c.cc.Invoke(ctx, "/grpc.gateway.examples.examplepb.UnannotatedEchoService/Echo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unannotatedEchoServiceClient) EchoBody(ctx context.Context, in *UnannotatedSimpleMessage, opts ...grpc.CallOption) (*UnannotatedSimpleMessage, error) {
	out := new(UnannotatedSimpleMessage)
	err := c.cc.Invoke(ctx, "/grpc.gateway.examples.examplepb.UnannotatedEchoService/EchoBody", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unannotatedEchoServiceClient) EchoDelete(ctx context.Context, in *UnannotatedSimpleMessage, opts ...grpc.CallOption) (*UnannotatedSimpleMessage, error) {
	out := new(UnannotatedSimpleMessage)
	err := c.cc.Invoke(ctx, "/grpc.gateway.examples.examplepb.UnannotatedEchoService/EchoDelete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnannotatedEchoServiceServer is the server API for UnannotatedEchoService service.
type UnannotatedEchoServiceServer interface {
	// Echo method receives a simple message and returns it.
	//
	// The message posted as the id parameter will also be
	// returned.
	Echo(context.Context, *UnannotatedSimpleMessage) (*UnannotatedSimpleMessage, error)
	// EchoBody method receives a simple message and returns it.
	EchoBody(context.Context, *UnannotatedSimpleMessage) (*UnannotatedSimpleMessage, error)
	// EchoDelete method receives a simple message and returns it.
	EchoDelete(context.Context, *UnannotatedSimpleMessage) (*UnannotatedSimpleMessage, error)
}

func RegisterUnannotatedEchoServiceServer(s *grpc.Server, srv UnannotatedEchoServiceServer) {
	s.RegisterService(&_UnannotatedEchoService_serviceDesc, srv)
}

func _UnannotatedEchoService_Echo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnannotatedSimpleMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnannotatedEchoServiceServer).Echo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.gateway.examples.examplepb.UnannotatedEchoService/Echo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnannotatedEchoServiceServer).Echo(ctx, req.(*UnannotatedSimpleMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnannotatedEchoService_EchoBody_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnannotatedSimpleMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnannotatedEchoServiceServer).EchoBody(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.gateway.examples.examplepb.UnannotatedEchoService/EchoBody",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnannotatedEchoServiceServer).EchoBody(ctx, req.(*UnannotatedSimpleMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnannotatedEchoService_EchoDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnannotatedSimpleMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnannotatedEchoServiceServer).EchoDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.gateway.examples.examplepb.UnannotatedEchoService/EchoDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnannotatedEchoServiceServer).EchoDelete(ctx, req.(*UnannotatedSimpleMessage))
	}
	return interceptor(ctx, in, info, handler)
}

var _UnannotatedEchoService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.gateway.examples.examplepb.UnannotatedEchoService",
	HandlerType: (*UnannotatedEchoServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Echo",
			Handler:    _UnannotatedEchoService_Echo_Handler,
		},
		{
			MethodName: "EchoBody",
			Handler:    _UnannotatedEchoService_EchoBody_Handler,
		},
		{
			MethodName: "EchoDelete",
			Handler:    _UnannotatedEchoService_EchoDelete_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "examples/proto/examplepb/unannotated_echo_service.proto",
}

func init() {
	proto.RegisterFile("examples/proto/examplepb/unannotated_echo_service.proto", fileDescriptor_unannotated_echo_service_ca2b904682e29806)
}

var fileDescriptor_unannotated_echo_service_ca2b904682e29806 = []byte{
	// 268 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x32, 0x4f, 0xad, 0x48, 0xcc,
	0x2d, 0xc8, 0x49, 0x2d, 0xd6, 0x2f, 0x28, 0xca, 0x2f, 0xc9, 0xd7, 0x87, 0x72, 0x0b, 0x92, 0xf4,
	0x4b, 0xf3, 0x12, 0xf3, 0xf2, 0xf2, 0x4b, 0x12, 0x4b, 0x52, 0x53, 0xe2, 0x53, 0x93, 0x33, 0xf2,
	0xe3, 0x8b, 0x53, 0x8b, 0xca, 0x32, 0x93, 0x53, 0xf5, 0xc0, 0x0a, 0x85, 0xe4, 0xd3, 0x8b, 0x0a,
	0x92, 0xf5, 0xd2, 0x13, 0x4b, 0x52, 0xcb, 0x13, 0x2b, 0xf5, 0x60, 0xa6, 0xe8, 0xc1, 0xf5, 0x4b,
	0xc9, 0xa5, 0xe7, 0xe7, 0xa7, 0xe7, 0xa4, 0x42, 0xcc, 0x4d, 0x2a, 0x4d, 0xd3, 0x4f, 0x29, 0x2d,
	0x4a, 0x2c, 0xc9, 0xcc, 0xcf, 0x83, 0x18, 0xa0, 0x54, 0xcc, 0x25, 0x11, 0x8a, 0xb0, 0x22, 0x38,
	0x13, 0xa4, 0xcd, 0x37, 0xb5, 0xb8, 0x38, 0x31, 0x3d, 0x55, 0x88, 0x8f, 0x8b, 0x29, 0x33, 0x45,
	0x82, 0x51, 0x81, 0x51, 0x83, 0x33, 0x88, 0x29, 0x33, 0x45, 0x48, 0x80, 0x8b, 0x39, 0xaf, 0x34,
	0x57, 0x82, 0x49, 0x81, 0x51, 0x83, 0x39, 0x08, 0xc4, 0x14, 0x32, 0xe5, 0xe2, 0x80, 0x99, 0x27,
	0xc1, 0xac, 0xc0, 0xa8, 0xc1, 0x6d, 0x24, 0xa9, 0x07, 0xb1, 0x50, 0x0f, 0x66, 0xa1, 0x9e, 0x0b,
	0x54, 0x41, 0x10, 0x5c, 0xa9, 0xd1, 0x3c, 0x66, 0x2e, 0x31, 0x24, 0x5b, 0x5d, 0x93, 0x33, 0xf2,
	0x83, 0x21, 0xde, 0x12, 0xaa, 0xe1, 0x62, 0x01, 0x71, 0x85, 0x2c, 0xf5, 0x08, 0xf8, 0x4c, 0x0f,
	0x97, 0xb3, 0xa5, 0xc8, 0xd7, 0x2a, 0xd4, 0xc0, 0xc8, 0xc5, 0x01, 0xb2, 0xde, 0x29, 0x3f, 0xa5,
	0x72, 0x80, 0x9c, 0xd0, 0xc4, 0xc8, 0xc5, 0x05, 0x72, 0x82, 0x4b, 0x6a, 0x4e, 0x6a, 0x49, 0xea,
	0xc0, 0x38, 0xc2, 0x89, 0x3b, 0x8a, 0x13, 0xae, 0x2a, 0x89, 0x0d, 0x1c, 0x95, 0xc6, 0x80, 0x00,
	0x00, 0x00, 0xff, 0xff, 0x9a, 0xa7, 0x7c, 0x41, 0xa5, 0x02, 0x00, 0x00,
}

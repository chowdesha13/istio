// Code generated by protoc-gen-go. DO NOT EDIT.
// source: examples/proto/examplepb/flow_combination.proto

package examplepb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
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

type EmptyProto struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EmptyProto) Reset()         { *m = EmptyProto{} }
func (m *EmptyProto) String() string { return proto.CompactTextString(m) }
func (*EmptyProto) ProtoMessage()    {}
func (*EmptyProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_flow_combination_63ace3110e4bd00b, []int{0}
}
func (m *EmptyProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EmptyProto.Unmarshal(m, b)
}
func (m *EmptyProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EmptyProto.Marshal(b, m, deterministic)
}
func (dst *EmptyProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EmptyProto.Merge(dst, src)
}
func (m *EmptyProto) XXX_Size() int {
	return xxx_messageInfo_EmptyProto.Size(m)
}
func (m *EmptyProto) XXX_DiscardUnknown() {
	xxx_messageInfo_EmptyProto.DiscardUnknown(m)
}

var xxx_messageInfo_EmptyProto proto.InternalMessageInfo

type NonEmptyProto struct {
	A                    string   `protobuf:"bytes,1,opt,name=a,proto3" json:"a,omitempty"`
	B                    string   `protobuf:"bytes,2,opt,name=b,proto3" json:"b,omitempty"`
	C                    string   `protobuf:"bytes,3,opt,name=c,proto3" json:"c,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NonEmptyProto) Reset()         { *m = NonEmptyProto{} }
func (m *NonEmptyProto) String() string { return proto.CompactTextString(m) }
func (*NonEmptyProto) ProtoMessage()    {}
func (*NonEmptyProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_flow_combination_63ace3110e4bd00b, []int{1}
}
func (m *NonEmptyProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NonEmptyProto.Unmarshal(m, b)
}
func (m *NonEmptyProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NonEmptyProto.Marshal(b, m, deterministic)
}
func (dst *NonEmptyProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NonEmptyProto.Merge(dst, src)
}
func (m *NonEmptyProto) XXX_Size() int {
	return xxx_messageInfo_NonEmptyProto.Size(m)
}
func (m *NonEmptyProto) XXX_DiscardUnknown() {
	xxx_messageInfo_NonEmptyProto.DiscardUnknown(m)
}

var xxx_messageInfo_NonEmptyProto proto.InternalMessageInfo

func (m *NonEmptyProto) GetA() string {
	if m != nil {
		return m.A
	}
	return ""
}

func (m *NonEmptyProto) GetB() string {
	if m != nil {
		return m.B
	}
	return ""
}

func (m *NonEmptyProto) GetC() string {
	if m != nil {
		return m.C
	}
	return ""
}

type UnaryProto struct {
	Str                  string   `protobuf:"bytes,1,opt,name=str,proto3" json:"str,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UnaryProto) Reset()         { *m = UnaryProto{} }
func (m *UnaryProto) String() string { return proto.CompactTextString(m) }
func (*UnaryProto) ProtoMessage()    {}
func (*UnaryProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_flow_combination_63ace3110e4bd00b, []int{2}
}
func (m *UnaryProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UnaryProto.Unmarshal(m, b)
}
func (m *UnaryProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UnaryProto.Marshal(b, m, deterministic)
}
func (dst *UnaryProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UnaryProto.Merge(dst, src)
}
func (m *UnaryProto) XXX_Size() int {
	return xxx_messageInfo_UnaryProto.Size(m)
}
func (m *UnaryProto) XXX_DiscardUnknown() {
	xxx_messageInfo_UnaryProto.DiscardUnknown(m)
}

var xxx_messageInfo_UnaryProto proto.InternalMessageInfo

func (m *UnaryProto) GetStr() string {
	if m != nil {
		return m.Str
	}
	return ""
}

type NestedProto struct {
	A                    *UnaryProto `protobuf:"bytes,1,opt,name=a,proto3" json:"a,omitempty"`
	B                    string      `protobuf:"bytes,2,opt,name=b,proto3" json:"b,omitempty"`
	C                    string      `protobuf:"bytes,3,opt,name=c,proto3" json:"c,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *NestedProto) Reset()         { *m = NestedProto{} }
func (m *NestedProto) String() string { return proto.CompactTextString(m) }
func (*NestedProto) ProtoMessage()    {}
func (*NestedProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_flow_combination_63ace3110e4bd00b, []int{3}
}
func (m *NestedProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NestedProto.Unmarshal(m, b)
}
func (m *NestedProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NestedProto.Marshal(b, m, deterministic)
}
func (dst *NestedProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NestedProto.Merge(dst, src)
}
func (m *NestedProto) XXX_Size() int {
	return xxx_messageInfo_NestedProto.Size(m)
}
func (m *NestedProto) XXX_DiscardUnknown() {
	xxx_messageInfo_NestedProto.DiscardUnknown(m)
}

var xxx_messageInfo_NestedProto proto.InternalMessageInfo

func (m *NestedProto) GetA() *UnaryProto {
	if m != nil {
		return m.A
	}
	return nil
}

func (m *NestedProto) GetB() string {
	if m != nil {
		return m.B
	}
	return ""
}

func (m *NestedProto) GetC() string {
	if m != nil {
		return m.C
	}
	return ""
}

type SingleNestedProto struct {
	A                    *UnaryProto `protobuf:"bytes,1,opt,name=a,proto3" json:"a,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *SingleNestedProto) Reset()         { *m = SingleNestedProto{} }
func (m *SingleNestedProto) String() string { return proto.CompactTextString(m) }
func (*SingleNestedProto) ProtoMessage()    {}
func (*SingleNestedProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_flow_combination_63ace3110e4bd00b, []int{4}
}
func (m *SingleNestedProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SingleNestedProto.Unmarshal(m, b)
}
func (m *SingleNestedProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SingleNestedProto.Marshal(b, m, deterministic)
}
func (dst *SingleNestedProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SingleNestedProto.Merge(dst, src)
}
func (m *SingleNestedProto) XXX_Size() int {
	return xxx_messageInfo_SingleNestedProto.Size(m)
}
func (m *SingleNestedProto) XXX_DiscardUnknown() {
	xxx_messageInfo_SingleNestedProto.DiscardUnknown(m)
}

var xxx_messageInfo_SingleNestedProto proto.InternalMessageInfo

func (m *SingleNestedProto) GetA() *UnaryProto {
	if m != nil {
		return m.A
	}
	return nil
}

func init() {
	proto.RegisterType((*EmptyProto)(nil), "grpc.gateway.examples.examplepb.EmptyProto")
	proto.RegisterType((*NonEmptyProto)(nil), "grpc.gateway.examples.examplepb.NonEmptyProto")
	proto.RegisterType((*UnaryProto)(nil), "grpc.gateway.examples.examplepb.UnaryProto")
	proto.RegisterType((*NestedProto)(nil), "grpc.gateway.examples.examplepb.NestedProto")
	proto.RegisterType((*SingleNestedProto)(nil), "grpc.gateway.examples.examplepb.SingleNestedProto")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// FlowCombinationClient is the client API for FlowCombination service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type FlowCombinationClient interface {
	RpcEmptyRpc(ctx context.Context, in *EmptyProto, opts ...grpc.CallOption) (*EmptyProto, error)
	RpcEmptyStream(ctx context.Context, in *EmptyProto, opts ...grpc.CallOption) (FlowCombination_RpcEmptyStreamClient, error)
	StreamEmptyRpc(ctx context.Context, opts ...grpc.CallOption) (FlowCombination_StreamEmptyRpcClient, error)
	StreamEmptyStream(ctx context.Context, opts ...grpc.CallOption) (FlowCombination_StreamEmptyStreamClient, error)
	RpcBodyRpc(ctx context.Context, in *NonEmptyProto, opts ...grpc.CallOption) (*EmptyProto, error)
	RpcPathSingleNestedRpc(ctx context.Context, in *SingleNestedProto, opts ...grpc.CallOption) (*EmptyProto, error)
	RpcPathNestedRpc(ctx context.Context, in *NestedProto, opts ...grpc.CallOption) (*EmptyProto, error)
	RpcBodyStream(ctx context.Context, in *NonEmptyProto, opts ...grpc.CallOption) (FlowCombination_RpcBodyStreamClient, error)
	RpcPathSingleNestedStream(ctx context.Context, in *SingleNestedProto, opts ...grpc.CallOption) (FlowCombination_RpcPathSingleNestedStreamClient, error)
	RpcPathNestedStream(ctx context.Context, in *NestedProto, opts ...grpc.CallOption) (FlowCombination_RpcPathNestedStreamClient, error)
}

type flowCombinationClient struct {
	cc *grpc.ClientConn
}

func NewFlowCombinationClient(cc *grpc.ClientConn) FlowCombinationClient {
	return &flowCombinationClient{cc}
}

func (c *flowCombinationClient) RpcEmptyRpc(ctx context.Context, in *EmptyProto, opts ...grpc.CallOption) (*EmptyProto, error) {
	out := new(EmptyProto)
	err := c.cc.Invoke(ctx, "/grpc.gateway.examples.examplepb.FlowCombination/RpcEmptyRpc", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *flowCombinationClient) RpcEmptyStream(ctx context.Context, in *EmptyProto, opts ...grpc.CallOption) (FlowCombination_RpcEmptyStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &_FlowCombination_serviceDesc.Streams[0], "/grpc.gateway.examples.examplepb.FlowCombination/RpcEmptyStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &flowCombinationRpcEmptyStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type FlowCombination_RpcEmptyStreamClient interface {
	Recv() (*EmptyProto, error)
	grpc.ClientStream
}

type flowCombinationRpcEmptyStreamClient struct {
	grpc.ClientStream
}

func (x *flowCombinationRpcEmptyStreamClient) Recv() (*EmptyProto, error) {
	m := new(EmptyProto)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *flowCombinationClient) StreamEmptyRpc(ctx context.Context, opts ...grpc.CallOption) (FlowCombination_StreamEmptyRpcClient, error) {
	stream, err := c.cc.NewStream(ctx, &_FlowCombination_serviceDesc.Streams[1], "/grpc.gateway.examples.examplepb.FlowCombination/StreamEmptyRpc", opts...)
	if err != nil {
		return nil, err
	}
	x := &flowCombinationStreamEmptyRpcClient{stream}
	return x, nil
}

type FlowCombination_StreamEmptyRpcClient interface {
	Send(*EmptyProto) error
	CloseAndRecv() (*EmptyProto, error)
	grpc.ClientStream
}

type flowCombinationStreamEmptyRpcClient struct {
	grpc.ClientStream
}

func (x *flowCombinationStreamEmptyRpcClient) Send(m *EmptyProto) error {
	return x.ClientStream.SendMsg(m)
}

func (x *flowCombinationStreamEmptyRpcClient) CloseAndRecv() (*EmptyProto, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(EmptyProto)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *flowCombinationClient) StreamEmptyStream(ctx context.Context, opts ...grpc.CallOption) (FlowCombination_StreamEmptyStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &_FlowCombination_serviceDesc.Streams[2], "/grpc.gateway.examples.examplepb.FlowCombination/StreamEmptyStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &flowCombinationStreamEmptyStreamClient{stream}
	return x, nil
}

type FlowCombination_StreamEmptyStreamClient interface {
	Send(*EmptyProto) error
	Recv() (*EmptyProto, error)
	grpc.ClientStream
}

type flowCombinationStreamEmptyStreamClient struct {
	grpc.ClientStream
}

func (x *flowCombinationStreamEmptyStreamClient) Send(m *EmptyProto) error {
	return x.ClientStream.SendMsg(m)
}

func (x *flowCombinationStreamEmptyStreamClient) Recv() (*EmptyProto, error) {
	m := new(EmptyProto)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *flowCombinationClient) RpcBodyRpc(ctx context.Context, in *NonEmptyProto, opts ...grpc.CallOption) (*EmptyProto, error) {
	out := new(EmptyProto)
	err := c.cc.Invoke(ctx, "/grpc.gateway.examples.examplepb.FlowCombination/RpcBodyRpc", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *flowCombinationClient) RpcPathSingleNestedRpc(ctx context.Context, in *SingleNestedProto, opts ...grpc.CallOption) (*EmptyProto, error) {
	out := new(EmptyProto)
	err := c.cc.Invoke(ctx, "/grpc.gateway.examples.examplepb.FlowCombination/RpcPathSingleNestedRpc", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *flowCombinationClient) RpcPathNestedRpc(ctx context.Context, in *NestedProto, opts ...grpc.CallOption) (*EmptyProto, error) {
	out := new(EmptyProto)
	err := c.cc.Invoke(ctx, "/grpc.gateway.examples.examplepb.FlowCombination/RpcPathNestedRpc", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *flowCombinationClient) RpcBodyStream(ctx context.Context, in *NonEmptyProto, opts ...grpc.CallOption) (FlowCombination_RpcBodyStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &_FlowCombination_serviceDesc.Streams[3], "/grpc.gateway.examples.examplepb.FlowCombination/RpcBodyStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &flowCombinationRpcBodyStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type FlowCombination_RpcBodyStreamClient interface {
	Recv() (*EmptyProto, error)
	grpc.ClientStream
}

type flowCombinationRpcBodyStreamClient struct {
	grpc.ClientStream
}

func (x *flowCombinationRpcBodyStreamClient) Recv() (*EmptyProto, error) {
	m := new(EmptyProto)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *flowCombinationClient) RpcPathSingleNestedStream(ctx context.Context, in *SingleNestedProto, opts ...grpc.CallOption) (FlowCombination_RpcPathSingleNestedStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &_FlowCombination_serviceDesc.Streams[4], "/grpc.gateway.examples.examplepb.FlowCombination/RpcPathSingleNestedStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &flowCombinationRpcPathSingleNestedStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type FlowCombination_RpcPathSingleNestedStreamClient interface {
	Recv() (*EmptyProto, error)
	grpc.ClientStream
}

type flowCombinationRpcPathSingleNestedStreamClient struct {
	grpc.ClientStream
}

func (x *flowCombinationRpcPathSingleNestedStreamClient) Recv() (*EmptyProto, error) {
	m := new(EmptyProto)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *flowCombinationClient) RpcPathNestedStream(ctx context.Context, in *NestedProto, opts ...grpc.CallOption) (FlowCombination_RpcPathNestedStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &_FlowCombination_serviceDesc.Streams[5], "/grpc.gateway.examples.examplepb.FlowCombination/RpcPathNestedStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &flowCombinationRpcPathNestedStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type FlowCombination_RpcPathNestedStreamClient interface {
	Recv() (*EmptyProto, error)
	grpc.ClientStream
}

type flowCombinationRpcPathNestedStreamClient struct {
	grpc.ClientStream
}

func (x *flowCombinationRpcPathNestedStreamClient) Recv() (*EmptyProto, error) {
	m := new(EmptyProto)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// FlowCombinationServer is the server API for FlowCombination service.
type FlowCombinationServer interface {
	RpcEmptyRpc(context.Context, *EmptyProto) (*EmptyProto, error)
	RpcEmptyStream(*EmptyProto, FlowCombination_RpcEmptyStreamServer) error
	StreamEmptyRpc(FlowCombination_StreamEmptyRpcServer) error
	StreamEmptyStream(FlowCombination_StreamEmptyStreamServer) error
	RpcBodyRpc(context.Context, *NonEmptyProto) (*EmptyProto, error)
	RpcPathSingleNestedRpc(context.Context, *SingleNestedProto) (*EmptyProto, error)
	RpcPathNestedRpc(context.Context, *NestedProto) (*EmptyProto, error)
	RpcBodyStream(*NonEmptyProto, FlowCombination_RpcBodyStreamServer) error
	RpcPathSingleNestedStream(*SingleNestedProto, FlowCombination_RpcPathSingleNestedStreamServer) error
	RpcPathNestedStream(*NestedProto, FlowCombination_RpcPathNestedStreamServer) error
}

func RegisterFlowCombinationServer(s *grpc.Server, srv FlowCombinationServer) {
	s.RegisterService(&_FlowCombination_serviceDesc, srv)
}

func _FlowCombination_RpcEmptyRpc_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmptyProto)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FlowCombinationServer).RpcEmptyRpc(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.gateway.examples.examplepb.FlowCombination/RpcEmptyRpc",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FlowCombinationServer).RpcEmptyRpc(ctx, req.(*EmptyProto))
	}
	return interceptor(ctx, in, info, handler)
}

func _FlowCombination_RpcEmptyStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(EmptyProto)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FlowCombinationServer).RpcEmptyStream(m, &flowCombinationRpcEmptyStreamServer{stream})
}

type FlowCombination_RpcEmptyStreamServer interface {
	Send(*EmptyProto) error
	grpc.ServerStream
}

type flowCombinationRpcEmptyStreamServer struct {
	grpc.ServerStream
}

func (x *flowCombinationRpcEmptyStreamServer) Send(m *EmptyProto) error {
	return x.ServerStream.SendMsg(m)
}

func _FlowCombination_StreamEmptyRpc_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(FlowCombinationServer).StreamEmptyRpc(&flowCombinationStreamEmptyRpcServer{stream})
}

type FlowCombination_StreamEmptyRpcServer interface {
	SendAndClose(*EmptyProto) error
	Recv() (*EmptyProto, error)
	grpc.ServerStream
}

type flowCombinationStreamEmptyRpcServer struct {
	grpc.ServerStream
}

func (x *flowCombinationStreamEmptyRpcServer) SendAndClose(m *EmptyProto) error {
	return x.ServerStream.SendMsg(m)
}

func (x *flowCombinationStreamEmptyRpcServer) Recv() (*EmptyProto, error) {
	m := new(EmptyProto)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _FlowCombination_StreamEmptyStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(FlowCombinationServer).StreamEmptyStream(&flowCombinationStreamEmptyStreamServer{stream})
}

type FlowCombination_StreamEmptyStreamServer interface {
	Send(*EmptyProto) error
	Recv() (*EmptyProto, error)
	grpc.ServerStream
}

type flowCombinationStreamEmptyStreamServer struct {
	grpc.ServerStream
}

func (x *flowCombinationStreamEmptyStreamServer) Send(m *EmptyProto) error {
	return x.ServerStream.SendMsg(m)
}

func (x *flowCombinationStreamEmptyStreamServer) Recv() (*EmptyProto, error) {
	m := new(EmptyProto)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _FlowCombination_RpcBodyRpc_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NonEmptyProto)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FlowCombinationServer).RpcBodyRpc(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.gateway.examples.examplepb.FlowCombination/RpcBodyRpc",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FlowCombinationServer).RpcBodyRpc(ctx, req.(*NonEmptyProto))
	}
	return interceptor(ctx, in, info, handler)
}

func _FlowCombination_RpcPathSingleNestedRpc_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SingleNestedProto)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FlowCombinationServer).RpcPathSingleNestedRpc(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.gateway.examples.examplepb.FlowCombination/RpcPathSingleNestedRpc",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FlowCombinationServer).RpcPathSingleNestedRpc(ctx, req.(*SingleNestedProto))
	}
	return interceptor(ctx, in, info, handler)
}

func _FlowCombination_RpcPathNestedRpc_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NestedProto)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FlowCombinationServer).RpcPathNestedRpc(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.gateway.examples.examplepb.FlowCombination/RpcPathNestedRpc",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FlowCombinationServer).RpcPathNestedRpc(ctx, req.(*NestedProto))
	}
	return interceptor(ctx, in, info, handler)
}

func _FlowCombination_RpcBodyStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(NonEmptyProto)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FlowCombinationServer).RpcBodyStream(m, &flowCombinationRpcBodyStreamServer{stream})
}

type FlowCombination_RpcBodyStreamServer interface {
	Send(*EmptyProto) error
	grpc.ServerStream
}

type flowCombinationRpcBodyStreamServer struct {
	grpc.ServerStream
}

func (x *flowCombinationRpcBodyStreamServer) Send(m *EmptyProto) error {
	return x.ServerStream.SendMsg(m)
}

func _FlowCombination_RpcPathSingleNestedStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SingleNestedProto)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FlowCombinationServer).RpcPathSingleNestedStream(m, &flowCombinationRpcPathSingleNestedStreamServer{stream})
}

type FlowCombination_RpcPathSingleNestedStreamServer interface {
	Send(*EmptyProto) error
	grpc.ServerStream
}

type flowCombinationRpcPathSingleNestedStreamServer struct {
	grpc.ServerStream
}

func (x *flowCombinationRpcPathSingleNestedStreamServer) Send(m *EmptyProto) error {
	return x.ServerStream.SendMsg(m)
}

func _FlowCombination_RpcPathNestedStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(NestedProto)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FlowCombinationServer).RpcPathNestedStream(m, &flowCombinationRpcPathNestedStreamServer{stream})
}

type FlowCombination_RpcPathNestedStreamServer interface {
	Send(*EmptyProto) error
	grpc.ServerStream
}

type flowCombinationRpcPathNestedStreamServer struct {
	grpc.ServerStream
}

func (x *flowCombinationRpcPathNestedStreamServer) Send(m *EmptyProto) error {
	return x.ServerStream.SendMsg(m)
}

var _FlowCombination_serviceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.gateway.examples.examplepb.FlowCombination",
	HandlerType: (*FlowCombinationServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RpcEmptyRpc",
			Handler:    _FlowCombination_RpcEmptyRpc_Handler,
		},
		{
			MethodName: "RpcBodyRpc",
			Handler:    _FlowCombination_RpcBodyRpc_Handler,
		},
		{
			MethodName: "RpcPathSingleNestedRpc",
			Handler:    _FlowCombination_RpcPathSingleNestedRpc_Handler,
		},
		{
			MethodName: "RpcPathNestedRpc",
			Handler:    _FlowCombination_RpcPathNestedRpc_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RpcEmptyStream",
			Handler:       _FlowCombination_RpcEmptyStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StreamEmptyRpc",
			Handler:       _FlowCombination_StreamEmptyRpc_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamEmptyStream",
			Handler:       _FlowCombination_StreamEmptyStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "RpcBodyStream",
			Handler:       _FlowCombination_RpcBodyStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "RpcPathSingleNestedStream",
			Handler:       _FlowCombination_RpcPathSingleNestedStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "RpcPathNestedStream",
			Handler:       _FlowCombination_RpcPathNestedStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "examples/proto/examplepb/flow_combination.proto",
}

func init() {
	proto.RegisterFile("examples/proto/examplepb/flow_combination.proto", fileDescriptor_flow_combination_63ace3110e4bd00b)
}

var fileDescriptor_flow_combination_63ace3110e4bd00b = []byte{
	// 655 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x96, 0xbf, 0x8f, 0x12, 0x41,
	0x14, 0xc7, 0xf3, 0xb8, 0xc4, 0xe4, 0x86, 0xfb, 0xc1, 0x2d, 0x06, 0x81, 0xc3, 0xe3, 0x6e, 0xbc,
	0x44, 0xe2, 0x8f, 0x5d, 0x82, 0xd5, 0x51, 0x9e, 0xd1, 0x92, 0x5c, 0xb8, 0xd8, 0x6c, 0x63, 0x66,
	0x87, 0x15, 0x48, 0x60, 0x67, 0x6e, 0x77, 0x0d, 0x5e, 0x08, 0x31, 0xb1, 0xb1, 0xb4, 0xf0, 0x0f,
	0xb0, 0xb4, 0xf2, 0x1f, 0xb0, 0xb3, 0xb2, 0x31, 0xb1, 0x30, 0xb1, 0xb3, 0xb3, 0xf3, 0x9f, 0x30,
	0xfb, 0xf6, 0xc7, 0xb0, 0x0a, 0x6e, 0x30, 0x62, 0xb7, 0x6f, 0xe6, 0xbd, 0x37, 0x9f, 0xf9, 0xce,
	0xf7, 0x11, 0x88, 0x61, 0x3f, 0x63, 0x63, 0x39, 0xb2, 0x3d, 0x43, 0xba, 0xc2, 0x17, 0x71, 0x28,
	0x2d, 0xe3, 0xc9, 0x48, 0x4c, 0x1e, 0x73, 0x31, 0xb6, 0x86, 0x0e, 0xf3, 0x87, 0xc2, 0xd1, 0x31,
	0x41, 0xab, 0xf7, 0x5d, 0xc9, 0xf5, 0x3e, 0xf3, 0xed, 0x09, 0xbb, 0xd4, 0xe3, 0x6a, 0x3d, 0xa9,
	0xab, 0xd6, 0xfa, 0x42, 0xf4, 0x47, 0xb6, 0xc1, 0xe4, 0xd0, 0x60, 0x8e, 0x23, 0x7c, 0xac, 0xf6,
	0xc2, 0x72, 0xba, 0x45, 0xc8, 0x83, 0xb1, 0xf4, 0x2f, 0xcf, 0x30, 0x3a, 0x21, 0xdb, 0x1d, 0xe1,
	0xa8, 0x05, 0x6d, 0x8b, 0x00, 0x2b, 0xc3, 0x21, 0x34, 0x36, 0xbb, 0xc0, 0x82, 0xc8, 0x2a, 0xe7,
	0xc2, 0xc8, 0x0a, 0x22, 0x5e, 0xde, 0x08, 0x23, 0x4e, 0x0f, 0x08, 0x79, 0xe4, 0x30, 0x37, 0xaa,
	0x2b, 0x90, 0x0d, 0xcf, 0x77, 0xa3, 0xca, 0xe0, 0x93, 0xf6, 0x48, 0xbe, 0x63, 0x7b, 0xbe, 0xdd,
	0x0b, 0x13, 0x4e, 0xe2, 0xc6, 0xf9, 0xd6, 0x6d, 0x3d, 0xe3, 0x0a, 0xba, 0x6a, 0x9c, 0x45, 0xd1,
	0x21, 0x7b, 0xe7, 0x43, 0xa7, 0x3f, 0xb2, 0xff, 0xcd, 0x59, 0xad, 0x4f, 0xbb, 0x64, 0xf7, 0xe1,
	0x48, 0x4c, 0xee, 0x2b, 0xdd, 0xb5, 0xe7, 0x24, 0xdf, 0x95, 0x1c, 0x45, 0xea, 0x4a, 0xae, 0x65,
	0xb7, 0x54, 0x7a, 0x56, 0x57, 0x49, 0xa6, 0xa5, 0x17, 0x5f, 0xbe, 0xbf, 0xce, 0x15, 0xe8, 0x8e,
	0xe1, 0x4a, 0x6e, 0xd8, 0xc1, 0x46, 0xf0, 0xa5, 0xbd, 0x04, 0xb2, 0x13, 0x13, 0x9c, 0xfb, 0xae,
	0xcd, 0xc6, 0x6b, 0x84, 0xa8, 0x20, 0x44, 0x91, 0xee, 0xcd, 0x41, 0x78, 0x78, 0x68, 0x13, 0x90,
	0x24, 0x24, 0xf8, 0x0f, 0x72, 0x28, 0x92, 0xf0, 0x7c, 0xa5, 0x48, 0x03, 0xb4, 0x57, 0x40, 0xf6,
	0xe6, 0x48, 0xd6, 0x2e, 0x4b, 0x0d, 0x61, 0x4a, 0xf4, 0x6a, 0x1a, 0x26, 0x0c, 0x1a, 0xd0, 0x04,
	0xed, 0x5d, 0x8e, 0x90, 0xae, 0xe4, 0xa7, 0xa2, 0x87, 0xba, 0xe8, 0x99, 0xdd, 0x53, 0x93, 0xb7,
	0x1a, 0xcd, 0x07, 0x40, 0x9c, 0xf7, 0x40, 0xb7, 0xf1, 0x99, 0x2c, 0xd1, 0x43, 0x61, 0xda, 0x70,
	0xcb, 0xdc, 0xa7, 0x15, 0x5c, 0x93, 0xcc, 0x1f, 0x18, 0x53, 0x36, 0x33, 0xa6, 0xd6, 0xcc, 0x98,
	0xf2, 0x59, 0xb0, 0x68, 0xc6, 0xe6, 0xba, 0x78, 0x6a, 0xbb, 0x58, 0x61, 0xd6, 0x69, 0x55, 0xb5,
	0x48, 0xd5, 0x60, 0x3f, 0x6e, 0x96, 0x69, 0x51, 0x25, 0x24, 0x75, 0xc1, 0xce, 0x11, 0xad, 0x2d,
	0x28, 0x4d, 0xa5, 0x54, 0xe8, 0xb5, 0x34, 0x4c, 0xb2, 0xab, 0xbd, 0x01, 0x52, 0xea, 0x4a, 0x7e,
	0xc6, 0xfc, 0xc1, 0xfc, 0x08, 0x07, 0xda, 0xb5, 0x32, 0xb5, 0xf8, 0x6d, 0xe8, 0x57, 0xd3, 0xef,
	0x18, 0xe5, 0x3b, 0x88, 0xf8, 0x03, 0xb8, 0xbb, 0x0e, 0xf6, 0x32, 0xa6, 0x4c, 0xf7, 0x7c, 0x17,
	0x2f, 0xaf, 0x7d, 0x03, 0x52, 0x88, 0x08, 0x15, 0xdb, 0x9d, 0xec, 0x77, 0xfd, 0x5b, 0x2a, 0x07,
	0xa9, 0x06, 0xf4, 0x70, 0x29, 0xd5, 0xdc, 0xb3, 0x64, 0xc0, 0x27, 0x8f, 0xb3, 0x64, 0xbf, 0x0d,
	0x5c, 0xfb, 0x98, 0x23, 0xdb, 0x91, 0x63, 0xa3, 0xf9, 0x59, 0xab, 0x69, 0xbf, 0x86, 0xa6, 0xfd,
	0x0c, 0xb4, 0xa0, 0x6c, 0x13, 0x0e, 0x50, 0xe0, 0xdb, 0xf9, 0x0b, 0xa5, 0x7c, 0x1b, 0xa6, 0x98,
	0xf1, 0x4f, 0x52, 0xe8, 0xa0, 0x68, 0x91, 0xd2, 0xeb, 0x4b, 0xdc, 0x1b, 0x37, 0xe6, 0xe6, 0x3e,
	0x2d, 0xfd, 0x6a, 0x60, 0xb5, 0x79, 0x4c, 0xeb, 0x4b, 0x3d, 0xac, 0xb2, 0x6a, 0xd1, 0x90, 0x2c,
	0x4c, 0x68, 0x82, 0xf6, 0x16, 0x48, 0x65, 0x81, 0x97, 0x23, 0x55, 0xd7, 0x6e, 0xe7, 0x9b, 0x28,
	0xec, 0x51, 0x74, 0x95, 0x45, 0x2f, 0x9e, 0x90, 0xfe, 0x00, 0x52, 0x4c, 0x79, 0x3a, 0x62, 0x5c,
	0xa3, 0xad, 0x27, 0x48, 0x77, 0x41, 0x6f, 0xfc, 0xd1, 0xd6, 0x4a, 0xec, 0xec, 0x7b, 0x24, 0xaf,
	0xb6, 0x3c, 0xa5, 0x0d, 0xbc, 0x09, 0xa7, 0x79, 0x73, 0x33, 0x41, 0xb2, 0xae, 0xe0, 0x3f, 0xa0,
	0x7b, 0x3f, 0x03, 0x00, 0x00, 0xff, 0xff, 0x36, 0xcd, 0x7d, 0x1f, 0x73, 0x09, 0x00, 0x00,
}

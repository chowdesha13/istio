// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/service/tap/v2alpha/tap.proto

package envoy_service_tap_v2alpha

import (
	context "context"
	fmt "fmt"
	io "io"
	math "math"

	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"

	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	v2alpha "github.com/envoyproxy/go-control-plane/envoy/data/tap/v2alpha"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// [#not-implemented-hide:] Stream message for the Tap API. Envoy will open a stream to the server
// and stream taps without ever expecting a response.
type StreamTapsRequest struct {
	// Identifier data effectively is a structured metadata. As a performance optimization this will
	// only be sent in the first message on the stream.
	Identifier *StreamTapsRequest_Identifier `protobuf:"bytes,1,opt,name=identifier,proto3" json:"identifier,omitempty"`
	// The trace id. this can be used to merge together a streaming trace. Note that the trace_id
	// is not guaranteed to be spatially or temporally unique.
	TraceId uint64 `protobuf:"varint,2,opt,name=trace_id,json=traceId,proto3" json:"trace_id,omitempty"`
	// The trace data.
	Trace                *v2alpha.TraceWrapper `protobuf:"bytes,3,opt,name=trace,proto3" json:"trace,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *StreamTapsRequest) Reset()         { *m = StreamTapsRequest{} }
func (m *StreamTapsRequest) String() string { return proto.CompactTextString(m) }
func (*StreamTapsRequest) ProtoMessage()    {}
func (*StreamTapsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e1e8ad5aa2b63d8d, []int{0}
}
func (m *StreamTapsRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *StreamTapsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_StreamTapsRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *StreamTapsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StreamTapsRequest.Merge(m, src)
}
func (m *StreamTapsRequest) XXX_Size() int {
	return m.Size()
}
func (m *StreamTapsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StreamTapsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StreamTapsRequest proto.InternalMessageInfo

func (m *StreamTapsRequest) GetIdentifier() *StreamTapsRequest_Identifier {
	if m != nil {
		return m.Identifier
	}
	return nil
}

func (m *StreamTapsRequest) GetTraceId() uint64 {
	if m != nil {
		return m.TraceId
	}
	return 0
}

func (m *StreamTapsRequest) GetTrace() *v2alpha.TraceWrapper {
	if m != nil {
		return m.Trace
	}
	return nil
}

type StreamTapsRequest_Identifier struct {
	// The node sending taps over the stream.
	Node *core.Node `protobuf:"bytes,1,opt,name=node,proto3" json:"node,omitempty"`
	// The opaque identifier that was set in the :ref:`output config
	// <envoy_api_field_service.tap.v2alpha.StreamingGrpcSink.tap_id>`.
	TapId                string   `protobuf:"bytes,2,opt,name=tap_id,json=tapId,proto3" json:"tap_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StreamTapsRequest_Identifier) Reset()         { *m = StreamTapsRequest_Identifier{} }
func (m *StreamTapsRequest_Identifier) String() string { return proto.CompactTextString(m) }
func (*StreamTapsRequest_Identifier) ProtoMessage()    {}
func (*StreamTapsRequest_Identifier) Descriptor() ([]byte, []int) {
	return fileDescriptor_e1e8ad5aa2b63d8d, []int{0, 0}
}
func (m *StreamTapsRequest_Identifier) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *StreamTapsRequest_Identifier) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_StreamTapsRequest_Identifier.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *StreamTapsRequest_Identifier) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StreamTapsRequest_Identifier.Merge(m, src)
}
func (m *StreamTapsRequest_Identifier) XXX_Size() int {
	return m.Size()
}
func (m *StreamTapsRequest_Identifier) XXX_DiscardUnknown() {
	xxx_messageInfo_StreamTapsRequest_Identifier.DiscardUnknown(m)
}

var xxx_messageInfo_StreamTapsRequest_Identifier proto.InternalMessageInfo

func (m *StreamTapsRequest_Identifier) GetNode() *core.Node {
	if m != nil {
		return m.Node
	}
	return nil
}

func (m *StreamTapsRequest_Identifier) GetTapId() string {
	if m != nil {
		return m.TapId
	}
	return ""
}

// [#not-implemented-hide:]
type StreamTapsResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StreamTapsResponse) Reset()         { *m = StreamTapsResponse{} }
func (m *StreamTapsResponse) String() string { return proto.CompactTextString(m) }
func (*StreamTapsResponse) ProtoMessage()    {}
func (*StreamTapsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e1e8ad5aa2b63d8d, []int{1}
}
func (m *StreamTapsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *StreamTapsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_StreamTapsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *StreamTapsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StreamTapsResponse.Merge(m, src)
}
func (m *StreamTapsResponse) XXX_Size() int {
	return m.Size()
}
func (m *StreamTapsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_StreamTapsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_StreamTapsResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*StreamTapsRequest)(nil), "envoy.service.tap.v2alpha.StreamTapsRequest")
	proto.RegisterType((*StreamTapsRequest_Identifier)(nil), "envoy.service.tap.v2alpha.StreamTapsRequest.Identifier")
	proto.RegisterType((*StreamTapsResponse)(nil), "envoy.service.tap.v2alpha.StreamTapsResponse")
}

func init() {
	proto.RegisterFile("envoy/service/tap/v2alpha/tap.proto", fileDescriptor_e1e8ad5aa2b63d8d)
}

var fileDescriptor_e1e8ad5aa2b63d8d = []byte{
	// 381 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x92, 0x3f, 0xcb, 0x13, 0x41,
	0x10, 0xc6, 0xdd, 0xfc, 0x33, 0x8e, 0x20, 0xba, 0x28, 0x49, 0x0e, 0x09, 0x21, 0x06, 0x4c, 0xa1,
	0x7b, 0x70, 0x16, 0x01, 0x3b, 0xd3, 0xa5, 0x91, 0x70, 0x39, 0x48, 0x23, 0xc8, 0x24, 0x3b, 0xe2,
	0x62, 0x72, 0xbb, 0xee, 0xad, 0xa7, 0xa9, 0xec, 0xfd, 0x16, 0x7e, 0x0d, 0x2b, 0x4b, 0x4b, 0x3f,
	0x82, 0xa4, 0xf3, 0x5b, 0xc8, 0xdd, 0x5e, 0x4c, 0xc2, 0x4b, 0xe0, 0x7d, 0xbb, 0x39, 0xe6, 0xf7,
	0x3c, 0xcf, 0xcc, 0xdc, 0xc2, 0x13, 0x4a, 0x73, 0xbd, 0x0b, 0x33, 0xb2, 0xb9, 0x5a, 0x53, 0xe8,
	0xd0, 0x84, 0x79, 0x84, 0x1b, 0xf3, 0x1e, 0x8b, 0x5a, 0x18, 0xab, 0x9d, 0xe6, 0xbd, 0x12, 0x12,
	0x15, 0x24, 0x8a, 0x46, 0x05, 0x05, 0x8f, 0xbd, 0x1e, 0x8d, 0x0a, 0xf3, 0x28, 0x5c, 0x6b, 0x4b,
	0xe1, 0x0a, 0x33, 0xf2, 0xc2, 0x60, 0xe4, 0xbb, 0x12, 0x1d, 0x9e, 0x59, 0x7f, 0xb6, 0x68, 0x0c,
	0xd9, 0x8a, 0xea, 0xe4, 0xb8, 0x51, 0x12, 0x1d, 0x85, 0x87, 0xc2, 0x37, 0x86, 0xdf, 0x6b, 0xf0,
	0x60, 0xe1, 0x2c, 0xe1, 0x36, 0x41, 0x93, 0xc5, 0xf4, 0xf1, 0x13, 0x65, 0x8e, 0x2f, 0x01, 0x94,
	0xa4, 0xd4, 0xa9, 0x77, 0x8a, 0x6c, 0x97, 0x0d, 0xd8, 0xf8, 0x6e, 0x34, 0x11, 0x17, 0x47, 0x14,
	0x57, 0x1c, 0xc4, 0xec, 0xbf, 0x3c, 0x3e, 0xb1, 0xe2, 0x3d, 0x68, 0x3b, 0x8b, 0x6b, 0x7a, 0xab,
	0x64, 0xb7, 0x36, 0x60, 0xe3, 0x46, 0x7c, 0xbb, 0xfc, 0x9e, 0x49, 0xfe, 0x12, 0x9a, 0x65, 0xd9,
	0xad, 0x97, 0x71, 0xa3, 0x2a, 0xae, 0x58, 0xec, 0x2c, 0x2b, 0x29, 0xa0, 0xa5, 0xdf, 0x2e, 0xf6,
	0x92, 0xe0, 0x0d, 0xc0, 0x31, 0x90, 0x4f, 0xa0, 0x91, 0x6a, 0x49, 0xd5, 0xdc, 0x9d, 0xca, 0x08,
	0x8d, 0x12, 0x79, 0x24, 0x8a, 0xfb, 0x89, 0xd7, 0x5a, 0xd2, 0x14, 0x7e, 0xfc, 0xfd, 0x59, 0x6f,
	0x7e, 0x63, 0xb5, 0xfb, 0x2c, 0x2e, 0x05, 0xfc, 0x11, 0xb4, 0x1c, 0x9a, 0xc3, 0x6c, 0x77, 0xe2,
	0xa6, 0x43, 0x33, 0x93, 0xc3, 0x87, 0xc0, 0x4f, 0x17, 0xcc, 0x8c, 0x4e, 0x33, 0x8a, 0xbe, 0xc2,
	0xbd, 0x04, 0xcd, 0x42, 0xa5, 0x1f, 0x16, 0xfe, 0x22, 0x7c, 0x0b, 0x70, 0xe4, 0xf8, 0xb3, 0x9b,
	0xdc, 0x2b, 0x78, 0x7e, 0x4d, 0xda, 0x87, 0x0f, 0x6f, 0x8d, 0xd9, 0xf4, 0xd5, 0xaf, 0x7d, 0x9f,
	0xfd, 0xde, 0xf7, 0xd9, 0x9f, 0x7d, 0x9f, 0xc1, 0x53, 0xa5, 0xbd, 0x85, 0xb1, 0xfa, 0xcb, 0xee,
	0xb2, 0xdb, 0xb4, 0x9d, 0xa0, 0x99, 0x17, 0xff, 0x7e, 0xce, 0x56, 0xad, 0xf2, 0x11, 0xbc, 0xf8,
	0x17, 0x00, 0x00, 0xff, 0xff, 0x6c, 0xb3, 0xae, 0x7e, 0xa3, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// TapSinkServiceClient is the client API for TapSinkService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TapSinkServiceClient interface {
	// Envoy will connect and send StreamTapsRequest messages forever. It does not expect any
	// response to be sent as nothing would be done in the case of failure. The server should
	// disconnect if it expects Envoy to reconnect.
	StreamTaps(ctx context.Context, opts ...grpc.CallOption) (TapSinkService_StreamTapsClient, error)
}

type tapSinkServiceClient struct {
	cc *grpc.ClientConn
}

func NewTapSinkServiceClient(cc *grpc.ClientConn) TapSinkServiceClient {
	return &tapSinkServiceClient{cc}
}

func (c *tapSinkServiceClient) StreamTaps(ctx context.Context, opts ...grpc.CallOption) (TapSinkService_StreamTapsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TapSinkService_serviceDesc.Streams[0], "/envoy.service.tap.v2alpha.TapSinkService/StreamTaps", opts...)
	if err != nil {
		return nil, err
	}
	x := &tapSinkServiceStreamTapsClient{stream}
	return x, nil
}

type TapSinkService_StreamTapsClient interface {
	Send(*StreamTapsRequest) error
	CloseAndRecv() (*StreamTapsResponse, error)
	grpc.ClientStream
}

type tapSinkServiceStreamTapsClient struct {
	grpc.ClientStream
}

func (x *tapSinkServiceStreamTapsClient) Send(m *StreamTapsRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *tapSinkServiceStreamTapsClient) CloseAndRecv() (*StreamTapsResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(StreamTapsResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// TapSinkServiceServer is the server API for TapSinkService service.
type TapSinkServiceServer interface {
	// Envoy will connect and send StreamTapsRequest messages forever. It does not expect any
	// response to be sent as nothing would be done in the case of failure. The server should
	// disconnect if it expects Envoy to reconnect.
	StreamTaps(TapSinkService_StreamTapsServer) error
}

func RegisterTapSinkServiceServer(s *grpc.Server, srv TapSinkServiceServer) {
	s.RegisterService(&_TapSinkService_serviceDesc, srv)
}

func _TapSinkService_StreamTaps_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TapSinkServiceServer).StreamTaps(&tapSinkServiceStreamTapsServer{stream})
}

type TapSinkService_StreamTapsServer interface {
	SendAndClose(*StreamTapsResponse) error
	Recv() (*StreamTapsRequest, error)
	grpc.ServerStream
}

type tapSinkServiceStreamTapsServer struct {
	grpc.ServerStream
}

func (x *tapSinkServiceStreamTapsServer) SendAndClose(m *StreamTapsResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *tapSinkServiceStreamTapsServer) Recv() (*StreamTapsRequest, error) {
	m := new(StreamTapsRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _TapSinkService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "envoy.service.tap.v2alpha.TapSinkService",
	HandlerType: (*TapSinkServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamTaps",
			Handler:       _TapSinkService_StreamTaps_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "envoy/service/tap/v2alpha/tap.proto",
}

func (m *StreamTapsRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *StreamTapsRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Identifier != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintTap(dAtA, i, uint64(m.Identifier.Size()))
		n1, err := m.Identifier.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.TraceId != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintTap(dAtA, i, uint64(m.TraceId))
	}
	if m.Trace != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintTap(dAtA, i, uint64(m.Trace.Size()))
		n2, err := m.Trace.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *StreamTapsRequest_Identifier) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *StreamTapsRequest_Identifier) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Node != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintTap(dAtA, i, uint64(m.Node.Size()))
		n3, err := m.Node.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	if len(m.TapId) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintTap(dAtA, i, uint64(len(m.TapId)))
		i += copy(dAtA[i:], m.TapId)
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *StreamTapsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *StreamTapsResponse) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintTap(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *StreamTapsRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Identifier != nil {
		l = m.Identifier.Size()
		n += 1 + l + sovTap(uint64(l))
	}
	if m.TraceId != 0 {
		n += 1 + sovTap(uint64(m.TraceId))
	}
	if m.Trace != nil {
		l = m.Trace.Size()
		n += 1 + l + sovTap(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *StreamTapsRequest_Identifier) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Node != nil {
		l = m.Node.Size()
		n += 1 + l + sovTap(uint64(l))
	}
	l = len(m.TapId)
	if l > 0 {
		n += 1 + l + sovTap(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *StreamTapsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovTap(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozTap(x uint64) (n int) {
	return sovTap(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *StreamTapsRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTap
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: StreamTapsRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: StreamTapsRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Identifier", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTap
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTap
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTap
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Identifier == nil {
				m.Identifier = &StreamTapsRequest_Identifier{}
			}
			if err := m.Identifier.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TraceId", wireType)
			}
			m.TraceId = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTap
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TraceId |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Trace", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTap
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTap
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTap
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Trace == nil {
				m.Trace = &v2alpha.TraceWrapper{}
			}
			if err := m.Trace.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTap(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTap
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTap
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *StreamTapsRequest_Identifier) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTap
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Identifier: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Identifier: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Node", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTap
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTap
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTap
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Node == nil {
				m.Node = &core.Node{}
			}
			if err := m.Node.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field TapId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTap
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTap
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTap
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.TapId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTap(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTap
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTap
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *StreamTapsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTap
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: StreamTapsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: StreamTapsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipTap(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTap
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTap
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTap(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTap
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTap
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTap
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthTap
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthTap
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowTap
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipTap(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthTap
				}
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthTap = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTap   = fmt.Errorf("proto: integer overflow")
)

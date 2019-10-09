// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: security/proto/workload_service.proto

package istio_v1_auth

import (
	context "context"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	rpc "istio.io/gogo-genproto/googleapis/google/rpc"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type CheckRequest struct {
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *CheckRequest) Reset()      { *m = CheckRequest{} }
func (*CheckRequest) ProtoMessage() {}
func (*CheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8303a7e25e3cf159, []int{0}
}
func (m *CheckRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CheckRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckRequest.Merge(m, src)
}
func (m *CheckRequest) XXX_Size() int {
	return m.Size()
}
func (m *CheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CheckRequest proto.InternalMessageInfo

func (m *CheckRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type CheckResponse struct {
	Status *rpc.Status `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
}

func (m *CheckResponse) Reset()      { *m = CheckResponse{} }
func (*CheckResponse) ProtoMessage() {}
func (*CheckResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8303a7e25e3cf159, []int{1}
}
func (m *CheckResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CheckResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CheckResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CheckResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckResponse.Merge(m, src)
}
func (m *CheckResponse) XXX_Size() int {
	return m.Size()
}
func (m *CheckResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CheckResponse proto.InternalMessageInfo

func (m *CheckResponse) GetStatus() *rpc.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func init() {
	proto.RegisterType((*CheckRequest)(nil), "istio.v1.auth.CheckRequest")
	proto.RegisterType((*CheckResponse)(nil), "istio.v1.auth.CheckResponse")
}

func init() {
	proto.RegisterFile("security/proto/workload_service.proto", fileDescriptor_8303a7e25e3cf159)
}

var fileDescriptor_8303a7e25e3cf159 = []byte{
	// 269 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x90, 0xc1, 0x4a, 0xc3, 0x30,
	0x18, 0xc7, 0x13, 0xd0, 0x81, 0xd1, 0x21, 0xe4, 0xa2, 0x4c, 0xf9, 0x90, 0x82, 0x20, 0x1e, 0x52,
	0x36, 0x8f, 0xde, 0xb6, 0x37, 0xe8, 0x10, 0xc1, 0x4b, 0xa9, 0xf1, 0x63, 0x2b, 0x9b, 0x4b, 0x4d,
	0xd2, 0x8a, 0x37, 0x1f, 0xc1, 0xc7, 0xf0, 0x51, 0x3c, 0xf6, 0xb8, 0xa3, 0x4d, 0x2f, 0x1e, 0xfb,
	0x08, 0x62, 0xd2, 0x83, 0x82, 0xb7, 0x90, 0xef, 0xc7, 0x8f, 0x1f, 0x7f, 0x76, 0x6e, 0x50, 0x96,
	0x3a, 0xb7, 0x2f, 0x71, 0xa1, 0x95, 0x55, 0xf1, 0xb3, 0xd2, 0xab, 0xb5, 0xca, 0x1e, 0x52, 0x83,
	0xba, 0xca, 0x25, 0x0a, 0xff, 0xcd, 0x87, 0xb9, 0xb1, 0xb9, 0x12, 0xd5, 0x58, 0x64, 0xa5, 0x5d,
	0x8e, 0x8e, 0x16, 0x4a, 0x2d, 0xd6, 0x18, 0xeb, 0x42, 0xc6, 0xc6, 0x66, 0xb6, 0x34, 0x81, 0x8b,
	0x22, 0x76, 0x30, 0x5b, 0xa2, 0x5c, 0x25, 0xf8, 0x54, 0xa2, 0xb1, 0x9c, 0xb3, 0x9d, 0x4d, 0xf6,
	0x88, 0xc7, 0xf4, 0x8c, 0x5e, 0xec, 0x25, 0xfe, 0x1d, 0x5d, 0xb3, 0x61, 0xcf, 0x98, 0x42, 0x6d,
	0x0c, 0xf2, 0x4b, 0x36, 0x08, 0x12, 0x8f, 0xed, 0x4f, 0xb8, 0x08, 0x7a, 0xa1, 0x0b, 0x29, 0xe6,
	0xfe, 0x92, 0xf4, 0xc4, 0xe4, 0x86, 0x1d, 0xde, 0xf6, 0x89, 0xf3, 0x50, 0xc8, 0xa7, 0x6c, 0xd7,
	0xfb, 0xf8, 0x89, 0xf8, 0x53, 0x29, 0x7e, 0x97, 0x8c, 0x4e, 0xff, 0x3f, 0x86, 0x84, 0xe9, 0xac,
	0x6e, 0x80, 0x6c, 0x1b, 0x20, 0x5d, 0x03, 0xf4, 0xd5, 0x01, 0x7d, 0x77, 0x40, 0x3f, 0x1c, 0xd0,
	0xda, 0x01, 0xfd, 0x74, 0x40, 0xbf, 0x1c, 0x90, 0xce, 0x01, 0x7d, 0x6b, 0x81, 0xd4, 0x2d, 0x90,
	0x6d, 0x0b, 0xe4, 0x2e, 0xac, 0x92, 0x56, 0xe3, 0xf4, 0x47, 0x79, 0x3f, 0xf0, 0x1b, 0x5c, 0x7d,
	0x07, 0x00, 0x00, 0xff, 0xff, 0xfa, 0xed, 0x11, 0x51, 0x54, 0x01, 0x00, 0x00,
}

func (this *CheckRequest) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*CheckRequest)
	if !ok {
		that2, ok := that.(CheckRequest)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Name != that1.Name {
		return false
	}
	return true
}
func (this *CheckResponse) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*CheckResponse)
	if !ok {
		that2, ok := that.(CheckResponse)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !this.Status.Equal(that1.Status) {
		return false
	}
	return true
}
func (this *CheckRequest) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&istio_v1_auth.CheckRequest{")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *CheckResponse) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&istio_v1_auth.CheckResponse{")
	if this.Status != nil {
		s = append(s, "Status: "+fmt.Sprintf("%#v", this.Status)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringWorkloadService(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// WorkloadServiceClient is the client API for WorkloadService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type WorkloadServiceClient interface {
	Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckResponse, error)
}

type workloadServiceClient struct {
	cc *grpc.ClientConn
}

func NewWorkloadServiceClient(cc *grpc.ClientConn) WorkloadServiceClient {
	return &workloadServiceClient{cc}
}

func (c *workloadServiceClient) Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckResponse, error) {
	out := new(CheckResponse)
	err := c.cc.Invoke(ctx, "/istio.v1.auth.WorkloadService/Check", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WorkloadServiceServer is the server API for WorkloadService service.
type WorkloadServiceServer interface {
	Check(context.Context, *CheckRequest) (*CheckResponse, error)
}

// UnimplementedWorkloadServiceServer can be embedded to have forward compatible implementations.
type UnimplementedWorkloadServiceServer struct {
}

func (*UnimplementedWorkloadServiceServer) Check(ctx context.Context, req *CheckRequest) (*CheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Check not implemented")
}

func RegisterWorkloadServiceServer(s *grpc.Server, srv WorkloadServiceServer) {
	s.RegisterService(&_WorkloadService_serviceDesc, srv)
}

func _WorkloadService_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WorkloadServiceServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/istio.v1.auth.WorkloadService/Check",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WorkloadServiceServer).Check(ctx, req.(*CheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _WorkloadService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "istio.v1.auth.WorkloadService",
	HandlerType: (*WorkloadServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Check",
			Handler:    _WorkloadService_Check_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "security/proto/workload_service.proto",
}

func (m *CheckRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CheckRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CheckRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintWorkloadService(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *CheckResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CheckResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CheckResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Status != nil {
		{
			size, err := m.Status.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintWorkloadService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintWorkloadService(dAtA []byte, offset int, v uint64) int {
	offset -= sovWorkloadService(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *CheckRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovWorkloadService(uint64(l))
	}
	return n
}

func (m *CheckResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Status != nil {
		l = m.Status.Size()
		n += 1 + l + sovWorkloadService(uint64(l))
	}
	return n
}

func sovWorkloadService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozWorkloadService(x uint64) (n int) {
	return sovWorkloadService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *CheckRequest) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&CheckRequest{`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`}`,
	}, "")
	return s
}
func (this *CheckResponse) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&CheckResponse{`,
		`Status:` + strings.Replace(fmt.Sprintf("%v", this.Status), "Status", "rpc.Status", 1) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringWorkloadService(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *CheckRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowWorkloadService
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
			return fmt.Errorf("proto: CheckRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CheckRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWorkloadService
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
				return ErrInvalidLengthWorkloadService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthWorkloadService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipWorkloadService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthWorkloadService
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthWorkloadService
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *CheckResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowWorkloadService
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
			return fmt.Errorf("proto: CheckResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CheckResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWorkloadService
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
				return ErrInvalidLengthWorkloadService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthWorkloadService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Status == nil {
				m.Status = &rpc.Status{}
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipWorkloadService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthWorkloadService
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthWorkloadService
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipWorkloadService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowWorkloadService
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
					return 0, ErrIntOverflowWorkloadService
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
					return 0, ErrIntOverflowWorkloadService
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
				return 0, ErrInvalidLengthWorkloadService
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthWorkloadService
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowWorkloadService
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
				next, err := skipWorkloadService(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthWorkloadService
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
	ErrInvalidLengthWorkloadService = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowWorkloadService   = fmt.Errorf("proto: integer overflow")
)

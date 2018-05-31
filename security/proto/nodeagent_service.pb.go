// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: security/proto/nodeagent_service.proto

/*
	Package istio_v1_auth is a generated protocol buffer package.

	It is generated from these files:
		security/proto/nodeagent_service.proto

	It has these top-level messages:
		NodeAgentMgmtResponse
		WorkloadInfo
*/
package istio_v1_auth

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import google_rpc "github.com/gogo/googleapis/google/rpc"

import strings "strings"
import reflect "reflect"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type NodeAgentMgmtResponse struct {
	Status *google_rpc.Status `protobuf:"bytes,1,opt,name=status" json:"status,omitempty"`
}

func (m *NodeAgentMgmtResponse) Reset()      { *m = NodeAgentMgmtResponse{} }
func (*NodeAgentMgmtResponse) ProtoMessage() {}
func (*NodeAgentMgmtResponse) Descriptor() ([]byte, []int) {
	return fileDescriptorNodeagentService, []int{0}
}

func (m *NodeAgentMgmtResponse) GetStatus() *google_rpc.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

type WorkloadInfo struct {
	// WorkloadAttributes are the properties of the workload that a caller,
	// Flexvolume driver knows off.
	// Node agent can use them to verify the credentials of the workload.
	Attrs *WorkloadInfo_WorkloadAttributes `protobuf:"bytes,1,opt,name=attrs" json:"attrs,omitempty"`
	// workloadpath is where the caller has hosted a volume specific for
	// the workload. The node agent will use this directory to communicate with the
	// specific workload.
	Workloadpath string `protobuf:"bytes,2,opt,name=workloadpath,proto3" json:"workloadpath,omitempty"`
}

func (m *WorkloadInfo) Reset()                    { *m = WorkloadInfo{} }
func (*WorkloadInfo) ProtoMessage()               {}
func (*WorkloadInfo) Descriptor() ([]byte, []int) { return fileDescriptorNodeagentService, []int{1} }

func (m *WorkloadInfo) GetAttrs() *WorkloadInfo_WorkloadAttributes {
	if m != nil {
		return m.Attrs
	}
	return nil
}

func (m *WorkloadInfo) GetWorkloadpath() string {
	if m != nil {
		return m.Workloadpath
	}
	return ""
}

type WorkloadInfo_WorkloadAttributes struct {
	// uid: Unique Id of the Workload.
	// During delete the uid is mandatory.
	Uid string `protobuf:"bytes,1,opt,name=uid,proto3" json:"uid,omitempty"`
	// workload identifier aka name.
	Workload string `protobuf:"bytes,2,opt,name=workload,proto3" json:"workload,omitempty"`
	// namespace of the workload.
	Namespace string `protobuf:"bytes,3,opt,name=namespace,proto3" json:"namespace,omitempty"`
	// service account of the workload.
	Serviceaccount string `protobuf:"bytes,4,opt,name=serviceaccount,proto3" json:"serviceaccount,omitempty"`
}

func (m *WorkloadInfo_WorkloadAttributes) Reset()      { *m = WorkloadInfo_WorkloadAttributes{} }
func (*WorkloadInfo_WorkloadAttributes) ProtoMessage() {}
func (*WorkloadInfo_WorkloadAttributes) Descriptor() ([]byte, []int) {
	return fileDescriptorNodeagentService, []int{1, 0}
}

func (m *WorkloadInfo_WorkloadAttributes) GetUid() string {
	if m != nil {
		return m.Uid
	}
	return ""
}

func (m *WorkloadInfo_WorkloadAttributes) GetWorkload() string {
	if m != nil {
		return m.Workload
	}
	return ""
}

func (m *WorkloadInfo_WorkloadAttributes) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *WorkloadInfo_WorkloadAttributes) GetServiceaccount() string {
	if m != nil {
		return m.Serviceaccount
	}
	return ""
}

func init() {
	proto.RegisterType((*NodeAgentMgmtResponse)(nil), "istio.v1.auth.NodeAgentMgmtResponse")
	proto.RegisterType((*WorkloadInfo)(nil), "istio.v1.auth.WorkloadInfo")
	proto.RegisterType((*WorkloadInfo_WorkloadAttributes)(nil), "istio.v1.auth.WorkloadInfo.WorkloadAttributes")
}
func (this *NodeAgentMgmtResponse) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*NodeAgentMgmtResponse)
	if !ok {
		that2, ok := that.(NodeAgentMgmtResponse)
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
func (this *WorkloadInfo) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*WorkloadInfo)
	if !ok {
		that2, ok := that.(WorkloadInfo)
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
	if !this.Attrs.Equal(that1.Attrs) {
		return false
	}
	if this.Workloadpath != that1.Workloadpath {
		return false
	}
	return true
}
func (this *WorkloadInfo_WorkloadAttributes) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*WorkloadInfo_WorkloadAttributes)
	if !ok {
		that2, ok := that.(WorkloadInfo_WorkloadAttributes)
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
	if this.Uid != that1.Uid {
		return false
	}
	if this.Workload != that1.Workload {
		return false
	}
	if this.Namespace != that1.Namespace {
		return false
	}
	if this.Serviceaccount != that1.Serviceaccount {
		return false
	}
	return true
}
func (this *NodeAgentMgmtResponse) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&istio_v1_auth.NodeAgentMgmtResponse{")
	if this.Status != nil {
		s = append(s, "Status: "+fmt.Sprintf("%#v", this.Status)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *WorkloadInfo) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 6)
	s = append(s, "&istio_v1_auth.WorkloadInfo{")
	if this.Attrs != nil {
		s = append(s, "Attrs: "+fmt.Sprintf("%#v", this.Attrs)+",\n")
	}
	s = append(s, "Workloadpath: "+fmt.Sprintf("%#v", this.Workloadpath)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *WorkloadInfo_WorkloadAttributes) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 8)
	s = append(s, "&istio_v1_auth.WorkloadInfo_WorkloadAttributes{")
	s = append(s, "Uid: "+fmt.Sprintf("%#v", this.Uid)+",\n")
	s = append(s, "Workload: "+fmt.Sprintf("%#v", this.Workload)+",\n")
	s = append(s, "Namespace: "+fmt.Sprintf("%#v", this.Namespace)+",\n")
	s = append(s, "Serviceaccount: "+fmt.Sprintf("%#v", this.Serviceaccount)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringNodeagentService(v interface{}, typ string) string {
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

// Client API for NodeAgentService service

type NodeAgentServiceClient interface {
	// WorkloadAdded is used to notify Node Agent about a workload getting
	WorkloadAdded(ctx context.Context, in *WorkloadInfo, opts ...grpc.CallOption) (*NodeAgentMgmtResponse, error)
	// WorkloadDeleted is used to notify Node Agent about a workload getting
	// added on a node.
	WorkloadDeleted(ctx context.Context, in *WorkloadInfo, opts ...grpc.CallOption) (*NodeAgentMgmtResponse, error)
}

type nodeAgentServiceClient struct {
	cc *grpc.ClientConn
}

func NewNodeAgentServiceClient(cc *grpc.ClientConn) NodeAgentServiceClient {
	return &nodeAgentServiceClient{cc}
}

func (c *nodeAgentServiceClient) WorkloadAdded(ctx context.Context, in *WorkloadInfo, opts ...grpc.CallOption) (*NodeAgentMgmtResponse, error) {
	out := new(NodeAgentMgmtResponse)
	err := grpc.Invoke(ctx, "/istio.v1.auth.NodeAgentService/WorkloadAdded", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nodeAgentServiceClient) WorkloadDeleted(ctx context.Context, in *WorkloadInfo, opts ...grpc.CallOption) (*NodeAgentMgmtResponse, error) {
	out := new(NodeAgentMgmtResponse)
	err := grpc.Invoke(ctx, "/istio.v1.auth.NodeAgentService/WorkloadDeleted", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for NodeAgentService service

type NodeAgentServiceServer interface {
	// WorkloadAdded is used to notify Node Agent about a workload getting
	WorkloadAdded(context.Context, *WorkloadInfo) (*NodeAgentMgmtResponse, error)
	// WorkloadDeleted is used to notify Node Agent about a workload getting
	// added on a node.
	WorkloadDeleted(context.Context, *WorkloadInfo) (*NodeAgentMgmtResponse, error)
}

func RegisterNodeAgentServiceServer(s *grpc.Server, srv NodeAgentServiceServer) {
	s.RegisterService(&_NodeAgentService_serviceDesc, srv)
}

func _NodeAgentService_WorkloadAdded_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(WorkloadInfo)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAgentServiceServer).WorkloadAdded(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/istio.v1.auth.NodeAgentService/WorkloadAdded",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAgentServiceServer).WorkloadAdded(ctx, req.(*WorkloadInfo))
	}
	return interceptor(ctx, in, info, handler)
}

func _NodeAgentService_WorkloadDeleted_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(WorkloadInfo)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAgentServiceServer).WorkloadDeleted(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/istio.v1.auth.NodeAgentService/WorkloadDeleted",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAgentServiceServer).WorkloadDeleted(ctx, req.(*WorkloadInfo))
	}
	return interceptor(ctx, in, info, handler)
}

var _NodeAgentService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "istio.v1.auth.NodeAgentService",
	HandlerType: (*NodeAgentServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "WorkloadAdded",
			Handler:    _NodeAgentService_WorkloadAdded_Handler,
		},
		{
			MethodName: "WorkloadDeleted",
			Handler:    _NodeAgentService_WorkloadDeleted_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "security/proto/nodeagent_service.proto",
}

func (m *NodeAgentMgmtResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *NodeAgentMgmtResponse) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Status != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintNodeagentService(dAtA, i, uint64(m.Status.Size()))
		n1, err := m.Status.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	return i, nil
}

func (m *WorkloadInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *WorkloadInfo) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Attrs != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintNodeagentService(dAtA, i, uint64(m.Attrs.Size()))
		n2, err := m.Attrs.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if len(m.Workloadpath) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintNodeagentService(dAtA, i, uint64(len(m.Workloadpath)))
		i += copy(dAtA[i:], m.Workloadpath)
	}
	return i, nil
}

func (m *WorkloadInfo_WorkloadAttributes) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *WorkloadInfo_WorkloadAttributes) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Uid) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintNodeagentService(dAtA, i, uint64(len(m.Uid)))
		i += copy(dAtA[i:], m.Uid)
	}
	if len(m.Workload) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintNodeagentService(dAtA, i, uint64(len(m.Workload)))
		i += copy(dAtA[i:], m.Workload)
	}
	if len(m.Namespace) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintNodeagentService(dAtA, i, uint64(len(m.Namespace)))
		i += copy(dAtA[i:], m.Namespace)
	}
	if len(m.Serviceaccount) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintNodeagentService(dAtA, i, uint64(len(m.Serviceaccount)))
		i += copy(dAtA[i:], m.Serviceaccount)
	}
	return i, nil
}

func encodeVarintNodeagentService(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *NodeAgentMgmtResponse) Size() (n int) {
	var l int
	_ = l
	if m.Status != nil {
		l = m.Status.Size()
		n += 1 + l + sovNodeagentService(uint64(l))
	}
	return n
}

func (m *WorkloadInfo) Size() (n int) {
	var l int
	_ = l
	if m.Attrs != nil {
		l = m.Attrs.Size()
		n += 1 + l + sovNodeagentService(uint64(l))
	}
	l = len(m.Workloadpath)
	if l > 0 {
		n += 1 + l + sovNodeagentService(uint64(l))
	}
	return n
}

func (m *WorkloadInfo_WorkloadAttributes) Size() (n int) {
	var l int
	_ = l
	l = len(m.Uid)
	if l > 0 {
		n += 1 + l + sovNodeagentService(uint64(l))
	}
	l = len(m.Workload)
	if l > 0 {
		n += 1 + l + sovNodeagentService(uint64(l))
	}
	l = len(m.Namespace)
	if l > 0 {
		n += 1 + l + sovNodeagentService(uint64(l))
	}
	l = len(m.Serviceaccount)
	if l > 0 {
		n += 1 + l + sovNodeagentService(uint64(l))
	}
	return n
}

func sovNodeagentService(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozNodeagentService(x uint64) (n int) {
	return sovNodeagentService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *NodeAgentMgmtResponse) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&NodeAgentMgmtResponse{`,
		`Status:` + strings.Replace(fmt.Sprintf("%v", this.Status), "Status", "google_rpc.Status", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *WorkloadInfo) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&WorkloadInfo{`,
		`Attrs:` + strings.Replace(fmt.Sprintf("%v", this.Attrs), "WorkloadInfo_WorkloadAttributes", "WorkloadInfo_WorkloadAttributes", 1) + `,`,
		`Workloadpath:` + fmt.Sprintf("%v", this.Workloadpath) + `,`,
		`}`,
	}, "")
	return s
}
func (this *WorkloadInfo_WorkloadAttributes) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&WorkloadInfo_WorkloadAttributes{`,
		`Uid:` + fmt.Sprintf("%v", this.Uid) + `,`,
		`Workload:` + fmt.Sprintf("%v", this.Workload) + `,`,
		`Namespace:` + fmt.Sprintf("%v", this.Namespace) + `,`,
		`Serviceaccount:` + fmt.Sprintf("%v", this.Serviceaccount) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringNodeagentService(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *NodeAgentMgmtResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNodeagentService
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: NodeAgentMgmtResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: NodeAgentMgmtResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNodeagentService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNodeagentService
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Status == nil {
				m.Status = &google_rpc.Status{}
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNodeagentService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthNodeagentService
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
func (m *WorkloadInfo) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNodeagentService
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: WorkloadInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: WorkloadInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Attrs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNodeagentService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNodeagentService
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Attrs == nil {
				m.Attrs = &WorkloadInfo_WorkloadAttributes{}
			}
			if err := m.Attrs.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Workloadpath", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNodeagentService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNodeagentService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Workloadpath = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNodeagentService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthNodeagentService
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
func (m *WorkloadInfo_WorkloadAttributes) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNodeagentService
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: WorkloadAttributes: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: WorkloadAttributes: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Uid", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNodeagentService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNodeagentService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Uid = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Workload", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNodeagentService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNodeagentService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Workload = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Namespace", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNodeagentService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNodeagentService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Namespace = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Serviceaccount", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNodeagentService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNodeagentService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Serviceaccount = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNodeagentService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthNodeagentService
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
func skipNodeagentService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowNodeagentService
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
					return 0, ErrIntOverflowNodeagentService
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
					return 0, ErrIntOverflowNodeagentService
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
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthNodeagentService
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowNodeagentService
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
				next, err := skipNodeagentService(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
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
	ErrInvalidLengthNodeagentService = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowNodeagentService   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("security/proto/nodeagent_service.proto", fileDescriptorNodeagentService)
}

var fileDescriptorNodeagentService = []byte{
	// 388 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x52, 0xbf, 0x6e, 0xda, 0x40,
	0x18, 0xf7, 0x41, 0x8b, 0xca, 0x15, 0x5a, 0x74, 0x52, 0x55, 0xcb, 0xad, 0x4e, 0x08, 0x55, 0x08,
	0x75, 0x38, 0x0b, 0x3a, 0x76, 0xa2, 0x65, 0xe9, 0xd0, 0x0e, 0xa6, 0x52, 0xa4, 0x2c, 0xe8, 0xb0,
	0x2f, 0xc6, 0x0a, 0xf8, 0xac, 0xbb, 0xcf, 0x44, 0xd9, 0x22, 0x65, 0xc9, 0x98, 0xc7, 0xc8, 0x43,
	0xe4, 0x01, 0x32, 0x32, 0x66, 0x0c, 0xce, 0x92, 0x91, 0x47, 0x88, 0xb0, 0x8d, 0x13, 0x48, 0x94,
	0x29, 0x9b, 0xbf, 0xdf, 0x3f, 0x7f, 0xfa, 0xdd, 0x87, 0xdb, 0x5a, 0xb8, 0xb1, 0x0a, 0xe0, 0xd8,
	0x8e, 0x94, 0x04, 0x69, 0x87, 0xd2, 0x13, 0xdc, 0x17, 0x21, 0x8c, 0xb4, 0x50, 0xf3, 0xc0, 0x15,
	0x2c, 0xc5, 0x49, 0x3d, 0xd0, 0x10, 0x48, 0x36, 0xef, 0x32, 0x1e, 0xc3, 0xc4, 0xfa, 0xec, 0x4b,
	0xe9, 0x4f, 0x85, 0xad, 0x22, 0xd7, 0xd6, 0xc0, 0x21, 0xd6, 0x99, 0xae, 0xf5, 0x1b, 0x7f, 0xfa,
	0x27, 0x3d, 0xd1, 0x5f, 0x47, 0xfc, 0xf5, 0x67, 0xe0, 0x08, 0x1d, 0xc9, 0x50, 0x0b, 0xf2, 0x1d,
	0x57, 0x32, 0xa1, 0x89, 0x9a, 0xa8, 0xf3, 0xbe, 0x47, 0x58, 0x16, 0xc1, 0x54, 0xe4, 0xb2, 0x61,
	0xca, 0x38, 0xb9, 0xa2, 0x75, 0x5a, 0xc2, 0xb5, 0x3d, 0xa9, 0x0e, 0xa7, 0x92, 0x7b, 0x7f, 0xc2,
	0x03, 0x49, 0x06, 0xf8, 0x2d, 0x07, 0x50, 0x1b, 0x2f, 0x63, 0x5b, 0xdb, 0xb0, 0xc7, 0xda, 0x62,
	0xe8, 0x03, 0xa8, 0x60, 0x1c, 0x83, 0xd0, 0x4e, 0x66, 0x26, 0x2d, 0x5c, 0x3b, 0xca, 0xc9, 0x88,
	0xc3, 0xc4, 0x2c, 0x35, 0x51, 0xa7, 0xea, 0x6c, 0x61, 0xd6, 0x19, 0xc2, 0xe4, 0x69, 0x02, 0x69,
	0xe0, 0x72, 0x1c, 0x78, 0xe9, 0xef, 0xab, 0xce, 0xfa, 0x93, 0x58, 0xf8, 0xdd, 0xc6, 0x98, 0x07,
	0x15, 0x33, 0xf9, 0x8a, 0xab, 0x21, 0x9f, 0x09, 0x1d, 0x71, 0x57, 0x98, 0xe5, 0x94, 0x7c, 0x00,
	0x48, 0x1b, 0x7f, 0xc8, 0xbb, 0xe5, 0xae, 0x2b, 0xe3, 0x10, 0xcc, 0x37, 0xa9, 0x64, 0x07, 0xed,
	0x5d, 0x22, 0xdc, 0x28, 0xba, 0x1c, 0x66, 0x1c, 0x71, 0x70, 0xbd, 0x58, 0xcf, 0xf3, 0x84, 0x47,
	0xbe, 0xbc, 0xd0, 0x85, 0xf5, 0x6d, 0x87, 0x7c, 0xfe, 0x69, 0xfe, 0xe3, 0x8f, 0x1b, 0xd7, 0x40,
	0x4c, 0x05, 0xbc, 0x4a, 0xea, 0xaf, 0x9f, 0x8b, 0x25, 0x35, 0xae, 0x97, 0xd4, 0x58, 0x2d, 0x29,
	0x3a, 0x49, 0x28, 0xba, 0x48, 0x28, 0xba, 0x4a, 0x28, 0x5a, 0x24, 0x14, 0xdd, 0x24, 0x14, 0xdd,
	0x25, 0xd4, 0x58, 0x25, 0x14, 0x9d, 0xdf, 0x52, 0x63, 0x3f, 0xbb, 0xaf, 0xd1, 0xbc, 0x3b, 0x5a,
	0x47, 0x8e, 0x2b, 0xe9, 0x35, 0xfd, 0xb8, 0x0f, 0x00, 0x00, 0xff, 0xff, 0xde, 0x77, 0x5a, 0xa8,
	0x9f, 0x02, 0x00, 0x00,
}

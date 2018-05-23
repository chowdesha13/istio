// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/test/spyAdapter/template/check/tmpl_handler_service.proto

/*
	Package samplecheck is a generated protocol buffer package.

	It is generated from these files:
		mixer/test/spyAdapter/template/check/tmpl_handler_service.proto

	It has these top-level messages:
		HandleSampleCheckRequest
		InstanceMsg
		Type
		InstanceParam
*/
package samplecheck

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "istio.io/api/mixer/adapter/model/v1beta1"
import google_protobuf1 "github.com/gogo/protobuf/types"
import istio_mixer_adapter_model_v1beta11 "istio.io/api/mixer/adapter/model/v1beta1"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import strings "strings"
import reflect "reflect"

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

// Request message for HandleSampleCheck method.
type HandleSampleCheckRequest struct {
	// 'samplecheck' instance.
	Instance *InstanceMsg `protobuf:"bytes,1,opt,name=instance" json:"instance,omitempty"`
	// Adapter specific handler configuration.
	//
	// Note: Backends can also implement [InfrastructureBackend][https://istio.io/docs/reference/config/mixer/istio.mixer.adapter.model.v1beta1.html#InfrastructureBackend]
	// service and therefore opt to receive handler configuration during session creation through [InfrastructureBackend.CreateSession][TODO: Link to this fragment]
	// call. In that case, adapter_config will have type_url as 'google.protobuf.Any.type_url' and would contain string
	// value of session_id (returned from InfrastructureBackend.CreateSession).
	AdapterConfig *google_protobuf1.Any `protobuf:"bytes,2,opt,name=adapter_config,json=adapterConfig" json:"adapter_config,omitempty"`
	// Id to dedupe identical requests from Mixer.
	DedupId string `protobuf:"bytes,3,opt,name=dedup_id,json=dedupId,proto3" json:"dedup_id,omitempty"`
}

func (m *HandleSampleCheckRequest) Reset()      { *m = HandleSampleCheckRequest{} }
func (*HandleSampleCheckRequest) ProtoMessage() {}
func (*HandleSampleCheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptorTmplHandlerService, []int{0}
}

// Contains instance payload for 'samplecheck' template. This is passed to infrastructure backends during request-time
// through HandleSampleCheckService.HandleSampleCheck.
type InstanceMsg struct {
	// Name of the instance as specified in configuration.
	Name            string `protobuf:"bytes,72295727,opt,name=name,proto3" json:"name,omitempty"`
	StringPrimitive string `protobuf:"bytes,4,opt,name=stringPrimitive,proto3" json:"stringPrimitive,omitempty"`
}

func (m *InstanceMsg) Reset()                    { *m = InstanceMsg{} }
func (*InstanceMsg) ProtoMessage()               {}
func (*InstanceMsg) Descriptor() ([]byte, []int) { return fileDescriptorTmplHandlerService, []int{1} }

// Contains inferred type information about specific instance of 'samplecheck' template. This is passed to
// infrastructure backends during configuration-time through [InfrastructureBackend.CreateSession][TODO: Link to this fragment].
type Type struct {
}

func (m *Type) Reset()                    { *m = Type{} }
func (*Type) ProtoMessage()               {}
func (*Type) Descriptor() ([]byte, []int) { return fileDescriptorTmplHandlerService, []int{2} }

// Represents instance configuration schema for 'samplecheck' template.
type InstanceParam struct {
	StringPrimitive string `protobuf:"bytes,4,opt,name=stringPrimitive,proto3" json:"stringPrimitive,omitempty"`
}

func (m *InstanceParam) Reset()                    { *m = InstanceParam{} }
func (*InstanceParam) ProtoMessage()               {}
func (*InstanceParam) Descriptor() ([]byte, []int) { return fileDescriptorTmplHandlerService, []int{3} }

func init() {
	proto.RegisterType((*HandleSampleCheckRequest)(nil), "samplecheck.HandleSampleCheckRequest")
	proto.RegisterType((*InstanceMsg)(nil), "samplecheck.InstanceMsg")
	proto.RegisterType((*Type)(nil), "samplecheck.Type")
	proto.RegisterType((*InstanceParam)(nil), "samplecheck.InstanceParam")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for HandleSampleCheckService service

type HandleSampleCheckServiceClient interface {
	// HandleSampleCheck is called by Mixer at request-time to deliver 'samplecheck' instances to the backend.
	HandleSampleCheck(ctx context.Context, in *HandleSampleCheckRequest, opts ...grpc.CallOption) (*istio_mixer_adapter_model_v1beta11.CheckResult, error)
}

type handleSampleCheckServiceClient struct {
	cc *grpc.ClientConn
}

func NewHandleSampleCheckServiceClient(cc *grpc.ClientConn) HandleSampleCheckServiceClient {
	return &handleSampleCheckServiceClient{cc}
}

func (c *handleSampleCheckServiceClient) HandleSampleCheck(ctx context.Context, in *HandleSampleCheckRequest, opts ...grpc.CallOption) (*istio_mixer_adapter_model_v1beta11.CheckResult, error) {
	out := new(istio_mixer_adapter_model_v1beta11.CheckResult)
	err := grpc.Invoke(ctx, "/samplecheck.HandleSampleCheckService/HandleSampleCheck", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for HandleSampleCheckService service

type HandleSampleCheckServiceServer interface {
	// HandleSampleCheck is called by Mixer at request-time to deliver 'samplecheck' instances to the backend.
	HandleSampleCheck(context.Context, *HandleSampleCheckRequest) (*istio_mixer_adapter_model_v1beta11.CheckResult, error)
}

func RegisterHandleSampleCheckServiceServer(s *grpc.Server, srv HandleSampleCheckServiceServer) {
	s.RegisterService(&_HandleSampleCheckService_serviceDesc, srv)
}

func _HandleSampleCheckService_HandleSampleCheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HandleSampleCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HandleSampleCheckServiceServer).HandleSampleCheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/samplecheck.HandleSampleCheckService/HandleSampleCheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HandleSampleCheckServiceServer).HandleSampleCheck(ctx, req.(*HandleSampleCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _HandleSampleCheckService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "samplecheck.HandleSampleCheckService",
	HandlerType: (*HandleSampleCheckServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "HandleSampleCheck",
			Handler:    _HandleSampleCheckService_HandleSampleCheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "mixer/test/spyAdapter/template/check/tmpl_handler_service.proto",
}

func (m *HandleSampleCheckRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *HandleSampleCheckRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Instance != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintTmplHandlerService(dAtA, i, uint64(m.Instance.Size()))
		n1, err := m.Instance.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.AdapterConfig != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintTmplHandlerService(dAtA, i, uint64(m.AdapterConfig.Size()))
		n2, err := m.AdapterConfig.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if len(m.DedupId) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintTmplHandlerService(dAtA, i, uint64(len(m.DedupId)))
		i += copy(dAtA[i:], m.DedupId)
	}
	return i, nil
}

func (m *InstanceMsg) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *InstanceMsg) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.StringPrimitive) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintTmplHandlerService(dAtA, i, uint64(len(m.StringPrimitive)))
		i += copy(dAtA[i:], m.StringPrimitive)
	}
	if len(m.Name) > 0 {
		dAtA[i] = 0xfa
		i++
		dAtA[i] = 0xd2
		i++
		dAtA[i] = 0xe4
		i++
		dAtA[i] = 0x93
		i++
		dAtA[i] = 0x2
		i++
		i = encodeVarintTmplHandlerService(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	return i, nil
}

func (m *Type) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Type) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	return i, nil
}

func (m *InstanceParam) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *InstanceParam) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.StringPrimitive) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintTmplHandlerService(dAtA, i, uint64(len(m.StringPrimitive)))
		i += copy(dAtA[i:], m.StringPrimitive)
	}
	return i, nil
}

func encodeVarintTmplHandlerService(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *HandleSampleCheckRequest) Size() (n int) {
	var l int
	_ = l
	if m.Instance != nil {
		l = m.Instance.Size()
		n += 1 + l + sovTmplHandlerService(uint64(l))
	}
	if m.AdapterConfig != nil {
		l = m.AdapterConfig.Size()
		n += 1 + l + sovTmplHandlerService(uint64(l))
	}
	l = len(m.DedupId)
	if l > 0 {
		n += 1 + l + sovTmplHandlerService(uint64(l))
	}
	return n
}

func (m *InstanceMsg) Size() (n int) {
	var l int
	_ = l
	l = len(m.StringPrimitive)
	if l > 0 {
		n += 1 + l + sovTmplHandlerService(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 5 + l + sovTmplHandlerService(uint64(l))
	}
	return n
}

func (m *Type) Size() (n int) {
	var l int
	_ = l
	return n
}

func (m *InstanceParam) Size() (n int) {
	var l int
	_ = l
	l = len(m.StringPrimitive)
	if l > 0 {
		n += 1 + l + sovTmplHandlerService(uint64(l))
	}
	return n
}

func sovTmplHandlerService(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozTmplHandlerService(x uint64) (n int) {
	return sovTmplHandlerService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *HandleSampleCheckRequest) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&HandleSampleCheckRequest{`,
		`Instance:` + strings.Replace(fmt.Sprintf("%v", this.Instance), "InstanceMsg", "InstanceMsg", 1) + `,`,
		`AdapterConfig:` + strings.Replace(fmt.Sprintf("%v", this.AdapterConfig), "Any", "google_protobuf1.Any", 1) + `,`,
		`DedupId:` + fmt.Sprintf("%v", this.DedupId) + `,`,
		`}`,
	}, "")
	return s
}
func (this *InstanceMsg) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&InstanceMsg{`,
		`StringPrimitive:` + fmt.Sprintf("%v", this.StringPrimitive) + `,`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Type) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Type{`,
		`}`,
	}, "")
	return s
}
func (this *InstanceParam) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&InstanceParam{`,
		`StringPrimitive:` + fmt.Sprintf("%v", this.StringPrimitive) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringTmplHandlerService(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *HandleSampleCheckRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTmplHandlerService
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
			return fmt.Errorf("proto: HandleSampleCheckRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: HandleSampleCheckRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Instance", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplHandlerService
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
				return ErrInvalidLengthTmplHandlerService
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Instance == nil {
				m.Instance = &InstanceMsg{}
			}
			if err := m.Instance.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AdapterConfig", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplHandlerService
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
				return ErrInvalidLengthTmplHandlerService
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.AdapterConfig == nil {
				m.AdapterConfig = &google_protobuf1.Any{}
			}
			if err := m.AdapterConfig.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DedupId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplHandlerService
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
				return ErrInvalidLengthTmplHandlerService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DedupId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTmplHandlerService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTmplHandlerService
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
func (m *InstanceMsg) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTmplHandlerService
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
			return fmt.Errorf("proto: InstanceMsg: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: InstanceMsg: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StringPrimitive", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplHandlerService
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
				return ErrInvalidLengthTmplHandlerService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.StringPrimitive = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 72295727:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplHandlerService
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
				return ErrInvalidLengthTmplHandlerService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTmplHandlerService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTmplHandlerService
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
func (m *Type) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTmplHandlerService
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
			return fmt.Errorf("proto: Type: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Type: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipTmplHandlerService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTmplHandlerService
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
func (m *InstanceParam) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTmplHandlerService
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
			return fmt.Errorf("proto: InstanceParam: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: InstanceParam: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StringPrimitive", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplHandlerService
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
				return ErrInvalidLengthTmplHandlerService
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.StringPrimitive = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTmplHandlerService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTmplHandlerService
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
func skipTmplHandlerService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTmplHandlerService
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
					return 0, ErrIntOverflowTmplHandlerService
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
					return 0, ErrIntOverflowTmplHandlerService
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
				return 0, ErrInvalidLengthTmplHandlerService
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowTmplHandlerService
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
				next, err := skipTmplHandlerService(dAtA[start:])
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
	ErrInvalidLengthTmplHandlerService = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTmplHandlerService   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("mixer/test/spyAdapter/template/check/tmpl_handler_service.proto", fileDescriptorTmplHandlerService)
}

var fileDescriptorTmplHandlerService = []byte{
	// 461 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0xbf, 0x6e, 0xd4, 0x40,
	0x10, 0xc6, 0xbd, 0xc7, 0x29, 0x84, 0x3d, 0x05, 0x84, 0x15, 0x24, 0xe7, 0x8a, 0x55, 0x64, 0x09,
	0x71, 0x05, 0xda, 0x55, 0x02, 0x0d, 0xa2, 0x40, 0x21, 0x05, 0xa4, 0x00, 0x45, 0x17, 0xfa, 0xd3,
	0x9e, 0x3d, 0x71, 0x16, 0xec, 0x5d, 0xe3, 0xdd, 0x3b, 0xe5, 0x3a, 0x44, 0x41, 0x8d, 0x94, 0x97,
	0x48, 0xc7, 0x0b, 0xf0, 0x00, 0x11, 0x55, 0x44, 0x45, 0x83, 0x84, 0x4d, 0x0a, 0xca, 0x94, 0x94,
	0x28, 0xe3, 0x0d, 0x3a, 0xfe, 0x2a, 0x9d, 0x67, 0xe6, 0x37, 0x33, 0x9f, 0xe7, 0x5b, 0xfa, 0xa0,
	0x50, 0xfb, 0x50, 0x09, 0x07, 0xd6, 0x09, 0x5b, 0xce, 0x36, 0x52, 0x59, 0x3a, 0x8c, 0x8b, 0x32,
	0x97, 0x0e, 0x44, 0xb2, 0x07, 0xc9, 0x0b, 0xe1, 0x8a, 0x32, 0x1f, 0xed, 0x49, 0x9d, 0xe6, 0x50,
	0x8d, 0x2c, 0x54, 0x53, 0x95, 0x00, 0x2f, 0x2b, 0xe3, 0x4c, 0xd8, 0xb3, 0xb2, 0x28, 0x73, 0x40,
	0xae, 0xbf, 0x9c, 0x99, 0xcc, 0x60, 0x5e, 0x9c, 0x7d, 0xb5, 0x48, 0xff, 0x76, 0xbb, 0x43, 0xfa,
	0xd9, 0x85, 0x49, 0x21, 0x17, 0xd3, 0xb5, 0x31, 0x38, 0xb9, 0x26, 0x60, 0xdf, 0x81, 0xb6, 0xca,
	0x68, 0xeb, 0xe9, 0x95, 0xcc, 0x98, 0x2c, 0x07, 0x81, 0xd1, 0x78, 0xb2, 0x2b, 0xa4, 0x9e, 0xf9,
	0xd2, 0xad, 0xff, 0x0d, 0x42, 0x05, 0x2d, 0x18, 0x1f, 0x12, 0x1a, 0x3d, 0x46, 0xb9, 0x3b, 0xa8,
	0x6e, 0xf3, 0xac, 0x36, 0x84, 0x97, 0x13, 0xb0, 0x2e, 0xbc, 0x4b, 0x17, 0x95, 0xb6, 0x4e, 0xea,
	0x04, 0x22, 0xb2, 0x4a, 0x06, 0xbd, 0xf5, 0x88, 0xcf, 0xfd, 0x04, 0xdf, 0xf2, 0xc5, 0x27, 0x36,
	0x1b, 0xfe, 0x24, 0xc3, 0xfb, 0xf4, 0xaa, 0xdf, 0x3b, 0x4a, 0x8c, 0xde, 0x55, 0x59, 0xd4, 0xc1,
	0xde, 0x65, 0xde, 0xea, 0xe5, 0xe7, 0x7a, 0xf9, 0x86, 0x9e, 0x0d, 0x97, 0x3c, 0xbb, 0x89, 0x68,
	0xb8, 0x42, 0x17, 0x53, 0x48, 0x27, 0xe5, 0x48, 0xa5, 0xd1, 0xa5, 0x55, 0x32, 0xb8, 0x32, 0xbc,
	0x8c, 0xf1, 0x56, 0x1a, 0x3f, 0xa5, 0xbd, 0xb9, 0x85, 0xe1, 0x80, 0x5e, 0xb3, 0xae, 0x52, 0x3a,
	0xdb, 0xae, 0x54, 0xa1, 0x9c, 0x9a, 0x42, 0xd4, 0xc5, 0x86, 0xdf, 0xd3, 0xe1, 0x0d, 0xda, 0xd5,
	0xb2, 0x80, 0xe8, 0xdd, 0x87, 0xf7, 0x31, 0x12, 0x18, 0xc6, 0x0b, 0xb4, 0xfb, 0x6c, 0x56, 0x42,
	0x7c, 0x8f, 0x2e, 0x9d, 0xcf, 0xdd, 0x96, 0x95, 0x2c, 0x2e, 0x3e, 0x79, 0xfd, 0xcd, 0xdf, 0xae,
	0xb7, 0xd3, 0xba, 0x1e, 0x3e, 0xa7, 0xd7, 0xff, 0xa8, 0x85, 0x37, 0x7f, 0x39, 0xe0, 0xbf, 0x2e,
	0xdf, 0xe7, 0x5c, 0x59, 0xa7, 0x0c, 0x47, 0x1b, 0xb9, 0x3f, 0x11, 0x47, 0x1b, 0xb9, 0xb7, 0x91,
	0xfb, 0x06, 0x3b, 0xc9, 0xdd, 0xc3, 0x47, 0x47, 0x35, 0x0b, 0x8e, 0x6b, 0x16, 0x7c, 0xaa, 0x59,
	0x70, 0x5a, 0xb3, 0xe0, 0x55, 0xc3, 0xc8, 0x61, 0xc3, 0x82, 0xa3, 0x86, 0x91, 0xe3, 0x86, 0x91,
	0x2f, 0x0d, 0x23, 0xdf, 0x1a, 0x16, 0x9c, 0x36, 0x8c, 0xbc, 0xfd, 0xca, 0x82, 0xef, 0x1f, 0x4f,
	0x0e, 0x3a, 0xc1, 0xeb, 0xcf, 0x27, 0x07, 0x9d, 0xf9, 0x77, 0x39, 0x5e, 0x40, 0x73, 0xee, 0xfc,
	0x08, 0x00, 0x00, 0xff, 0xff, 0x71, 0x05, 0xaf, 0x25, 0xee, 0x02, 0x00, 0x00,
}

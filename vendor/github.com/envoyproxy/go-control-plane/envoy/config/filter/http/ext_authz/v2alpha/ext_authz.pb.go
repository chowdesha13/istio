// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/config/filter/http/ext_authz/v2alpha/ext_authz.proto

package v2alpha

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"

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

// External Authorization filter calls out to an external service over either:
//
//  1. gRPC Authorization API defined by :ref:`CheckRequest
//     <envoy_api_msg_service.auth.v2alpha.CheckRequest>`.
//  2. Raw HTTP Authorization server by passing the request headers to the service.
//
// A failed check will cause this filter to close the HTTP request normally with 403 (Forbidden),
// unless a different status code has been indicated in the authorization response.
type ExtAuthz struct {
	// Types that are valid to be assigned to Services:
	//	*ExtAuthz_GrpcService
	//	*ExtAuthz_HttpService
	Services isExtAuthz_Services `protobuf_oneof:"services"`
	// The filter's behaviour in case the external authorization service does
	// not respond back. When it is set to true, Envoy will also allow traffic in case of
	// an error occurs during the authorization process.
	// Defaults to false.
	FailureModeAllow     bool     `protobuf:"varint,2,opt,name=failure_mode_allow,json=failureModeAllow,proto3" json:"failure_mode_allow,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExtAuthz) Reset()         { *m = ExtAuthz{} }
func (m *ExtAuthz) String() string { return proto.CompactTextString(m) }
func (*ExtAuthz) ProtoMessage()    {}
func (*ExtAuthz) Descriptor() ([]byte, []int) {
	return fileDescriptor_ext_authz_a9ec494a4c3db5d2, []int{0}
}
func (m *ExtAuthz) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ExtAuthz) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ExtAuthz.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *ExtAuthz) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExtAuthz.Merge(dst, src)
}
func (m *ExtAuthz) XXX_Size() int {
	return m.Size()
}
func (m *ExtAuthz) XXX_DiscardUnknown() {
	xxx_messageInfo_ExtAuthz.DiscardUnknown(m)
}

var xxx_messageInfo_ExtAuthz proto.InternalMessageInfo

type isExtAuthz_Services interface {
	isExtAuthz_Services()
	MarshalTo([]byte) (int, error)
	Size() int
}

type ExtAuthz_GrpcService struct {
	GrpcService *core.GrpcService `protobuf:"bytes,1,opt,name=grpc_service,json=grpcService,oneof"`
}
type ExtAuthz_HttpService struct {
	HttpService *HttpService `protobuf:"bytes,3,opt,name=http_service,json=httpService,oneof"`
}

func (*ExtAuthz_GrpcService) isExtAuthz_Services() {}
func (*ExtAuthz_HttpService) isExtAuthz_Services() {}

func (m *ExtAuthz) GetServices() isExtAuthz_Services {
	if m != nil {
		return m.Services
	}
	return nil
}

func (m *ExtAuthz) GetGrpcService() *core.GrpcService {
	if x, ok := m.GetServices().(*ExtAuthz_GrpcService); ok {
		return x.GrpcService
	}
	return nil
}

func (m *ExtAuthz) GetHttpService() *HttpService {
	if x, ok := m.GetServices().(*ExtAuthz_HttpService); ok {
		return x.HttpService
	}
	return nil
}

func (m *ExtAuthz) GetFailureModeAllow() bool {
	if m != nil {
		return m.FailureModeAllow
	}
	return false
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*ExtAuthz) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _ExtAuthz_OneofMarshaler, _ExtAuthz_OneofUnmarshaler, _ExtAuthz_OneofSizer, []interface{}{
		(*ExtAuthz_GrpcService)(nil),
		(*ExtAuthz_HttpService)(nil),
	}
}

func _ExtAuthz_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*ExtAuthz)
	// services
	switch x := m.Services.(type) {
	case *ExtAuthz_GrpcService:
		_ = b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.GrpcService); err != nil {
			return err
		}
	case *ExtAuthz_HttpService:
		_ = b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.HttpService); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("ExtAuthz.Services has unexpected type %T", x)
	}
	return nil
}

func _ExtAuthz_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*ExtAuthz)
	switch tag {
	case 1: // services.grpc_service
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(core.GrpcService)
		err := b.DecodeMessage(msg)
		m.Services = &ExtAuthz_GrpcService{msg}
		return true, err
	case 3: // services.http_service
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(HttpService)
		err := b.DecodeMessage(msg)
		m.Services = &ExtAuthz_HttpService{msg}
		return true, err
	default:
		return false, nil
	}
}

func _ExtAuthz_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*ExtAuthz)
	// services
	switch x := m.Services.(type) {
	case *ExtAuthz_GrpcService:
		s := proto.Size(x.GrpcService)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *ExtAuthz_HttpService:
		s := proto.Size(x.HttpService)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// External Authorization filter calls out to an upstream authorization server by passing the raw
// HTTP request headers to the server. This allows the authorization service to take a decision
// whether the request is authorized or not.
//
// A successful check allows the authorization service adding or overriding headers from the
// original request before dispatching it to the upstream. This is done by configuring which headers
// in the authorization response should be sent to the upstream. See *allowed_authorization_headers*
// bellow.
//
// A failed check will cause this filter to close the HTTP request with 403 (Forbidden),
// unless a different status code has been indicated by the authorization server via response
// headers.
//
// If an error happens during the checking process, two situations may occur depending on the
// filter's configuration:
//
//  1. When *failure_mode_allow* is true, traffic will be allowed in the presence of an error. This
//     includes any of the HTTP 5xx errors, or a communication failure between the filter and the
//     authorization server.
//  2. When *failure_mode_allow* is false, the filter will *always* return a *Forbidden response* to
//     the client. It will *not allow* traffic to the upstream in the presence of an error. This
//     includes any of the HTTP 5xx errors, or a communication failure between the filter and the
//     authorization server.
//
// Note that filter will produce stats on error. See *Statistics* at :ref:`configuration overview
// <config_http_filters_ext_authz>`.
type HttpService struct {
	// Sets the HTTP server URI which the authorization requests must be sent to.
	ServerUri *core.HttpUri `protobuf:"bytes,1,opt,name=server_uri,json=serverUri" json:"server_uri,omitempty"`
	// Sets an optional prefix to the value of authorization request header *Path*.
	PathPrefix string `protobuf:"bytes,2,opt,name=path_prefix,json=pathPrefix,proto3" json:"path_prefix,omitempty"`
	// Sets a list of headers that can be sent from the authorization server to the upstream service,
	// or to the downstream client when present in the authorization response. Note that a matched
	// request header will have its value overridden by the ones sent from the authorization server.
	AllowedAuthorizationHeaders []string `protobuf:"bytes,4,rep,name=allowed_authorization_headers,json=allowedAuthorizationHeaders" json:"allowed_authorization_headers,omitempty"`
	// Sets a list of headers that should be sent *from the filter* to the authorization server
	// when they are also present in the client request. Note that *Content-Length*, *Authority*,
	// *Method* and *Path* are always dispatched to the authorization server by default. The message
	// will not contain body data and the *Content-Length* will be set to zero.
	AllowedRequestHeaders []string `protobuf:"bytes,5,rep,name=allowed_request_headers,json=allowedRequestHeaders" json:"allowed_request_headers,omitempty"`
	// Sets a list of headers and their values that will be added to the request to external
	// authorization server. Note that these will override the headers coming from the downstream.
	AuthorizationHeadersToAdd []*core.HeaderValue `protobuf:"bytes,6,rep,name=authorization_headers_to_add,json=authorizationHeadersToAdd" json:"authorization_headers_to_add,omitempty"`
	XXX_NoUnkeyedLiteral      struct{}            `json:"-"`
	XXX_unrecognized          []byte              `json:"-"`
	XXX_sizecache             int32               `json:"-"`
}

func (m *HttpService) Reset()         { *m = HttpService{} }
func (m *HttpService) String() string { return proto.CompactTextString(m) }
func (*HttpService) ProtoMessage()    {}
func (*HttpService) Descriptor() ([]byte, []int) {
	return fileDescriptor_ext_authz_a9ec494a4c3db5d2, []int{1}
}
func (m *HttpService) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *HttpService) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_HttpService.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *HttpService) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HttpService.Merge(dst, src)
}
func (m *HttpService) XXX_Size() int {
	return m.Size()
}
func (m *HttpService) XXX_DiscardUnknown() {
	xxx_messageInfo_HttpService.DiscardUnknown(m)
}

var xxx_messageInfo_HttpService proto.InternalMessageInfo

func (m *HttpService) GetServerUri() *core.HttpUri {
	if m != nil {
		return m.ServerUri
	}
	return nil
}

func (m *HttpService) GetPathPrefix() string {
	if m != nil {
		return m.PathPrefix
	}
	return ""
}

func (m *HttpService) GetAllowedAuthorizationHeaders() []string {
	if m != nil {
		return m.AllowedAuthorizationHeaders
	}
	return nil
}

func (m *HttpService) GetAllowedRequestHeaders() []string {
	if m != nil {
		return m.AllowedRequestHeaders
	}
	return nil
}

func (m *HttpService) GetAuthorizationHeadersToAdd() []*core.HeaderValue {
	if m != nil {
		return m.AuthorizationHeadersToAdd
	}
	return nil
}

func init() {
	proto.RegisterType((*ExtAuthz)(nil), "envoy.config.filter.http.ext_authz.v2alpha.ExtAuthz")
	proto.RegisterType((*HttpService)(nil), "envoy.config.filter.http.ext_authz.v2alpha.HttpService")
}
func (m *ExtAuthz) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ExtAuthz) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Services != nil {
		nn1, err := m.Services.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += nn1
	}
	if m.FailureModeAllow {
		dAtA[i] = 0x10
		i++
		if m.FailureModeAllow {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *ExtAuthz_GrpcService) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	if m.GrpcService != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintExtAuthz(dAtA, i, uint64(m.GrpcService.Size()))
		n2, err := m.GrpcService.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	return i, nil
}
func (m *ExtAuthz_HttpService) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	if m.HttpService != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintExtAuthz(dAtA, i, uint64(m.HttpService.Size()))
		n3, err := m.HttpService.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	return i, nil
}
func (m *HttpService) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *HttpService) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.ServerUri != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintExtAuthz(dAtA, i, uint64(m.ServerUri.Size()))
		n4, err := m.ServerUri.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n4
	}
	if len(m.PathPrefix) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintExtAuthz(dAtA, i, uint64(len(m.PathPrefix)))
		i += copy(dAtA[i:], m.PathPrefix)
	}
	if len(m.AllowedAuthorizationHeaders) > 0 {
		for _, s := range m.AllowedAuthorizationHeaders {
			dAtA[i] = 0x22
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	if len(m.AllowedRequestHeaders) > 0 {
		for _, s := range m.AllowedRequestHeaders {
			dAtA[i] = 0x2a
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	if len(m.AuthorizationHeadersToAdd) > 0 {
		for _, msg := range m.AuthorizationHeadersToAdd {
			dAtA[i] = 0x32
			i++
			i = encodeVarintExtAuthz(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintExtAuthz(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *ExtAuthz) Size() (n int) {
	var l int
	_ = l
	if m.Services != nil {
		n += m.Services.Size()
	}
	if m.FailureModeAllow {
		n += 2
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *ExtAuthz_GrpcService) Size() (n int) {
	var l int
	_ = l
	if m.GrpcService != nil {
		l = m.GrpcService.Size()
		n += 1 + l + sovExtAuthz(uint64(l))
	}
	return n
}
func (m *ExtAuthz_HttpService) Size() (n int) {
	var l int
	_ = l
	if m.HttpService != nil {
		l = m.HttpService.Size()
		n += 1 + l + sovExtAuthz(uint64(l))
	}
	return n
}
func (m *HttpService) Size() (n int) {
	var l int
	_ = l
	if m.ServerUri != nil {
		l = m.ServerUri.Size()
		n += 1 + l + sovExtAuthz(uint64(l))
	}
	l = len(m.PathPrefix)
	if l > 0 {
		n += 1 + l + sovExtAuthz(uint64(l))
	}
	if len(m.AllowedAuthorizationHeaders) > 0 {
		for _, s := range m.AllowedAuthorizationHeaders {
			l = len(s)
			n += 1 + l + sovExtAuthz(uint64(l))
		}
	}
	if len(m.AllowedRequestHeaders) > 0 {
		for _, s := range m.AllowedRequestHeaders {
			l = len(s)
			n += 1 + l + sovExtAuthz(uint64(l))
		}
	}
	if len(m.AuthorizationHeadersToAdd) > 0 {
		for _, e := range m.AuthorizationHeadersToAdd {
			l = e.Size()
			n += 1 + l + sovExtAuthz(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovExtAuthz(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozExtAuthz(x uint64) (n int) {
	return sovExtAuthz(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ExtAuthz) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowExtAuthz
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
			return fmt.Errorf("proto: ExtAuthz: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ExtAuthz: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field GrpcService", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
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
				return ErrInvalidLengthExtAuthz
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &core.GrpcService{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Services = &ExtAuthz_GrpcService{v}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field FailureModeAllow", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.FailureModeAllow = bool(v != 0)
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HttpService", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
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
				return ErrInvalidLengthExtAuthz
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &HttpService{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Services = &ExtAuthz_HttpService{v}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipExtAuthz(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthExtAuthz
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
func (m *HttpService) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowExtAuthz
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
			return fmt.Errorf("proto: HttpService: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: HttpService: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ServerUri", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
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
				return ErrInvalidLengthExtAuthz
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ServerUri == nil {
				m.ServerUri = &core.HttpUri{}
			}
			if err := m.ServerUri.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PathPrefix", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
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
				return ErrInvalidLengthExtAuthz
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PathPrefix = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AllowedAuthorizationHeaders", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
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
				return ErrInvalidLengthExtAuthz
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AllowedAuthorizationHeaders = append(m.AllowedAuthorizationHeaders, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AllowedRequestHeaders", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
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
				return ErrInvalidLengthExtAuthz
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AllowedRequestHeaders = append(m.AllowedRequestHeaders, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AuthorizationHeadersToAdd", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExtAuthz
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
				return ErrInvalidLengthExtAuthz
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AuthorizationHeadersToAdd = append(m.AuthorizationHeadersToAdd, &core.HeaderValue{})
			if err := m.AuthorizationHeadersToAdd[len(m.AuthorizationHeadersToAdd)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipExtAuthz(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthExtAuthz
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
func skipExtAuthz(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowExtAuthz
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
					return 0, ErrIntOverflowExtAuthz
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
					return 0, ErrIntOverflowExtAuthz
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
				return 0, ErrInvalidLengthExtAuthz
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowExtAuthz
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
				next, err := skipExtAuthz(dAtA[start:])
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
	ErrInvalidLengthExtAuthz = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowExtAuthz   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("envoy/config/filter/http/ext_authz/v2alpha/ext_authz.proto", fileDescriptor_ext_authz_a9ec494a4c3db5d2)
}

var fileDescriptor_ext_authz_a9ec494a4c3db5d2 = []byte{
	// 441 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x41, 0x8b, 0x13, 0x31,
	0x14, 0xc7, 0x9d, 0x6d, 0x5d, 0xdb, 0x74, 0x0f, 0x4b, 0x60, 0xb1, 0xd6, 0xb5, 0x0e, 0x8b, 0x87,
	0x22, 0x92, 0x40, 0x05, 0x45, 0x6f, 0xad, 0x88, 0x45, 0x10, 0x64, 0x74, 0x3d, 0x88, 0x10, 0xb2,
	0x93, 0xd7, 0x4e, 0x60, 0x6c, 0x62, 0x26, 0x33, 0xd6, 0xfd, 0x84, 0x1e, 0x3c, 0xf8, 0x11, 0xa4,
	0x17, 0xbf, 0x86, 0x24, 0x99, 0x3a, 0x03, 0xad, 0xe0, 0x31, 0xef, 0xfd, 0xfe, 0xff, 0xff, 0x7b,
	0x49, 0xd0, 0x73, 0x58, 0x57, 0xea, 0x1b, 0x4d, 0xd5, 0x7a, 0x29, 0x57, 0x74, 0x29, 0x73, 0x0b,
	0x86, 0x66, 0xd6, 0x6a, 0x0a, 0x1b, 0xcb, 0x78, 0x69, 0xb3, 0x6b, 0x5a, 0x4d, 0x79, 0xae, 0x33,
	0xde, 0x54, 0x88, 0x36, 0xca, 0x2a, 0xfc, 0xd0, 0x6b, 0x49, 0xd0, 0x92, 0xa0, 0x25, 0x4e, 0x4b,
	0x1a, 0xb2, 0xd6, 0x8e, 0xce, 0x43, 0x0e, 0xd7, 0x92, 0x56, 0x53, 0x9a, 0x2a, 0x03, 0xf4, 0x8a,
	0x17, 0x10, 0x9c, 0x46, 0x0f, 0xf6, 0xbb, 0x2b, 0xa3, 0x53, 0x56, 0x80, 0xa9, 0x64, 0xba, 0xa3,
	0xe2, 0x7d, 0xca, 0xa5, 0xb1, 0xd2, 0xc8, 0x40, 0x5c, 0xfc, 0x8e, 0x50, 0xef, 0xe5, 0xc6, 0xce,
	0x5c, 0x34, 0x7e, 0x81, 0x4e, 0xda, 0x26, 0xc3, 0x28, 0x8e, 0x26, 0x83, 0xe9, 0x98, 0x84, 0xa9,
	0xb9, 0x96, 0xa4, 0x9a, 0x12, 0xe7, 0x42, 0x5e, 0x19, 0x9d, 0xbe, 0x0b, 0xd4, 0xe2, 0x46, 0x32,
	0x58, 0x35, 0x47, 0xfc, 0x08, 0xe1, 0x25, 0x97, 0x79, 0x69, 0x80, 0x7d, 0x56, 0x02, 0x18, 0xcf,
	0x73, 0xf5, 0x75, 0x78, 0x14, 0x47, 0x93, 0x5e, 0x72, 0x5a, 0x77, 0xde, 0x28, 0x01, 0x33, 0x57,
	0xc7, 0x9f, 0xd0, 0x89, 0x9f, 0x68, 0x17, 0xd9, 0xf1, 0x91, 0x4f, 0xc9, 0xff, 0x5f, 0x14, 0x59,
	0x58, 0xab, 0x5b, 0xb3, 0x64, 0xcd, 0x71, 0x8e, 0x50, 0xaf, 0x36, 0x2e, 0x2e, 0x7e, 0x1c, 0xa1,
	0x41, 0x0b, 0xc5, 0xcf, 0x10, 0x72, 0x3d, 0x30, 0xee, 0x36, 0xea, 0x55, 0x47, 0x07, 0x56, 0x75,
	0x9a, 0x4b, 0x23, 0x93, 0x7e, 0xa0, 0x2f, 0x8d, 0xc4, 0xf7, 0xd1, 0x40, 0x73, 0x9b, 0x31, 0x6d,
	0x60, 0x29, 0x37, 0x7e, 0xb7, 0x7e, 0x82, 0x5c, 0xe9, 0xad, 0xaf, 0xe0, 0x39, 0xba, 0xe7, 0xd7,
	0x06, 0xe1, 0x67, 0x55, 0x46, 0x5e, 0x73, 0x2b, 0xd5, 0x9a, 0x65, 0xc0, 0x05, 0x98, 0x62, 0xd8,
	0x8d, 0x3b, 0x93, 0x7e, 0x72, 0xb7, 0x86, 0x66, 0x6d, 0x66, 0x11, 0x10, 0xfc, 0x04, 0xdd, 0xde,
	0x79, 0x18, 0xf8, 0x52, 0x42, 0x61, 0xff, 0xaa, 0x6f, 0x7a, 0xf5, 0x59, 0xdd, 0x4e, 0x42, 0x77,
	0xa7, 0x63, 0xe8, 0xfc, 0x60, 0x26, 0xb3, 0x8a, 0x71, 0x21, 0x86, 0xc7, 0x71, 0xe7, 0x1f, 0x8f,
	0x1a, 0x1c, 0x3e, 0xf0, 0xbc, 0x84, 0xe4, 0x0e, 0x3f, 0x30, 0xd3, 0x7b, 0x35, 0x13, 0xe2, 0x75,
	0xb7, 0xd7, 0x39, 0xed, 0xce, 0xcf, 0xbe, 0x6f, 0xc7, 0xd1, 0xcf, 0xed, 0x38, 0xfa, 0xb5, 0x1d,
	0x47, 0x1f, 0x6f, 0xd5, 0x8f, 0x71, 0x75, 0xec, 0xbf, 0xd5, 0xe3, 0x3f, 0x01, 0x00, 0x00, 0xff,
	0xff, 0x5d, 0x36, 0xe2, 0x3a, 0x26, 0x03, 0x00, 0x00,
}

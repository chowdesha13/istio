// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/api/v2/core/protocol.proto

package core

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/types"
import google_protobuf "github.com/gogo/protobuf/types"
import _ "github.com/lyft/protoc-gen-validate/validate"
import _ "github.com/gogo/protobuf/gogoproto"

import time "time"

import github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// [#not-implemented-hide:]
type TcpProtocolOptions struct {
}

func (m *TcpProtocolOptions) Reset()                    { *m = TcpProtocolOptions{} }
func (m *TcpProtocolOptions) String() string            { return proto.CompactTextString(m) }
func (*TcpProtocolOptions) ProtoMessage()               {}
func (*TcpProtocolOptions) Descriptor() ([]byte, []int) { return fileDescriptorProtocol, []int{0} }

type HttpProtocolOptions struct {
	// The idle timeout for upstream connection pool connections. The idle timeout is defined as the
	// period in which there are no active requests. If not set, there is no idle timeout. When the
	// idle timeout is reached the connection will be closed. Note that request based timeouts mean
	// that HTTP/2 PINGs will not keep the connection alive.
	IdleTimeout *time.Duration `protobuf:"bytes,1,opt,name=idle_timeout,json=idleTimeout,stdduration" json:"idle_timeout,omitempty"`
}

func (m *HttpProtocolOptions) Reset()                    { *m = HttpProtocolOptions{} }
func (m *HttpProtocolOptions) String() string            { return proto.CompactTextString(m) }
func (*HttpProtocolOptions) ProtoMessage()               {}
func (*HttpProtocolOptions) Descriptor() ([]byte, []int) { return fileDescriptorProtocol, []int{1} }

func (m *HttpProtocolOptions) GetIdleTimeout() *time.Duration {
	if m != nil {
		return m.IdleTimeout
	}
	return nil
}

type Http1ProtocolOptions struct {
	// Handle HTTP requests with absolute URLs in the requests. These requests
	// are generally sent by clients to forward/explicit proxies. This allows clients to configure
	// envoy as their HTTP proxy. In Unix, for example, this is typically done by setting the
	// *http_proxy* environment variable.
	AllowAbsoluteUrl *google_protobuf.BoolValue `protobuf:"bytes,1,opt,name=allow_absolute_url,json=allowAbsoluteUrl" json:"allow_absolute_url,omitempty"`
	// Handle incoming HTTP/1.0 and HTTP 0.9 requests.
	// This is off by default, and not fully standards compliant. There is support for pre-HTTP/1.1
	// style connect logic, dechunking, and handling lack of client host iff
	// *default_host_for_http_10* is configured.
	AcceptHttp_10 bool `protobuf:"varint,2,opt,name=accept_http_10,json=acceptHttp10,proto3" json:"accept_http_10,omitempty"`
	// A default host for HTTP/1.0 requests. This is highly suggested if *accept_http_10* is true as
	// Envoy does not otherwise support HTTP/1.0 without a Host header.
	// This is a no-op if *accept_http_10* is not true.
	DefaultHostForHttp_10 string `protobuf:"bytes,3,opt,name=default_host_for_http_10,json=defaultHostForHttp10,proto3" json:"default_host_for_http_10,omitempty"`
}

func (m *Http1ProtocolOptions) Reset()                    { *m = Http1ProtocolOptions{} }
func (m *Http1ProtocolOptions) String() string            { return proto.CompactTextString(m) }
func (*Http1ProtocolOptions) ProtoMessage()               {}
func (*Http1ProtocolOptions) Descriptor() ([]byte, []int) { return fileDescriptorProtocol, []int{2} }

func (m *Http1ProtocolOptions) GetAllowAbsoluteUrl() *google_protobuf.BoolValue {
	if m != nil {
		return m.AllowAbsoluteUrl
	}
	return nil
}

func (m *Http1ProtocolOptions) GetAcceptHttp_10() bool {
	if m != nil {
		return m.AcceptHttp_10
	}
	return false
}

func (m *Http1ProtocolOptions) GetDefaultHostForHttp_10() string {
	if m != nil {
		return m.DefaultHostForHttp_10
	}
	return ""
}

type Http2ProtocolOptions struct {
	// `Maximum table size <http://httpwg.org/specs/rfc7541.html#rfc.section.4.2>`_
	// (in octets) that the encoder is permitted to use for the dynamic HPACK table. Valid values
	// range from 0 to 4294967295 (2^32 - 1) and defaults to 4096. 0 effectively disables header
	// compression.
	HpackTableSize *google_protobuf.UInt32Value `protobuf:"bytes,1,opt,name=hpack_table_size,json=hpackTableSize" json:"hpack_table_size,omitempty"`
	// `Maximum concurrent streams <http://httpwg.org/specs/rfc7540.html#rfc.section.5.1.2>`_
	// allowed for peer on one HTTP/2 connection. Valid values range from 1 to 2147483647 (2^31 - 1)
	// and defaults to 2147483647.
	MaxConcurrentStreams *google_protobuf.UInt32Value `protobuf:"bytes,2,opt,name=max_concurrent_streams,json=maxConcurrentStreams" json:"max_concurrent_streams,omitempty"`
	// This field also acts as a soft limit on the number of bytes Envoy will buffer per-stream in the
	// HTTP/2 codec buffers. Once the buffer reaches this pointer, watermark callbacks will fire to
	// stop the flow of data to the codec buffers.
	InitialStreamWindowSize *google_protobuf.UInt32Value `protobuf:"bytes,3,opt,name=initial_stream_window_size,json=initialStreamWindowSize" json:"initial_stream_window_size,omitempty"`
	// Similar to *initial_stream_window_size*, but for connection-level flow-control
	// window. Currently, this has the same minimum/maximum/default as *initial_stream_window_size*.
	InitialConnectionWindowSize *google_protobuf.UInt32Value `protobuf:"bytes,4,opt,name=initial_connection_window_size,json=initialConnectionWindowSize" json:"initial_connection_window_size,omitempty"`
}

func (m *Http2ProtocolOptions) Reset()                    { *m = Http2ProtocolOptions{} }
func (m *Http2ProtocolOptions) String() string            { return proto.CompactTextString(m) }
func (*Http2ProtocolOptions) ProtoMessage()               {}
func (*Http2ProtocolOptions) Descriptor() ([]byte, []int) { return fileDescriptorProtocol, []int{3} }

func (m *Http2ProtocolOptions) GetHpackTableSize() *google_protobuf.UInt32Value {
	if m != nil {
		return m.HpackTableSize
	}
	return nil
}

func (m *Http2ProtocolOptions) GetMaxConcurrentStreams() *google_protobuf.UInt32Value {
	if m != nil {
		return m.MaxConcurrentStreams
	}
	return nil
}

func (m *Http2ProtocolOptions) GetInitialStreamWindowSize() *google_protobuf.UInt32Value {
	if m != nil {
		return m.InitialStreamWindowSize
	}
	return nil
}

func (m *Http2ProtocolOptions) GetInitialConnectionWindowSize() *google_protobuf.UInt32Value {
	if m != nil {
		return m.InitialConnectionWindowSize
	}
	return nil
}

// [#not-implemented-hide:]
type GrpcProtocolOptions struct {
	Http2ProtocolOptions *Http2ProtocolOptions `protobuf:"bytes,1,opt,name=http2_protocol_options,json=http2ProtocolOptions" json:"http2_protocol_options,omitempty"`
}

func (m *GrpcProtocolOptions) Reset()                    { *m = GrpcProtocolOptions{} }
func (m *GrpcProtocolOptions) String() string            { return proto.CompactTextString(m) }
func (*GrpcProtocolOptions) ProtoMessage()               {}
func (*GrpcProtocolOptions) Descriptor() ([]byte, []int) { return fileDescriptorProtocol, []int{4} }

func (m *GrpcProtocolOptions) GetHttp2ProtocolOptions() *Http2ProtocolOptions {
	if m != nil {
		return m.Http2ProtocolOptions
	}
	return nil
}

func init() {
	proto.RegisterType((*TcpProtocolOptions)(nil), "envoy.api.v2.core.TcpProtocolOptions")
	proto.RegisterType((*HttpProtocolOptions)(nil), "envoy.api.v2.core.HttpProtocolOptions")
	proto.RegisterType((*Http1ProtocolOptions)(nil), "envoy.api.v2.core.Http1ProtocolOptions")
	proto.RegisterType((*Http2ProtocolOptions)(nil), "envoy.api.v2.core.Http2ProtocolOptions")
	proto.RegisterType((*GrpcProtocolOptions)(nil), "envoy.api.v2.core.GrpcProtocolOptions")
}
func (this *TcpProtocolOptions) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*TcpProtocolOptions)
	if !ok {
		that2, ok := that.(TcpProtocolOptions)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		if this == nil {
			return true
		}
		return false
	} else if this == nil {
		return false
	}
	return true
}
func (this *HttpProtocolOptions) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*HttpProtocolOptions)
	if !ok {
		that2, ok := that.(HttpProtocolOptions)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		if this == nil {
			return true
		}
		return false
	} else if this == nil {
		return false
	}
	if this.IdleTimeout != nil && that1.IdleTimeout != nil {
		if *this.IdleTimeout != *that1.IdleTimeout {
			return false
		}
	} else if this.IdleTimeout != nil {
		return false
	} else if that1.IdleTimeout != nil {
		return false
	}
	return true
}
func (this *Http1ProtocolOptions) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*Http1ProtocolOptions)
	if !ok {
		that2, ok := that.(Http1ProtocolOptions)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		if this == nil {
			return true
		}
		return false
	} else if this == nil {
		return false
	}
	if !this.AllowAbsoluteUrl.Equal(that1.AllowAbsoluteUrl) {
		return false
	}
	if this.AcceptHttp_10 != that1.AcceptHttp_10 {
		return false
	}
	if this.DefaultHostForHttp_10 != that1.DefaultHostForHttp_10 {
		return false
	}
	return true
}
func (this *Http2ProtocolOptions) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*Http2ProtocolOptions)
	if !ok {
		that2, ok := that.(Http2ProtocolOptions)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		if this == nil {
			return true
		}
		return false
	} else if this == nil {
		return false
	}
	if !this.HpackTableSize.Equal(that1.HpackTableSize) {
		return false
	}
	if !this.MaxConcurrentStreams.Equal(that1.MaxConcurrentStreams) {
		return false
	}
	if !this.InitialStreamWindowSize.Equal(that1.InitialStreamWindowSize) {
		return false
	}
	if !this.InitialConnectionWindowSize.Equal(that1.InitialConnectionWindowSize) {
		return false
	}
	return true
}
func (this *GrpcProtocolOptions) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*GrpcProtocolOptions)
	if !ok {
		that2, ok := that.(GrpcProtocolOptions)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		if this == nil {
			return true
		}
		return false
	} else if this == nil {
		return false
	}
	if !this.Http2ProtocolOptions.Equal(that1.Http2ProtocolOptions) {
		return false
	}
	return true
}
func (m *TcpProtocolOptions) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *TcpProtocolOptions) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	return i, nil
}

func (m *HttpProtocolOptions) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *HttpProtocolOptions) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.IdleTimeout != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(*m.IdleTimeout)))
		n1, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(*m.IdleTimeout, dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	return i, nil
}

func (m *Http1ProtocolOptions) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Http1ProtocolOptions) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.AllowAbsoluteUrl != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(m.AllowAbsoluteUrl.Size()))
		n2, err := m.AllowAbsoluteUrl.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if m.AcceptHttp_10 {
		dAtA[i] = 0x10
		i++
		if m.AcceptHttp_10 {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	if len(m.DefaultHostForHttp_10) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(len(m.DefaultHostForHttp_10)))
		i += copy(dAtA[i:], m.DefaultHostForHttp_10)
	}
	return i, nil
}

func (m *Http2ProtocolOptions) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Http2ProtocolOptions) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.HpackTableSize != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(m.HpackTableSize.Size()))
		n3, err := m.HpackTableSize.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	if m.MaxConcurrentStreams != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(m.MaxConcurrentStreams.Size()))
		n4, err := m.MaxConcurrentStreams.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n4
	}
	if m.InitialStreamWindowSize != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(m.InitialStreamWindowSize.Size()))
		n5, err := m.InitialStreamWindowSize.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n5
	}
	if m.InitialConnectionWindowSize != nil {
		dAtA[i] = 0x22
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(m.InitialConnectionWindowSize.Size()))
		n6, err := m.InitialConnectionWindowSize.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n6
	}
	return i, nil
}

func (m *GrpcProtocolOptions) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GrpcProtocolOptions) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Http2ProtocolOptions != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintProtocol(dAtA, i, uint64(m.Http2ProtocolOptions.Size()))
		n7, err := m.Http2ProtocolOptions.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n7
	}
	return i, nil
}

func encodeVarintProtocol(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *TcpProtocolOptions) Size() (n int) {
	var l int
	_ = l
	return n
}

func (m *HttpProtocolOptions) Size() (n int) {
	var l int
	_ = l
	if m.IdleTimeout != nil {
		l = github_com_gogo_protobuf_types.SizeOfStdDuration(*m.IdleTimeout)
		n += 1 + l + sovProtocol(uint64(l))
	}
	return n
}

func (m *Http1ProtocolOptions) Size() (n int) {
	var l int
	_ = l
	if m.AllowAbsoluteUrl != nil {
		l = m.AllowAbsoluteUrl.Size()
		n += 1 + l + sovProtocol(uint64(l))
	}
	if m.AcceptHttp_10 {
		n += 2
	}
	l = len(m.DefaultHostForHttp_10)
	if l > 0 {
		n += 1 + l + sovProtocol(uint64(l))
	}
	return n
}

func (m *Http2ProtocolOptions) Size() (n int) {
	var l int
	_ = l
	if m.HpackTableSize != nil {
		l = m.HpackTableSize.Size()
		n += 1 + l + sovProtocol(uint64(l))
	}
	if m.MaxConcurrentStreams != nil {
		l = m.MaxConcurrentStreams.Size()
		n += 1 + l + sovProtocol(uint64(l))
	}
	if m.InitialStreamWindowSize != nil {
		l = m.InitialStreamWindowSize.Size()
		n += 1 + l + sovProtocol(uint64(l))
	}
	if m.InitialConnectionWindowSize != nil {
		l = m.InitialConnectionWindowSize.Size()
		n += 1 + l + sovProtocol(uint64(l))
	}
	return n
}

func (m *GrpcProtocolOptions) Size() (n int) {
	var l int
	_ = l
	if m.Http2ProtocolOptions != nil {
		l = m.Http2ProtocolOptions.Size()
		n += 1 + l + sovProtocol(uint64(l))
	}
	return n
}

func sovProtocol(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozProtocol(x uint64) (n int) {
	return sovProtocol(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *TcpProtocolOptions) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocol
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
			return fmt.Errorf("proto: TcpProtocolOptions: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: TcpProtocolOptions: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipProtocol(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocol
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
func (m *HttpProtocolOptions) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocol
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
			return fmt.Errorf("proto: HttpProtocolOptions: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: HttpProtocolOptions: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IdleTimeout", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.IdleTimeout == nil {
				m.IdleTimeout = new(time.Duration)
			}
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(m.IdleTimeout, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipProtocol(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocol
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
func (m *Http1ProtocolOptions) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocol
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
			return fmt.Errorf("proto: Http1ProtocolOptions: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Http1ProtocolOptions: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AllowAbsoluteUrl", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.AllowAbsoluteUrl == nil {
				m.AllowAbsoluteUrl = &google_protobuf.BoolValue{}
			}
			if err := m.AllowAbsoluteUrl.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AcceptHttp_10", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
			m.AcceptHttp_10 = bool(v != 0)
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DefaultHostForHttp_10", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DefaultHostForHttp_10 = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipProtocol(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocol
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
func (m *Http2ProtocolOptions) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocol
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
			return fmt.Errorf("proto: Http2ProtocolOptions: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Http2ProtocolOptions: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HpackTableSize", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.HpackTableSize == nil {
				m.HpackTableSize = &google_protobuf.UInt32Value{}
			}
			if err := m.HpackTableSize.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxConcurrentStreams", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MaxConcurrentStreams == nil {
				m.MaxConcurrentStreams = &google_protobuf.UInt32Value{}
			}
			if err := m.MaxConcurrentStreams.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field InitialStreamWindowSize", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.InitialStreamWindowSize == nil {
				m.InitialStreamWindowSize = &google_protobuf.UInt32Value{}
			}
			if err := m.InitialStreamWindowSize.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field InitialConnectionWindowSize", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.InitialConnectionWindowSize == nil {
				m.InitialConnectionWindowSize = &google_protobuf.UInt32Value{}
			}
			if err := m.InitialConnectionWindowSize.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipProtocol(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocol
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
func (m *GrpcProtocolOptions) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocol
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
			return fmt.Errorf("proto: GrpcProtocolOptions: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GrpcProtocolOptions: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Http2ProtocolOptions", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocol
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
				return ErrInvalidLengthProtocol
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Http2ProtocolOptions == nil {
				m.Http2ProtocolOptions = &Http2ProtocolOptions{}
			}
			if err := m.Http2ProtocolOptions.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipProtocol(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocol
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
func skipProtocol(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowProtocol
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
					return 0, ErrIntOverflowProtocol
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
					return 0, ErrIntOverflowProtocol
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
				return 0, ErrInvalidLengthProtocol
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowProtocol
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
				next, err := skipProtocol(dAtA[start:])
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
	ErrInvalidLengthProtocol = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowProtocol   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("envoy/api/v2/core/protocol.proto", fileDescriptorProtocol) }

var fileDescriptorProtocol = []byte{
	// 540 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x93, 0xc1, 0x6e, 0xd3, 0x40,
	0x10, 0x86, 0x65, 0x52, 0x41, 0xd9, 0x46, 0x25, 0x75, 0xad, 0x36, 0x04, 0x64, 0xa2, 0x08, 0x89,
	0xa8, 0x07, 0xbb, 0x75, 0x25, 0xee, 0xa4, 0xa8, 0x84, 0x13, 0xc8, 0x4d, 0x41, 0x1c, 0xd0, 0x6a,
	0xb3, 0xd9, 0x24, 0x2b, 0x36, 0x9e, 0xd5, 0x7a, 0x9d, 0x94, 0x3e, 0x09, 0x6f, 0x00, 0xcf, 0xc0,
	0x01, 0x71, 0xe4, 0xc8, 0x1b, 0x80, 0x72, 0xe3, 0x29, 0x8c, 0xec, 0xdd, 0x04, 0x91, 0x54, 0x02,
	0xf5, 0xb6, 0x9a, 0x99, 0xff, 0xff, 0xfe, 0xf1, 0xc8, 0xa8, 0xc9, 0x92, 0x29, 0xbc, 0x0f, 0x89,
	0xe4, 0xe1, 0x34, 0x0a, 0x29, 0x28, 0x16, 0x4a, 0x05, 0x1a, 0x28, 0x88, 0xa0, 0x7c, 0xb8, 0x3b,
	0xe5, 0x44, 0x40, 0x24, 0x0f, 0xa6, 0x51, 0x50, 0x4c, 0x34, 0xfc, 0x11, 0xc0, 0x48, 0xd8, 0xc9,
	0x7e, 0x36, 0x0c, 0x07, 0x99, 0x22, 0x9a, 0x43, 0x62, 0x24, 0xeb, 0xfd, 0x99, 0x22, 0x52, 0x32,
	0x95, 0xda, 0xfe, 0xfe, 0x94, 0x08, 0x3e, 0x20, 0x9a, 0x85, 0x8b, 0x87, 0x6d, 0x78, 0x23, 0x18,
	0x41, 0xf9, 0x0c, 0x8b, 0x97, 0xa9, 0xb6, 0x3c, 0xe4, 0xf6, 0xa8, 0x7c, 0x69, 0x63, 0xbd, 0x90,
	0x05, 0x29, 0x6d, 0xbd, 0x41, 0xbb, 0x5d, 0xad, 0x57, 0xcb, 0x6e, 0x07, 0x55, 0xf9, 0x40, 0x30,
	0xac, 0xf9, 0x84, 0x41, 0xa6, 0xeb, 0x4e, 0xd3, 0x69, 0x6f, 0x45, 0x77, 0x03, 0x13, 0x29, 0x58,
	0x44, 0x0a, 0x9e, 0xda, 0xc8, 0x9d, 0x8d, 0x0f, 0x3f, 0x1e, 0x38, 0xf1, 0x56, 0x21, 0xea, 0x19,
	0x4d, 0xeb, 0x8b, 0x83, 0xbc, 0xc2, 0xfb, 0x68, 0xd5, 0xbc, 0x8b, 0x5c, 0x22, 0x04, 0xcc, 0x30,
	0xe9, 0xa7, 0x20, 0x32, 0xcd, 0x70, 0xa6, 0x84, 0x45, 0x34, 0xd6, 0x10, 0x1d, 0x00, 0xf1, 0x8a,
	0x88, 0x8c, 0xc5, 0xb5, 0x52, 0xf5, 0xc4, 0x8a, 0xce, 0x95, 0x70, 0x1f, 0xa2, 0x6d, 0x42, 0x29,
	0x93, 0x1a, 0x8f, 0xb5, 0x96, 0xf8, 0xe8, 0xb0, 0x7e, 0xa3, 0xe9, 0xb4, 0x37, 0xe3, 0xaa, 0xa9,
	0x96, 0xf4, 0x43, 0xf7, 0x31, 0xaa, 0x0f, 0xd8, 0x90, 0x64, 0x42, 0xe3, 0x31, 0xa4, 0x1a, 0x0f,
	0x41, 0x2d, 0xe7, 0x2b, 0x4d, 0xa7, 0x7d, 0x3b, 0xf6, 0x6c, 0xbf, 0x0b, 0xa9, 0x3e, 0x05, 0x65,
	0x74, 0xad, 0x8f, 0x15, 0xb3, 0x40, 0xb4, 0xba, 0xc0, 0x29, 0xaa, 0x8d, 0x25, 0xa1, 0xef, 0xb0,
	0x26, 0x7d, 0xc1, 0x70, 0xca, 0x2f, 0x99, 0x8d, 0x7f, 0x7f, 0x2d, 0xfe, 0xf9, 0xf3, 0x44, 0x1f,
	0x47, 0x66, 0x81, 0xed, 0x52, 0xd5, 0x2b, 0x44, 0x67, 0xfc, 0x92, 0xb9, 0x14, 0xed, 0x4d, 0xc8,
	0x05, 0xa6, 0x90, 0xd0, 0x4c, 0x29, 0x96, 0x68, 0x9c, 0x6a, 0xc5, 0xc8, 0x24, 0x2d, 0xd7, 0xf8,
	0x87, 0x5b, 0xe7, 0xce, 0xe7, 0x5f, 0x5f, 0x2b, 0xe8, 0x60, 0xb3, 0x9e, 0xe7, 0x79, 0x7e, 0xab,
	0xed, 0xc4, 0xde, 0x84, 0x5c, 0x9c, 0x2c, 0xbd, 0xce, 0x8c, 0x95, 0x2b, 0x50, 0x83, 0x27, 0x5c,
	0x73, 0x22, 0xac, 0x3b, 0x9e, 0xf1, 0x64, 0x00, 0x33, 0x13, 0xbb, 0xf2, 0x1f, 0xa0, 0x9d, 0x02,
	0x54, 0x3d, 0x40, 0x16, 0x94, 0xe7, 0x95, 0x78, 0xdf, 0x5a, 0x1a, 0xc8, 0xeb, 0xd2, 0xb0, 0x5c,
	0x49, 0x23, 0x7f, 0x41, 0xa3, 0x90, 0x24, 0x8c, 0x16, 0x5f, 0xec, 0x2f, 0xe2, 0xc6, 0xf5, 0x88,
	0xf7, 0xac, 0xed, 0xc9, 0xd2, 0xf5, 0x0f, 0xb5, 0xa5, 0xd1, 0xee, 0x33, 0x25, 0xe9, 0xea, 0x9d,
	0xde, 0xa2, 0xbd, 0xe2, 0xce, 0x11, 0x5e, 0xfc, 0x8c, 0x18, 0x4c, 0xc7, 0x5e, 0xeb, 0x51, 0xb0,
	0xf6, 0x57, 0x06, 0x57, 0x1d, 0x3c, 0xf6, 0xc6, 0x57, 0x54, 0x3b, 0xb5, 0x4f, 0x73, 0xdf, 0xf9,
	0x36, 0xf7, 0x9d, 0xef, 0x73, 0xdf, 0xf9, 0x39, 0xf7, 0x9d, 0xfe, 0xcd, 0x12, 0x74, 0xfc, 0x3b,
	0x00, 0x00, 0xff, 0xff, 0xd0, 0x8c, 0x8d, 0xbc, 0x10, 0x04, 0x00, 0x00,
}

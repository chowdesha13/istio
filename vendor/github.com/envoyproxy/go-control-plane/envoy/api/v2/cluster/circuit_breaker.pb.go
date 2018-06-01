// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/api/v2/cluster/circuit_breaker.proto

/*
	Package cluster is a generated protocol buffer package.

	It is generated from these files:
		envoy/api/v2/cluster/circuit_breaker.proto
		envoy/api/v2/cluster/outlier_detection.proto

	It has these top-level messages:
		CircuitBreakers
		OutlierDetection
*/
package cluster

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
import google_protobuf1 "github.com/gogo/protobuf/types"
import _ "github.com/gogo/protobuf/gogoproto"

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

// :ref:`Circuit breaking<arch_overview_circuit_break>` settings can be
// specified individually for each defined priority.
type CircuitBreakers struct {
	// If multiple :ref:`Thresholds<envoy_api_msg_cluster.CircuitBreakers.Thresholds>`
	// are defined with the same :ref:`RoutingPriority<envoy_api_enum_core.RoutingPriority>`,
	// the first one in the list is used. If no Thresholds is defined for a given
	// :ref:`RoutingPriority<envoy_api_enum_core.RoutingPriority>`, the default values
	// are used.
	Thresholds []*CircuitBreakers_Thresholds `protobuf:"bytes,1,rep,name=thresholds" json:"thresholds,omitempty"`
}

func (m *CircuitBreakers) Reset()                    { *m = CircuitBreakers{} }
func (m *CircuitBreakers) String() string            { return proto.CompactTextString(m) }
func (*CircuitBreakers) ProtoMessage()               {}
func (*CircuitBreakers) Descriptor() ([]byte, []int) { return fileDescriptorCircuitBreaker, []int{0} }

func (m *CircuitBreakers) GetThresholds() []*CircuitBreakers_Thresholds {
	if m != nil {
		return m.Thresholds
	}
	return nil
}

// A Thresholds defines CircuitBreaker settings for a
// :ref:`RoutingPriority<envoy_api_enum_core.RoutingPriority>`.
type CircuitBreakers_Thresholds struct {
	// The :ref:`RoutingPriority<envoy_api_enum_core.RoutingPriority>`
	// the specified CircuitBreaker settings apply to.
	// [#comment:TODO(htuch): add (validate.rules).enum.defined_only = true once
	// https://github.com/lyft/protoc-gen-validate/issues/42 is resolved.]
	Priority envoy_api_v2_core.RoutingPriority `protobuf:"varint,1,opt,name=priority,proto3,enum=envoy.api.v2.core.RoutingPriority" json:"priority,omitempty"`
	// The maximum number of connections that Envoy will make to the upstream
	// cluster. If not specified, the default is 1024.
	MaxConnections *google_protobuf1.UInt32Value `protobuf:"bytes,2,opt,name=max_connections,json=maxConnections" json:"max_connections,omitempty"`
	// The maximum number of pending requests that Envoy will allow to the
	// upstream cluster. If not specified, the default is 1024.
	MaxPendingRequests *google_protobuf1.UInt32Value `protobuf:"bytes,3,opt,name=max_pending_requests,json=maxPendingRequests" json:"max_pending_requests,omitempty"`
	// The maximum number of parallel requests that Envoy will make to the
	// upstream cluster. If not specified, the default is 1024.
	MaxRequests *google_protobuf1.UInt32Value `protobuf:"bytes,4,opt,name=max_requests,json=maxRequests" json:"max_requests,omitempty"`
	// The maximum number of parallel retries that Envoy will allow to the
	// upstream cluster. If not specified, the default is 3.
	MaxRetries *google_protobuf1.UInt32Value `protobuf:"bytes,5,opt,name=max_retries,json=maxRetries" json:"max_retries,omitempty"`
}

func (m *CircuitBreakers_Thresholds) Reset()         { *m = CircuitBreakers_Thresholds{} }
func (m *CircuitBreakers_Thresholds) String() string { return proto.CompactTextString(m) }
func (*CircuitBreakers_Thresholds) ProtoMessage()    {}
func (*CircuitBreakers_Thresholds) Descriptor() ([]byte, []int) {
	return fileDescriptorCircuitBreaker, []int{0, 0}
}

func (m *CircuitBreakers_Thresholds) GetPriority() envoy_api_v2_core.RoutingPriority {
	if m != nil {
		return m.Priority
	}
	return envoy_api_v2_core.RoutingPriority_DEFAULT
}

func (m *CircuitBreakers_Thresholds) GetMaxConnections() *google_protobuf1.UInt32Value {
	if m != nil {
		return m.MaxConnections
	}
	return nil
}

func (m *CircuitBreakers_Thresholds) GetMaxPendingRequests() *google_protobuf1.UInt32Value {
	if m != nil {
		return m.MaxPendingRequests
	}
	return nil
}

func (m *CircuitBreakers_Thresholds) GetMaxRequests() *google_protobuf1.UInt32Value {
	if m != nil {
		return m.MaxRequests
	}
	return nil
}

func (m *CircuitBreakers_Thresholds) GetMaxRetries() *google_protobuf1.UInt32Value {
	if m != nil {
		return m.MaxRetries
	}
	return nil
}

func init() {
	proto.RegisterType((*CircuitBreakers)(nil), "envoy.api.v2.cluster.CircuitBreakers")
	proto.RegisterType((*CircuitBreakers_Thresholds)(nil), "envoy.api.v2.cluster.CircuitBreakers.Thresholds")
}
func (this *CircuitBreakers) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*CircuitBreakers)
	if !ok {
		that2, ok := that.(CircuitBreakers)
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
	if len(this.Thresholds) != len(that1.Thresholds) {
		return false
	}
	for i := range this.Thresholds {
		if !this.Thresholds[i].Equal(that1.Thresholds[i]) {
			return false
		}
	}
	return true
}
func (this *CircuitBreakers_Thresholds) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*CircuitBreakers_Thresholds)
	if !ok {
		that2, ok := that.(CircuitBreakers_Thresholds)
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
	if this.Priority != that1.Priority {
		return false
	}
	if !this.MaxConnections.Equal(that1.MaxConnections) {
		return false
	}
	if !this.MaxPendingRequests.Equal(that1.MaxPendingRequests) {
		return false
	}
	if !this.MaxRequests.Equal(that1.MaxRequests) {
		return false
	}
	if !this.MaxRetries.Equal(that1.MaxRetries) {
		return false
	}
	return true
}
func (m *CircuitBreakers) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CircuitBreakers) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Thresholds) > 0 {
		for _, msg := range m.Thresholds {
			dAtA[i] = 0xa
			i++
			i = encodeVarintCircuitBreaker(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func (m *CircuitBreakers_Thresholds) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CircuitBreakers_Thresholds) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Priority != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintCircuitBreaker(dAtA, i, uint64(m.Priority))
	}
	if m.MaxConnections != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintCircuitBreaker(dAtA, i, uint64(m.MaxConnections.Size()))
		n1, err := m.MaxConnections.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.MaxPendingRequests != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintCircuitBreaker(dAtA, i, uint64(m.MaxPendingRequests.Size()))
		n2, err := m.MaxPendingRequests.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if m.MaxRequests != nil {
		dAtA[i] = 0x22
		i++
		i = encodeVarintCircuitBreaker(dAtA, i, uint64(m.MaxRequests.Size()))
		n3, err := m.MaxRequests.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	if m.MaxRetries != nil {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintCircuitBreaker(dAtA, i, uint64(m.MaxRetries.Size()))
		n4, err := m.MaxRetries.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n4
	}
	return i, nil
}

func encodeVarintCircuitBreaker(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *CircuitBreakers) Size() (n int) {
	var l int
	_ = l
	if len(m.Thresholds) > 0 {
		for _, e := range m.Thresholds {
			l = e.Size()
			n += 1 + l + sovCircuitBreaker(uint64(l))
		}
	}
	return n
}

func (m *CircuitBreakers_Thresholds) Size() (n int) {
	var l int
	_ = l
	if m.Priority != 0 {
		n += 1 + sovCircuitBreaker(uint64(m.Priority))
	}
	if m.MaxConnections != nil {
		l = m.MaxConnections.Size()
		n += 1 + l + sovCircuitBreaker(uint64(l))
	}
	if m.MaxPendingRequests != nil {
		l = m.MaxPendingRequests.Size()
		n += 1 + l + sovCircuitBreaker(uint64(l))
	}
	if m.MaxRequests != nil {
		l = m.MaxRequests.Size()
		n += 1 + l + sovCircuitBreaker(uint64(l))
	}
	if m.MaxRetries != nil {
		l = m.MaxRetries.Size()
		n += 1 + l + sovCircuitBreaker(uint64(l))
	}
	return n
}

func sovCircuitBreaker(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozCircuitBreaker(x uint64) (n int) {
	return sovCircuitBreaker(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *CircuitBreakers) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCircuitBreaker
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
			return fmt.Errorf("proto: CircuitBreakers: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CircuitBreakers: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Thresholds", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCircuitBreaker
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
				return ErrInvalidLengthCircuitBreaker
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Thresholds = append(m.Thresholds, &CircuitBreakers_Thresholds{})
			if err := m.Thresholds[len(m.Thresholds)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCircuitBreaker(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCircuitBreaker
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
func (m *CircuitBreakers_Thresholds) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCircuitBreaker
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
			return fmt.Errorf("proto: Thresholds: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Thresholds: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Priority", wireType)
			}
			m.Priority = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCircuitBreaker
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Priority |= (envoy_api_v2_core.RoutingPriority(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxConnections", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCircuitBreaker
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
				return ErrInvalidLengthCircuitBreaker
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MaxConnections == nil {
				m.MaxConnections = &google_protobuf1.UInt32Value{}
			}
			if err := m.MaxConnections.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxPendingRequests", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCircuitBreaker
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
				return ErrInvalidLengthCircuitBreaker
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MaxPendingRequests == nil {
				m.MaxPendingRequests = &google_protobuf1.UInt32Value{}
			}
			if err := m.MaxPendingRequests.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxRequests", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCircuitBreaker
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
				return ErrInvalidLengthCircuitBreaker
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MaxRequests == nil {
				m.MaxRequests = &google_protobuf1.UInt32Value{}
			}
			if err := m.MaxRequests.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxRetries", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCircuitBreaker
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
				return ErrInvalidLengthCircuitBreaker
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MaxRetries == nil {
				m.MaxRetries = &google_protobuf1.UInt32Value{}
			}
			if err := m.MaxRetries.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCircuitBreaker(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCircuitBreaker
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
func skipCircuitBreaker(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowCircuitBreaker
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
					return 0, ErrIntOverflowCircuitBreaker
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
					return 0, ErrIntOverflowCircuitBreaker
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
				return 0, ErrInvalidLengthCircuitBreaker
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowCircuitBreaker
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
				next, err := skipCircuitBreaker(dAtA[start:])
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
	ErrInvalidLengthCircuitBreaker = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCircuitBreaker   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("envoy/api/v2/cluster/circuit_breaker.proto", fileDescriptorCircuitBreaker)
}

var fileDescriptorCircuitBreaker = []byte{
	// 363 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x91, 0xcf, 0x4a, 0xeb, 0x40,
	0x14, 0xc6, 0x99, 0xf6, 0xfe, 0x63, 0x72, 0x69, 0x21, 0x74, 0x91, 0x5b, 0x4a, 0x28, 0x5d, 0x95,
	0xbb, 0x98, 0x91, 0x74, 0xad, 0x42, 0x8b, 0x0b, 0x37, 0x52, 0x82, 0xba, 0x70, 0x53, 0x26, 0xe9,
	0x31, 0x1d, 0x4c, 0x66, 0xe2, 0xcc, 0xa4, 0xa6, 0x6f, 0xe4, 0xa3, 0xe8, 0xce, 0x47, 0x90, 0xf8,
	0x22, 0xd2, 0x24, 0xa6, 0x5a, 0x5c, 0x74, 0x77, 0x92, 0xf3, 0xfd, 0x7e, 0x7c, 0x9c, 0xc1, 0xff,
	0x41, 0xac, 0xe5, 0x86, 0xb2, 0x94, 0xd3, 0xb5, 0x47, 0xc3, 0x38, 0xd3, 0x06, 0x14, 0x0d, 0xb9,
	0x0a, 0x33, 0x6e, 0x16, 0x81, 0x02, 0x76, 0x07, 0x8a, 0xa4, 0x4a, 0x1a, 0x69, 0xf7, 0xca, 0x2c,
	0x61, 0x29, 0x27, 0x6b, 0x8f, 0xd4, 0xd9, 0xfe, 0xe0, 0xab, 0x41, 0x2a, 0xa0, 0x01, 0xd3, 0x50,
	0x31, 0x7d, 0x37, 0x92, 0x32, 0x8a, 0x81, 0x96, 0x5f, 0x41, 0x76, 0x4b, 0x1f, 0x14, 0x4b, 0x53,
	0x50, 0xba, 0xde, 0xf7, 0x22, 0x19, 0xc9, 0x72, 0xa4, 0xdb, 0xa9, 0xfa, 0x3b, 0x7a, 0x6e, 0xe3,
	0xee, 0xac, 0xea, 0x30, 0xad, 0x2a, 0x68, 0x7b, 0x8e, 0xb1, 0x59, 0x29, 0xd0, 0x2b, 0x19, 0x2f,
	0xb5, 0x83, 0x86, 0xed, 0xb1, 0xe5, 0x1d, 0x91, 0xef, 0x2a, 0x91, 0x3d, 0x94, 0x5c, 0x36, 0x9c,
	0xff, 0xc9, 0xd1, 0x7f, 0x6b, 0x61, 0xbc, 0x5b, 0xd9, 0x27, 0xf8, 0x4f, 0xaa, 0xb8, 0x54, 0xdc,
	0x6c, 0x1c, 0x34, 0x44, 0xe3, 0x8e, 0x37, 0xda, 0xd3, 0x4b, 0x05, 0xc4, 0x97, 0x99, 0xe1, 0x22,
	0x9a, 0xd7, 0x49, 0xbf, 0x61, 0xec, 0x33, 0xdc, 0x4d, 0x58, 0xbe, 0x08, 0xa5, 0x10, 0x10, 0x1a,
	0x2e, 0x85, 0x76, 0x5a, 0x43, 0x34, 0xb6, 0xbc, 0x01, 0xa9, 0x8e, 0x40, 0x3e, 0x8e, 0x40, 0xae,
	0xce, 0x85, 0x99, 0x78, 0xd7, 0x2c, 0xce, 0xc0, 0xef, 0x24, 0x2c, 0x9f, 0xed, 0x18, 0xfb, 0x02,
	0xf7, 0xb6, 0x9a, 0x14, 0xc4, 0x92, 0x8b, 0x68, 0xa1, 0xe0, 0x3e, 0x03, 0x6d, 0xb4, 0xd3, 0x3e,
	0xc0, 0x65, 0x27, 0x2c, 0x9f, 0x57, 0xa0, 0x5f, 0x73, 0xf6, 0x29, 0xfe, 0xbb, 0xf5, 0x35, 0x9e,
	0x1f, 0x07, 0x78, 0xac, 0x84, 0xe5, 0x8d, 0xe0, 0x18, 0x5b, 0x95, 0xc0, 0x28, 0x0e, 0xda, 0xf9,
	0x79, 0x00, 0x8f, 0x4b, 0xbe, 0xcc, 0x4f, 0xff, 0x3d, 0x16, 0x2e, 0x7a, 0x2a, 0x5c, 0xf4, 0x52,
	0xb8, 0xe8, 0xb5, 0x70, 0xd1, 0xcd, 0xef, 0xfa, 0x9d, 0x82, 0x5f, 0x25, 0x3c, 0x79, 0x0f, 0x00,
	0x00, 0xff, 0xff, 0x12, 0x24, 0xbd, 0x97, 0x85, 0x02, 0x00, 0x00,
}

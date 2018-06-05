// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/config/filter/network/redis_proxy/v2/redis_proxy.proto

/*
	Package v2 is a generated protocol buffer package.

	It is generated from these files:
		envoy/config/filter/network/redis_proxy/v2/redis_proxy.proto

	It has these top-level messages:
		RedisProxy
*/
package v2

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/types"
import _ "github.com/lyft/protoc-gen-validate/validate"
import _ "github.com/gogo/protobuf/gogoproto"

import time "time"

import types "github.com/gogo/protobuf/types"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type RedisProxy struct {
	// The prefix to use when emitting :ref:`statistics <config_network_filters_redis_proxy_stats>`.
	StatPrefix string `protobuf:"bytes,1,opt,name=stat_prefix,json=statPrefix,proto3" json:"stat_prefix,omitempty"`
	// Name of cluster from cluster manager. See the :ref:`configuration section
	// <arch_overview_redis_configuration>` of the architecture overview for recommendations on
	// configuring the backing cluster.
	Cluster string `protobuf:"bytes,2,opt,name=cluster,proto3" json:"cluster,omitempty"`
	// Network settings for the connection pool to the upstream cluster.
	Settings *RedisProxy_ConnPoolSettings `protobuf:"bytes,3,opt,name=settings" json:"settings,omitempty"`
}

func (m *RedisProxy) Reset()                    { *m = RedisProxy{} }
func (m *RedisProxy) String() string            { return proto.CompactTextString(m) }
func (*RedisProxy) ProtoMessage()               {}
func (*RedisProxy) Descriptor() ([]byte, []int) { return fileDescriptorRedisProxy, []int{0} }

func (m *RedisProxy) GetStatPrefix() string {
	if m != nil {
		return m.StatPrefix
	}
	return ""
}

func (m *RedisProxy) GetCluster() string {
	if m != nil {
		return m.Cluster
	}
	return ""
}

func (m *RedisProxy) GetSettings() *RedisProxy_ConnPoolSettings {
	if m != nil {
		return m.Settings
	}
	return nil
}

// Redis connection pool settings.
type RedisProxy_ConnPoolSettings struct {
	// Per-operation timeout in milliseconds. The timer starts when the first
	// command of a pipeline is written to the backend connection. Each response received from Redis
	// resets the timer since it signifies that the next command is being processed by the backend.
	// The only exception to this behavior is when a connection to a backend is not yet established.
	// In that case, the connect timeout on the cluster will govern the timeout until the connection
	// is ready.
	OpTimeout *time.Duration `protobuf:"bytes,1,opt,name=op_timeout,json=opTimeout,stdduration" json:"op_timeout,omitempty"`
}

func (m *RedisProxy_ConnPoolSettings) Reset()         { *m = RedisProxy_ConnPoolSettings{} }
func (m *RedisProxy_ConnPoolSettings) String() string { return proto.CompactTextString(m) }
func (*RedisProxy_ConnPoolSettings) ProtoMessage()    {}
func (*RedisProxy_ConnPoolSettings) Descriptor() ([]byte, []int) {
	return fileDescriptorRedisProxy, []int{0, 0}
}

func (m *RedisProxy_ConnPoolSettings) GetOpTimeout() *time.Duration {
	if m != nil {
		return m.OpTimeout
	}
	return nil
}

func init() {
	proto.RegisterType((*RedisProxy)(nil), "envoy.config.filter.network.redis_proxy.v2.RedisProxy")
	proto.RegisterType((*RedisProxy_ConnPoolSettings)(nil), "envoy.config.filter.network.redis_proxy.v2.RedisProxy.ConnPoolSettings")
}
func (m *RedisProxy) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RedisProxy) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.StatPrefix) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintRedisProxy(dAtA, i, uint64(len(m.StatPrefix)))
		i += copy(dAtA[i:], m.StatPrefix)
	}
	if len(m.Cluster) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintRedisProxy(dAtA, i, uint64(len(m.Cluster)))
		i += copy(dAtA[i:], m.Cluster)
	}
	if m.Settings != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintRedisProxy(dAtA, i, uint64(m.Settings.Size()))
		n1, err := m.Settings.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	return i, nil
}

func (m *RedisProxy_ConnPoolSettings) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RedisProxy_ConnPoolSettings) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.OpTimeout != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintRedisProxy(dAtA, i, uint64(types.SizeOfStdDuration(*m.OpTimeout)))
		n2, err := types.StdDurationMarshalTo(*m.OpTimeout, dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	return i, nil
}

func encodeVarintRedisProxy(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *RedisProxy) Size() (n int) {
	var l int
	_ = l
	l = len(m.StatPrefix)
	if l > 0 {
		n += 1 + l + sovRedisProxy(uint64(l))
	}
	l = len(m.Cluster)
	if l > 0 {
		n += 1 + l + sovRedisProxy(uint64(l))
	}
	if m.Settings != nil {
		l = m.Settings.Size()
		n += 1 + l + sovRedisProxy(uint64(l))
	}
	return n
}

func (m *RedisProxy_ConnPoolSettings) Size() (n int) {
	var l int
	_ = l
	if m.OpTimeout != nil {
		l = types.SizeOfStdDuration(*m.OpTimeout)
		n += 1 + l + sovRedisProxy(uint64(l))
	}
	return n
}

func sovRedisProxy(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozRedisProxy(x uint64) (n int) {
	return sovRedisProxy(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *RedisProxy) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowRedisProxy
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
			return fmt.Errorf("proto: RedisProxy: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: RedisProxy: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StatPrefix", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRedisProxy
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
				return ErrInvalidLengthRedisProxy
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.StatPrefix = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Cluster", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRedisProxy
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
				return ErrInvalidLengthRedisProxy
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Cluster = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Settings", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRedisProxy
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
				return ErrInvalidLengthRedisProxy
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Settings == nil {
				m.Settings = &RedisProxy_ConnPoolSettings{}
			}
			if err := m.Settings.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipRedisProxy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthRedisProxy
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
func (m *RedisProxy_ConnPoolSettings) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowRedisProxy
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
			return fmt.Errorf("proto: ConnPoolSettings: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ConnPoolSettings: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field OpTimeout", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRedisProxy
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
				return ErrInvalidLengthRedisProxy
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.OpTimeout == nil {
				m.OpTimeout = new(time.Duration)
			}
			if err := types.StdDurationUnmarshal(m.OpTimeout, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipRedisProxy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthRedisProxy
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
func skipRedisProxy(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowRedisProxy
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
					return 0, ErrIntOverflowRedisProxy
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
					return 0, ErrIntOverflowRedisProxy
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
				return 0, ErrInvalidLengthRedisProxy
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowRedisProxy
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
				next, err := skipRedisProxy(dAtA[start:])
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
	ErrInvalidLengthRedisProxy = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowRedisProxy   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("envoy/config/filter/network/redis_proxy/v2/redis_proxy.proto", fileDescriptorRedisProxy)
}

var fileDescriptorRedisProxy = []byte{
	// 339 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0xc1, 0x4a, 0xf3, 0x40,
	0x14, 0x85, 0x99, 0xf4, 0xff, 0xb5, 0x9d, 0x82, 0x94, 0x20, 0x58, 0xbb, 0x88, 0x45, 0x37, 0xa5,
	0x8b, 0x19, 0x88, 0x5b, 0x57, 0x51, 0xd0, 0x65, 0x89, 0xae, 0x44, 0x28, 0x69, 0x3b, 0x09, 0x83,
	0x71, 0x6e, 0x98, 0xdc, 0xc4, 0xf6, 0x15, 0x7c, 0x02, 0x9f, 0x41, 0x7c, 0x02, 0x57, 0x2e, 0x5d,
	0xfa, 0x06, 0x4a, 0x77, 0xbe, 0x85, 0x64, 0x26, 0xd5, 0xd2, 0x95, 0xbb, 0x9b, 0x9c, 0xfb, 0x9d,
	0x33, 0xf7, 0xd0, 0x13, 0xa1, 0x4a, 0x58, 0xf0, 0x29, 0xa8, 0x58, 0x26, 0x3c, 0x96, 0x29, 0x0a,
	0xcd, 0x95, 0xc0, 0x7b, 0xd0, 0xb7, 0x5c, 0x8b, 0x99, 0xcc, 0xc7, 0x99, 0x86, 0xf9, 0x82, 0x97,
	0xfe, 0xfa, 0x27, 0xcb, 0x34, 0x20, 0xb8, 0x43, 0x43, 0x33, 0x4b, 0x33, 0x4b, 0xb3, 0x9a, 0x66,
	0xeb, 0xeb, 0xa5, 0xdf, 0xf3, 0x12, 0x80, 0x24, 0x15, 0xdc, 0x90, 0x93, 0x22, 0xe6, 0xb3, 0x42,
	0x47, 0x28, 0x41, 0x59, 0xaf, 0xde, 0x5e, 0x19, 0xa5, 0x72, 0x16, 0xa1, 0xe0, 0xab, 0xa1, 0x16,
	0x76, 0x13, 0x48, 0xc0, 0x8c, 0xbc, 0x9a, 0xec, 0xdf, 0xc3, 0x67, 0x87, 0xd2, 0xb0, 0x4a, 0x18,
	0x55, 0x01, 0xee, 0x90, 0xb6, 0x73, 0x8c, 0x70, 0x9c, 0x69, 0x11, 0xcb, 0x79, 0x97, 0xf4, 0xc9,
	0xa0, 0x15, 0xb4, 0x5e, 0xbe, 0x5e, 0x1b, 0xff, 0xb4, 0xd3, 0x27, 0x21, 0xad, 0xd4, 0x91, 0x11,
	0xdd, 0x23, 0xba, 0x3d, 0x4d, 0x8b, 0x1c, 0x85, 0xee, 0x3a, 0x9b, 0x7b, 0x2b, 0xc5, 0x05, 0xda,
	0xcc, 0x05, 0xa2, 0x54, 0x49, 0xde, 0x6d, 0xf4, 0xc9, 0xa0, 0xed, 0x9f, 0xb3, 0xbf, 0x5f, 0xcb,
	0x7e, 0x9f, 0xc6, 0x4e, 0x41, 0xa9, 0x11, 0x40, 0x7a, 0x59, 0xdb, 0x05, 0xb4, 0x8a, 0xfb, 0xff,
	0x40, 0x9c, 0x0e, 0x09, 0x7f, 0x42, 0x7a, 0x37, 0xb4, 0xb3, 0xb9, 0xe9, 0x5e, 0x50, 0x0a, 0xd9,
	0x18, 0xe5, 0x9d, 0x80, 0x02, 0xcd, 0x51, 0x6d, 0x7f, 0x9f, 0xd9, 0x22, 0xd9, 0xaa, 0x48, 0x76,
	0x56, 0x17, 0x19, 0xec, 0x3c, 0x7e, 0x1c, 0x10, 0x63, 0xfe, 0x44, 0x9c, 0x26, 0x09, 0x5b, 0x90,
	0x5d, 0x59, 0x36, 0xe8, 0xbc, 0x2d, 0x3d, 0xf2, 0xbe, 0xf4, 0xc8, 0xe7, 0xd2, 0x23, 0xd7, 0x4e,
	0xe9, 0x4f, 0xb6, 0x0c, 0x7f, 0xfc, 0x1d, 0x00, 0x00, 0xff, 0xff, 0xeb, 0x5e, 0xf1, 0xe0, 0x02,
	0x02, 0x00, 0x00,
}

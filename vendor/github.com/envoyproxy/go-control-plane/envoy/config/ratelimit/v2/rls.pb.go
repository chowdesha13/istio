// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/config/ratelimit/v2/rls.proto

package v2

import (
	fmt "fmt"
	io "io"
	math "math"

	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/gogo/protobuf/proto"

	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
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

// Rate limit :ref:`configuration overview <config_rate_limit_service>`.
type RateLimitServiceConfig struct {
	// Specifies the gRPC service that hosts the rate limit service. The client
	// will connect to this cluster when it needs to make rate limit service
	// requests.
	GrpcService          *core.GrpcService `protobuf:"bytes,2,opt,name=grpc_service,json=grpcService,proto3" json:"grpc_service,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *RateLimitServiceConfig) Reset()         { *m = RateLimitServiceConfig{} }
func (m *RateLimitServiceConfig) String() string { return proto.CompactTextString(m) }
func (*RateLimitServiceConfig) ProtoMessage()    {}
func (*RateLimitServiceConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_3154ecf621be8917, []int{0}
}
func (m *RateLimitServiceConfig) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *RateLimitServiceConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_RateLimitServiceConfig.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *RateLimitServiceConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RateLimitServiceConfig.Merge(m, src)
}
func (m *RateLimitServiceConfig) XXX_Size() int {
	return m.Size()
}
func (m *RateLimitServiceConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_RateLimitServiceConfig.DiscardUnknown(m)
}

var xxx_messageInfo_RateLimitServiceConfig proto.InternalMessageInfo

func (m *RateLimitServiceConfig) GetGrpcService() *core.GrpcService {
	if m != nil {
		return m.GrpcService
	}
	return nil
}

func init() {
	proto.RegisterType((*RateLimitServiceConfig)(nil), "envoy.config.ratelimit.v2.RateLimitServiceConfig")
}

func init() {
	proto.RegisterFile("envoy/config/ratelimit/v2/rls.proto", fileDescriptor_3154ecf621be8917)
}

var fileDescriptor_3154ecf621be8917 = []byte{
	// 246 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x4e, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0x2f, 0x4a, 0x2c, 0x49, 0xcd, 0xc9, 0xcc,
	0xcd, 0x2c, 0xd1, 0x2f, 0x33, 0xd2, 0x2f, 0xca, 0x29, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17,
	0x92, 0x04, 0x2b, 0xd2, 0x83, 0x28, 0xd2, 0x83, 0x2b, 0xd2, 0x2b, 0x33, 0x92, 0x52, 0x81, 0xe8,
	0x4f, 0x2c, 0xc8, 0x04, 0x69, 0x49, 0xce, 0x2f, 0x4a, 0xd5, 0x4f, 0x2f, 0x2a, 0x48, 0x8e, 0x2f,
	0x4e, 0x2d, 0x2a, 0xcb, 0x4c, 0x4e, 0x85, 0x18, 0x20, 0x25, 0x5e, 0x96, 0x98, 0x93, 0x99, 0x92,
	0x58, 0x92, 0xaa, 0x0f, 0x63, 0x40, 0x24, 0x94, 0x8a, 0xb9, 0xc4, 0x82, 0x12, 0x4b, 0x52, 0x7d,
	0x40, 0xc6, 0x05, 0x43, 0xb4, 0x38, 0x83, 0x6d, 0x11, 0xf2, 0xe5, 0xe2, 0x41, 0x36, 0x48, 0x82,
	0x49, 0x81, 0x51, 0x83, 0xdb, 0x48, 0x4e, 0x0f, 0xe2, 0x94, 0xc4, 0x82, 0x4c, 0xbd, 0x32, 0x23,
	0x3d, 0x90, 0x7d, 0x7a, 0xee, 0x45, 0x05, 0xc9, 0x50, 0xbd, 0x4e, 0x5c, 0xbb, 0x5e, 0x1e, 0x60,
	0x66, 0xed, 0x62, 0x64, 0x12, 0x60, 0x0c, 0xe2, 0x4e, 0x47, 0x48, 0x78, 0xb1, 0x70, 0x30, 0x0a,
	0x30, 0x79, 0xb1, 0x70, 0x30, 0x0b, 0xb0, 0x38, 0xb9, 0x9e, 0x78, 0x24, 0xc7, 0x78, 0xe1, 0x91,
	0x1c, 0xe3, 0x83, 0x47, 0x72, 0x8c, 0x5c, 0xea, 0x99, 0xf9, 0x10, 0x43, 0x0b, 0x8a, 0xf2, 0x2b,
	0x2a, 0xf5, 0x70, 0x7a, 0xd5, 0x89, 0x23, 0x28, 0xa7, 0x38, 0x00, 0xe4, 0xea, 0x00, 0xc6, 0x28,
	0xa6, 0x32, 0xa3, 0x24, 0x36, 0xb0, 0x17, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x5d, 0xdc,
	0xc9, 0x9d, 0x43, 0x01, 0x00, 0x00,
}

func (m *RateLimitServiceConfig) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RateLimitServiceConfig) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.GrpcService != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintRls(dAtA, i, uint64(m.GrpcService.Size()))
		n1, err := m.GrpcService.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintRls(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *RateLimitServiceConfig) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.GrpcService != nil {
		l = m.GrpcService.Size()
		n += 1 + l + sovRls(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovRls(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozRls(x uint64) (n int) {
	return sovRls(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *RateLimitServiceConfig) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowRls
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
			return fmt.Errorf("proto: RateLimitServiceConfig: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: RateLimitServiceConfig: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field GrpcService", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRls
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
				return ErrInvalidLengthRls
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthRls
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.GrpcService == nil {
				m.GrpcService = &core.GrpcService{}
			}
			if err := m.GrpcService.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipRls(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthRls
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthRls
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
func skipRls(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowRls
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
					return 0, ErrIntOverflowRls
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
					return 0, ErrIntOverflowRls
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
				return 0, ErrInvalidLengthRls
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthRls
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowRls
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
				next, err := skipRls(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthRls
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
	ErrInvalidLengthRls = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowRls   = fmt.Errorf("proto: integer overflow")
)

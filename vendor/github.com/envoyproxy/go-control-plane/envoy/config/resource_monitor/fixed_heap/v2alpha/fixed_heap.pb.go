// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/config/resource_monitor/fixed_heap/v2alpha/fixed_heap.proto

package v2alpha

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

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

// The fixed heap resource monitor reports the Envoy process memory pressure, computed as a
// fraction of currently reserved heap memory divided by a statically configured maximum
// specified in the FixedHeapConfig.
type FixedHeapConfig struct {
	MaxHeapSizeBytes     uint64   `protobuf:"varint,1,opt,name=max_heap_size_bytes,json=maxHeapSizeBytes,proto3" json:"max_heap_size_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FixedHeapConfig) Reset()         { *m = FixedHeapConfig{} }
func (m *FixedHeapConfig) String() string { return proto.CompactTextString(m) }
func (*FixedHeapConfig) ProtoMessage()    {}
func (*FixedHeapConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_fixed_heap_de9752cd546c58fc, []int{0}
}
func (m *FixedHeapConfig) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *FixedHeapConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_FixedHeapConfig.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *FixedHeapConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FixedHeapConfig.Merge(dst, src)
}
func (m *FixedHeapConfig) XXX_Size() int {
	return m.Size()
}
func (m *FixedHeapConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_FixedHeapConfig.DiscardUnknown(m)
}

var xxx_messageInfo_FixedHeapConfig proto.InternalMessageInfo

func (m *FixedHeapConfig) GetMaxHeapSizeBytes() uint64 {
	if m != nil {
		return m.MaxHeapSizeBytes
	}
	return 0
}

func init() {
	proto.RegisterType((*FixedHeapConfig)(nil), "envoy.config.resource_monitor.fixed_heap.v2alpha.FixedHeapConfig")
}
func (m *FixedHeapConfig) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *FixedHeapConfig) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.MaxHeapSizeBytes != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintFixedHeap(dAtA, i, uint64(m.MaxHeapSizeBytes))
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintFixedHeap(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *FixedHeapConfig) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.MaxHeapSizeBytes != 0 {
		n += 1 + sovFixedHeap(uint64(m.MaxHeapSizeBytes))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovFixedHeap(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozFixedHeap(x uint64) (n int) {
	return sovFixedHeap(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *FixedHeapConfig) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowFixedHeap
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
			return fmt.Errorf("proto: FixedHeapConfig: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: FixedHeapConfig: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxHeapSizeBytes", wireType)
			}
			m.MaxHeapSizeBytes = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowFixedHeap
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxHeapSizeBytes |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipFixedHeap(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthFixedHeap
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
func skipFixedHeap(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowFixedHeap
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
					return 0, ErrIntOverflowFixedHeap
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
					return 0, ErrIntOverflowFixedHeap
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
				return 0, ErrInvalidLengthFixedHeap
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowFixedHeap
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
				next, err := skipFixedHeap(dAtA[start:])
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
	ErrInvalidLengthFixedHeap = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowFixedHeap   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("envoy/config/resource_monitor/fixed_heap/v2alpha/fixed_heap.proto", fileDescriptor_fixed_heap_de9752cd546c58fc)
}

var fileDescriptor_fixed_heap_de9752cd546c58fc = []byte{
	// 176 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x72, 0x4c, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0x2f, 0x4a, 0x2d, 0xce, 0x2f, 0x2d, 0x4a,
	0x4e, 0x8d, 0xcf, 0xcd, 0xcf, 0xcb, 0x2c, 0xc9, 0x2f, 0xd2, 0x4f, 0xcb, 0xac, 0x48, 0x4d, 0x89,
	0xcf, 0x48, 0x4d, 0x2c, 0xd0, 0x2f, 0x33, 0x4a, 0xcc, 0x29, 0xc8, 0x48, 0x44, 0x12, 0xd2, 0x2b,
	0x28, 0xca, 0x2f, 0xc9, 0x17, 0x32, 0x00, 0x1b, 0xa1, 0x07, 0x31, 0x42, 0x0f, 0xdd, 0x08, 0x3d,
	0x24, 0xf5, 0x50, 0x23, 0x94, 0x1c, 0xb8, 0xf8, 0xdd, 0x40, 0xa2, 0x1e, 0xa9, 0x89, 0x05, 0xce,
	0x60, 0x6d, 0x42, 0xba, 0x5c, 0xc2, 0xb9, 0x89, 0x15, 0x60, 0x65, 0xf1, 0xc5, 0x99, 0x55, 0xa9,
	0xf1, 0x49, 0x95, 0x25, 0xa9, 0xc5, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x2c, 0x41, 0x02, 0xb9, 0x89,
	0x15, 0x20, 0xb5, 0xc1, 0x99, 0x55, 0xa9, 0x4e, 0x20, 0x71, 0x27, 0xd1, 0x13, 0x8f, 0xe4, 0x18,
	0x2f, 0x3c, 0x92, 0x63, 0x7c, 0xf0, 0x48, 0x8e, 0x31, 0x8a, 0x1d, 0x6a, 0x70, 0x12, 0x1b, 0xd8,
	0x45, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7d, 0x59, 0x6c, 0xd3, 0xd6, 0x00, 0x00, 0x00,
}

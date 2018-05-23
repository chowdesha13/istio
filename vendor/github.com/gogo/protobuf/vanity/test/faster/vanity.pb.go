// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: vanity.proto

/*
	Package vanity is a generated protocol buffer package.

	It is generated from these files:
		vanity.proto

	It has these top-level messages:
		A
*/
package vanity

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

type A struct {
	Strings string `protobuf:"bytes,1,opt,name=Strings" json:"Strings"`
	Int     int64  `protobuf:"varint,2,req,name=Int" json:"Int"`
}

func (m *A) Reset()                    { *m = A{} }
func (m *A) String() string            { return proto.CompactTextString(m) }
func (*A) ProtoMessage()               {}
func (*A) Descriptor() ([]byte, []int) { return fileDescriptorVanity, []int{0} }

func (m *A) GetStrings() string {
	if m != nil {
		return m.Strings
	}
	return ""
}

func (m *A) GetInt() int64 {
	if m != nil {
		return m.Int
	}
	return 0
}

func init() {
	proto.RegisterType((*A)(nil), "vanity.A")
}
func (m *A) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *A) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintVanity(dAtA, i, uint64(len(m.Strings)))
	i += copy(dAtA[i:], m.Strings)
	dAtA[i] = 0x10
	i++
	i = encodeVarintVanity(dAtA, i, uint64(m.Int))
	return i, nil
}

func encodeVarintVanity(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *A) Size() (n int) {
	var l int
	_ = l
	l = len(m.Strings)
	n += 1 + l + sovVanity(uint64(l))
	n += 1 + sovVanity(uint64(m.Int))
	return n
}

func sovVanity(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozVanity(x uint64) (n int) {
	return sovVanity(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *A) Unmarshal(dAtA []byte) error {
	var hasFields [1]uint64
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowVanity
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
			return fmt.Errorf("proto: A: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: A: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Strings", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowVanity
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
				return ErrInvalidLengthVanity
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Strings = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Int", wireType)
			}
			m.Int = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowVanity
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Int |= (int64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			hasFields[0] |= uint64(0x00000001)
		default:
			iNdEx = preIndex
			skippy, err := skipVanity(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthVanity
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}
	if hasFields[0]&uint64(0x00000001) == 0 {
		return proto.NewRequiredNotSetError("Int")
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipVanity(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowVanity
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
					return 0, ErrIntOverflowVanity
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
					return 0, ErrIntOverflowVanity
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
				return 0, ErrInvalidLengthVanity
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowVanity
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
				next, err := skipVanity(dAtA[start:])
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
	ErrInvalidLengthVanity = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowVanity   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("vanity.proto", fileDescriptorVanity) }

var fileDescriptorVanity = []byte{
	// 109 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x29, 0x4b, 0xcc, 0xcb,
	0x2c, 0xa9, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x83, 0xf0, 0x94, 0xac, 0xb9, 0x18,
	0x1d, 0x85, 0xe4, 0xb8, 0xd8, 0x83, 0x4b, 0x8a, 0x32, 0xf3, 0xd2, 0x8b, 0x25, 0x18, 0x15, 0x18,
	0x35, 0x38, 0x9d, 0x58, 0x4e, 0xdc, 0x93, 0x67, 0x08, 0x82, 0x09, 0x0a, 0x89, 0x71, 0x31, 0x7b,
	0xe6, 0x95, 0x48, 0x30, 0x29, 0x30, 0x69, 0x30, 0x43, 0xe5, 0x40, 0x02, 0x4e, 0x02, 0x27, 0x1e,
	0xc9, 0x31, 0x5e, 0x78, 0x24, 0xc7, 0xf8, 0xe0, 0x91, 0x1c, 0xe3, 0x84, 0xc7, 0x72, 0x0c, 0x80,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x56, 0x0d, 0x52, 0xbb, 0x65, 0x00, 0x00, 0x00,
}

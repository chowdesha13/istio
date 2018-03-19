// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/test/spyAdapter/template/apa/tmpl_instance.proto

/*
	Package sampleapa is a generated protocol buffer package.

	It is generated from these files:
		mixer/test/spyAdapter/template/apa/tmpl_instance.proto

	It has these top-level messages:
		InstanceParam
*/
package sampleapa

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "istio.io/api/mixer/adapter/model/v1beta1"

import strings "strings"
import reflect "reflect"
import github_com_gogo_protobuf_sortkeys "github.com/gogo/protobuf/sortkeys"

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

type InstanceParam struct {
	Int64Primitive  string `protobuf:"bytes,1,opt,name=int64Primitive,proto3" json:"int64Primitive,omitempty"`
	BoolPrimitive   string `protobuf:"bytes,2,opt,name=boolPrimitive,proto3" json:"boolPrimitive,omitempty"`
	DoublePrimitive string `protobuf:"bytes,3,opt,name=doublePrimitive,proto3" json:"doublePrimitive,omitempty"`
	StringPrimitive string `protobuf:"bytes,4,opt,name=stringPrimitive,proto3" json:"stringPrimitive,omitempty"`
	// Attribute names to expression mapping. These expressions can use the fields from the output object
	// returned by the attribute producing adapters using $out.<fieldName> notation. For example:
	// source.ip : $out.source_pod_ip
	// In the above example, source.ip attribute will be added to the existing attribute list and its value will be set to
	// the value of source_pod_ip field of the output returned by the adapter.
	AttributeBindings map[string]string `protobuf:"bytes,72295728,rep,name=attribute_bindings,json=attributeBindings" json:"attribute_bindings,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *InstanceParam) Reset()                    { *m = InstanceParam{} }
func (*InstanceParam) ProtoMessage()               {}
func (*InstanceParam) Descriptor() ([]byte, []int) { return fileDescriptorTmplInstance, []int{0} }

func (m *InstanceParam) GetInt64Primitive() string {
	if m != nil {
		return m.Int64Primitive
	}
	return ""
}

func (m *InstanceParam) GetBoolPrimitive() string {
	if m != nil {
		return m.BoolPrimitive
	}
	return ""
}

func (m *InstanceParam) GetDoublePrimitive() string {
	if m != nil {
		return m.DoublePrimitive
	}
	return ""
}

func (m *InstanceParam) GetStringPrimitive() string {
	if m != nil {
		return m.StringPrimitive
	}
	return ""
}

func (m *InstanceParam) GetAttributeBindings() map[string]string {
	if m != nil {
		return m.AttributeBindings
	}
	return nil
}

func init() {
	proto.RegisterType((*InstanceParam)(nil), "sampleapa.InstanceParam")
}
func (this *InstanceParam) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*InstanceParam)
	if !ok {
		that2, ok := that.(InstanceParam)
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
	if this.Int64Primitive != that1.Int64Primitive {
		return false
	}
	if this.BoolPrimitive != that1.BoolPrimitive {
		return false
	}
	if this.DoublePrimitive != that1.DoublePrimitive {
		return false
	}
	if this.StringPrimitive != that1.StringPrimitive {
		return false
	}
	if len(this.AttributeBindings) != len(that1.AttributeBindings) {
		return false
	}
	for i := range this.AttributeBindings {
		if this.AttributeBindings[i] != that1.AttributeBindings[i] {
			return false
		}
	}
	return true
}
func (this *InstanceParam) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 9)
	s = append(s, "&sampleapa.InstanceParam{")
	s = append(s, "Int64Primitive: "+fmt.Sprintf("%#v", this.Int64Primitive)+",\n")
	s = append(s, "BoolPrimitive: "+fmt.Sprintf("%#v", this.BoolPrimitive)+",\n")
	s = append(s, "DoublePrimitive: "+fmt.Sprintf("%#v", this.DoublePrimitive)+",\n")
	s = append(s, "StringPrimitive: "+fmt.Sprintf("%#v", this.StringPrimitive)+",\n")
	keysForAttributeBindings := make([]string, 0, len(this.AttributeBindings))
	for k, _ := range this.AttributeBindings {
		keysForAttributeBindings = append(keysForAttributeBindings, k)
	}
	github_com_gogo_protobuf_sortkeys.Strings(keysForAttributeBindings)
	mapStringForAttributeBindings := "map[string]string{"
	for _, k := range keysForAttributeBindings {
		mapStringForAttributeBindings += fmt.Sprintf("%#v: %#v,", k, this.AttributeBindings[k])
	}
	mapStringForAttributeBindings += "}"
	if this.AttributeBindings != nil {
		s = append(s, "AttributeBindings: "+mapStringForAttributeBindings+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringTmplInstance(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
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
	if len(m.Int64Primitive) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintTmplInstance(dAtA, i, uint64(len(m.Int64Primitive)))
		i += copy(dAtA[i:], m.Int64Primitive)
	}
	if len(m.BoolPrimitive) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintTmplInstance(dAtA, i, uint64(len(m.BoolPrimitive)))
		i += copy(dAtA[i:], m.BoolPrimitive)
	}
	if len(m.DoublePrimitive) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintTmplInstance(dAtA, i, uint64(len(m.DoublePrimitive)))
		i += copy(dAtA[i:], m.DoublePrimitive)
	}
	if len(m.StringPrimitive) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintTmplInstance(dAtA, i, uint64(len(m.StringPrimitive)))
		i += copy(dAtA[i:], m.StringPrimitive)
	}
	if len(m.AttributeBindings) > 0 {
		for k, _ := range m.AttributeBindings {
			dAtA[i] = 0x82
			i++
			dAtA[i] = 0xd3
			i++
			dAtA[i] = 0xe4
			i++
			dAtA[i] = 0x93
			i++
			dAtA[i] = 0x2
			i++
			v := m.AttributeBindings[k]
			mapSize := 1 + len(k) + sovTmplInstance(uint64(len(k))) + 1 + len(v) + sovTmplInstance(uint64(len(v)))
			i = encodeVarintTmplInstance(dAtA, i, uint64(mapSize))
			dAtA[i] = 0xa
			i++
			i = encodeVarintTmplInstance(dAtA, i, uint64(len(k)))
			i += copy(dAtA[i:], k)
			dAtA[i] = 0x12
			i++
			i = encodeVarintTmplInstance(dAtA, i, uint64(len(v)))
			i += copy(dAtA[i:], v)
		}
	}
	return i, nil
}

func encodeVarintTmplInstance(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *InstanceParam) Size() (n int) {
	var l int
	_ = l
	l = len(m.Int64Primitive)
	if l > 0 {
		n += 1 + l + sovTmplInstance(uint64(l))
	}
	l = len(m.BoolPrimitive)
	if l > 0 {
		n += 1 + l + sovTmplInstance(uint64(l))
	}
	l = len(m.DoublePrimitive)
	if l > 0 {
		n += 1 + l + sovTmplInstance(uint64(l))
	}
	l = len(m.StringPrimitive)
	if l > 0 {
		n += 1 + l + sovTmplInstance(uint64(l))
	}
	if len(m.AttributeBindings) > 0 {
		for k, v := range m.AttributeBindings {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovTmplInstance(uint64(len(k))) + 1 + len(v) + sovTmplInstance(uint64(len(v)))
			n += mapEntrySize + 5 + sovTmplInstance(uint64(mapEntrySize))
		}
	}
	return n
}

func sovTmplInstance(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozTmplInstance(x uint64) (n int) {
	return sovTmplInstance(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *InstanceParam) String() string {
	if this == nil {
		return "nil"
	}
	keysForAttributeBindings := make([]string, 0, len(this.AttributeBindings))
	for k, _ := range this.AttributeBindings {
		keysForAttributeBindings = append(keysForAttributeBindings, k)
	}
	github_com_gogo_protobuf_sortkeys.Strings(keysForAttributeBindings)
	mapStringForAttributeBindings := "map[string]string{"
	for _, k := range keysForAttributeBindings {
		mapStringForAttributeBindings += fmt.Sprintf("%v: %v,", k, this.AttributeBindings[k])
	}
	mapStringForAttributeBindings += "}"
	s := strings.Join([]string{`&InstanceParam{`,
		`Int64Primitive:` + fmt.Sprintf("%v", this.Int64Primitive) + `,`,
		`BoolPrimitive:` + fmt.Sprintf("%v", this.BoolPrimitive) + `,`,
		`DoublePrimitive:` + fmt.Sprintf("%v", this.DoublePrimitive) + `,`,
		`StringPrimitive:` + fmt.Sprintf("%v", this.StringPrimitive) + `,`,
		`AttributeBindings:` + mapStringForAttributeBindings + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringTmplInstance(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *InstanceParam) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTmplInstance
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
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Int64Primitive", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplInstance
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
				return ErrInvalidLengthTmplInstance
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Int64Primitive = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field BoolPrimitive", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplInstance
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
				return ErrInvalidLengthTmplInstance
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.BoolPrimitive = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DoublePrimitive", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplInstance
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
				return ErrInvalidLengthTmplInstance
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DoublePrimitive = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StringPrimitive", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplInstance
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
				return ErrInvalidLengthTmplInstance
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.StringPrimitive = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 72295728:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AttributeBindings", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTmplInstance
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
				return ErrInvalidLengthTmplInstance
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.AttributeBindings == nil {
				m.AttributeBindings = make(map[string]string)
			}
			var mapkey string
			var mapvalue string
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowTmplInstance
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
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowTmplInstance
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= (uint64(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthTmplInstance
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = string(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var stringLenmapvalue uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowTmplInstance
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapvalue |= (uint64(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapvalue := int(stringLenmapvalue)
					if intStringLenmapvalue < 0 {
						return ErrInvalidLengthTmplInstance
					}
					postStringIndexmapvalue := iNdEx + intStringLenmapvalue
					if postStringIndexmapvalue > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = string(dAtA[iNdEx:postStringIndexmapvalue])
					iNdEx = postStringIndexmapvalue
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipTmplInstance(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if skippy < 0 {
						return ErrInvalidLengthTmplInstance
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.AttributeBindings[mapkey] = mapvalue
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTmplInstance(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTmplInstance
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
func skipTmplInstance(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTmplInstance
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
					return 0, ErrIntOverflowTmplInstance
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
					return 0, ErrIntOverflowTmplInstance
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
				return 0, ErrInvalidLengthTmplInstance
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowTmplInstance
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
				next, err := skipTmplInstance(dAtA[start:])
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
	ErrInvalidLengthTmplInstance = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTmplInstance   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("mixer/test/spyAdapter/template/apa/tmpl_instance.proto", fileDescriptorTmplInstance)
}

var fileDescriptorTmplInstance = []byte{
	// 356 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x91, 0x3f, 0x6a, 0xe3, 0x40,
	0x14, 0xc6, 0x35, 0xd2, 0xee, 0x82, 0x67, 0xf1, 0xfe, 0x19, 0x96, 0xc5, 0xb8, 0x18, 0x8c, 0x59,
	0x16, 0x17, 0x8b, 0x84, 0xbd, 0xc1, 0x84, 0x74, 0x36, 0x49, 0x91, 0xce, 0xf8, 0x02, 0xe6, 0x29,
	0x1a, 0xcc, 0x10, 0x69, 0x34, 0x68, 0x9e, 0x8d, 0xdd, 0xe5, 0x08, 0x81, 0x5c, 0x22, 0x65, 0x0e,
	0x90, 0x03, 0x84, 0x54, 0x26, 0x55, 0x48, 0x15, 0x2b, 0x29, 0x52, 0xba, 0x4c, 0x19, 0x2c, 0xc9,
	0x31, 0x16, 0xe9, 0xe6, 0xfd, 0xf8, 0x7d, 0x0f, 0xe6, 0x7b, 0xb4, 0x1b, 0xc9, 0x99, 0x48, 0x3c,
	0x14, 0x06, 0x3d, 0xa3, 0xe7, 0xbd, 0x00, 0x34, 0x66, 0x73, 0xa4, 0x43, 0x40, 0xe1, 0x81, 0x06,
	0x0f, 0x23, 0x1d, 0x8e, 0xa4, 0x32, 0x08, 0xea, 0x44, 0xb8, 0x3a, 0x89, 0x31, 0x66, 0x15, 0x03,
	0x91, 0x0e, 0x05, 0x68, 0xa8, 0xff, 0xcb, 0x57, 0x40, 0x11, 0x8d, 0xe2, 0x40, 0x84, 0xde, 0xb4,
	0xed, 0x0b, 0x84, 0xb6, 0x27, 0x66, 0x28, 0x94, 0x91, 0xb1, 0x32, 0x79, 0xb0, 0xf9, 0x60, 0xd3,
	0xea, 0x71, 0xb1, 0x6b, 0x00, 0x09, 0x44, 0xec, 0x2f, 0xfd, 0x26, 0x15, 0x76, 0xf7, 0x06, 0x89,
	0x8c, 0x24, 0xca, 0xa9, 0xa8, 0x91, 0x06, 0x69, 0x55, 0x86, 0x25, 0xca, 0xfe, 0xd0, 0xaa, 0x1f,
	0xc7, 0xe1, 0x56, 0xb3, 0x33, 0x6d, 0x17, 0xb2, 0x16, 0xfd, 0x1e, 0xc4, 0x13, 0x3f, 0x14, 0x5b,
	0xcf, 0xc9, 0xbc, 0x32, 0x5e, 0x9b, 0x06, 0x13, 0xa9, 0xc6, 0x5b, 0xf3, 0x53, 0x6e, 0x96, 0x30,
	0x03, 0xca, 0x00, 0x31, 0x91, 0xfe, 0x04, 0xc5, 0xc8, 0x97, 0x2a, 0x90, 0x6a, 0x6c, 0x6a, 0x57,
	0xb7, 0xd7, 0xcd, 0x86, 0xd3, 0xfa, 0xda, 0xf1, 0xdc, 0xf7, 0x32, 0xdc, 0x9d, 0xaf, 0xb9, 0xbd,
	0x4d, 0xaa, 0x5f, 0x84, 0x8e, 0x14, 0x26, 0xf3, 0xe1, 0x4f, 0x28, 0xf3, 0xfa, 0x21, 0xfd, 0xfd,
	0xb1, 0xcc, 0x7e, 0x50, 0xe7, 0x54, 0xcc, 0x8b, 0x4e, 0xd6, 0x4f, 0xf6, 0x8b, 0x7e, 0x9e, 0x42,
	0x38, 0xd9, 0x14, 0x90, 0x0f, 0x07, 0xf6, 0x3e, 0xe9, 0x77, 0x16, 0x4b, 0x6e, 0xdd, 0x2f, 0xb9,
	0xb5, 0x5a, 0x72, 0x72, 0x96, 0x72, 0x72, 0x99, 0x72, 0x72, 0x93, 0x72, 0xb2, 0x48, 0x39, 0x79,
	0x4c, 0x39, 0x79, 0x49, 0xb9, 0xb5, 0x4a, 0x39, 0x39, 0x7f, 0xe2, 0xd6, 0xeb, 0xdd, 0xf3, 0x85,
	0xed, 0xf8, 0x5f, 0xb2, 0xbb, 0xfc, 0x7f, 0x0b, 0x00, 0x00, 0xff, 0xff, 0xfa, 0x44, 0xd7, 0xa3,
	0x0a, 0x02, 0x00, 0x00,
}

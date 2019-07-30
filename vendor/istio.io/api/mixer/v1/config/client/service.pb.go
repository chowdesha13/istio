// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/v1/config/client/service.proto

package client

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_gogo_protobuf_sortkeys "github.com/gogo/protobuf/sortkeys"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
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

// IstioService identifies a service and optionally service version.
// The FQDN of the service is composed from the name, namespace, and implementation-specific domain suffix
// (e.g. on Kubernetes, "reviews" + "default" + "svc.cluster.local" -> "reviews.default.svc.cluster.local").
type IstioService struct {
	// The short name of the service such as "foo".
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Optional namespace of the service. Defaults to value of metadata namespace field.
	Namespace string `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	// Domain suffix used to construct the service FQDN in implementations that support such specification.
	Domain string `protobuf:"bytes,3,opt,name=domain,proto3" json:"domain,omitempty"`
	// The service FQDN.
	Service string `protobuf:"bytes,4,opt,name=service,proto3" json:"service,omitempty"`
	// Optional one or more labels that uniquely identify the service version.
	//
	// *Note:* When used for a VirtualService destination, labels MUST be empty.
	//
	Labels map[string]string `protobuf:"bytes,5,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *IstioService) Reset()      { *m = IstioService{} }
func (*IstioService) ProtoMessage() {}
func (*IstioService) Descriptor() ([]byte, []int) {
	return fileDescriptor_3358a28a51c817d5, []int{0}
}
func (m *IstioService) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *IstioService) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *IstioService) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IstioService.Merge(m, src)
}
func (m *IstioService) XXX_Size() int {
	return m.Size()
}
func (m *IstioService) XXX_DiscardUnknown() {
	xxx_messageInfo_IstioService.DiscardUnknown(m)
}

var xxx_messageInfo_IstioService proto.InternalMessageInfo

func init() {
	proto.RegisterType((*IstioService)(nil), "istio.mixer.v1.config.client.IstioService")
	proto.RegisterMapType((map[string]string)(nil), "istio.mixer.v1.config.client.IstioService.LabelsEntry")
}

func init() {
	proto.RegisterFile("mixer/v1/config/client/service.proto", fileDescriptor_3358a28a51c817d5)
}

var fileDescriptor_3358a28a51c817d5 = []byte{
	// 318 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x51, 0x3f, 0x4b, 0x3b, 0x31,
	0x18, 0x4e, 0xfa, 0xef, 0x47, 0xd3, 0xdf, 0x20, 0xa1, 0x48, 0x28, 0xe5, 0xa5, 0xa8, 0x43, 0xa7,
	0x84, 0x2a, 0x88, 0x3a, 0x0a, 0x0e, 0x82, 0x38, 0xd4, 0xcd, 0x2d, 0x3d, 0x63, 0x09, 0x5e, 0x2f,
	0xe5, 0xee, 0x3c, 0xec, 0xe6, 0x47, 0xf0, 0x63, 0xf8, 0x51, 0x3a, 0x76, 0xec, 0xe8, 0xe5, 0x16,
	0xc7, 0x7e, 0x01, 0x41, 0x2e, 0xb9, 0x62, 0x07, 0x71, 0xca, 0xf3, 0xbc, 0xcf, 0xf3, 0xbc, 0x3c,
	0x49, 0xc8, 0xd1, 0x4c, 0xbf, 0xa8, 0x58, 0x64, 0x23, 0x11, 0x98, 0xe8, 0x51, 0x4f, 0x45, 0x10,
	0x6a, 0x15, 0xa5, 0x22, 0x51, 0x71, 0xa6, 0x03, 0xc5, 0xe7, 0xb1, 0x49, 0x0d, 0xed, 0xeb, 0x24,
	0xd5, 0x86, 0x3b, 0x2f, 0xcf, 0x46, 0xdc, 0x7b, 0xb9, 0xf7, 0xf6, 0xba, 0x53, 0x33, 0x35, 0xce,
	0x28, 0x4a, 0xe4, 0x33, 0x07, 0x5f, 0x98, 0xfc, 0xbf, 0x2e, 0x63, 0x77, 0x7e, 0x15, 0xa5, 0xa4,
	0x11, 0xc9, 0x99, 0x62, 0x78, 0x80, 0x87, 0xed, 0xb1, 0xc3, 0xb4, 0x4f, 0xda, 0xe5, 0x99, 0xcc,
	0x65, 0xa0, 0x58, 0xcd, 0x09, 0x3f, 0x03, 0xba, 0x4f, 0x5a, 0x0f, 0x66, 0x26, 0x75, 0xc4, 0xea,
	0x4e, 0xaa, 0x18, 0x65, 0xe4, 0x5f, 0xd5, 0x8f, 0x35, 0x9c, 0xb0, 0xa5, 0xf4, 0x96, 0xb4, 0x42,
	0x39, 0x51, 0x61, 0xc2, 0x9a, 0x83, 0xfa, 0xb0, 0x73, 0x7c, 0xca, 0xff, 0x6a, 0xce, 0x77, 0xfb,
	0xf1, 0x1b, 0x17, 0xbc, 0x8a, 0xd2, 0x78, 0x31, 0xae, 0xb6, 0xf4, 0xce, 0x49, 0x67, 0x67, 0x4c,
	0xf7, 0x48, 0xfd, 0x49, 0x2d, 0xaa, 0x1b, 0x94, 0x90, 0x76, 0x49, 0x33, 0x93, 0xe1, 0xf3, 0xb6,
	0xbc, 0x27, 0x17, 0xb5, 0x33, 0x7c, 0x29, 0x97, 0x39, 0xa0, 0x55, 0x0e, 0x68, 0x9d, 0x03, 0xda,
	0xe4, 0x80, 0x5e, 0x2d, 0xe0, 0x77, 0x0b, 0x68, 0x69, 0x01, 0xaf, 0x2c, 0xe0, 0xb5, 0x05, 0xfc,
	0x61, 0x01, 0x7f, 0x5a, 0x40, 0x1b, 0x0b, 0xf8, 0xad, 0x00, 0xb4, 0x2a, 0x00, 0xad, 0x0b, 0x40,
	0xf7, 0x87, 0xbe, 0xb7, 0x36, 0x42, 0xce, 0xb5, 0xf8, 0xfd, 0x93, 0x26, 0x2d, 0xf7, 0xd2, 0x27,
	0xdf, 0x01, 0x00, 0x00, 0xff, 0xff, 0xab, 0x14, 0xde, 0x44, 0xc5, 0x01, 0x00, 0x00,
}

func (m *IstioService) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *IstioService) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *IstioService) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Labels) > 0 {
		keysForLabels := make([]string, 0, len(m.Labels))
		for k := range m.Labels {
			keysForLabels = append(keysForLabels, string(k))
		}
		github_com_gogo_protobuf_sortkeys.Strings(keysForLabels)
		for iNdEx := len(keysForLabels) - 1; iNdEx >= 0; iNdEx-- {
			v := m.Labels[string(keysForLabels[iNdEx])]
			baseI := i
			i -= len(v)
			copy(dAtA[i:], v)
			i = encodeVarintService(dAtA, i, uint64(len(v)))
			i--
			dAtA[i] = 0x12
			i -= len(keysForLabels[iNdEx])
			copy(dAtA[i:], keysForLabels[iNdEx])
			i = encodeVarintService(dAtA, i, uint64(len(keysForLabels[iNdEx])))
			i--
			dAtA[i] = 0xa
			i = encodeVarintService(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x2a
		}
	}
	if len(m.Service) > 0 {
		i -= len(m.Service)
		copy(dAtA[i:], m.Service)
		i = encodeVarintService(dAtA, i, uint64(len(m.Service)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.Domain) > 0 {
		i -= len(m.Domain)
		copy(dAtA[i:], m.Domain)
		i = encodeVarintService(dAtA, i, uint64(len(m.Domain)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Namespace) > 0 {
		i -= len(m.Namespace)
		copy(dAtA[i:], m.Namespace)
		i = encodeVarintService(dAtA, i, uint64(len(m.Namespace)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintService(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintService(dAtA []byte, offset int, v uint64) int {
	offset -= sovService(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *IstioService) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovService(uint64(l))
	}
	l = len(m.Namespace)
	if l > 0 {
		n += 1 + l + sovService(uint64(l))
	}
	l = len(m.Domain)
	if l > 0 {
		n += 1 + l + sovService(uint64(l))
	}
	l = len(m.Service)
	if l > 0 {
		n += 1 + l + sovService(uint64(l))
	}
	if len(m.Labels) > 0 {
		for k, v := range m.Labels {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovService(uint64(len(k))) + 1 + len(v) + sovService(uint64(len(v)))
			n += mapEntrySize + 1 + sovService(uint64(mapEntrySize))
		}
	}
	return n
}

func sovService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozService(x uint64) (n int) {
	return sovService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *IstioService) String() string {
	if this == nil {
		return "nil"
	}
	keysForLabels := make([]string, 0, len(this.Labels))
	for k, _ := range this.Labels {
		keysForLabels = append(keysForLabels, k)
	}
	github_com_gogo_protobuf_sortkeys.Strings(keysForLabels)
	mapStringForLabels := "map[string]string{"
	for _, k := range keysForLabels {
		mapStringForLabels += fmt.Sprintf("%v: %v,", k, this.Labels[k])
	}
	mapStringForLabels += "}"
	s := strings.Join([]string{`&IstioService{`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`Namespace:` + fmt.Sprintf("%v", this.Namespace) + `,`,
		`Domain:` + fmt.Sprintf("%v", this.Domain) + `,`,
		`Service:` + fmt.Sprintf("%v", this.Service) + `,`,
		`Labels:` + mapStringForLabels + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringService(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *IstioService) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowService
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
			return fmt.Errorf("proto: IstioService: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: IstioService: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Namespace", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Namespace = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Domain", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Domain = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Service", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Service = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Labels", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
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
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Labels == nil {
				m.Labels = make(map[string]string)
			}
			var mapkey string
			var mapvalue string
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowService
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
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowService
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthService
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey < 0 {
						return ErrInvalidLengthService
					}
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = string(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var stringLenmapvalue uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowService
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapvalue |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapvalue := int(stringLenmapvalue)
					if intStringLenmapvalue < 0 {
						return ErrInvalidLengthService
					}
					postStringIndexmapvalue := iNdEx + intStringLenmapvalue
					if postStringIndexmapvalue < 0 {
						return ErrInvalidLengthService
					}
					if postStringIndexmapvalue > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = string(dAtA[iNdEx:postStringIndexmapvalue])
					iNdEx = postStringIndexmapvalue
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipService(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if skippy < 0 {
						return ErrInvalidLengthService
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.Labels[mapkey] = mapvalue
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthService
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthService
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
func skipService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowService
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
					return 0, ErrIntOverflowService
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
					return 0, ErrIntOverflowService
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
				return 0, ErrInvalidLengthService
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthService
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowService
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
				next, err := skipService(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthService
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
	ErrInvalidLengthService = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowService   = fmt.Errorf("proto: integer overflow")
)

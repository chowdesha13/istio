// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/adapter/circonus/config/config.proto

/*
	Package config is a generated protocol buffer package.

	The `circonus` adapter enables Istio to deliver metric data to the
	[Circonus](https://www.circonus.com) monitoring backend.

	This adapter supports the [metric template](https://istio.io/docs/reference/config/policy-and-telemetry/templates/metric/).

	It is generated from these files:
		mixer/adapter/circonus/config/config.proto

	It has these top-level messages:
		Params
*/
package config

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "github.com/gogo/protobuf/types"

import time "time"

import strconv "strconv"

import types "github.com/gogo/protobuf/types"

import strings "strings"
import reflect "reflect"

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

// The type of metric.
type Params_MetricInfo_Type int32

const (
	UNKNOWN      Params_MetricInfo_Type = 0
	COUNTER      Params_MetricInfo_Type = 1
	GAUGE        Params_MetricInfo_Type = 2
	DISTRIBUTION Params_MetricInfo_Type = 3
)

var Params_MetricInfo_Type_name = map[int32]string{
	0: "UNKNOWN",
	1: "COUNTER",
	2: "GAUGE",
	3: "DISTRIBUTION",
}
var Params_MetricInfo_Type_value = map[string]int32{
	"UNKNOWN":      0,
	"COUNTER":      1,
	"GAUGE":        2,
	"DISTRIBUTION": 3,
}

func (Params_MetricInfo_Type) EnumDescriptor() ([]byte, []int) {
	return fileDescriptorConfig, []int{0, 0, 0}
}

// Configuration format for the Circonus adapter.
type Params struct {
	// Circonus SubmissionURL to HTTPTrap check
	SubmissionUrl      string               `protobuf:"bytes,1,opt,name=submission_url,json=submissionUrl,proto3" json:"submission_url,omitempty"`
	SubmissionInterval time.Duration        `protobuf:"bytes,2,opt,name=submission_interval,json=submissionInterval,stdduration" json:"submission_interval"`
	Metrics            []*Params_MetricInfo `protobuf:"bytes,3,rep,name=metrics" json:"metrics,omitempty"`
}

func (m *Params) Reset()                    { *m = Params{} }
func (*Params) ProtoMessage()               {}
func (*Params) Descriptor() ([]byte, []int) { return fileDescriptorConfig, []int{0} }

// Describes how to represent a metric
type Params_MetricInfo struct {
	// name
	Name string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Type Params_MetricInfo_Type `protobuf:"varint,2,opt,name=type,proto3,enum=adapter.circonus.config.Params_MetricInfo_Type" json:"type,omitempty"`
}

func (m *Params_MetricInfo) Reset()                    { *m = Params_MetricInfo{} }
func (*Params_MetricInfo) ProtoMessage()               {}
func (*Params_MetricInfo) Descriptor() ([]byte, []int) { return fileDescriptorConfig, []int{0, 0} }

func init() {
	proto.RegisterType((*Params)(nil), "adapter.circonus.config.Params")
	proto.RegisterType((*Params_MetricInfo)(nil), "adapter.circonus.config.Params.MetricInfo")
	proto.RegisterEnum("adapter.circonus.config.Params_MetricInfo_Type", Params_MetricInfo_Type_name, Params_MetricInfo_Type_value)
}
func (x Params_MetricInfo_Type) String() string {
	s, ok := Params_MetricInfo_Type_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (m *Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.SubmissionUrl) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.SubmissionUrl)))
		i += copy(dAtA[i:], m.SubmissionUrl)
	}
	dAtA[i] = 0x12
	i++
	i = encodeVarintConfig(dAtA, i, uint64(types.SizeOfStdDuration(m.SubmissionInterval)))
	n1, err := types.StdDurationMarshalTo(m.SubmissionInterval, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	if len(m.Metrics) > 0 {
		for _, msg := range m.Metrics {
			dAtA[i] = 0x1a
			i++
			i = encodeVarintConfig(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func (m *Params_MetricInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_MetricInfo) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	if m.Type != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.Type))
	}
	return i, nil
}

func encodeVarintConfig(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *Params) Size() (n int) {
	var l int
	_ = l
	l = len(m.SubmissionUrl)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	l = types.SizeOfStdDuration(m.SubmissionInterval)
	n += 1 + l + sovConfig(uint64(l))
	if len(m.Metrics) > 0 {
		for _, e := range m.Metrics {
			l = e.Size()
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	return n
}

func (m *Params_MetricInfo) Size() (n int) {
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.Type != 0 {
		n += 1 + sovConfig(uint64(m.Type))
	}
	return n
}

func sovConfig(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozConfig(x uint64) (n int) {
	return sovConfig(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *Params) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Params{`,
		`SubmissionUrl:` + fmt.Sprintf("%v", this.SubmissionUrl) + `,`,
		`SubmissionInterval:` + strings.Replace(strings.Replace(this.SubmissionInterval.String(), "Duration", "google_protobuf1.Duration", 1), `&`, ``, 1) + `,`,
		`Metrics:` + strings.Replace(fmt.Sprintf("%v", this.Metrics), "Params_MetricInfo", "Params_MetricInfo", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Params_MetricInfo) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Params_MetricInfo{`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`Type:` + fmt.Sprintf("%v", this.Type) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringConfig(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *Params) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
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
			return fmt.Errorf("proto: Params: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Params: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SubmissionUrl", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
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
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SubmissionUrl = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SubmissionInterval", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
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
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := types.StdDurationUnmarshal(&m.SubmissionInterval, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metrics", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
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
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Metrics = append(m.Metrics, &Params_MetricInfo{})
			if err := m.Metrics[len(m.Metrics)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
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
func (m *Params_MetricInfo) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
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
			return fmt.Errorf("proto: MetricInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MetricInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
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
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= (Params_MetricInfo_Type(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
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
func skipConfig(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowConfig
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
					return 0, ErrIntOverflowConfig
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
					return 0, ErrIntOverflowConfig
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
				return 0, ErrInvalidLengthConfig
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowConfig
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
				next, err := skipConfig(dAtA[start:])
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
	ErrInvalidLengthConfig = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConfig   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("mixer/adapter/circonus/config/config.proto", fileDescriptorConfig) }

var fileDescriptorConfig = []byte{
	// 401 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0x4d, 0x8b, 0xda, 0x40,
	0x1c, 0xc6, 0x67, 0xd4, 0x6a, 0x1d, 0x5b, 0x09, 0xd3, 0x42, 0xad, 0x87, 0x51, 0x84, 0x82, 0x78,
	0x98, 0x80, 0xbd, 0xf4, 0xd2, 0x43, 0x7d, 0x41, 0x42, 0x69, 0x2c, 0x69, 0x42, 0xa1, 0x97, 0x12,
	0xe3, 0x18, 0x06, 0x92, 0x4c, 0x98, 0x24, 0xa5, 0xde, 0xfa, 0x11, 0x7a, 0xec, 0x07, 0xe8, 0xa1,
	0x1f, 0xc5, 0xa3, 0xc7, 0x9e, 0x76, 0x37, 0xd9, 0xcb, 0x1e, 0x65, 0x3f, 0xc1, 0x62, 0x12, 0x71,
	0x2f, 0x0b, 0x7b, 0x9a, 0xff, 0xcb, 0xef, 0xe1, 0x79, 0xfe, 0x83, 0x46, 0x3e, 0xff, 0xc9, 0xa4,
	0x6a, 0xaf, 0xed, 0x30, 0x66, 0x52, 0x75, 0xb8, 0x74, 0x44, 0x90, 0x44, 0xaa, 0x23, 0x82, 0x0d,
	0x77, 0xcb, 0x87, 0x86, 0x52, 0xc4, 0x02, 0xbf, 0x2a, 0x29, 0x7a, 0xa2, 0x68, 0xb1, 0xee, 0xbe,
	0x74, 0x85, 0x2b, 0x72, 0x46, 0x3d, 0x56, 0x05, 0xde, 0x25, 0xae, 0x10, 0xae, 0xc7, 0xd4, 0xbc,
	0x5b, 0x25, 0x1b, 0x75, 0x9d, 0x48, 0x3b, 0xe6, 0x22, 0x28, 0xf6, 0x83, 0xdb, 0x0a, 0xaa, 0x7f,
	0xb6, 0xa5, 0xed, 0x47, 0xf8, 0x0d, 0x6a, 0x47, 0xc9, 0xca, 0xe7, 0x51, 0xc4, 0x45, 0xf0, 0x3d,
	0x91, 0x5e, 0x07, 0xf6, 0xe1, 0xb0, 0x69, 0x3c, 0x3f, 0x4f, 0x2d, 0xe9, 0x61, 0x13, 0xbd, 0xb8,
	0x87, 0xf1, 0x20, 0x66, 0xf2, 0x87, 0xed, 0x75, 0x2a, 0x7d, 0x38, 0x6c, 0x8d, 0x5f, 0xd3, 0xc2,
	0x8f, 0x9e, 0xfc, 0xe8, 0xac, 0xf4, 0x9b, 0x3c, 0xdd, 0x5d, 0xf4, 0xc0, 0x9f, 0xcb, 0x1e, 0x34,
	0xf0, 0x59, 0xaf, 0x95, 0x72, 0x3c, 0x43, 0x0d, 0x9f, 0xc5, 0x92, 0x3b, 0x51, 0xa7, 0xda, 0xaf,
	0x0e, 0x5b, 0xe3, 0x11, 0x7d, 0xe0, 0x50, 0x5a, 0xc4, 0xa5, 0x9f, 0x72, 0x5c, 0x0b, 0x36, 0xc2,
	0x38, 0x49, 0xbb, 0x7f, 0x21, 0x42, 0xe7, 0x39, 0xc6, 0xa8, 0x16, 0xd8, 0x3e, 0x2b, 0xef, 0xc8,
	0x6b, 0x3c, 0x45, 0xb5, 0x78, 0x1b, 0xb2, 0x3c, 0x6f, 0x7b, 0xac, 0x3e, 0xde, 0x85, 0x9a, 0xdb,
	0x90, 0x19, 0xb9, 0x78, 0xf0, 0x1e, 0xd5, 0x8e, 0x1d, 0x6e, 0xa1, 0x86, 0xa5, 0x7f, 0xd4, 0x97,
	0x5f, 0x75, 0x05, 0x1c, 0x9b, 0xe9, 0xd2, 0xd2, 0xcd, 0xb9, 0xa1, 0x40, 0xdc, 0x44, 0x4f, 0x16,
	0x1f, 0xac, 0xc5, 0x5c, 0xa9, 0x60, 0x05, 0x3d, 0x9b, 0x69, 0x5f, 0x4c, 0x43, 0x9b, 0x58, 0xa6,
	0xb6, 0xd4, 0x95, 0xea, 0xe4, 0xdd, 0x2e, 0x25, 0x60, 0x9f, 0x12, 0xf0, 0x3f, 0x25, 0xe0, 0x90,
	0x12, 0xf0, 0x2b, 0x23, 0xf0, 0x5f, 0x46, 0xc0, 0x2e, 0x23, 0x70, 0x9f, 0x11, 0x78, 0x95, 0x11,
	0x78, 0x93, 0x11, 0x70, 0xc8, 0x08, 0xfc, 0x7d, 0x4d, 0xc0, 0xb7, 0x7a, 0x91, 0x6a, 0x55, 0xcf,
	0xff, 0xf5, 0xed, 0x5d, 0x00, 0x00, 0x00, 0xff, 0xff, 0xb8, 0xfc, 0x59, 0xa9, 0x32, 0x02, 0x00,
	0x00,
}

// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/adapter/list/config/config.proto

/*
	Package config is a generated protocol buffer package.

	It is generated from these files:
		mixer/adapter/list/config/config.proto

	It has these top-level messages:
		Params
*/
package config

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/types"
import _ "github.com/gogo/protobuf/gogoproto"

import time "time"

import strconv "strconv"

import github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"

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

type Params_ListEntryType int32

const (
	// List entries are treated as plain strings.
	STRINGS Params_ListEntryType = 0
	// List entries are treated as case-insensitive strings.
	CASE_INSENSITIVE_STRINGS Params_ListEntryType = 1
	// List entries are treated as IP addresses and ranges.
	IP_ADDRESSES Params_ListEntryType = 2
)

var Params_ListEntryType_name = map[int32]string{
	0: "STRINGS",
	1: "CASE_INSENSITIVE_STRINGS",
	2: "IP_ADDRESSES",
}
var Params_ListEntryType_value = map[string]int32{
	"STRINGS":                  0,
	"CASE_INSENSITIVE_STRINGS": 1,
	"IP_ADDRESSES":             2,
}

func (Params_ListEntryType) EnumDescriptor() ([]byte, []int) { return fileDescriptorConfig, []int{0, 0} }

type Params struct {
	// Where to find the list to check against. This may be ommited for a completely local list.
	ProviderUrl string `protobuf:"bytes,1,opt,name=provider_url,json=providerUrl,proto3" json:"provider_url,omitempty"`
	// Determines how often the provider is polled for
	// an updated list
	RefreshInterval time.Duration `protobuf:"bytes,2,opt,name=refresh_interval,json=refreshInterval,stdduration" json:"refresh_interval"`
	// Indicates how long to keep a list before discarding it.
	// Typically, the TTL value should be set to noticeably longer (> 2x) than the
	// refresh interval to ensure continued operation in the face of transient
	// server outages.
	Ttl time.Duration `protobuf:"bytes,3,opt,name=ttl,stdduration" json:"ttl"`
	// Indicates the amount of time a caller of this adapter can cache an answer
	// before it should ask the adapter again.
	CachingInterval time.Duration `protobuf:"bytes,4,opt,name=caching_interval,json=cachingInterval,stdduration" json:"caching_interval"`
	// Indicates the number of times a caller of this adapter can use a cached answer
	// before it should ask the adapter again.
	CachingUseCount int32 `protobuf:"varint,5,opt,name=caching_use_count,json=cachingUseCount,proto3" json:"caching_use_count,omitempty"`
	// List entries that are consulted first, before the list from the server
	Overrides []string `protobuf:"bytes,6,rep,name=overrides" json:"overrides,omitempty"`
	// Determines the kind of list entry and overrides.
	EntryType Params_ListEntryType `protobuf:"varint,7,opt,name=entry_type,json=entryType,proto3,enum=adapter.list.config.Params_ListEntryType" json:"entry_type,omitempty"`
	// Whether the list operates as a blacklist or a whitelist.
	Blacklist bool `protobuf:"varint,8,opt,name=blacklist,proto3" json:"blacklist,omitempty"`
}

func (m *Params) Reset()                    { *m = Params{} }
func (*Params) ProtoMessage()               {}
func (*Params) Descriptor() ([]byte, []int) { return fileDescriptorConfig, []int{0} }

func init() {
	proto.RegisterType((*Params)(nil), "adapter.list.config.Params")
	proto.RegisterEnum("adapter.list.config.Params_ListEntryType", Params_ListEntryType_name, Params_ListEntryType_value)
}
func (x Params_ListEntryType) String() string {
	s, ok := Params_ListEntryType_name[int32(x)]
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
	if len(m.ProviderUrl) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.ProviderUrl)))
		i += copy(dAtA[i:], m.ProviderUrl)
	}
	dAtA[i] = 0x12
	i++
	i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(m.RefreshInterval)))
	n1, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(m.RefreshInterval, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	dAtA[i] = 0x1a
	i++
	i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(m.Ttl)))
	n2, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(m.Ttl, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n2
	dAtA[i] = 0x22
	i++
	i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(m.CachingInterval)))
	n3, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(m.CachingInterval, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n3
	if m.CachingUseCount != 0 {
		dAtA[i] = 0x28
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.CachingUseCount))
	}
	if len(m.Overrides) > 0 {
		for _, s := range m.Overrides {
			dAtA[i] = 0x32
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
	if m.EntryType != 0 {
		dAtA[i] = 0x38
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.EntryType))
	}
	if m.Blacklist {
		dAtA[i] = 0x40
		i++
		if m.Blacklist {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
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
	l = len(m.ProviderUrl)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	l = github_com_gogo_protobuf_types.SizeOfStdDuration(m.RefreshInterval)
	n += 1 + l + sovConfig(uint64(l))
	l = github_com_gogo_protobuf_types.SizeOfStdDuration(m.Ttl)
	n += 1 + l + sovConfig(uint64(l))
	l = github_com_gogo_protobuf_types.SizeOfStdDuration(m.CachingInterval)
	n += 1 + l + sovConfig(uint64(l))
	if m.CachingUseCount != 0 {
		n += 1 + sovConfig(uint64(m.CachingUseCount))
	}
	if len(m.Overrides) > 0 {
		for _, s := range m.Overrides {
			l = len(s)
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	if m.EntryType != 0 {
		n += 1 + sovConfig(uint64(m.EntryType))
	}
	if m.Blacklist {
		n += 2
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
		`ProviderUrl:` + fmt.Sprintf("%v", this.ProviderUrl) + `,`,
		`RefreshInterval:` + strings.Replace(strings.Replace(this.RefreshInterval.String(), "Duration", "google_protobuf.Duration", 1), `&`, ``, 1) + `,`,
		`Ttl:` + strings.Replace(strings.Replace(this.Ttl.String(), "Duration", "google_protobuf.Duration", 1), `&`, ``, 1) + `,`,
		`CachingInterval:` + strings.Replace(strings.Replace(this.CachingInterval.String(), "Duration", "google_protobuf.Duration", 1), `&`, ``, 1) + `,`,
		`CachingUseCount:` + fmt.Sprintf("%v", this.CachingUseCount) + `,`,
		`Overrides:` + fmt.Sprintf("%v", this.Overrides) + `,`,
		`EntryType:` + fmt.Sprintf("%v", this.EntryType) + `,`,
		`Blacklist:` + fmt.Sprintf("%v", this.Blacklist) + `,`,
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
				return fmt.Errorf("proto: wrong wireType = %d for field ProviderUrl", wireType)
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
			m.ProviderUrl = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RefreshInterval", wireType)
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
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(&m.RefreshInterval, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ttl", wireType)
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
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(&m.Ttl, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CachingInterval", wireType)
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
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(&m.CachingInterval, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field CachingUseCount", wireType)
			}
			m.CachingUseCount = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.CachingUseCount |= (int32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Overrides", wireType)
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
			m.Overrides = append(m.Overrides, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field EntryType", wireType)
			}
			m.EntryType = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.EntryType |= (Params_ListEntryType(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 8:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Blacklist", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
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
			m.Blacklist = bool(v != 0)
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

func init() { proto.RegisterFile("mixer/adapter/list/config/config.proto", fileDescriptorConfig) }

var fileDescriptorConfig = []byte{
	// 458 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x91, 0xb1, 0x6e, 0xd3, 0x40,
	0x1c, 0xc6, 0xef, 0x9a, 0x36, 0x4d, 0x2e, 0x05, 0xc2, 0xc1, 0x60, 0xaa, 0xea, 0x6a, 0x3a, 0x20,
	0xc3, 0x70, 0x96, 0x8a, 0x90, 0x58, 0xdb, 0xc6, 0x02, 0x4b, 0x55, 0x54, 0xd9, 0x29, 0x03, 0x8b,
	0xe5, 0x38, 0x17, 0xf7, 0x84, 0xeb, 0xb3, 0xce, 0xe7, 0x88, 0x6c, 0x88, 0x27, 0x60, 0xe4, 0x11,
	0x78, 0x94, 0x8c, 0x1d, 0x99, 0x80, 0x98, 0x85, 0xb1, 0x8f, 0x80, 0x2e, 0xb6, 0x13, 0x21, 0x31,
	0xc0, 0xe4, 0xbf, 0xbe, 0xfb, 0x7e, 0xf7, 0x7d, 0xfe, 0x1f, 0x7a, 0x72, 0xcd, 0xdf, 0x33, 0x69,
	0x87, 0x93, 0x30, 0x53, 0x4c, 0xda, 0x09, 0xcf, 0x95, 0x1d, 0x89, 0x74, 0xca, 0xe3, 0xfa, 0x43,
	0x33, 0x29, 0x94, 0xc0, 0x0f, 0x6a, 0x07, 0xd5, 0x0e, 0x5a, 0x1d, 0xed, 0x93, 0x58, 0x88, 0x38,
	0x61, 0xf6, 0xca, 0x32, 0x2e, 0xa6, 0xf6, 0xa4, 0x90, 0xa1, 0xe2, 0x22, 0xad, 0xa0, 0xfd, 0x87,
	0xb1, 0x88, 0xc5, 0x6a, 0xb4, 0xf5, 0x54, 0xa9, 0x47, 0x1f, 0xb7, 0x51, 0xfb, 0x22, 0x94, 0xe1,
	0x75, 0x8e, 0x1f, 0xa3, 0xbd, 0x4c, 0x8a, 0x19, 0x9f, 0x30, 0x19, 0x14, 0x32, 0x31, 0xa0, 0x09,
	0xad, 0xae, 0xd7, 0x6b, 0xb4, 0x4b, 0x99, 0xe0, 0x21, 0xea, 0x4b, 0x36, 0x95, 0x2c, 0xbf, 0x0a,
	0x78, 0xaa, 0x98, 0x9c, 0x85, 0x89, 0xb1, 0x65, 0x42, 0xab, 0x77, 0xfc, 0x88, 0x56, 0xf1, 0xb4,
	0x89, 0xa7, 0x83, 0x3a, 0xfe, 0xb4, 0xb3, 0xf8, 0x76, 0x08, 0x3e, 0x7f, 0x3f, 0x84, 0xde, 0xbd,
	0x1a, 0x76, 0x6b, 0x16, 0xbf, 0x40, 0x2d, 0xa5, 0x12, 0xa3, 0xf5, 0xef, 0x57, 0x68, 0xbf, 0xae,
	0x11, 0x85, 0xd1, 0x15, 0x4f, 0xe3, 0x4d, 0x8d, 0xed, 0xff, 0xa8, 0x51, 0xc3, 0xeb, 0x1a, 0xcf,
	0xd0, 0xfd, 0xe6, 0xbe, 0x22, 0x67, 0x41, 0x24, 0x8a, 0x54, 0x19, 0x3b, 0x26, 0xb4, 0x76, 0xd6,
	0xde, 0xcb, 0x9c, 0x9d, 0x69, 0x19, 0x1f, 0xa0, 0xae, 0x98, 0x31, 0x29, 0xf9, 0x84, 0xe5, 0x46,
	0xdb, 0x6c, 0x59, 0x5d, 0x6f, 0x23, 0xe0, 0xd7, 0x08, 0xb1, 0x54, 0xc9, 0x79, 0xa0, 0xe6, 0x19,
	0x33, 0x76, 0x4d, 0x68, 0xdd, 0x3d, 0x7e, 0x4a, 0xff, 0xf2, 0x5c, 0xb4, 0x5a, 0x3a, 0x3d, 0xe7,
	0xb9, 0x72, 0x34, 0x31, 0x9a, 0x67, 0xcc, 0xeb, 0xb2, 0x66, 0xd4, 0x39, 0xe3, 0x24, 0x8c, 0xde,
	0x69, 0xc6, 0xe8, 0x98, 0xd0, 0xea, 0x78, 0x1b, 0xe1, 0xe8, 0x1c, 0xdd, 0xf9, 0x83, 0xc4, 0x3d,
	0xb4, 0xeb, 0x8f, 0x3c, 0x77, 0xf8, 0xca, 0xef, 0x03, 0x7c, 0x80, 0x8c, 0xb3, 0x13, 0xdf, 0x09,
	0xdc, 0xa1, 0xef, 0x0c, 0x7d, 0x77, 0xe4, 0xbe, 0x71, 0x82, 0xe6, 0x14, 0xe2, 0x3e, 0xda, 0x73,
	0x2f, 0x82, 0x93, 0xc1, 0xc0, 0x73, 0x7c, 0xdf, 0xf1, 0xfb, 0x5b, 0xa7, 0x2f, 0x17, 0x4b, 0x02,
	0x6e, 0x96, 0x04, 0x7c, 0x5d, 0x12, 0x70, 0xbb, 0x24, 0xe0, 0x43, 0x49, 0xe0, 0x97, 0x92, 0x80,
	0x45, 0x49, 0xe0, 0x4d, 0x49, 0xe0, 0x8f, 0x92, 0xc0, 0x5f, 0x25, 0x01, 0xb7, 0x25, 0x81, 0x9f,
	0x7e, 0x12, 0xf0, 0xb6, 0x5d, 0xfd, 0xc5, 0xb8, 0xbd, 0xda, 0xf3, 0xf3, 0xdf, 0x01, 0x00, 0x00,
	0xff, 0xff, 0x99, 0x80, 0x5e, 0x42, 0xba, 0x02, 0x00, 0x00,
}

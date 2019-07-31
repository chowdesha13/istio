// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/adapter/memquota/config/config.proto

// The `memquota` adapter can be used to support Istio's quota management
// system. Although functional, this adapter is not intended for production
// use and is suited for local testing only. The reason for this limitation
// is that this adapter can only be used in meshes where there is a single
// instance of Mixer running for the whole mesh (i.e. non-HA configuration)
// and if that single instance crashes, all outstanding quota values will
// be lost.
//
// This adapter supports the [quota template](https://istio.io/docs/reference/config/policy-and-telemetry/templates/quota/).

package config

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_gogo_protobuf_sortkeys "github.com/gogo/protobuf/sortkeys"
	_ "github.com/gogo/protobuf/types"
	github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"
	io "io"
	math "math"
	reflect "reflect"
	strings "strings"
	time "time"
)

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

// Configuration format for the `memquota` adapter.
type Params struct {
	// The set of known quotas.
	Quotas []Params_Quota `protobuf:"bytes,1,rep,name=quotas,proto3" json:"quotas"`
	// Minimum number of seconds that deduplication is possible for a given operation.
	MinDeduplicationDuration time.Duration `protobuf:"bytes,2,opt,name=min_deduplication_duration,json=minDeduplicationDuration,proto3,stdduration" json:"min_deduplication_duration"`
}

func (m *Params) Reset()      { *m = Params{} }
func (*Params) ProtoMessage() {}
func (*Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_67b4efe0be29bdbf, []int{0}
}
func (m *Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params.Merge(m, src)
}
func (m *Params) XXX_Size() int {
	return m.Size()
}
func (m *Params) XXX_DiscardUnknown() {
	xxx_messageInfo_Params.DiscardUnknown(m)
}

var xxx_messageInfo_Params proto.InternalMessageInfo

// Defines a quota's limit and duration.
type Params_Quota struct {
	// The name of the quota
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The upper limit for this quota.
	MaxAmount int64 `protobuf:"varint,2,opt,name=max_amount,json=maxAmount,proto3" json:"max_amount,omitempty"`
	// The amount of time allocated quota remains valid before it is
	// automatically released. This is only meaningful for rate limit
	// quotas, otherwise the value must be zero.
	ValidDuration time.Duration `protobuf:"bytes,3,opt,name=valid_duration,json=validDuration,proto3,stdduration" json:"valid_duration"`
	// Overrides associated with this quota.
	// The first matching override is applied.
	Overrides []Params_Override `protobuf:"bytes,4,rep,name=overrides,proto3" json:"overrides"`
}

func (m *Params_Quota) Reset()      { *m = Params_Quota{} }
func (*Params_Quota) ProtoMessage() {}
func (*Params_Quota) Descriptor() ([]byte, []int) {
	return fileDescriptor_67b4efe0be29bdbf, []int{0, 0}
}
func (m *Params_Quota) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params_Quota) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params_Quota.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params_Quota) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params_Quota.Merge(m, src)
}
func (m *Params_Quota) XXX_Size() int {
	return m.Size()
}
func (m *Params_Quota) XXX_DiscardUnknown() {
	xxx_messageInfo_Params_Quota.DiscardUnknown(m)
}

var xxx_messageInfo_Params_Quota proto.InternalMessageInfo

func (m *Params_Quota) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Params_Quota) GetMaxAmount() int64 {
	if m != nil {
		return m.MaxAmount
	}
	return 0
}

func (m *Params_Quota) GetValidDuration() time.Duration {
	if m != nil {
		return m.ValidDuration
	}
	return 0
}

func (m *Params_Quota) GetOverrides() []Params_Override {
	if m != nil {
		return m.Overrides
	}
	return nil
}

// Defines an override value for a quota. If no override matches
// a particular quota request, the default for the quota is used.
type Params_Override struct {
	// The specific dimensions for which this override applies.
	// String representation of instance dimensions is used to check against configured dimensions.
	Dimensions map[string]string `protobuf:"bytes,1,rep,name=dimensions,proto3" json:"dimensions,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// The upper limit for this quota.
	MaxAmount int64 `protobuf:"varint,2,opt,name=max_amount,json=maxAmount,proto3" json:"max_amount,omitempty"`
	// The amount of time allocated quota remains valid before it is
	// automatically released. This is only meaningful for rate limit
	// quotas, otherwise the value must be zero.
	ValidDuration time.Duration `protobuf:"bytes,3,opt,name=valid_duration,json=validDuration,proto3,stdduration" json:"valid_duration"`
}

func (m *Params_Override) Reset()      { *m = Params_Override{} }
func (*Params_Override) ProtoMessage() {}
func (*Params_Override) Descriptor() ([]byte, []int) {
	return fileDescriptor_67b4efe0be29bdbf, []int{0, 1}
}
func (m *Params_Override) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params_Override) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params_Override.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params_Override) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params_Override.Merge(m, src)
}
func (m *Params_Override) XXX_Size() int {
	return m.Size()
}
func (m *Params_Override) XXX_DiscardUnknown() {
	xxx_messageInfo_Params_Override.DiscardUnknown(m)
}

var xxx_messageInfo_Params_Override proto.InternalMessageInfo

func (m *Params_Override) GetDimensions() map[string]string {
	if m != nil {
		return m.Dimensions
	}
	return nil
}

func (m *Params_Override) GetMaxAmount() int64 {
	if m != nil {
		return m.MaxAmount
	}
	return 0
}

func (m *Params_Override) GetValidDuration() time.Duration {
	if m != nil {
		return m.ValidDuration
	}
	return 0
}

func init() {
	proto.RegisterType((*Params)(nil), "adapter.memquota.config.Params")
	proto.RegisterType((*Params_Quota)(nil), "adapter.memquota.config.Params.Quota")
	proto.RegisterType((*Params_Override)(nil), "adapter.memquota.config.Params.Override")
	proto.RegisterMapType((map[string]string)(nil), "adapter.memquota.config.Params.Override.DimensionsEntry")
}

func init() {
	proto.RegisterFile("mixer/adapter/memquota/config/config.proto", fileDescriptor_67b4efe0be29bdbf)
}

var fileDescriptor_67b4efe0be29bdbf = []byte{
	// 457 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x91, 0x3f, 0x8b, 0x13, 0x41,
	0x18, 0xc6, 0x67, 0xf2, 0x8f, 0xcb, 0x7b, 0xf8, 0x87, 0xe1, 0xc0, 0x75, 0xc1, 0x49, 0x10, 0x84,
	0x60, 0x31, 0x0b, 0x67, 0x73, 0x1c, 0x08, 0x1a, 0x63, 0x23, 0x82, 0xba, 0x95, 0xd8, 0x84, 0xb9,
	0xdb, 0xb9, 0x65, 0x30, 0x33, 0x13, 0x27, 0xbb, 0x21, 0xd7, 0x59, 0x5a, 0x5a, 0x58, 0x58, 0x5a,
	0x58, 0xf8, 0x51, 0x52, 0xa6, 0x3c, 0x2c, 0xd4, 0x6c, 0x1a, 0xcb, 0xfb, 0x08, 0xb2, 0x33, 0xbb,
	0xde, 0x21, 0x88, 0xa9, 0xac, 0xf6, 0xdd, 0x99, 0xe7, 0x79, 0xde, 0x1f, 0xcf, 0xc0, 0x5d, 0x25,
	0x17, 0xc2, 0x46, 0x3c, 0xe1, 0xd3, 0x4c, 0xd8, 0x48, 0x09, 0xf5, 0x26, 0x37, 0x19, 0x8f, 0x8e,
	0x8d, 0x3e, 0x91, 0x69, 0xf5, 0x61, 0x53, 0x6b, 0x32, 0x43, 0x6e, 0x54, 0x2a, 0x56, 0xab, 0x98,
	0xbf, 0x0e, 0x69, 0x6a, 0x4c, 0x3a, 0x11, 0x91, 0x93, 0x1d, 0xe5, 0x27, 0x51, 0x92, 0x5b, 0x9e,
	0x49, 0xa3, 0xbd, 0x31, 0xdc, 0x4b, 0x4d, 0x6a, 0xdc, 0x18, 0x95, 0x93, 0x3f, 0xbd, 0xfd, 0xb9,
	0x0d, 0x9d, 0xe7, 0xdc, 0x72, 0x35, 0x23, 0x8f, 0xa0, 0xe3, 0x02, 0x67, 0x01, 0xee, 0x37, 0x07,
	0xbb, 0xfb, 0x77, 0xd8, 0x5f, 0x56, 0x31, 0x6f, 0x60, 0x2f, 0xca, 0xb3, 0x61, 0x6b, 0xf9, 0xad,
	0x87, 0xe2, 0xca, 0x4a, 0x38, 0x84, 0x4a, 0xea, 0x71, 0x22, 0x92, 0x7c, 0x3a, 0x91, 0xc7, 0x0e,
	0x60, 0x5c, 0x93, 0x04, 0x8d, 0x3e, 0x1e, 0xec, 0xee, 0xdf, 0x64, 0x1e, 0x95, 0xd5, 0xa8, 0x6c,
	0x54, 0x09, 0x86, 0x3b, 0x65, 0xd8, 0xc7, 0xef, 0x3d, 0x1c, 0x07, 0x4a, 0xea, 0xd1, 0xe5, 0x94,
	0x5a, 0x13, 0x7e, 0xc5, 0xd0, 0x76, 0xab, 0x09, 0x81, 0x96, 0xe6, 0x4a, 0x04, 0xb8, 0x8f, 0x07,
	0xdd, 0xd8, 0xcd, 0xe4, 0x16, 0x80, 0xe2, 0x8b, 0x31, 0x57, 0x26, 0xd7, 0x99, 0x5b, 0xd8, 0x8c,
	0xbb, 0x8a, 0x2f, 0x1e, 0xba, 0x03, 0xf2, 0x04, 0xae, 0xce, 0xf9, 0x44, 0x26, 0x17, 0x4c, 0xcd,
	0xed, 0x99, 0xae, 0x38, 0x6b, 0x7d, 0x41, 0x9e, 0x42, 0xd7, 0xcc, 0x85, 0xb5, 0x32, 0x11, 0xb3,
	0xa0, 0xe5, 0x3a, 0x1b, 0xfc, 0xab, 0xb3, 0x67, 0x95, 0xa1, 0xaa, 0xed, 0x22, 0xe0, 0xb0, 0xf5,
	0xee, 0x53, 0x0f, 0x87, 0x1f, 0x1a, 0xb0, 0x53, 0x6b, 0xc8, 0x4b, 0x80, 0x44, 0x2a, 0xa1, 0x67,
	0xd2, 0xe8, 0xfa, 0x55, 0x0e, 0xb6, 0xdd, 0xc0, 0x46, 0xbf, 0xad, 0x8f, 0x75, 0x66, 0x4f, 0xe3,
	0x4b, 0x59, 0xff, 0xb1, 0xa5, 0xf0, 0x3e, 0x5c, 0xfb, 0x83, 0x84, 0x5c, 0x87, 0xe6, 0x6b, 0x71,
	0x5a, 0x3d, 0x5b, 0x39, 0x92, 0x3d, 0x68, 0xcf, 0xf9, 0x24, 0x17, 0x0e, 0xa5, 0x1b, 0xfb, 0x9f,
	0xc3, 0xc6, 0x01, 0xf6, 0xb5, 0x0c, 0x1f, 0x2c, 0xd7, 0x14, 0xad, 0xd6, 0x14, 0x9d, 0xad, 0x29,
	0x3a, 0x5f, 0x53, 0xf4, 0xb6, 0xa0, 0xf8, 0x4b, 0x41, 0xd1, 0xb2, 0xa0, 0x78, 0x55, 0x50, 0xfc,
	0xa3, 0xa0, 0xf8, 0x67, 0x41, 0xd1, 0x79, 0x41, 0xf1, 0xfb, 0x0d, 0x45, 0xab, 0x0d, 0x45, 0x67,
	0x1b, 0x8a, 0x5e, 0x75, 0x7c, 0x3b, 0x47, 0x1d, 0x87, 0x7c, 0xef, 0x57, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x56, 0x02, 0x85, 0x8b, 0x6c, 0x03, 0x00, 0x00,
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
	if len(m.Quotas) > 0 {
		for _, msg := range m.Quotas {
			dAtA[i] = 0xa
			i++
			i = encodeVarintConfig(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	dAtA[i] = 0x12
	i++
	i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(m.MinDeduplicationDuration)))
	n1, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(m.MinDeduplicationDuration, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	return i, nil
}

func (m *Params_Quota) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_Quota) MarshalTo(dAtA []byte) (int, error) {
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
	if m.MaxAmount != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.MaxAmount))
	}
	dAtA[i] = 0x1a
	i++
	i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(m.ValidDuration)))
	n2, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(m.ValidDuration, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n2
	if len(m.Overrides) > 0 {
		for _, msg := range m.Overrides {
			dAtA[i] = 0x22
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

func (m *Params_Override) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_Override) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Dimensions) > 0 {
		for k, _ := range m.Dimensions {
			dAtA[i] = 0xa
			i++
			v := m.Dimensions[k]
			mapSize := 1 + len(k) + sovConfig(uint64(len(k))) + 1 + len(v) + sovConfig(uint64(len(v)))
			i = encodeVarintConfig(dAtA, i, uint64(mapSize))
			dAtA[i] = 0xa
			i++
			i = encodeVarintConfig(dAtA, i, uint64(len(k)))
			i += copy(dAtA[i:], k)
			dAtA[i] = 0x12
			i++
			i = encodeVarintConfig(dAtA, i, uint64(len(v)))
			i += copy(dAtA[i:], v)
		}
	}
	if m.MaxAmount != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.MaxAmount))
	}
	dAtA[i] = 0x1a
	i++
	i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(m.ValidDuration)))
	n3, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(m.ValidDuration, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n3
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
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Quotas) > 0 {
		for _, e := range m.Quotas {
			l = e.Size()
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	l = github_com_gogo_protobuf_types.SizeOfStdDuration(m.MinDeduplicationDuration)
	n += 1 + l + sovConfig(uint64(l))
	return n
}

func (m *Params_Quota) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.MaxAmount != 0 {
		n += 1 + sovConfig(uint64(m.MaxAmount))
	}
	l = github_com_gogo_protobuf_types.SizeOfStdDuration(m.ValidDuration)
	n += 1 + l + sovConfig(uint64(l))
	if len(m.Overrides) > 0 {
		for _, e := range m.Overrides {
			l = e.Size()
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	return n
}

func (m *Params_Override) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Dimensions) > 0 {
		for k, v := range m.Dimensions {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovConfig(uint64(len(k))) + 1 + len(v) + sovConfig(uint64(len(v)))
			n += mapEntrySize + 1 + sovConfig(uint64(mapEntrySize))
		}
	}
	if m.MaxAmount != 0 {
		n += 1 + sovConfig(uint64(m.MaxAmount))
	}
	l = github_com_gogo_protobuf_types.SizeOfStdDuration(m.ValidDuration)
	n += 1 + l + sovConfig(uint64(l))
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
		`Quotas:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.Quotas), "Params_Quota", "Params_Quota", 1), `&`, ``, 1) + `,`,
		`MinDeduplicationDuration:` + strings.Replace(strings.Replace(this.MinDeduplicationDuration.String(), "Duration", "types.Duration", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Params_Quota) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Params_Quota{`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`MaxAmount:` + fmt.Sprintf("%v", this.MaxAmount) + `,`,
		`ValidDuration:` + strings.Replace(strings.Replace(this.ValidDuration.String(), "Duration", "types.Duration", 1), `&`, ``, 1) + `,`,
		`Overrides:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.Overrides), "Params_Override", "Params_Override", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Params_Override) String() string {
	if this == nil {
		return "nil"
	}
	keysForDimensions := make([]string, 0, len(this.Dimensions))
	for k, _ := range this.Dimensions {
		keysForDimensions = append(keysForDimensions, k)
	}
	github_com_gogo_protobuf_sortkeys.Strings(keysForDimensions)
	mapStringForDimensions := "map[string]string{"
	for _, k := range keysForDimensions {
		mapStringForDimensions += fmt.Sprintf("%v: %v,", k, this.Dimensions[k])
	}
	mapStringForDimensions += "}"
	s := strings.Join([]string{`&Params_Override{`,
		`Dimensions:` + mapStringForDimensions + `,`,
		`MaxAmount:` + fmt.Sprintf("%v", this.MaxAmount) + `,`,
		`ValidDuration:` + strings.Replace(strings.Replace(this.ValidDuration.String(), "Duration", "types.Duration", 1), `&`, ``, 1) + `,`,
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
			wire |= uint64(b&0x7F) << shift
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
				return fmt.Errorf("proto: wrong wireType = %d for field Quotas", wireType)
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
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Quotas = append(m.Quotas, Params_Quota{})
			if err := m.Quotas[len(m.Quotas)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MinDeduplicationDuration", wireType)
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
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(&m.MinDeduplicationDuration, dAtA[iNdEx:postIndex]); err != nil {
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
			if (iNdEx + skippy) < 0 {
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
func (m *Params_Quota) Unmarshal(dAtA []byte) error {
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
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Quota: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Quota: illegal tag %d (wire type %d)", fieldNum, wire)
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
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxAmount", wireType)
			}
			m.MaxAmount = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxAmount |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ValidDuration", wireType)
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
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(&m.ValidDuration, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Overrides", wireType)
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
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Overrides = append(m.Overrides, Params_Override{})
			if err := m.Overrides[len(m.Overrides)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
			if (iNdEx + skippy) < 0 {
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
func (m *Params_Override) Unmarshal(dAtA []byte) error {
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
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Override: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Override: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Dimensions", wireType)
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
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Dimensions == nil {
				m.Dimensions = make(map[string]string)
			}
			var mapkey string
			var mapvalue string
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
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
							return ErrIntOverflowConfig
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
						return ErrInvalidLengthConfig
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey < 0 {
						return ErrInvalidLengthConfig
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
							return ErrIntOverflowConfig
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
						return ErrInvalidLengthConfig
					}
					postStringIndexmapvalue := iNdEx + intStringLenmapvalue
					if postStringIndexmapvalue < 0 {
						return ErrInvalidLengthConfig
					}
					if postStringIndexmapvalue > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = string(dAtA[iNdEx:postStringIndexmapvalue])
					iNdEx = postStringIndexmapvalue
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipConfig(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if skippy < 0 {
						return ErrInvalidLengthConfig
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.Dimensions[mapkey] = mapvalue
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxAmount", wireType)
			}
			m.MaxAmount = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxAmount |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ValidDuration", wireType)
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
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(&m.ValidDuration, dAtA[iNdEx:postIndex]); err != nil {
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
			if (iNdEx + skippy) < 0 {
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
			if length < 0 {
				return 0, ErrInvalidLengthConfig
			}
			iNdEx += length
			if iNdEx < 0 {
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
				if iNdEx < 0 {
					return 0, ErrInvalidLengthConfig
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
	ErrInvalidLengthConfig = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConfig   = fmt.Errorf("proto: integer overflow")
)

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/api/config_change.proto

package configchange // import "google.golang.org/genproto/googleapis/api/configchange"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Classifies set of possible modifications to an object in the service
// configuration.
type ChangeType int32

const (
	// No value was provided.
	ChangeType_CHANGE_TYPE_UNSPECIFIED ChangeType = 0
	// The changed object exists in the 'new' service configuration, but not
	// in the 'old' service configuration.
	ChangeType_ADDED ChangeType = 1
	// The changed object exists in the 'old' service configuration, but not
	// in the 'new' service configuration.
	ChangeType_REMOVED ChangeType = 2
	// The changed object exists in both service configurations, but its value
	// is different.
	ChangeType_MODIFIED ChangeType = 3
)

var ChangeType_name = map[int32]string{
	0: "CHANGE_TYPE_UNSPECIFIED",
	1: "ADDED",
	2: "REMOVED",
	3: "MODIFIED",
}
var ChangeType_value = map[string]int32{
	"CHANGE_TYPE_UNSPECIFIED": 0,
	"ADDED":                   1,
	"REMOVED":                 2,
	"MODIFIED":                3,
}

func (x ChangeType) String() string {
	return proto.EnumName(ChangeType_name, int32(x))
}
func (ChangeType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_config_change_ef3c642f4673b39c, []int{0}
}

// Output generated from semantically comparing two versions of a service
// configuration.
//
// Includes detailed information about a field that have changed with
// applicable advice about potential consequences for the change, such as
// backwards-incompatibility.
type ConfigChange struct {
	// Object hierarchy path to the change, with levels separated by a '.'
	// character. For repeated fields, an applicable unique identifier field is
	// used for the index (usually selector, name, or id). For maps, the term
	// 'key' is used. If the field has no unique identifier, the numeric index
	// is used.
	// Examples:
	// -
	// visibility.rules[selector=="google.LibraryService.CreateBook"].restriction
	// - quota.metric_rules[selector=="google"].metric_costs[key=="reads"].value
	// - logging.producer_destinations[0]
	Element string `protobuf:"bytes,1,opt,name=element,proto3" json:"element,omitempty"`
	// Value of the changed object in the old Service configuration,
	// in JSON format. This field will not be populated if ChangeType == ADDED.
	OldValue string `protobuf:"bytes,2,opt,name=old_value,json=oldValue,proto3" json:"old_value,omitempty"`
	// Value of the changed object in the new Service configuration,
	// in JSON format. This field will not be populated if ChangeType == REMOVED.
	NewValue string `protobuf:"bytes,3,opt,name=new_value,json=newValue,proto3" json:"new_value,omitempty"`
	// The type for this change, either ADDED, REMOVED, or MODIFIED.
	ChangeType ChangeType `protobuf:"varint,4,opt,name=change_type,json=changeType,proto3,enum=google.api.ChangeType" json:"change_type,omitempty"`
	// Collection of advice provided for this change, useful for determining the
	// possible impact of this change.
	Advices              []*Advice `protobuf:"bytes,5,rep,name=advices,proto3" json:"advices,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *ConfigChange) Reset()         { *m = ConfigChange{} }
func (m *ConfigChange) String() string { return proto.CompactTextString(m) }
func (*ConfigChange) ProtoMessage()    {}
func (*ConfigChange) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_change_ef3c642f4673b39c, []int{0}
}
func (m *ConfigChange) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConfigChange.Unmarshal(m, b)
}
func (m *ConfigChange) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConfigChange.Marshal(b, m, deterministic)
}
func (dst *ConfigChange) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConfigChange.Merge(dst, src)
}
func (m *ConfigChange) XXX_Size() int {
	return xxx_messageInfo_ConfigChange.Size(m)
}
func (m *ConfigChange) XXX_DiscardUnknown() {
	xxx_messageInfo_ConfigChange.DiscardUnknown(m)
}

var xxx_messageInfo_ConfigChange proto.InternalMessageInfo

func (m *ConfigChange) GetElement() string {
	if m != nil {
		return m.Element
	}
	return ""
}

func (m *ConfigChange) GetOldValue() string {
	if m != nil {
		return m.OldValue
	}
	return ""
}

func (m *ConfigChange) GetNewValue() string {
	if m != nil {
		return m.NewValue
	}
	return ""
}

func (m *ConfigChange) GetChangeType() ChangeType {
	if m != nil {
		return m.ChangeType
	}
	return ChangeType_CHANGE_TYPE_UNSPECIFIED
}

func (m *ConfigChange) GetAdvices() []*Advice {
	if m != nil {
		return m.Advices
	}
	return nil
}

// Generated advice about this change, used for providing more
// information about how a change will affect the existing service.
type Advice struct {
	// Useful description for why this advice was applied and what actions should
	// be taken to mitigate any implied risks.
	Description          string   `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Advice) Reset()         { *m = Advice{} }
func (m *Advice) String() string { return proto.CompactTextString(m) }
func (*Advice) ProtoMessage()    {}
func (*Advice) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_change_ef3c642f4673b39c, []int{1}
}
func (m *Advice) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Advice.Unmarshal(m, b)
}
func (m *Advice) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Advice.Marshal(b, m, deterministic)
}
func (dst *Advice) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Advice.Merge(dst, src)
}
func (m *Advice) XXX_Size() int {
	return xxx_messageInfo_Advice.Size(m)
}
func (m *Advice) XXX_DiscardUnknown() {
	xxx_messageInfo_Advice.DiscardUnknown(m)
}

var xxx_messageInfo_Advice proto.InternalMessageInfo

func (m *Advice) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func init() {
	proto.RegisterType((*ConfigChange)(nil), "google.api.ConfigChange")
	proto.RegisterType((*Advice)(nil), "google.api.Advice")
	proto.RegisterEnum("google.api.ChangeType", ChangeType_name, ChangeType_value)
}

func init() {
	proto.RegisterFile("google/api/config_change.proto", fileDescriptor_config_change_ef3c642f4673b39c)
}

var fileDescriptor_config_change_ef3c642f4673b39c = []byte{
	// 338 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x91, 0xcd, 0x4e, 0xc2, 0x40,
	0x14, 0x85, 0x2d, 0xff, 0xdc, 0x12, 0x82, 0xb3, 0xd0, 0x26, 0x24, 0xa6, 0x61, 0x45, 0x88, 0x69,
	0x13, 0x5c, 0xb8, 0x70, 0x55, 0xda, 0x8a, 0x2c, 0x80, 0xa6, 0x22, 0x89, 0x6e, 0x9a, 0xb1, 0x1d,
	0xc7, 0x49, 0xca, 0xcc, 0x08, 0x15, 0xc2, 0xeb, 0xf8, 0x36, 0xbe, 0x95, 0xa1, 0x03, 0xd2, 0xdd,
	0x9c, 0xf9, 0xce, 0xcd, 0x3d, 0x39, 0x17, 0x6e, 0xa8, 0x10, 0x34, 0x25, 0x36, 0x96, 0xcc, 0x8e,
	0x05, 0xff, 0x60, 0x34, 0x8a, 0x3f, 0x31, 0xa7, 0xc4, 0x92, 0x6b, 0x91, 0x09, 0x04, 0x8a, 0x5b,
	0x58, 0xb2, 0xde, 0xaf, 0x06, 0x2d, 0x37, 0xf7, 0xb8, 0xb9, 0x05, 0x19, 0x50, 0x27, 0x29, 0x59,
	0x11, 0x9e, 0x19, 0x9a, 0xa9, 0xf5, 0x9b, 0xe1, 0x49, 0xa2, 0x2e, 0x34, 0x45, 0x9a, 0x44, 0x5b,
	0x9c, 0x7e, 0x13, 0xa3, 0x94, 0xb3, 0x86, 0x48, 0x93, 0xe5, 0x41, 0x1f, 0x20, 0x27, 0xbb, 0x23,
	0x2c, 0x2b, 0xc8, 0xc9, 0x4e, 0xc1, 0x7b, 0xd0, 0x55, 0x80, 0x28, 0xdb, 0x4b, 0x62, 0x54, 0x4c,
	0xad, 0xdf, 0x1e, 0x5e, 0x59, 0xe7, 0x18, 0x96, 0x5a, 0xbe, 0xd8, 0x4b, 0x12, 0x42, 0xfc, 0xff,
	0x46, 0xb7, 0x50, 0xc7, 0xc9, 0x96, 0xc5, 0x64, 0x63, 0x54, 0xcd, 0x72, 0x5f, 0x1f, 0xa2, 0xe2,
	0x90, 0x93, 0xa3, 0xf0, 0x64, 0xe9, 0x0d, 0xa0, 0xa6, 0xbe, 0x90, 0x09, 0x7a, 0x42, 0x36, 0xf1,
	0x9a, 0xc9, 0x8c, 0x09, 0x7e, 0x0c, 0x5b, 0xfc, 0x1a, 0xcc, 0x01, 0xce, 0x3b, 0x51, 0x17, 0xae,
	0xdd, 0x27, 0x67, 0x36, 0xf6, 0xa3, 0xc5, 0x6b, 0xe0, 0x47, 0x2f, 0xb3, 0xe7, 0xc0, 0x77, 0x27,
	0x8f, 0x13, 0xdf, 0xeb, 0x5c, 0xa0, 0x26, 0x54, 0x1d, 0xcf, 0xf3, 0xbd, 0x8e, 0x86, 0x74, 0xa8,
	0x87, 0xfe, 0x74, 0xbe, 0xf4, 0xbd, 0x4e, 0x09, 0xb5, 0xa0, 0x31, 0x9d, 0x7b, 0xca, 0x55, 0x1e,
	0x7d, 0x41, 0x3b, 0x16, 0xab, 0x42, 0xbc, 0xd1, 0x65, 0xb1, 0xd7, 0xe0, 0xd0, 0x7c, 0xa0, 0xbd,
	0xb9, 0x47, 0x03, 0x15, 0x29, 0xe6, 0xd4, 0x12, 0x6b, 0x6a, 0x53, 0xc2, 0xf3, 0xbb, 0xd8, 0x0a,
	0x61, 0xc9, 0x36, 0x85, 0xd3, 0xa9, 0x36, 0x1e, 0x8a, 0xe2, 0xa7, 0x54, 0x19, 0x3b, 0xc1, 0xe4,
	0xbd, 0x96, 0x8f, 0xdd, 0xfd, 0x05, 0x00, 0x00, 0xff, 0xff, 0x46, 0x8b, 0xd3, 0xf5, 0xf0, 0x01,
	0x00, 0x00,
}

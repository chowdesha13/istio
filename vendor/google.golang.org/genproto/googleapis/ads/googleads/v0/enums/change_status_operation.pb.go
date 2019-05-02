// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/enums/change_status_operation.proto

package enums // import "google.golang.org/genproto/googleapis/ads/googleads/v0/enums"

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

// Status of the changed resource
type ChangeStatusOperationEnum_ChangeStatusOperation int32

const (
	// No value has been specified.
	ChangeStatusOperationEnum_UNSPECIFIED ChangeStatusOperationEnum_ChangeStatusOperation = 0
	// Used for return value only. Represents an unclassified resource unknown
	// in this version.
	ChangeStatusOperationEnum_UNKNOWN ChangeStatusOperationEnum_ChangeStatusOperation = 1
	// The resource was created.
	ChangeStatusOperationEnum_ADDED ChangeStatusOperationEnum_ChangeStatusOperation = 2
	// The resource was modified.
	ChangeStatusOperationEnum_CHANGED ChangeStatusOperationEnum_ChangeStatusOperation = 3
	// The resource was removed.
	ChangeStatusOperationEnum_REMOVED ChangeStatusOperationEnum_ChangeStatusOperation = 4
)

var ChangeStatusOperationEnum_ChangeStatusOperation_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "ADDED",
	3: "CHANGED",
	4: "REMOVED",
}
var ChangeStatusOperationEnum_ChangeStatusOperation_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"ADDED":       2,
	"CHANGED":     3,
	"REMOVED":     4,
}

func (x ChangeStatusOperationEnum_ChangeStatusOperation) String() string {
	return proto.EnumName(ChangeStatusOperationEnum_ChangeStatusOperation_name, int32(x))
}
func (ChangeStatusOperationEnum_ChangeStatusOperation) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_change_status_operation_ed761e3f0b9eaec4, []int{0, 0}
}

// Container for enum describing operations for the ChangeStatus resource.
type ChangeStatusOperationEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ChangeStatusOperationEnum) Reset()         { *m = ChangeStatusOperationEnum{} }
func (m *ChangeStatusOperationEnum) String() string { return proto.CompactTextString(m) }
func (*ChangeStatusOperationEnum) ProtoMessage()    {}
func (*ChangeStatusOperationEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_change_status_operation_ed761e3f0b9eaec4, []int{0}
}
func (m *ChangeStatusOperationEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ChangeStatusOperationEnum.Unmarshal(m, b)
}
func (m *ChangeStatusOperationEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ChangeStatusOperationEnum.Marshal(b, m, deterministic)
}
func (dst *ChangeStatusOperationEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChangeStatusOperationEnum.Merge(dst, src)
}
func (m *ChangeStatusOperationEnum) XXX_Size() int {
	return xxx_messageInfo_ChangeStatusOperationEnum.Size(m)
}
func (m *ChangeStatusOperationEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_ChangeStatusOperationEnum.DiscardUnknown(m)
}

var xxx_messageInfo_ChangeStatusOperationEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ChangeStatusOperationEnum)(nil), "google.ads.googleads.v0.enums.ChangeStatusOperationEnum")
	proto.RegisterEnum("google.ads.googleads.v0.enums.ChangeStatusOperationEnum_ChangeStatusOperation", ChangeStatusOperationEnum_ChangeStatusOperation_name, ChangeStatusOperationEnum_ChangeStatusOperation_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/enums/change_status_operation.proto", fileDescriptor_change_status_operation_ed761e3f0b9eaec4)
}

var fileDescriptor_change_status_operation_ed761e3f0b9eaec4 = []byte{
	// 303 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xb2, 0x4e, 0xcf, 0xcf, 0x4f,
	0xcf, 0x49, 0xd5, 0x4f, 0x4c, 0x29, 0xd6, 0x87, 0x30, 0x41, 0xac, 0x32, 0x03, 0xfd, 0xd4, 0xbc,
	0xd2, 0xdc, 0x62, 0xfd, 0xe4, 0x8c, 0xc4, 0xbc, 0xf4, 0xd4, 0xf8, 0xe2, 0x92, 0xc4, 0x92, 0xd2,
	0xe2, 0xf8, 0xfc, 0x82, 0xd4, 0xa2, 0xc4, 0x92, 0xcc, 0xfc, 0x3c, 0xbd, 0x82, 0xa2, 0xfc, 0x92,
	0x7c, 0x21, 0x59, 0x88, 0x0e, 0xbd, 0xc4, 0x94, 0x62, 0x3d, 0xb8, 0x66, 0xbd, 0x32, 0x03, 0x3d,
	0xb0, 0x66, 0xa5, 0x72, 0x2e, 0x49, 0x67, 0xb0, 0xfe, 0x60, 0xb0, 0x76, 0x7f, 0x98, 0x6e, 0xd7,
	0xbc, 0xd2, 0x5c, 0xa5, 0x28, 0x2e, 0x51, 0xac, 0x92, 0x42, 0xfc, 0x5c, 0xdc, 0xa1, 0x7e, 0xc1,
	0x01, 0xae, 0xce, 0x9e, 0x6e, 0x9e, 0xae, 0x2e, 0x02, 0x0c, 0x42, 0xdc, 0x5c, 0xec, 0xa1, 0x7e,
	0xde, 0x7e, 0xfe, 0xe1, 0x7e, 0x02, 0x8c, 0x42, 0x9c, 0x5c, 0xac, 0x8e, 0x2e, 0x2e, 0xae, 0x2e,
	0x02, 0x4c, 0x20, 0x71, 0x67, 0x0f, 0x47, 0x3f, 0x77, 0x57, 0x17, 0x01, 0x66, 0x10, 0x27, 0xc8,
	0xd5, 0xd7, 0x3f, 0xcc, 0xd5, 0x45, 0x80, 0xc5, 0xe9, 0x3d, 0x23, 0x97, 0x62, 0x72, 0x7e, 0xae,
	0x1e, 0x5e, 0xe7, 0x39, 0x49, 0x61, 0xb5, 0x3f, 0x00, 0xe4, 0xb3, 0x00, 0xc6, 0x28, 0x27, 0xa8,
	0xe6, 0xf4, 0xfc, 0x9c, 0xc4, 0xbc, 0x74, 0xbd, 0xfc, 0xa2, 0x74, 0xfd, 0xf4, 0xd4, 0x3c, 0xb0,
	0xbf, 0x61, 0x01, 0x55, 0x90, 0x59, 0x8c, 0x23, 0xdc, 0xac, 0xc1, 0xe4, 0x22, 0x26, 0x66, 0x77,
	0x47, 0xc7, 0x55, 0x4c, 0xb2, 0xee, 0x10, 0xa3, 0x1c, 0x53, 0x8a, 0xf5, 0x20, 0x4c, 0x10, 0x2b,
	0xcc, 0x40, 0x0f, 0x14, 0x10, 0xc5, 0xa7, 0x60, 0xf2, 0x31, 0x8e, 0x29, 0xc5, 0x31, 0x70, 0xf9,
	0x98, 0x30, 0x83, 0x18, 0xb0, 0xfc, 0x2b, 0x26, 0x45, 0x88, 0xa0, 0x95, 0x95, 0x63, 0x4a, 0xb1,
	0x95, 0x15, 0x5c, 0x85, 0x95, 0x55, 0x98, 0x81, 0x95, 0x15, 0x58, 0x4d, 0x12, 0x1b, 0xd8, 0x61,
	0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x15, 0xbc, 0x11, 0x65, 0xcf, 0x01, 0x00, 0x00,
}

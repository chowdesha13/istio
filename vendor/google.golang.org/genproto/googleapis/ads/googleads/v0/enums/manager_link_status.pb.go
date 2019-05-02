// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/enums/manager_link_status.proto

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

// Possible statuses of a link.
type ManagerLinkStatusEnum_ManagerLinkStatus int32

const (
	// Not specified.
	ManagerLinkStatusEnum_UNSPECIFIED ManagerLinkStatusEnum_ManagerLinkStatus = 0
	// Used for return value only. Represents value unknown in this version.
	ManagerLinkStatusEnum_UNKNOWN ManagerLinkStatusEnum_ManagerLinkStatus = 1
	// Indicates current in-effect relationship
	ManagerLinkStatusEnum_ACTIVE ManagerLinkStatusEnum_ManagerLinkStatus = 2
	// Indicates terminated relationship
	ManagerLinkStatusEnum_INACTIVE ManagerLinkStatusEnum_ManagerLinkStatus = 3
	// Indicates relationship has been requested by manager, but the client
	// hasn't accepted yet.
	ManagerLinkStatusEnum_PENDING ManagerLinkStatusEnum_ManagerLinkStatus = 4
	// Relationship was requested by the manager, but the client has refused.
	ManagerLinkStatusEnum_REFUSED ManagerLinkStatusEnum_ManagerLinkStatus = 5
	// Indicates relationship has been requested by manager, but manager
	// canceled it.
	ManagerLinkStatusEnum_CANCELED ManagerLinkStatusEnum_ManagerLinkStatus = 6
)

var ManagerLinkStatusEnum_ManagerLinkStatus_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "ACTIVE",
	3: "INACTIVE",
	4: "PENDING",
	5: "REFUSED",
	6: "CANCELED",
}
var ManagerLinkStatusEnum_ManagerLinkStatus_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"ACTIVE":      2,
	"INACTIVE":    3,
	"PENDING":     4,
	"REFUSED":     5,
	"CANCELED":    6,
}

func (x ManagerLinkStatusEnum_ManagerLinkStatus) String() string {
	return proto.EnumName(ManagerLinkStatusEnum_ManagerLinkStatus_name, int32(x))
}
func (ManagerLinkStatusEnum_ManagerLinkStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_manager_link_status_214e164d8f357bee, []int{0, 0}
}

// Container for enum describing possible status of a manager and client link.
type ManagerLinkStatusEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ManagerLinkStatusEnum) Reset()         { *m = ManagerLinkStatusEnum{} }
func (m *ManagerLinkStatusEnum) String() string { return proto.CompactTextString(m) }
func (*ManagerLinkStatusEnum) ProtoMessage()    {}
func (*ManagerLinkStatusEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_manager_link_status_214e164d8f357bee, []int{0}
}
func (m *ManagerLinkStatusEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ManagerLinkStatusEnum.Unmarshal(m, b)
}
func (m *ManagerLinkStatusEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ManagerLinkStatusEnum.Marshal(b, m, deterministic)
}
func (dst *ManagerLinkStatusEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ManagerLinkStatusEnum.Merge(dst, src)
}
func (m *ManagerLinkStatusEnum) XXX_Size() int {
	return xxx_messageInfo_ManagerLinkStatusEnum.Size(m)
}
func (m *ManagerLinkStatusEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_ManagerLinkStatusEnum.DiscardUnknown(m)
}

var xxx_messageInfo_ManagerLinkStatusEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ManagerLinkStatusEnum)(nil), "google.ads.googleads.v0.enums.ManagerLinkStatusEnum")
	proto.RegisterEnum("google.ads.googleads.v0.enums.ManagerLinkStatusEnum_ManagerLinkStatus", ManagerLinkStatusEnum_ManagerLinkStatus_name, ManagerLinkStatusEnum_ManagerLinkStatus_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/enums/manager_link_status.proto", fileDescriptor_manager_link_status_214e164d8f357bee)
}

var fileDescriptor_manager_link_status_214e164d8f357bee = []byte{
	// 320 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0xd1, 0x4a, 0xf3, 0x30,
	0x1c, 0xc5, 0xbf, 0x76, 0x9f, 0x53, 0x32, 0xc1, 0x58, 0xd0, 0xbb, 0x5d, 0x6c, 0x0f, 0x90, 0x16,
	0xbc, 0x10, 0xe2, 0x55, 0xd6, 0x66, 0xa3, 0x38, 0x63, 0x71, 0xae, 0x82, 0x14, 0x46, 0xb4, 0x25,
	0x8c, 0xad, 0xc9, 0x58, 0xb6, 0x3d, 0x85, 0x4f, 0xe1, 0xa5, 0x8f, 0xe2, 0xa3, 0xe8, 0x4b, 0x48,
	0x92, 0x6d, 0x37, 0x43, 0x6f, 0xc2, 0xf9, 0xe7, 0x9c, 0x5f, 0xf8, 0xe7, 0x80, 0x6b, 0xa1, 0x94,
	0x98, 0x57, 0x21, 0x2f, 0x75, 0xe8, 0xa4, 0x51, 0x9b, 0x28, 0xac, 0xe4, 0xba, 0xd6, 0x61, 0xcd,
	0x25, 0x17, 0xd5, 0x72, 0x32, 0x9f, 0xca, 0xd9, 0x44, 0xaf, 0xf8, 0x6a, 0xad, 0xd1, 0x62, 0xa9,
	0x56, 0x2a, 0x68, 0xbb, 0x34, 0xe2, 0xa5, 0x46, 0x7b, 0x10, 0x6d, 0x22, 0x64, 0xc1, 0xee, 0x9b,
	0x07, 0x2e, 0xee, 0x1c, 0x3c, 0x9c, 0xca, 0xd9, 0xc8, 0xa2, 0x54, 0xae, 0xeb, 0xae, 0x06, 0xe7,
	0x07, 0x46, 0x70, 0x06, 0x5a, 0x63, 0x36, 0xca, 0x68, 0x9c, 0xf6, 0x53, 0x9a, 0xc0, 0x7f, 0x41,
	0x0b, 0x1c, 0x8f, 0xd9, 0x2d, 0xbb, 0x7f, 0x62, 0xd0, 0x0b, 0x00, 0x68, 0x92, 0xf8, 0x31, 0xcd,
	0x29, 0xf4, 0x83, 0x53, 0x70, 0x92, 0xb2, 0xed, 0xd4, 0x30, 0xb1, 0x8c, 0xb2, 0x24, 0x65, 0x03,
	0xf8, 0xdf, 0x0c, 0x0f, 0xb4, 0x3f, 0x1e, 0xd1, 0x04, 0x1e, 0x99, 0x5c, 0x4c, 0x58, 0x4c, 0x87,
	0x34, 0x81, 0xcd, 0xde, 0xb7, 0x07, 0x3a, 0xaf, 0xaa, 0x46, 0x7f, 0x2e, 0xdd, 0xbb, 0x3c, 0x58,
	0x2c, 0x33, 0x7f, 0xcd, 0xbc, 0xe7, 0xde, 0x16, 0x14, 0x6a, 0xce, 0xa5, 0x40, 0x6a, 0x29, 0x42,
	0x51, 0x49, 0xdb, 0xc4, 0xae, 0xb6, 0xc5, 0x54, 0xff, 0xd2, 0xe2, 0x8d, 0x3d, 0xdf, 0xfd, 0xc6,
	0x80, 0x90, 0x0f, 0xbf, 0x3d, 0x70, 0x4f, 0x91, 0x52, 0x23, 0x27, 0x8d, 0xca, 0x23, 0x64, 0xda,
	0xd1, 0x9f, 0x3b, 0xbf, 0x20, 0xa5, 0x2e, 0xf6, 0x7e, 0x91, 0x47, 0x85, 0xf5, 0xbf, 0xfc, 0x8e,
	0xbb, 0xc4, 0x98, 0x94, 0x1a, 0xe3, 0x7d, 0x02, 0xe3, 0x3c, 0xc2, 0xd8, 0x66, 0x5e, 0x9a, 0x76,
	0xb1, 0xab, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xd6, 0x9e, 0xae, 0xdd, 0xdd, 0x01, 0x00, 0x00,
}

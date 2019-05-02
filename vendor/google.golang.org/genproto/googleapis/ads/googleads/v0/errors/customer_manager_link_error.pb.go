// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/errors/customer_manager_link_error.proto

package errors // import "google.golang.org/genproto/googleapis/ads/googleads/v0/errors"

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

// Enum describing possible CustomerManagerLink errors.
type CustomerManagerLinkErrorEnum_CustomerManagerLinkError int32

const (
	// Enum unspecified.
	CustomerManagerLinkErrorEnum_UNSPECIFIED CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 0
	// The received error code is not known in this version.
	CustomerManagerLinkErrorEnum_UNKNOWN CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 1
	// No pending invitation.
	CustomerManagerLinkErrorEnum_NO_PENDING_INVITE CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 2
	// Attempt to operate on the same client more than once in the same call.
	CustomerManagerLinkErrorEnum_SAME_CLIENT_MORE_THAN_ONCE_PER_CALL CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 3
	// Manager account has the maximum number of linked accounts.
	CustomerManagerLinkErrorEnum_MANAGER_HAS_MAX_NUMBER_OF_LINKED_ACCOUNTS CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 4
	// If no active user on account it cannot be unlinked from its manager.
	CustomerManagerLinkErrorEnum_CANNOT_UNLINK_ACCOUNT_WITHOUT_ACTIVE_USER CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 5
	// Account should have at least one active owner on it before being
	// unlinked.
	CustomerManagerLinkErrorEnum_CANNOT_REMOVE_LAST_CLIENT_ACCOUNT_OWNER CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 6
	// Only account owners may change their permission role.
	CustomerManagerLinkErrorEnum_CANNOT_CHANGE_ROLE_BY_NON_ACCOUNT_OWNER CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 7
	// When a client's link to its manager is not active, the link role cannot
	// be changed.
	CustomerManagerLinkErrorEnum_CANNOT_CHANGE_ROLE_FOR_NON_ACTIVE_LINK_ACCOUNT CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 8
	// Attempt to link a child to a parent that contains or will contain
	// duplicate children.
	CustomerManagerLinkErrorEnum_DUPLICATE_CHILD_FOUND CustomerManagerLinkErrorEnum_CustomerManagerLinkError = 9
)

var CustomerManagerLinkErrorEnum_CustomerManagerLinkError_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "NO_PENDING_INVITE",
	3: "SAME_CLIENT_MORE_THAN_ONCE_PER_CALL",
	4: "MANAGER_HAS_MAX_NUMBER_OF_LINKED_ACCOUNTS",
	5: "CANNOT_UNLINK_ACCOUNT_WITHOUT_ACTIVE_USER",
	6: "CANNOT_REMOVE_LAST_CLIENT_ACCOUNT_OWNER",
	7: "CANNOT_CHANGE_ROLE_BY_NON_ACCOUNT_OWNER",
	8: "CANNOT_CHANGE_ROLE_FOR_NON_ACTIVE_LINK_ACCOUNT",
	9: "DUPLICATE_CHILD_FOUND",
}
var CustomerManagerLinkErrorEnum_CustomerManagerLinkError_value = map[string]int32{
	"UNSPECIFIED":                         0,
	"UNKNOWN":                             1,
	"NO_PENDING_INVITE":                   2,
	"SAME_CLIENT_MORE_THAN_ONCE_PER_CALL": 3,
	"MANAGER_HAS_MAX_NUMBER_OF_LINKED_ACCOUNTS":      4,
	"CANNOT_UNLINK_ACCOUNT_WITHOUT_ACTIVE_USER":      5,
	"CANNOT_REMOVE_LAST_CLIENT_ACCOUNT_OWNER":        6,
	"CANNOT_CHANGE_ROLE_BY_NON_ACCOUNT_OWNER":        7,
	"CANNOT_CHANGE_ROLE_FOR_NON_ACTIVE_LINK_ACCOUNT": 8,
	"DUPLICATE_CHILD_FOUND":                          9,
}

func (x CustomerManagerLinkErrorEnum_CustomerManagerLinkError) String() string {
	return proto.EnumName(CustomerManagerLinkErrorEnum_CustomerManagerLinkError_name, int32(x))
}
func (CustomerManagerLinkErrorEnum_CustomerManagerLinkError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_customer_manager_link_error_6e4a9e1e36cd1ffb, []int{0, 0}
}

// Container for enum describing possible CustomerManagerLink errors.
type CustomerManagerLinkErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CustomerManagerLinkErrorEnum) Reset()         { *m = CustomerManagerLinkErrorEnum{} }
func (m *CustomerManagerLinkErrorEnum) String() string { return proto.CompactTextString(m) }
func (*CustomerManagerLinkErrorEnum) ProtoMessage()    {}
func (*CustomerManagerLinkErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_customer_manager_link_error_6e4a9e1e36cd1ffb, []int{0}
}
func (m *CustomerManagerLinkErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CustomerManagerLinkErrorEnum.Unmarshal(m, b)
}
func (m *CustomerManagerLinkErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CustomerManagerLinkErrorEnum.Marshal(b, m, deterministic)
}
func (dst *CustomerManagerLinkErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CustomerManagerLinkErrorEnum.Merge(dst, src)
}
func (m *CustomerManagerLinkErrorEnum) XXX_Size() int {
	return xxx_messageInfo_CustomerManagerLinkErrorEnum.Size(m)
}
func (m *CustomerManagerLinkErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_CustomerManagerLinkErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_CustomerManagerLinkErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*CustomerManagerLinkErrorEnum)(nil), "google.ads.googleads.v0.errors.CustomerManagerLinkErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v0.errors.CustomerManagerLinkErrorEnum_CustomerManagerLinkError", CustomerManagerLinkErrorEnum_CustomerManagerLinkError_name, CustomerManagerLinkErrorEnum_CustomerManagerLinkError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/errors/customer_manager_link_error.proto", fileDescriptor_customer_manager_link_error_6e4a9e1e36cd1ffb)
}

var fileDescriptor_customer_manager_link_error_6e4a9e1e36cd1ffb = []byte{
	// 479 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0x41, 0x8b, 0xd3, 0x40,
	0x1c, 0xc5, 0xdd, 0x56, 0x77, 0x75, 0xf6, 0x60, 0x0c, 0x2c, 0x28, 0xe8, 0x1e, 0xea, 0x61, 0x11,
	0x71, 0x5a, 0xf4, 0x16, 0x2f, 0x4e, 0x27, 0xff, 0xb6, 0xc3, 0x26, 0xff, 0x09, 0xc9, 0x24, 0x55,
	0x29, 0xfc, 0xa9, 0xdb, 0x12, 0xca, 0xb6, 0xc9, 0x92, 0xec, 0xee, 0xe7, 0x11, 0x8f, 0x7e, 0x14,
	0x3f, 0x8a, 0x9f, 0xc0, 0x9b, 0x92, 0x4e, 0x5b, 0x16, 0xb1, 0x9e, 0xf2, 0xc8, 0xfb, 0xcd, 0x9b,
	0x07, 0xf3, 0xd8, 0x87, 0xbc, 0x2c, 0xf3, 0xe5, 0xbc, 0x3b, 0x9d, 0xd5, 0x5d, 0x2b, 0x1b, 0x75,
	0xdb, 0xeb, 0xce, 0xab, 0xaa, 0xac, 0xea, 0xee, 0xc5, 0x4d, 0x7d, 0x5d, 0xae, 0xe6, 0x15, 0xad,
	0xa6, 0xc5, 0x34, 0x9f, 0x57, 0xb4, 0x5c, 0x14, 0x97, 0xb4, 0x36, 0xf9, 0x55, 0x55, 0x5e, 0x97,
	0xee, 0xa9, 0x3d, 0xc6, 0xa7, 0xb3, 0x9a, 0xef, 0x12, 0xf8, 0x6d, 0x8f, 0xdb, 0x84, 0xce, 0xd7,
	0x36, 0x7b, 0x2e, 0x37, 0x29, 0xa1, 0x0d, 0x09, 0x16, 0xc5, 0x25, 0x34, 0x2e, 0x14, 0x37, 0xab,
	0xce, 0xef, 0x16, 0x7b, 0xba, 0x0f, 0x70, 0x1f, 0xb3, 0xe3, 0x14, 0x93, 0x08, 0xa4, 0x1a, 0x28,
	0xf0, 0x9d, 0x7b, 0xee, 0x31, 0x3b, 0x4a, 0xf1, 0x1c, 0xf5, 0x18, 0x9d, 0x03, 0xf7, 0x84, 0x3d,
	0x41, 0x4d, 0x11, 0xa0, 0xaf, 0x70, 0x48, 0x0a, 0x33, 0x65, 0xc0, 0x69, 0xb9, 0x67, 0xec, 0x65,
	0x22, 0x42, 0x20, 0x19, 0x28, 0x40, 0x43, 0xa1, 0x8e, 0x81, 0xcc, 0x48, 0x20, 0x69, 0x94, 0x40,
	0x11, 0xc4, 0x24, 0x45, 0x10, 0x38, 0x6d, 0xf7, 0x0d, 0x7b, 0x15, 0x0a, 0x14, 0x43, 0x88, 0x69,
	0x24, 0x12, 0x0a, 0xc5, 0x47, 0xc2, 0x34, 0xec, 0x43, 0x4c, 0x7a, 0x40, 0x81, 0xc2, 0x73, 0xf0,
	0x49, 0x48, 0xa9, 0x53, 0x34, 0x89, 0x73, 0xbf, 0xc1, 0xa5, 0x40, 0xd4, 0x86, 0x52, 0x6c, 0xdc,
	0xad, 0x47, 0x63, 0x65, 0x46, 0x3a, 0x35, 0x24, 0xa4, 0x51, 0x19, 0x50, 0x9a, 0x40, 0xec, 0x3c,
	0x70, 0x5f, 0xb3, 0xb3, 0x0d, 0x1e, 0x43, 0xa8, 0x33, 0xa0, 0x40, 0x24, 0x66, 0x5b, 0x6a, 0x7b,
	0x54, 0x8f, 0x11, 0x62, 0xe7, 0xf0, 0x0e, 0x2c, 0x47, 0x02, 0x87, 0x40, 0xb1, 0x0e, 0x80, 0xfa,
	0x9f, 0x08, 0x35, 0xfe, 0x05, 0x1f, 0xb9, 0x6f, 0x19, 0xff, 0x07, 0x3c, 0xd0, 0xf1, 0x86, 0x5e,
	0xb7, 0xb8, 0xdb, 0xd0, 0x79, 0xe8, 0x3e, 0x63, 0x27, 0x7e, 0x1a, 0x05, 0x4a, 0x0a, 0x03, 0x24,
	0x47, 0x2a, 0xf0, 0x69, 0xa0, 0x53, 0xf4, 0x9d, 0x47, 0xfd, 0x5f, 0x07, 0xac, 0x73, 0x51, 0xae,
	0xf8, 0xff, 0x5f, 0xb2, 0xff, 0x62, 0xdf, 0x2b, 0x45, 0xcd, 0x10, 0xa2, 0x83, 0xcf, 0xfe, 0x26,
	0x20, 0x2f, 0x97, 0xd3, 0x22, 0xe7, 0x65, 0x95, 0x77, 0xf3, 0x79, 0xb1, 0x9e, 0xc9, 0x76, 0x5c,
	0x57, 0x8b, 0x7a, 0xdf, 0xd6, 0xde, 0xdb, 0xcf, 0xb7, 0x56, 0x7b, 0x28, 0xc4, 0xf7, 0xd6, 0xe9,
	0xd0, 0x86, 0x89, 0x59, 0xcd, 0xad, 0x6c, 0x54, 0xd6, 0xe3, 0xeb, 0x2b, 0xeb, 0x1f, 0x5b, 0x60,
	0x22, 0x66, 0xf5, 0x64, 0x07, 0x4c, 0xb2, 0xde, 0xc4, 0x02, 0x3f, 0x5b, 0x1d, 0xfb, 0xd7, 0xf3,
	0xc4, 0xac, 0xf6, 0xbc, 0x1d, 0xe2, 0x79, 0x59, 0xcf, 0xf3, 0x2c, 0xf4, 0xe5, 0x70, 0xdd, 0xee,
	0xdd, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x76, 0x52, 0x96, 0x2c, 0x08, 0x03, 0x00, 0x00,
}

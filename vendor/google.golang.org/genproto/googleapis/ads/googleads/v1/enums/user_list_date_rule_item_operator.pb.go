// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/user_list_date_rule_item_operator.proto

package enums // import "google.golang.org/genproto/googleapis/ads/googleads/v1/enums"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Enum describing possible user list date rule item operators.
type UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator int32

const (
	// Not specified.
	UserListDateRuleItemOperatorEnum_UNSPECIFIED UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator = 0
	// Used for return value only. Represents value unknown in this version.
	UserListDateRuleItemOperatorEnum_UNKNOWN UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator = 1
	// Equals.
	UserListDateRuleItemOperatorEnum_EQUALS UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator = 2
	// Not Equals.
	UserListDateRuleItemOperatorEnum_NOT_EQUALS UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator = 3
	// Before.
	UserListDateRuleItemOperatorEnum_BEFORE UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator = 4
	// After.
	UserListDateRuleItemOperatorEnum_AFTER UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator = 5
)

var UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "EQUALS",
	3: "NOT_EQUALS",
	4: "BEFORE",
	5: "AFTER",
}
var UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"EQUALS":      2,
	"NOT_EQUALS":  3,
	"BEFORE":      4,
	"AFTER":       5,
}

func (x UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator) String() string {
	return proto.EnumName(UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator_name, int32(x))
}
func (UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_user_list_date_rule_item_operator_4c5a62a3adeb1fd9, []int{0, 0}
}

// Supported rule operator for date type.
type UserListDateRuleItemOperatorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UserListDateRuleItemOperatorEnum) Reset()         { *m = UserListDateRuleItemOperatorEnum{} }
func (m *UserListDateRuleItemOperatorEnum) String() string { return proto.CompactTextString(m) }
func (*UserListDateRuleItemOperatorEnum) ProtoMessage()    {}
func (*UserListDateRuleItemOperatorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_user_list_date_rule_item_operator_4c5a62a3adeb1fd9, []int{0}
}
func (m *UserListDateRuleItemOperatorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UserListDateRuleItemOperatorEnum.Unmarshal(m, b)
}
func (m *UserListDateRuleItemOperatorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UserListDateRuleItemOperatorEnum.Marshal(b, m, deterministic)
}
func (dst *UserListDateRuleItemOperatorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UserListDateRuleItemOperatorEnum.Merge(dst, src)
}
func (m *UserListDateRuleItemOperatorEnum) XXX_Size() int {
	return xxx_messageInfo_UserListDateRuleItemOperatorEnum.Size(m)
}
func (m *UserListDateRuleItemOperatorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_UserListDateRuleItemOperatorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_UserListDateRuleItemOperatorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*UserListDateRuleItemOperatorEnum)(nil), "google.ads.googleads.v1.enums.UserListDateRuleItemOperatorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator", UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator_name, UserListDateRuleItemOperatorEnum_UserListDateRuleItemOperator_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/user_list_date_rule_item_operator.proto", fileDescriptor_user_list_date_rule_item_operator_4c5a62a3adeb1fd9)
}

var fileDescriptor_user_list_date_rule_item_operator_4c5a62a3adeb1fd9 = []byte{
	// 346 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x51, 0x41, 0x6a, 0xeb, 0x30,
	0x14, 0xfc, 0x76, 0x7e, 0x52, 0xaa, 0x40, 0x6b, 0xbc, 0x2c, 0x09, 0x34, 0x39, 0x80, 0x8c, 0xe9,
	0x4e, 0x5d, 0xc9, 0x8d, 0x12, 0x42, 0x83, 0x9d, 0x26, 0x71, 0x0a, 0xc5, 0x60, 0xd4, 0x5a, 0x18,
	0x83, 0x2d, 0x19, 0x49, 0xce, 0x45, 0x7a, 0x83, 0x2e, 0x7b, 0x94, 0x1e, 0xa5, 0x07, 0xe8, 0xba,
	0xd8, 0x4e, 0xb2, 0xab, 0x37, 0x62, 0xa4, 0x99, 0x37, 0xef, 0xcd, 0x13, 0x20, 0xa9, 0x10, 0x69,
	0xce, 0x1c, 0x9a, 0x28, 0xa7, 0x85, 0x35, 0x3a, 0xb8, 0x0e, 0xe3, 0x55, 0xa1, 0x9c, 0x4a, 0x31,
	0x19, 0xe7, 0x99, 0xd2, 0x71, 0x42, 0x35, 0x8b, 0x65, 0x95, 0xb3, 0x38, 0xd3, 0xac, 0x88, 0x45,
	0xc9, 0x24, 0xd5, 0x42, 0xc2, 0x52, 0x0a, 0x2d, 0xec, 0x71, 0x5b, 0x0b, 0x69, 0xa2, 0xe0, 0xd9,
	0x06, 0x1e, 0x5c, 0xd8, 0xd8, 0xdc, 0x8c, 0x4e, 0x5d, 0xca, 0xcc, 0xa1, 0x9c, 0x0b, 0x4d, 0x75,
	0x26, 0xb8, 0x6a, 0x8b, 0xa7, 0xef, 0x06, 0xb8, 0x0d, 0x15, 0x93, 0xab, 0x4c, 0xe9, 0x19, 0xd5,
	0x6c, 0x53, 0xe5, 0x6c, 0xa9, 0x59, 0x11, 0x1c, 0x7b, 0x10, 0x5e, 0x15, 0x53, 0x01, 0x46, 0x5d,
	0x1a, 0xfb, 0x1a, 0x0c, 0x43, 0x7f, 0xbb, 0x26, 0x0f, 0xcb, 0xf9, 0x92, 0xcc, 0xac, 0x7f, 0xf6,
	0x10, 0x5c, 0x84, 0xfe, 0xa3, 0x1f, 0x3c, 0xfb, 0x96, 0x61, 0x03, 0x30, 0x20, 0x4f, 0x21, 0x5e,
	0x6d, 0x2d, 0xd3, 0xbe, 0x02, 0xc0, 0x0f, 0x76, 0xf1, 0xf1, 0xde, 0xab, 0x39, 0x8f, 0xcc, 0x83,
	0x0d, 0xb1, 0xfe, 0xdb, 0x97, 0xa0, 0x8f, 0xe7, 0x3b, 0xb2, 0xb1, 0xfa, 0xde, 0x8f, 0x01, 0x26,
	0x6f, 0xa2, 0x80, 0x9d, 0xc9, 0xbc, 0x49, 0xd7, 0x50, 0xeb, 0x3a, 0xde, 0xda, 0x78, 0xf1, 0x8e,
	0x1e, 0xa9, 0xc8, 0x29, 0x4f, 0xa1, 0x90, 0xa9, 0x93, 0x32, 0xde, 0x84, 0x3f, 0x2d, 0xbd, 0xcc,
	0xd4, 0x1f, 0x7f, 0x70, 0xdf, 0x9c, 0x1f, 0x66, 0x6f, 0x81, 0xf1, 0xa7, 0x39, 0x5e, 0xb4, 0x56,
	0x38, 0x51, 0xb0, 0x85, 0x35, 0xda, 0xbb, 0xb0, 0x5e, 0x92, 0xfa, 0x3a, 0xf1, 0x11, 0x4e, 0x54,
	0x74, 0xe6, 0xa3, 0xbd, 0x1b, 0x35, 0xfc, 0xb7, 0x39, 0x69, 0x1f, 0x11, 0xc2, 0x89, 0x42, 0xe8,
	0xac, 0x40, 0x68, 0xef, 0x22, 0xd4, 0x68, 0x5e, 0x07, 0xcd, 0x60, 0x77, 0xbf, 0x01, 0x00, 0x00,
	0xff, 0xff, 0x45, 0xbf, 0xc8, 0x51, 0x1b, 0x02, 0x00, 0x00,
}

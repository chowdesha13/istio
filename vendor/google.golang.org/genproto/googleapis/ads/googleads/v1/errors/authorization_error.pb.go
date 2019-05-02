// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/errors/authorization_error.proto

package errors // import "google.golang.org/genproto/googleapis/ads/googleads/v1/errors"

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

// Enum describing possible authorization errors.
type AuthorizationErrorEnum_AuthorizationError int32

const (
	// Enum unspecified.
	AuthorizationErrorEnum_UNSPECIFIED AuthorizationErrorEnum_AuthorizationError = 0
	// The received error code is not known in this version.
	AuthorizationErrorEnum_UNKNOWN AuthorizationErrorEnum_AuthorizationError = 1
	// User doesn't have permission to access customer.
	AuthorizationErrorEnum_USER_PERMISSION_DENIED AuthorizationErrorEnum_AuthorizationError = 2
	// The developer token is not whitelisted.
	AuthorizationErrorEnum_DEVELOPER_TOKEN_NOT_WHITELISTED AuthorizationErrorEnum_AuthorizationError = 3
	// The developer token is not allowed with the project sent in the request.
	AuthorizationErrorEnum_DEVELOPER_TOKEN_PROHIBITED AuthorizationErrorEnum_AuthorizationError = 4
	// The Google Cloud project sent in the request does not have permission to
	// access the api.
	AuthorizationErrorEnum_PROJECT_DISABLED AuthorizationErrorEnum_AuthorizationError = 5
	// Authorization of the client failed.
	AuthorizationErrorEnum_AUTHORIZATION_ERROR AuthorizationErrorEnum_AuthorizationError = 6
	// The user does not have permission to perform this action
	// (e.g., ADD, UPDATE, REMOVE) on the resource or call a method.
	AuthorizationErrorEnum_ACTION_NOT_PERMITTED AuthorizationErrorEnum_AuthorizationError = 7
	// Signup not complete.
	AuthorizationErrorEnum_INCOMPLETE_SIGNUP AuthorizationErrorEnum_AuthorizationError = 8
	// The customer can't be used because it isn't enabled.
	AuthorizationErrorEnum_CUSTOMER_NOT_ENABLED AuthorizationErrorEnum_AuthorizationError = 24
	// The developer must sign the terms of service. They can be found here:
	// ads.google.com/aw/apicenter
	AuthorizationErrorEnum_MISSING_TOS AuthorizationErrorEnum_AuthorizationError = 9
	// The developer token is not approved. Non-approved developer tokens can
	// only be used with test accounts.
	AuthorizationErrorEnum_DEVELOPER_TOKEN_NOT_APPROVED AuthorizationErrorEnum_AuthorizationError = 10
)

var AuthorizationErrorEnum_AuthorizationError_name = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "UNKNOWN",
	2:  "USER_PERMISSION_DENIED",
	3:  "DEVELOPER_TOKEN_NOT_WHITELISTED",
	4:  "DEVELOPER_TOKEN_PROHIBITED",
	5:  "PROJECT_DISABLED",
	6:  "AUTHORIZATION_ERROR",
	7:  "ACTION_NOT_PERMITTED",
	8:  "INCOMPLETE_SIGNUP",
	24: "CUSTOMER_NOT_ENABLED",
	9:  "MISSING_TOS",
	10: "DEVELOPER_TOKEN_NOT_APPROVED",
}
var AuthorizationErrorEnum_AuthorizationError_value = map[string]int32{
	"UNSPECIFIED":                     0,
	"UNKNOWN":                         1,
	"USER_PERMISSION_DENIED":          2,
	"DEVELOPER_TOKEN_NOT_WHITELISTED": 3,
	"DEVELOPER_TOKEN_PROHIBITED":      4,
	"PROJECT_DISABLED":                5,
	"AUTHORIZATION_ERROR":             6,
	"ACTION_NOT_PERMITTED":            7,
	"INCOMPLETE_SIGNUP":               8,
	"CUSTOMER_NOT_ENABLED":            24,
	"MISSING_TOS":                     9,
	"DEVELOPER_TOKEN_NOT_APPROVED":    10,
}

func (x AuthorizationErrorEnum_AuthorizationError) String() string {
	return proto.EnumName(AuthorizationErrorEnum_AuthorizationError_name, int32(x))
}
func (AuthorizationErrorEnum_AuthorizationError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_authorization_error_b90c41b1b65e63c0, []int{0, 0}
}

// Container for enum describing possible authorization errors.
type AuthorizationErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthorizationErrorEnum) Reset()         { *m = AuthorizationErrorEnum{} }
func (m *AuthorizationErrorEnum) String() string { return proto.CompactTextString(m) }
func (*AuthorizationErrorEnum) ProtoMessage()    {}
func (*AuthorizationErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_authorization_error_b90c41b1b65e63c0, []int{0}
}
func (m *AuthorizationErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthorizationErrorEnum.Unmarshal(m, b)
}
func (m *AuthorizationErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthorizationErrorEnum.Marshal(b, m, deterministic)
}
func (dst *AuthorizationErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthorizationErrorEnum.Merge(dst, src)
}
func (m *AuthorizationErrorEnum) XXX_Size() int {
	return xxx_messageInfo_AuthorizationErrorEnum.Size(m)
}
func (m *AuthorizationErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthorizationErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_AuthorizationErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*AuthorizationErrorEnum)(nil), "google.ads.googleads.v1.errors.AuthorizationErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.errors.AuthorizationErrorEnum_AuthorizationError", AuthorizationErrorEnum_AuthorizationError_name, AuthorizationErrorEnum_AuthorizationError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/errors/authorization_error.proto", fileDescriptor_authorization_error_b90c41b1b65e63c0)
}

var fileDescriptor_authorization_error_b90c41b1b65e63c0 = []byte{
	// 462 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xc1, 0x6e, 0xd3, 0x30,
	0x18, 0xc7, 0x69, 0x06, 0x1b, 0x78, 0x07, 0x82, 0x19, 0xdb, 0x54, 0x4d, 0x05, 0x95, 0x7b, 0xa2,
	0x88, 0x0b, 0x0a, 0x27, 0x37, 0xf9, 0x68, 0xcd, 0x5a, 0xdb, 0x72, 0x9c, 0x4c, 0x9a, 0x2a, 0x45,
	0x81, 0x54, 0xa1, 0xd2, 0x16, 0x57, 0x49, 0xb7, 0x03, 0x8f, 0xc3, 0x91, 0xa7, 0xe0, 0xcc, 0x2b,
	0xf0, 0x06, 0x1c, 0x79, 0x02, 0xe4, 0x98, 0x56, 0x88, 0xc2, 0x4e, 0xf9, 0xf4, 0xf9, 0xf7, 0xff,
	0xff, 0xfd, 0xe5, 0x33, 0x7a, 0x5d, 0x69, 0x5d, 0x5d, 0x2d, 0xfc, 0xa2, 0x6c, 0x7d, 0x5b, 0x9a,
	0xea, 0x36, 0xf0, 0x17, 0x4d, 0xa3, 0x9b, 0xd6, 0x2f, 0x6e, 0xd6, 0x1f, 0x75, 0xb3, 0xfc, 0x54,
	0xac, 0x97, 0xba, 0xce, 0xbb, 0xa6, 0xb7, 0x6a, 0xf4, 0x5a, 0xe3, 0x81, 0xc5, 0xbd, 0xa2, 0x6c,
	0xbd, 0xad, 0xd2, 0xbb, 0x0d, 0x3c, 0xab, 0xec, 0x9f, 0x6d, 0x9c, 0x57, 0x4b, 0xbf, 0xa8, 0x6b,
	0xbd, 0xee, 0x2c, 0x5a, 0xab, 0x1e, 0x7e, 0x77, 0xd0, 0x31, 0xf9, 0xd3, 0x1b, 0x8c, 0x0a, 0xea,
	0x9b, 0xeb, 0xe1, 0x57, 0x07, 0xe1, 0xdd, 0x23, 0xfc, 0x18, 0x1d, 0xa6, 0x2c, 0x11, 0x10, 0xd1,
	0xb7, 0x14, 0x62, 0xf7, 0x1e, 0x3e, 0x44, 0x07, 0x29, 0x3b, 0x67, 0xfc, 0x82, 0xb9, 0x3d, 0xdc,
	0x47, 0xc7, 0x69, 0x02, 0x32, 0x17, 0x20, 0x67, 0x34, 0x49, 0x28, 0x67, 0x79, 0x0c, 0xcc, 0x80,
	0x0e, 0x7e, 0x89, 0x9e, 0xc7, 0x90, 0xc1, 0x94, 0x0b, 0x90, 0xb9, 0xe2, 0xe7, 0xc0, 0x72, 0xc6,
	0x55, 0x7e, 0x31, 0xa1, 0x0a, 0xa6, 0x34, 0x51, 0x10, 0xbb, 0x7b, 0x78, 0x80, 0xfa, 0x7f, 0x43,
	0x42, 0xf2, 0x09, 0x1d, 0x51, 0x73, 0x7e, 0x1f, 0x1f, 0x21, 0x57, 0x48, 0xfe, 0x0e, 0x22, 0x95,
	0xc7, 0x34, 0x21, 0xa3, 0x29, 0xc4, 0xee, 0x03, 0x7c, 0x82, 0x9e, 0x92, 0x54, 0x4d, 0xb8, 0xa4,
	0x97, 0x44, 0x99, 0x50, 0x90, 0x92, 0x4b, 0x77, 0x1f, 0x9f, 0xa2, 0x23, 0x12, 0x75, 0x1d, 0x13,
	0xd5, 0xdd, 0x4a, 0x19, 0xa3, 0x03, 0xfc, 0x0c, 0x3d, 0xa1, 0x2c, 0xe2, 0x33, 0x31, 0x05, 0x05,
	0x79, 0x42, 0xc7, 0x2c, 0x15, 0xee, 0x43, 0x23, 0x88, 0xd2, 0x44, 0xf1, 0x19, 0xc8, 0x4e, 0x02,
	0xcc, 0x66, 0x9c, 0x9a, 0xc1, 0xbb, 0x91, 0xd8, 0x38, 0x57, 0x3c, 0x71, 0x1f, 0xe1, 0x17, 0xe8,
	0xec, 0x5f, 0xf3, 0x10, 0x21, 0x24, 0xcf, 0x20, 0x76, 0xd1, 0xe8, 0x67, 0x0f, 0x0d, 0x3f, 0xe8,
	0x6b, 0xef, 0xee, 0x15, 0x8d, 0x4e, 0x76, 0x7f, 0xb3, 0x30, 0xdb, 0x11, 0xbd, 0xcb, 0xf8, 0xb7,
	0xb4, 0xd2, 0x57, 0x45, 0x5d, 0x79, 0xba, 0xa9, 0xfc, 0x6a, 0x51, 0x77, 0xbb, 0xdb, 0xbc, 0x93,
	0xd5, 0xb2, 0xfd, 0xdf, 0xb3, 0x79, 0x63, 0x3f, 0x9f, 0x9d, 0xbd, 0x31, 0x21, 0x5f, 0x9c, 0xc1,
	0xd8, 0x9a, 0x91, 0xb2, 0xf5, 0x6c, 0x69, 0xaa, 0x2c, 0xf0, 0xba, 0xc8, 0xf6, 0xdb, 0x06, 0x98,
	0x93, 0xb2, 0x9d, 0x6f, 0x81, 0x79, 0x16, 0xcc, 0x2d, 0xf0, 0xc3, 0x19, 0xda, 0x6e, 0x18, 0x92,
	0xb2, 0x0d, 0xc3, 0x2d, 0x12, 0x86, 0x59, 0x10, 0x86, 0x16, 0x7a, 0xbf, 0xdf, 0xdd, 0xee, 0xd5,
	0xaf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x68, 0x0f, 0xf8, 0xb2, 0xd3, 0x02, 0x00, 0x00,
}

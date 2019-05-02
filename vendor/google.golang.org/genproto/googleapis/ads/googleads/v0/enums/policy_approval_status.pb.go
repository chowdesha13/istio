// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/enums/policy_approval_status.proto

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

// The possible policy approval statuses. When there are several approval
// statuses available the most severe one will be used. The order of severity
// is DISAPPROVED, AREA_OF_INTEREST_ONLY, APPROVED_LIMITED and APPROVED.
type PolicyApprovalStatusEnum_PolicyApprovalStatus int32

const (
	// No value has been specified.
	PolicyApprovalStatusEnum_UNSPECIFIED PolicyApprovalStatusEnum_PolicyApprovalStatus = 0
	// The received value is not known in this version.
	//
	// This is a response-only value.
	PolicyApprovalStatusEnum_UNKNOWN PolicyApprovalStatusEnum_PolicyApprovalStatus = 1
	// Will not serve.
	PolicyApprovalStatusEnum_DISAPPROVED PolicyApprovalStatusEnum_PolicyApprovalStatus = 2
	// Serves with restrictions.
	PolicyApprovalStatusEnum_APPROVED_LIMITED PolicyApprovalStatusEnum_PolicyApprovalStatus = 3
	// Serves without restrictions.
	PolicyApprovalStatusEnum_APPROVED PolicyApprovalStatusEnum_PolicyApprovalStatus = 4
	// Will not serve in targeted countries, but may serve for users who are
	// searching for information about the targeted countries.
	PolicyApprovalStatusEnum_AREA_OF_INTEREST_ONLY PolicyApprovalStatusEnum_PolicyApprovalStatus = 5
)

var PolicyApprovalStatusEnum_PolicyApprovalStatus_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "DISAPPROVED",
	3: "APPROVED_LIMITED",
	4: "APPROVED",
	5: "AREA_OF_INTEREST_ONLY",
}
var PolicyApprovalStatusEnum_PolicyApprovalStatus_value = map[string]int32{
	"UNSPECIFIED":           0,
	"UNKNOWN":               1,
	"DISAPPROVED":           2,
	"APPROVED_LIMITED":      3,
	"APPROVED":              4,
	"AREA_OF_INTEREST_ONLY": 5,
}

func (x PolicyApprovalStatusEnum_PolicyApprovalStatus) String() string {
	return proto.EnumName(PolicyApprovalStatusEnum_PolicyApprovalStatus_name, int32(x))
}
func (PolicyApprovalStatusEnum_PolicyApprovalStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_policy_approval_status_45853cd948082e5a, []int{0, 0}
}

// Container for enum describing possible policy approval statuses.
type PolicyApprovalStatusEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PolicyApprovalStatusEnum) Reset()         { *m = PolicyApprovalStatusEnum{} }
func (m *PolicyApprovalStatusEnum) String() string { return proto.CompactTextString(m) }
func (*PolicyApprovalStatusEnum) ProtoMessage()    {}
func (*PolicyApprovalStatusEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_policy_approval_status_45853cd948082e5a, []int{0}
}
func (m *PolicyApprovalStatusEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PolicyApprovalStatusEnum.Unmarshal(m, b)
}
func (m *PolicyApprovalStatusEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PolicyApprovalStatusEnum.Marshal(b, m, deterministic)
}
func (dst *PolicyApprovalStatusEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PolicyApprovalStatusEnum.Merge(dst, src)
}
func (m *PolicyApprovalStatusEnum) XXX_Size() int {
	return xxx_messageInfo_PolicyApprovalStatusEnum.Size(m)
}
func (m *PolicyApprovalStatusEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_PolicyApprovalStatusEnum.DiscardUnknown(m)
}

var xxx_messageInfo_PolicyApprovalStatusEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*PolicyApprovalStatusEnum)(nil), "google.ads.googleads.v0.enums.PolicyApprovalStatusEnum")
	proto.RegisterEnum("google.ads.googleads.v0.enums.PolicyApprovalStatusEnum_PolicyApprovalStatus", PolicyApprovalStatusEnum_PolicyApprovalStatus_name, PolicyApprovalStatusEnum_PolicyApprovalStatus_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/enums/policy_approval_status.proto", fileDescriptor_policy_approval_status_45853cd948082e5a)
}

var fileDescriptor_policy_approval_status_45853cd948082e5a = []byte{
	// 332 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0x4f, 0x4b, 0xc3, 0x30,
	0x18, 0xc6, 0x6d, 0xe7, 0x3f, 0x32, 0xc1, 0x52, 0x26, 0xb8, 0xc3, 0x0e, 0xdb, 0x07, 0x48, 0x0b,
	0xde, 0xe2, 0x29, 0xb3, 0xd9, 0x28, 0xce, 0x36, 0xac, 0x5b, 0x45, 0x29, 0x84, 0xb8, 0x8e, 0x30,
	0xe8, 0x9a, 0xb2, 0x6c, 0x03, 0xef, 0x7e, 0x11, 0x3d, 0xfa, 0x51, 0xfc, 0x28, 0x1e, 0xfc, 0x0c,
	0xd2, 0x74, 0xeb, 0x69, 0x7a, 0x09, 0x4f, 0xf2, 0x3c, 0xbf, 0xf0, 0xbe, 0x0f, 0x40, 0x42, 0x4a,
	0x91, 0xcd, 0x1d, 0x9e, 0x2a, 0xa7, 0x92, 0xa5, 0xda, 0xba, 0xce, 0x3c, 0xdf, 0x2c, 0x95, 0x53,
	0xc8, 0x6c, 0x31, 0x7b, 0x65, 0xbc, 0x28, 0x56, 0x72, 0xcb, 0x33, 0xa6, 0xd6, 0x7c, 0xbd, 0x51,
	0xb0, 0x58, 0xc9, 0xb5, 0xb4, 0x3b, 0x15, 0x00, 0x79, 0xaa, 0x60, 0xcd, 0xc2, 0xad, 0x0b, 0x35,
	0xdb, 0x7b, 0x37, 0xc0, 0x35, 0xd5, 0x3c, 0xde, 0xe1, 0x91, 0xa6, 0x49, 0xbe, 0x59, 0xf6, 0xde,
	0x0c, 0xd0, 0x3a, 0x64, 0xda, 0x97, 0xa0, 0x39, 0x0d, 0x22, 0x4a, 0xee, 0xfc, 0x81, 0x4f, 0x3c,
	0xeb, 0xc8, 0x6e, 0x82, 0xb3, 0x69, 0x70, 0x1f, 0x84, 0x8f, 0x81, 0x65, 0x94, 0xae, 0xe7, 0x47,
	0x98, 0xd2, 0x71, 0x18, 0x13, 0xcf, 0x32, 0xed, 0x16, 0xb0, 0xf6, 0x37, 0x36, 0xf2, 0x1f, 0xfc,
	0x09, 0xf1, 0xac, 0x86, 0x7d, 0x01, 0xce, 0xeb, 0xcc, 0xb1, 0xdd, 0x06, 0x57, 0x78, 0x4c, 0x30,
	0x0b, 0x07, 0xcc, 0x0f, 0x26, 0x64, 0x4c, 0xa2, 0x09, 0x0b, 0x83, 0xd1, 0x93, 0x75, 0xd2, 0xff,
	0x31, 0x40, 0x77, 0x26, 0x97, 0xf0, 0xdf, 0x4d, 0xfa, 0xed, 0x43, 0x93, 0xd2, 0xb2, 0x03, 0x6a,
	0x3c, 0xf7, 0x77, 0xac, 0x90, 0x19, 0xcf, 0x05, 0x94, 0x2b, 0xe1, 0x88, 0x79, 0xae, 0x1b, 0xda,
	0x37, 0x5a, 0x2c, 0xd4, 0x1f, 0x05, 0xdf, 0xea, 0xf3, 0xc3, 0x6c, 0x0c, 0x31, 0xfe, 0x34, 0x3b,
	0xc3, 0xea, 0x2b, 0x9c, 0x2a, 0x58, 0xc9, 0x52, 0xc5, 0x2e, 0x2c, 0x2b, 0x53, 0x5f, 0x7b, 0x3f,
	0xc1, 0xa9, 0x4a, 0x6a, 0x3f, 0x89, 0xdd, 0x44, 0xfb, 0xdf, 0x66, 0xb7, 0x7a, 0x44, 0x08, 0xa7,
	0x0a, 0xa1, 0x3a, 0x81, 0x50, 0xec, 0x22, 0xa4, 0x33, 0x2f, 0xa7, 0x7a, 0xb0, 0x9b, 0xdf, 0x00,
	0x00, 0x00, 0xff, 0xff, 0x31, 0xf6, 0x47, 0xdc, 0xf8, 0x01, 0x00, 0x00,
}

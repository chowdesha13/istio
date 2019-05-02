// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/common/keyword_plan_common.proto

package common // import "google.golang.org/genproto/googleapis/ads/googleads/v1/common"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import wrappers "github.com/golang/protobuf/ptypes/wrappers"
import enums "google.golang.org/genproto/googleapis/ads/googleads/v1/enums"
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

// Historical metrics.
type KeywordPlanHistoricalMetrics struct {
	// Average monthly searches for the past 12 months.
	AvgMonthlySearches *wrappers.Int64Value `protobuf:"bytes,1,opt,name=avg_monthly_searches,json=avgMonthlySearches,proto3" json:"avg_monthly_searches,omitempty"`
	// The competition level for the query.
	Competition          enums.KeywordPlanCompetitionLevelEnum_KeywordPlanCompetitionLevel `protobuf:"varint,2,opt,name=competition,proto3,enum=google.ads.googleads.v1.enums.KeywordPlanCompetitionLevelEnum_KeywordPlanCompetitionLevel" json:"competition,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                                          `json:"-"`
	XXX_unrecognized     []byte                                                            `json:"-"`
	XXX_sizecache        int32                                                             `json:"-"`
}

func (m *KeywordPlanHistoricalMetrics) Reset()         { *m = KeywordPlanHistoricalMetrics{} }
func (m *KeywordPlanHistoricalMetrics) String() string { return proto.CompactTextString(m) }
func (*KeywordPlanHistoricalMetrics) ProtoMessage()    {}
func (*KeywordPlanHistoricalMetrics) Descriptor() ([]byte, []int) {
	return fileDescriptor_keyword_plan_common_4e2e51c5040e95c3, []int{0}
}
func (m *KeywordPlanHistoricalMetrics) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeywordPlanHistoricalMetrics.Unmarshal(m, b)
}
func (m *KeywordPlanHistoricalMetrics) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeywordPlanHistoricalMetrics.Marshal(b, m, deterministic)
}
func (dst *KeywordPlanHistoricalMetrics) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeywordPlanHistoricalMetrics.Merge(dst, src)
}
func (m *KeywordPlanHistoricalMetrics) XXX_Size() int {
	return xxx_messageInfo_KeywordPlanHistoricalMetrics.Size(m)
}
func (m *KeywordPlanHistoricalMetrics) XXX_DiscardUnknown() {
	xxx_messageInfo_KeywordPlanHistoricalMetrics.DiscardUnknown(m)
}

var xxx_messageInfo_KeywordPlanHistoricalMetrics proto.InternalMessageInfo

func (m *KeywordPlanHistoricalMetrics) GetAvgMonthlySearches() *wrappers.Int64Value {
	if m != nil {
		return m.AvgMonthlySearches
	}
	return nil
}

func (m *KeywordPlanHistoricalMetrics) GetCompetition() enums.KeywordPlanCompetitionLevelEnum_KeywordPlanCompetitionLevel {
	if m != nil {
		return m.Competition
	}
	return enums.KeywordPlanCompetitionLevelEnum_UNSPECIFIED
}

func init() {
	proto.RegisterType((*KeywordPlanHistoricalMetrics)(nil), "google.ads.googleads.v1.common.KeywordPlanHistoricalMetrics")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/common/keyword_plan_common.proto", fileDescriptor_keyword_plan_common_4e2e51c5040e95c3)
}

var fileDescriptor_keyword_plan_common_4e2e51c5040e95c3 = []byte{
	// 388 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x52, 0xcf, 0x6a, 0xdb, 0x30,
	0x18, 0xc7, 0x1e, 0xec, 0xe0, 0xc0, 0x0e, 0x66, 0x8c, 0x90, 0x85, 0x10, 0x72, 0xca, 0x49, 0xc2,
	0xd9, 0x18, 0x43, 0x3b, 0x39, 0x6b, 0x49, 0x4b, 0x1b, 0x08, 0x29, 0xf8, 0x10, 0x0c, 0x46, 0xb1,
	0x55, 0xc5, 0x54, 0x96, 0x8c, 0x24, 0x3b, 0x04, 0xfa, 0x34, 0x3d, 0xf6, 0x51, 0xfa, 0x28, 0xed,
	0xa9, 0x6f, 0x50, 0x6c, 0xd9, 0x69, 0x4a, 0x49, 0x4e, 0xfe, 0xac, 0xef, 0xf7, 0x47, 0xbf, 0xef,
	0x93, 0xf3, 0x97, 0x0a, 0x41, 0x19, 0x81, 0x38, 0x51, 0xd0, 0x94, 0x55, 0x55, 0x7a, 0x30, 0x16,
	0x59, 0x26, 0x38, 0xbc, 0x23, 0xbb, 0xad, 0x90, 0x49, 0x94, 0x33, 0xcc, 0x23, 0x73, 0x06, 0x72,
	0x29, 0xb4, 0x70, 0x07, 0x06, 0x0e, 0x70, 0xa2, 0xc0, 0x9e, 0x09, 0x4a, 0x0f, 0x18, 0x54, 0x6f,
	0x7a, 0x4c, 0x99, 0xf0, 0x22, 0x53, 0x9f, 0x84, 0x73, 0xa2, 0x53, 0x9d, 0x0a, 0x1e, 0x31, 0x52,
	0x12, 0x66, 0x3c, 0x7a, 0x8d, 0x07, 0xac, 0xff, 0xd6, 0xc5, 0x2d, 0xdc, 0x4a, 0x9c, 0xe7, 0x44,
	0xaa, 0xa6, 0xdf, 0x6f, 0x3d, 0xf2, 0x14, 0x62, 0xce, 0x85, 0xc6, 0x95, 0x44, 0xd3, 0x1d, 0xbd,
	0x58, 0x4e, 0xff, 0xca, 0xd8, 0x2c, 0x18, 0xe6, 0x17, 0xa9, 0xd2, 0x42, 0xa6, 0x31, 0x66, 0x73,
	0xa2, 0x65, 0x1a, 0x2b, 0x77, 0xee, 0x7c, 0xc7, 0x25, 0x8d, 0x32, 0xc1, 0xf5, 0x86, 0xed, 0x22,
	0x45, 0xb0, 0x8c, 0x37, 0x44, 0x75, 0xad, 0xa1, 0x35, 0xee, 0x4c, 0x7e, 0x36, 0xb1, 0x40, 0xeb,
	0x0e, 0x2e, 0xb9, 0xfe, 0xf3, 0x3b, 0xc0, 0xac, 0x20, 0x4b, 0x17, 0x97, 0x74, 0x6e, 0x78, 0x37,
	0x0d, 0xcd, 0xbd, 0x77, 0x3a, 0x07, 0x41, 0xba, 0xf6, 0xd0, 0x1a, 0x7f, 0x9b, 0xac, 0xc0, 0xb1,
	0x39, 0xd5, 0x73, 0x00, 0x07, 0x17, 0xfc, 0xff, 0x4e, 0xbe, 0xae, 0x86, 0x70, 0xce, 0x8b, 0xec,
	0x54, 0x7f, 0x79, 0x68, 0x37, 0x7d, 0xb5, 0x9c, 0x51, 0x2c, 0x32, 0x70, 0x7a, 0x2d, 0xd3, 0x1f,
	0x1f, 0x05, 0x33, 0xc1, 0x17, 0x55, 0xbc, 0x85, 0xb5, 0x3a, 0x6b, 0x98, 0x54, 0x30, 0xcc, 0x29,
	0x10, 0x92, 0x42, 0x4a, 0x78, 0x1d, 0xbe, 0x5d, 0x60, 0x9e, 0xaa, 0x63, 0x2f, 0xe5, 0x9f, 0xf9,
	0x3c, 0xd8, 0x5f, 0x66, 0xbe, 0xff, 0x68, 0x0f, 0x66, 0x46, 0xcc, 0x4f, 0x14, 0x30, 0x65, 0x55,
	0x05, 0x1e, 0x30, 0x9e, 0x4f, 0x2d, 0x20, 0xf4, 0x13, 0x15, 0xee, 0x01, 0x61, 0xe0, 0x85, 0x06,
	0xf0, 0x6c, 0x8f, 0xcc, 0x29, 0x42, 0x7e, 0xa2, 0x10, 0xda, 0x43, 0x10, 0x0a, 0x3c, 0x84, 0x0c,
	0x68, 0xfd, 0xb5, 0xbe, 0xdd, 0xaf, 0xb7, 0x00, 0x00, 0x00, 0xff, 0xff, 0x22, 0x94, 0x59, 0xd1,
	0xc6, 0x02, 0x00, 0x00,
}

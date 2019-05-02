// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/errors/bidding_error.proto

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

// Enum describing possible bidding errors.
type BiddingErrorEnum_BiddingError int32

const (
	// Enum unspecified.
	BiddingErrorEnum_UNSPECIFIED BiddingErrorEnum_BiddingError = 0
	// The received error code is not known in this version.
	BiddingErrorEnum_UNKNOWN BiddingErrorEnum_BiddingError = 1
	// Cannot transition to new bidding strategy.
	BiddingErrorEnum_BIDDING_STRATEGY_TRANSITION_NOT_ALLOWED BiddingErrorEnum_BiddingError = 2
	// Cannot attach bidding strategy to campaign.
	BiddingErrorEnum_CANNOT_ATTACH_BIDDING_STRATEGY_TO_CAMPAIGN BiddingErrorEnum_BiddingError = 7
	// Bidding strategy is not supported or cannot be used as anonymous.
	BiddingErrorEnum_INVALID_ANONYMOUS_BIDDING_STRATEGY_TYPE BiddingErrorEnum_BiddingError = 10
	// The type does not match the named strategy's type.
	BiddingErrorEnum_INVALID_BIDDING_STRATEGY_TYPE BiddingErrorEnum_BiddingError = 14
	// The bid is invalid.
	BiddingErrorEnum_INVALID_BID BiddingErrorEnum_BiddingError = 17
	// Bidding strategy is not available for the account type.
	BiddingErrorEnum_BIDDING_STRATEGY_NOT_AVAILABLE_FOR_ACCOUNT_TYPE BiddingErrorEnum_BiddingError = 18
	// Conversion tracking is not enabled for the campaign for VBB transition.
	BiddingErrorEnum_CONVERSION_TRACKING_NOT_ENABLED BiddingErrorEnum_BiddingError = 19
	// Not enough conversions tracked for VBB transitions.
	BiddingErrorEnum_NOT_ENOUGH_CONVERSIONS BiddingErrorEnum_BiddingError = 20
	// Campaign can not be created with given bidding strategy. It can be
	// transitioned to the strategy, once eligible.
	BiddingErrorEnum_CANNOT_CREATE_CAMPAIGN_WITH_BIDDING_STRATEGY BiddingErrorEnum_BiddingError = 21
	// Cannot target content network only as campaign uses Page One Promoted
	// bidding strategy.
	BiddingErrorEnum_CANNOT_TARGET_CONTENT_NETWORK_ONLY_WITH_CAMPAIGN_LEVEL_POP_BIDDING_STRATEGY BiddingErrorEnum_BiddingError = 23
	// Budget Optimizer and Target Spend bidding strategies are not supported
	// for campaigns with AdSchedule targeting.
	BiddingErrorEnum_BIDDING_STRATEGY_NOT_SUPPORTED_WITH_AD_SCHEDULE BiddingErrorEnum_BiddingError = 24
	// Pay per conversion is not available to all the customer, only few
	// whitelisted customers can use this.
	BiddingErrorEnum_PAY_PER_CONVERSION_NOT_AVAILABLE_FOR_CUSTOMER BiddingErrorEnum_BiddingError = 25
	// Pay per conversion is not allowed with Target CPA.
	BiddingErrorEnum_PAY_PER_CONVERSION_NOT_ALLOWED_WITH_TARGET_CPA BiddingErrorEnum_BiddingError = 26
	// Cannot set bidding strategy to Manual CPM for search network only
	// campaigns.
	BiddingErrorEnum_BIDDING_STRATEGY_NOT_ALLOWED_FOR_SEARCH_ONLY_CAMPAIGNS BiddingErrorEnum_BiddingError = 27
	// The bidding strategy is not supported for use in drafts or experiments.
	BiddingErrorEnum_BIDDING_STRATEGY_NOT_SUPPORTED_IN_DRAFTS_OR_EXPERIMENTS BiddingErrorEnum_BiddingError = 28
	// Bidding strategy type does not support product type ad group criterion.
	BiddingErrorEnum_BIDDING_STRATEGY_TYPE_DOES_NOT_SUPPORT_PRODUCT_TYPE_ADGROUP_CRITERION BiddingErrorEnum_BiddingError = 29
	// Bid amount is too small.
	BiddingErrorEnum_BID_TOO_SMALL BiddingErrorEnum_BiddingError = 30
	// Bid amount is too big.
	BiddingErrorEnum_BID_TOO_BIG BiddingErrorEnum_BiddingError = 31
	// Bid has too many fractional digit precision.
	BiddingErrorEnum_BID_TOO_MANY_FRACTIONAL_DIGITS BiddingErrorEnum_BiddingError = 32
	// Invalid domain name specified.
	BiddingErrorEnum_INVALID_DOMAIN_NAME BiddingErrorEnum_BiddingError = 33
	// The field is not compatible with payment mode.
	BiddingErrorEnum_NOT_COMPATIBLE_WITH_PAYMENT_MODE BiddingErrorEnum_BiddingError = 34
)

var BiddingErrorEnum_BiddingError_name = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "UNKNOWN",
	2:  "BIDDING_STRATEGY_TRANSITION_NOT_ALLOWED",
	7:  "CANNOT_ATTACH_BIDDING_STRATEGY_TO_CAMPAIGN",
	10: "INVALID_ANONYMOUS_BIDDING_STRATEGY_TYPE",
	14: "INVALID_BIDDING_STRATEGY_TYPE",
	17: "INVALID_BID",
	18: "BIDDING_STRATEGY_NOT_AVAILABLE_FOR_ACCOUNT_TYPE",
	19: "CONVERSION_TRACKING_NOT_ENABLED",
	20: "NOT_ENOUGH_CONVERSIONS",
	21: "CANNOT_CREATE_CAMPAIGN_WITH_BIDDING_STRATEGY",
	23: "CANNOT_TARGET_CONTENT_NETWORK_ONLY_WITH_CAMPAIGN_LEVEL_POP_BIDDING_STRATEGY",
	24: "BIDDING_STRATEGY_NOT_SUPPORTED_WITH_AD_SCHEDULE",
	25: "PAY_PER_CONVERSION_NOT_AVAILABLE_FOR_CUSTOMER",
	26: "PAY_PER_CONVERSION_NOT_ALLOWED_WITH_TARGET_CPA",
	27: "BIDDING_STRATEGY_NOT_ALLOWED_FOR_SEARCH_ONLY_CAMPAIGNS",
	28: "BIDDING_STRATEGY_NOT_SUPPORTED_IN_DRAFTS_OR_EXPERIMENTS",
	29: "BIDDING_STRATEGY_TYPE_DOES_NOT_SUPPORT_PRODUCT_TYPE_ADGROUP_CRITERION",
	30: "BID_TOO_SMALL",
	31: "BID_TOO_BIG",
	32: "BID_TOO_MANY_FRACTIONAL_DIGITS",
	33: "INVALID_DOMAIN_NAME",
	34: "NOT_COMPATIBLE_WITH_PAYMENT_MODE",
}
var BiddingErrorEnum_BiddingError_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"BIDDING_STRATEGY_TRANSITION_NOT_ALLOWED":                                     2,
	"CANNOT_ATTACH_BIDDING_STRATEGY_TO_CAMPAIGN":                                  7,
	"INVALID_ANONYMOUS_BIDDING_STRATEGY_TYPE":                                     10,
	"INVALID_BIDDING_STRATEGY_TYPE":                                               14,
	"INVALID_BID":                                                                 17,
	"BIDDING_STRATEGY_NOT_AVAILABLE_FOR_ACCOUNT_TYPE":                             18,
	"CONVERSION_TRACKING_NOT_ENABLED":                                             19,
	"NOT_ENOUGH_CONVERSIONS":                                                      20,
	"CANNOT_CREATE_CAMPAIGN_WITH_BIDDING_STRATEGY":                                21,
	"CANNOT_TARGET_CONTENT_NETWORK_ONLY_WITH_CAMPAIGN_LEVEL_POP_BIDDING_STRATEGY": 23,
	"BIDDING_STRATEGY_NOT_SUPPORTED_WITH_AD_SCHEDULE":                             24,
	"PAY_PER_CONVERSION_NOT_AVAILABLE_FOR_CUSTOMER":                               25,
	"PAY_PER_CONVERSION_NOT_ALLOWED_WITH_TARGET_CPA":                              26,
	"BIDDING_STRATEGY_NOT_ALLOWED_FOR_SEARCH_ONLY_CAMPAIGNS":                      27,
	"BIDDING_STRATEGY_NOT_SUPPORTED_IN_DRAFTS_OR_EXPERIMENTS":                     28,
	"BIDDING_STRATEGY_TYPE_DOES_NOT_SUPPORT_PRODUCT_TYPE_ADGROUP_CRITERION":       29,
	"BID_TOO_SMALL":                    30,
	"BID_TOO_BIG":                      31,
	"BID_TOO_MANY_FRACTIONAL_DIGITS":   32,
	"INVALID_DOMAIN_NAME":              33,
	"NOT_COMPATIBLE_WITH_PAYMENT_MODE": 34,
}

func (x BiddingErrorEnum_BiddingError) String() string {
	return proto.EnumName(BiddingErrorEnum_BiddingError_name, int32(x))
}
func (BiddingErrorEnum_BiddingError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_bidding_error_d0cef9752ce8e4a4, []int{0, 0}
}

// Container for enum describing possible bidding errors.
type BiddingErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BiddingErrorEnum) Reset()         { *m = BiddingErrorEnum{} }
func (m *BiddingErrorEnum) String() string { return proto.CompactTextString(m) }
func (*BiddingErrorEnum) ProtoMessage()    {}
func (*BiddingErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_bidding_error_d0cef9752ce8e4a4, []int{0}
}
func (m *BiddingErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BiddingErrorEnum.Unmarshal(m, b)
}
func (m *BiddingErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BiddingErrorEnum.Marshal(b, m, deterministic)
}
func (dst *BiddingErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BiddingErrorEnum.Merge(dst, src)
}
func (m *BiddingErrorEnum) XXX_Size() int {
	return xxx_messageInfo_BiddingErrorEnum.Size(m)
}
func (m *BiddingErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_BiddingErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_BiddingErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*BiddingErrorEnum)(nil), "google.ads.googleads.v0.errors.BiddingErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v0.errors.BiddingErrorEnum_BiddingError", BiddingErrorEnum_BiddingError_name, BiddingErrorEnum_BiddingError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/errors/bidding_error.proto", fileDescriptor_bidding_error_d0cef9752ce8e4a4)
}

var fileDescriptor_bidding_error_d0cef9752ce8e4a4 = []byte{
	// 697 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x54, 0xdb, 0x6e, 0x2b, 0x35,
	0x14, 0xa5, 0x41, 0x22, 0x92, 0x0f, 0x17, 0xd7, 0x07, 0x38, 0x70, 0xe0, 0xa4, 0x6d, 0x40, 0x42,
	0xe2, 0x32, 0x09, 0xad, 0x04, 0xd2, 0xf4, 0x69, 0x67, 0xec, 0x4c, 0xac, 0xcc, 0xd8, 0x96, 0xed,
	0x49, 0x08, 0x8a, 0x64, 0xb5, 0xa4, 0x8a, 0x2a, 0xb5, 0x99, 0x2a, 0x03, 0xfd, 0x20, 0x1e, 0xf9,
	0x94, 0xfe, 0x04, 0xef, 0x88, 0x8f, 0x40, 0x1e, 0x67, 0x42, 0xa4, 0xa4, 0xf0, 0x94, 0x9d, 0xa5,
	0xb5, 0x96, 0xbd, 0xf6, 0x6c, 0x6f, 0x74, 0xbe, 0x2c, 0xcb, 0xe5, 0xdd, 0x4d, 0xef, 0x6a, 0x51,
	0xf5, 0x42, 0xe9, 0xab, 0xc7, 0x7e, 0xef, 0x66, 0xbd, 0x2e, 0xd7, 0x55, 0xef, 0xfa, 0x76, 0xb1,
	0xb8, 0x5d, 0x2d, 0x5d, 0xfd, 0x37, 0x7a, 0x58, 0x97, 0xbf, 0x96, 0xa4, 0x13, 0x88, 0xd1, 0xd5,
	0xa2, 0x8a, 0xb6, 0x9a, 0xe8, 0xb1, 0x1f, 0x05, 0x4d, 0xf7, 0xcf, 0x36, 0xc2, 0x83, 0xa0, 0x63,
	0x1e, 0x61, 0xab, 0xdf, 0xee, 0xbb, 0x4f, 0x6d, 0xf4, 0xee, 0x2e, 0x48, 0x3e, 0x40, 0x2f, 0x0a,
	0x61, 0x14, 0x4b, 0xf8, 0x90, 0x33, 0x8a, 0xdf, 0x22, 0x2f, 0x50, 0xbb, 0x10, 0x63, 0x21, 0xa7,
	0x02, 0x1f, 0x91, 0x6f, 0xd0, 0x57, 0x03, 0x4e, 0x29, 0x17, 0xa9, 0x33, 0x56, 0x83, 0x65, 0xe9,
	0xcc, 0x59, 0x0d, 0xc2, 0x70, 0xcb, 0xa5, 0x70, 0x42, 0x5a, 0x07, 0x59, 0x26, 0xa7, 0x8c, 0xe2,
	0x16, 0x89, 0xd0, 0xd7, 0x09, 0x88, 0x1a, 0xb3, 0x16, 0x92, 0x91, 0xdb, 0x97, 0x4a, 0x97, 0x40,
	0xae, 0x80, 0xa7, 0x02, 0xb7, 0xbd, 0x39, 0x17, 0x13, 0xc8, 0x38, 0x75, 0x20, 0xa4, 0x98, 0xe5,
	0xb2, 0x30, 0x07, 0x34, 0x33, 0xc5, 0x30, 0x22, 0x67, 0xe8, 0x4d, 0x43, 0x3e, 0x4c, 0x79, 0xdf,
	0x47, 0xd9, 0xa1, 0xe0, 0x63, 0x72, 0x81, 0x7a, 0x7b, 0xdc, 0xfa, 0x7a, 0x13, 0xe0, 0x19, 0x0c,
	0x32, 0xe6, 0x86, 0x52, 0x3b, 0x48, 0x12, 0x59, 0x08, 0x1b, 0x5c, 0x08, 0xf9, 0x02, 0x9d, 0x24,
	0x52, 0x4c, 0x98, 0x36, 0x3e, 0xa1, 0xd5, 0x90, 0x8c, 0xbd, 0x81, 0xd7, 0x31, 0xe1, 0x45, 0x14,
	0xbf, 0x24, 0xaf, 0xd1, 0xc7, 0x01, 0x90, 0x45, 0x3a, 0x72, 0xff, 0xf2, 0x0d, 0xfe, 0x90, 0xf4,
	0xd1, 0xb7, 0x9b, 0x36, 0x24, 0x9a, 0x81, 0x65, 0xdb, 0xc8, 0x6e, 0xca, 0xed, 0x7e, 0x53, 0xf0,
	0x47, 0x44, 0xa2, 0xf1, 0x46, 0x61, 0x41, 0xa7, 0xcc, 0x7a, 0x43, 0xcb, 0x84, 0x75, 0x82, 0xd9,
	0xa9, 0xd4, 0x63, 0x27, 0x45, 0x36, 0x0b, 0xea, 0xad, 0x57, 0xc6, 0x26, 0x2c, 0x73, 0x4a, 0xaa,
	0x7d, 0xc3, 0x57, 0xcf, 0x06, 0x37, 0x85, 0x52, 0x52, 0x5b, 0x46, 0x83, 0x19, 0x50, 0x67, 0x92,
	0x11, 0xa3, 0x45, 0xc6, 0xf0, 0x27, 0xe4, 0x7b, 0xf4, 0x9d, 0x82, 0x99, 0x53, 0x4c, 0xef, 0x04,
	0x3a, 0xd0, 0xaf, 0xa4, 0x30, 0x56, 0xe6, 0x4c, 0xe3, 0x4f, 0xc9, 0x39, 0x8a, 0x9e, 0x93, 0x84,
	0xa9, 0x08, 0xe7, 0x34, 0xa9, 0x14, 0xe0, 0xd7, 0x24, 0x46, 0x3f, 0x1c, 0xfe, 0x28, 0x1b, 0x85,
	0x3f, 0xc2, 0x30, 0xd0, 0xc9, 0x28, 0xc4, 0x6e, 0x12, 0x1b, 0xfc, 0x19, 0xb9, 0x44, 0x3f, 0xfe,
	0x4f, 0x2e, 0x2e, 0x1c, 0xd5, 0x30, 0xb4, 0xc6, 0x49, 0xed, 0xd8, 0x4f, 0x8a, 0x69, 0x9e, 0x33,
	0x61, 0x0d, 0xfe, 0x9c, 0x70, 0xc4, 0x0e, 0x4e, 0x8e, 0xa3, 0x92, 0x99, 0x5d, 0x1b, 0xa7, 0xb4,
	0xa4, 0x45, 0x12, 0x26, 0xc2, 0x01, 0x4d, 0xb5, 0x2c, 0x94, 0x4b, 0x34, 0xb7, 0x4c, 0x73, 0x29,
	0xf0, 0x1b, 0x72, 0x8c, 0xde, 0x1b, 0x70, 0xea, 0xac, 0x94, 0xce, 0xe4, 0x90, 0x65, 0xb8, 0xe3,
	0x87, 0xaf, 0x81, 0x06, 0x3c, 0xc5, 0x27, 0xa4, 0x8b, 0x3a, 0x0d, 0x90, 0x83, 0x98, 0xb9, 0xa1,
	0x86, 0xc4, 0x3f, 0x1a, 0xc8, 0x1c, 0xe5, 0x29, 0xb7, 0x06, 0x9f, 0x92, 0x57, 0xe8, 0x65, 0x33,
	0xb1, 0x54, 0xe6, 0xc0, 0x85, 0x13, 0x90, 0x33, 0x7c, 0x46, 0xbe, 0x44, 0xa7, 0xf5, 0x00, 0xc9,
	0x5c, 0x81, 0xe5, 0xbe, 0xf3, 0x75, 0x23, 0x15, 0xcc, 0x7c, 0x1a, 0x97, 0x4b, 0xca, 0x70, 0x77,
	0xf0, 0xf7, 0x11, 0xea, 0xfe, 0x52, 0xde, 0x47, 0xff, 0xbd, 0x08, 0x06, 0xc7, 0xbb, 0x0f, 0x5e,
	0xf9, 0xdd, 0xa1, 0x8e, 0x7e, 0xa6, 0x1b, 0xd1, 0xb2, 0xbc, 0xbb, 0x5a, 0x2d, 0xa3, 0x72, 0xbd,
	0xec, 0x2d, 0x6f, 0x56, 0xf5, 0x66, 0x69, 0x36, 0xd0, 0xc3, 0x6d, 0xf5, 0xdc, 0x42, 0xba, 0x0c,
	0x3f, 0xbf, 0xb7, 0xde, 0x4e, 0x01, 0xfe, 0x68, 0x75, 0xd2, 0x60, 0x06, 0x8b, 0x2a, 0x0a, 0xa5,
	0xaf, 0x26, 0xfd, 0xa8, 0x3e, 0xb2, 0x7a, 0x6a, 0x08, 0x73, 0x58, 0x54, 0xf3, 0x2d, 0x61, 0x3e,
	0xe9, 0xcf, 0x03, 0xe1, 0xaf, 0x56, 0x37, 0xa0, 0x71, 0x0c, 0x8b, 0x2a, 0x8e, 0xb7, 0x94, 0x38,
	0x9e, 0xf4, 0xe3, 0x38, 0x90, 0xae, 0xdf, 0xa9, 0x6f, 0x77, 0xf1, 0x4f, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x99, 0xa1, 0xcf, 0xd2, 0x2d, 0x05, 0x00, 0x00,
}

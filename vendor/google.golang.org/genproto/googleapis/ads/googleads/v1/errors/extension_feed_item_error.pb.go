// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/errors/extension_feed_item_error.proto

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

// Enum describing possible extension feed item errors.
type ExtensionFeedItemErrorEnum_ExtensionFeedItemError int32

const (
	// Enum unspecified.
	ExtensionFeedItemErrorEnum_UNSPECIFIED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 0
	// The received error code is not known in this version.
	ExtensionFeedItemErrorEnum_UNKNOWN ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 1
	// Value is not within the accepted range.
	ExtensionFeedItemErrorEnum_VALUE_OUT_OF_RANGE ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 2
	// Url list is too long.
	ExtensionFeedItemErrorEnum_URL_LIST_TOO_LONG ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 3
	// Cannot have a geo targeting restriction without having geo targeting.
	ExtensionFeedItemErrorEnum_CANNOT_HAVE_RESTRICTION_ON_EMPTY_GEO_TARGETING ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 4
	// Cannot simultaneously set sitelink field with final urls.
	ExtensionFeedItemErrorEnum_CANNOT_SET_WITH_FINAL_URLS ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 5
	// Must set field with final urls.
	ExtensionFeedItemErrorEnum_CANNOT_SET_WITHOUT_FINAL_URLS ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 6
	// Phone number for a call extension is invalid.
	ExtensionFeedItemErrorEnum_INVALID_PHONE_NUMBER ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 7
	// Phone number for a call extension is not supported for the given country
	// code.
	ExtensionFeedItemErrorEnum_PHONE_NUMBER_NOT_SUPPORTED_FOR_COUNTRY ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 8
	// A carrier specific number in short format is not allowed for call
	// extensions.
	ExtensionFeedItemErrorEnum_CARRIER_SPECIFIC_SHORT_NUMBER_NOT_ALLOWED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 9
	// Premium rate numbers are not allowed for call extensions.
	ExtensionFeedItemErrorEnum_PREMIUM_RATE_NUMBER_NOT_ALLOWED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 10
	// Phone number type for a call extension is not allowed.
	// For example, personal number is not allowed for a call extension in
	// most regions.
	ExtensionFeedItemErrorEnum_DISALLOWED_NUMBER_TYPE ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 11
	// Phone number for a call extension does not meet domestic format
	// requirements.
	ExtensionFeedItemErrorEnum_INVALID_DOMESTIC_PHONE_NUMBER_FORMAT ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 12
	// Vanity phone numbers (i.e. those including letters) are not allowed for
	// call extensions.
	ExtensionFeedItemErrorEnum_VANITY_PHONE_NUMBER_NOT_ALLOWED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 13
	// Call conversion action provided for a call extension is invalid.
	ExtensionFeedItemErrorEnum_INVALID_CALL_CONVERSION_ACTION ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 14
	// For a call extension, the customer is not whitelisted for call tracking.
	ExtensionFeedItemErrorEnum_CUSTOMER_NOT_WHITELISTED_FOR_CALLTRACKING ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 15
	// Call tracking is not supported for the given country for a call
	// extension.
	ExtensionFeedItemErrorEnum_CALLTRACKING_NOT_SUPPORTED_FOR_COUNTRY ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 16
	// Customer hasn't consented for call recording, which is required for
	// creating/updating call feed items.
	ExtensionFeedItemErrorEnum_CUSTOMER_CONSENT_FOR_CALL_RECORDING_REQUIRED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 17
	// App id provided for an app extension is invalid.
	ExtensionFeedItemErrorEnum_INVALID_APP_ID ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 18
	// Quotation marks present in the review text for a review extension.
	ExtensionFeedItemErrorEnum_QUOTES_IN_REVIEW_EXTENSION_SNIPPET ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 19
	// Hyphen character present in the review text for a review extension.
	ExtensionFeedItemErrorEnum_HYPHENS_IN_REVIEW_EXTENSION_SNIPPET ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 20
	// A blacklisted review source name or url was provided for a review
	// extension.
	ExtensionFeedItemErrorEnum_REVIEW_EXTENSION_SOURCE_INELIGIBLE ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 21
	// Review source name should not be found in the review text.
	ExtensionFeedItemErrorEnum_SOURCE_NAME_IN_REVIEW_EXTENSION_TEXT ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 22
	// Inconsistent currency codes.
	ExtensionFeedItemErrorEnum_INCONSISTENT_CURRENCY_CODES ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 23
	// Price extension cannot have duplicated headers.
	ExtensionFeedItemErrorEnum_PRICE_EXTENSION_HAS_DUPLICATED_HEADERS ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 24
	// Price item cannot have duplicated header and description.
	ExtensionFeedItemErrorEnum_PRICE_ITEM_HAS_DUPLICATED_HEADER_AND_DESCRIPTION ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 25
	// Price extension has too few items.
	ExtensionFeedItemErrorEnum_PRICE_EXTENSION_HAS_TOO_FEW_ITEMS ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 26
	// Price extension has too many items.
	ExtensionFeedItemErrorEnum_PRICE_EXTENSION_HAS_TOO_MANY_ITEMS ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 27
	// The input value is not currently supported.
	ExtensionFeedItemErrorEnum_UNSUPPORTED_VALUE ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 28
	// The input value is not currently supported in the selected language of an
	// extension.
	ExtensionFeedItemErrorEnum_UNSUPPORTED_VALUE_IN_SELECTED_LANGUAGE ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 29
	// Unknown or unsupported device preference.
	ExtensionFeedItemErrorEnum_INVALID_DEVICE_PREFERENCE ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 30
	// Invalid feed item schedule end time (i.e., endHour = 24 and endMinute !=
	// 0).
	ExtensionFeedItemErrorEnum_INVALID_SCHEDULE_END ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 31
	// Date time zone does not match the account's time zone.
	ExtensionFeedItemErrorEnum_DATE_TIME_MUST_BE_IN_ACCOUNT_TIME_ZONE ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 32
	// Invalid structured snippet header.
	ExtensionFeedItemErrorEnum_INVALID_SNIPPETS_HEADER ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 33
	// Cannot operate on removed feed item.
	ExtensionFeedItemErrorEnum_CANNOT_OPERATE_ON_REMOVED_FEED_ITEM ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 34
	// Phone number not supported when call tracking enabled for country.
	ExtensionFeedItemErrorEnum_PHONE_NUMBER_NOT_SUPPORTED_WITH_CALLTRACKING_FOR_COUNTRY ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 35
	// Cannot set call_conversion_action while call_conversion_tracking_enabled
	// is set to true.
	ExtensionFeedItemErrorEnum_CONFLICTING_CALL_CONVERSION_SETTINGS ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 36
	// The type of the input extension feed item doesn't match the existing
	// extension feed item.
	ExtensionFeedItemErrorEnum_EXTENSION_TYPE_MISMATCH ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 37
	// The oneof field extension i.e. subtype of extension feed item is
	// required.
	ExtensionFeedItemErrorEnum_EXTENSION_SUBTYPE_REQUIRED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 38
	// The referenced feed item is not mapped to a supported extension type.
	ExtensionFeedItemErrorEnum_EXTENSION_TYPE_UNSUPPORTED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 39
	// Cannot operate on a Feed with more than one active FeedMapping.
	ExtensionFeedItemErrorEnum_CANNOT_OPERATE_ON_FEED_WITH_MULTIPLE_MAPPINGS ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 40
	// Cannot operate on a Feed that has key attributes.
	ExtensionFeedItemErrorEnum_CANNOT_OPERATE_ON_FEED_WITH_KEY_ATTRIBUTES ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 41
	// Input price is not in a valid format.
	ExtensionFeedItemErrorEnum_INVALID_PRICE_FORMAT ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 42
	// The promotion time is invalid.
	ExtensionFeedItemErrorEnum_PROMOTION_INVALID_TIME ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 43
	// This field has too many decimal places specified.
	ExtensionFeedItemErrorEnum_TOO_MANY_DECIMAL_PLACES_SPECIFIED ExtensionFeedItemErrorEnum_ExtensionFeedItemError = 44
)

var ExtensionFeedItemErrorEnum_ExtensionFeedItemError_name = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "UNKNOWN",
	2:  "VALUE_OUT_OF_RANGE",
	3:  "URL_LIST_TOO_LONG",
	4:  "CANNOT_HAVE_RESTRICTION_ON_EMPTY_GEO_TARGETING",
	5:  "CANNOT_SET_WITH_FINAL_URLS",
	6:  "CANNOT_SET_WITHOUT_FINAL_URLS",
	7:  "INVALID_PHONE_NUMBER",
	8:  "PHONE_NUMBER_NOT_SUPPORTED_FOR_COUNTRY",
	9:  "CARRIER_SPECIFIC_SHORT_NUMBER_NOT_ALLOWED",
	10: "PREMIUM_RATE_NUMBER_NOT_ALLOWED",
	11: "DISALLOWED_NUMBER_TYPE",
	12: "INVALID_DOMESTIC_PHONE_NUMBER_FORMAT",
	13: "VANITY_PHONE_NUMBER_NOT_ALLOWED",
	14: "INVALID_CALL_CONVERSION_ACTION",
	15: "CUSTOMER_NOT_WHITELISTED_FOR_CALLTRACKING",
	16: "CALLTRACKING_NOT_SUPPORTED_FOR_COUNTRY",
	17: "CUSTOMER_CONSENT_FOR_CALL_RECORDING_REQUIRED",
	18: "INVALID_APP_ID",
	19: "QUOTES_IN_REVIEW_EXTENSION_SNIPPET",
	20: "HYPHENS_IN_REVIEW_EXTENSION_SNIPPET",
	21: "REVIEW_EXTENSION_SOURCE_INELIGIBLE",
	22: "SOURCE_NAME_IN_REVIEW_EXTENSION_TEXT",
	23: "INCONSISTENT_CURRENCY_CODES",
	24: "PRICE_EXTENSION_HAS_DUPLICATED_HEADERS",
	25: "PRICE_ITEM_HAS_DUPLICATED_HEADER_AND_DESCRIPTION",
	26: "PRICE_EXTENSION_HAS_TOO_FEW_ITEMS",
	27: "PRICE_EXTENSION_HAS_TOO_MANY_ITEMS",
	28: "UNSUPPORTED_VALUE",
	29: "UNSUPPORTED_VALUE_IN_SELECTED_LANGUAGE",
	30: "INVALID_DEVICE_PREFERENCE",
	31: "INVALID_SCHEDULE_END",
	32: "DATE_TIME_MUST_BE_IN_ACCOUNT_TIME_ZONE",
	33: "INVALID_SNIPPETS_HEADER",
	34: "CANNOT_OPERATE_ON_REMOVED_FEED_ITEM",
	35: "PHONE_NUMBER_NOT_SUPPORTED_WITH_CALLTRACKING_FOR_COUNTRY",
	36: "CONFLICTING_CALL_CONVERSION_SETTINGS",
	37: "EXTENSION_TYPE_MISMATCH",
	38: "EXTENSION_SUBTYPE_REQUIRED",
	39: "EXTENSION_TYPE_UNSUPPORTED",
	40: "CANNOT_OPERATE_ON_FEED_WITH_MULTIPLE_MAPPINGS",
	41: "CANNOT_OPERATE_ON_FEED_WITH_KEY_ATTRIBUTES",
	42: "INVALID_PRICE_FORMAT",
	43: "PROMOTION_INVALID_TIME",
	44: "TOO_MANY_DECIMAL_PLACES_SPECIFIED",
}
var ExtensionFeedItemErrorEnum_ExtensionFeedItemError_value = map[string]int32{
	"UNSPECIFIED":        0,
	"UNKNOWN":            1,
	"VALUE_OUT_OF_RANGE": 2,
	"URL_LIST_TOO_LONG":  3,
	"CANNOT_HAVE_RESTRICTION_ON_EMPTY_GEO_TARGETING":           4,
	"CANNOT_SET_WITH_FINAL_URLS":                               5,
	"CANNOT_SET_WITHOUT_FINAL_URLS":                            6,
	"INVALID_PHONE_NUMBER":                                     7,
	"PHONE_NUMBER_NOT_SUPPORTED_FOR_COUNTRY":                   8,
	"CARRIER_SPECIFIC_SHORT_NUMBER_NOT_ALLOWED":                9,
	"PREMIUM_RATE_NUMBER_NOT_ALLOWED":                          10,
	"DISALLOWED_NUMBER_TYPE":                                   11,
	"INVALID_DOMESTIC_PHONE_NUMBER_FORMAT":                     12,
	"VANITY_PHONE_NUMBER_NOT_ALLOWED":                          13,
	"INVALID_CALL_CONVERSION_ACTION":                           14,
	"CUSTOMER_NOT_WHITELISTED_FOR_CALLTRACKING":                15,
	"CALLTRACKING_NOT_SUPPORTED_FOR_COUNTRY":                   16,
	"CUSTOMER_CONSENT_FOR_CALL_RECORDING_REQUIRED":             17,
	"INVALID_APP_ID":                                           18,
	"QUOTES_IN_REVIEW_EXTENSION_SNIPPET":                       19,
	"HYPHENS_IN_REVIEW_EXTENSION_SNIPPET":                      20,
	"REVIEW_EXTENSION_SOURCE_INELIGIBLE":                       21,
	"SOURCE_NAME_IN_REVIEW_EXTENSION_TEXT":                     22,
	"INCONSISTENT_CURRENCY_CODES":                              23,
	"PRICE_EXTENSION_HAS_DUPLICATED_HEADERS":                   24,
	"PRICE_ITEM_HAS_DUPLICATED_HEADER_AND_DESCRIPTION":         25,
	"PRICE_EXTENSION_HAS_TOO_FEW_ITEMS":                        26,
	"PRICE_EXTENSION_HAS_TOO_MANY_ITEMS":                       27,
	"UNSUPPORTED_VALUE":                                        28,
	"UNSUPPORTED_VALUE_IN_SELECTED_LANGUAGE":                   29,
	"INVALID_DEVICE_PREFERENCE":                                30,
	"INVALID_SCHEDULE_END":                                     31,
	"DATE_TIME_MUST_BE_IN_ACCOUNT_TIME_ZONE":                   32,
	"INVALID_SNIPPETS_HEADER":                                  33,
	"CANNOT_OPERATE_ON_REMOVED_FEED_ITEM":                      34,
	"PHONE_NUMBER_NOT_SUPPORTED_WITH_CALLTRACKING_FOR_COUNTRY": 35,
	"CONFLICTING_CALL_CONVERSION_SETTINGS":                     36,
	"EXTENSION_TYPE_MISMATCH":                                  37,
	"EXTENSION_SUBTYPE_REQUIRED":                               38,
	"EXTENSION_TYPE_UNSUPPORTED":                               39,
	"CANNOT_OPERATE_ON_FEED_WITH_MULTIPLE_MAPPINGS":            40,
	"CANNOT_OPERATE_ON_FEED_WITH_KEY_ATTRIBUTES":               41,
	"INVALID_PRICE_FORMAT":                                     42,
	"PROMOTION_INVALID_TIME":                                   43,
	"TOO_MANY_DECIMAL_PLACES_SPECIFIED":                        44,
}

func (x ExtensionFeedItemErrorEnum_ExtensionFeedItemError) String() string {
	return proto.EnumName(ExtensionFeedItemErrorEnum_ExtensionFeedItemError_name, int32(x))
}
func (ExtensionFeedItemErrorEnum_ExtensionFeedItemError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_extension_feed_item_error_620418e9a72e0e82, []int{0, 0}
}

// Container for enum describing possible extension feed item error.
type ExtensionFeedItemErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExtensionFeedItemErrorEnum) Reset()         { *m = ExtensionFeedItemErrorEnum{} }
func (m *ExtensionFeedItemErrorEnum) String() string { return proto.CompactTextString(m) }
func (*ExtensionFeedItemErrorEnum) ProtoMessage()    {}
func (*ExtensionFeedItemErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_extension_feed_item_error_620418e9a72e0e82, []int{0}
}
func (m *ExtensionFeedItemErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExtensionFeedItemErrorEnum.Unmarshal(m, b)
}
func (m *ExtensionFeedItemErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExtensionFeedItemErrorEnum.Marshal(b, m, deterministic)
}
func (dst *ExtensionFeedItemErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExtensionFeedItemErrorEnum.Merge(dst, src)
}
func (m *ExtensionFeedItemErrorEnum) XXX_Size() int {
	return xxx_messageInfo_ExtensionFeedItemErrorEnum.Size(m)
}
func (m *ExtensionFeedItemErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_ExtensionFeedItemErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_ExtensionFeedItemErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ExtensionFeedItemErrorEnum)(nil), "google.ads.googleads.v1.errors.ExtensionFeedItemErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.errors.ExtensionFeedItemErrorEnum_ExtensionFeedItemError", ExtensionFeedItemErrorEnum_ExtensionFeedItemError_name, ExtensionFeedItemErrorEnum_ExtensionFeedItemError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/errors/extension_feed_item_error.proto", fileDescriptor_extension_feed_item_error_620418e9a72e0e82)
}

var fileDescriptor_extension_feed_item_error_620418e9a72e0e82 = []byte{
	// 1056 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x55, 0xdd, 0x8e, 0x53, 0x37,
	0x10, 0x2e, 0x4b, 0x0b, 0xad, 0x29, 0x60, 0x5c, 0x58, 0x60, 0x17, 0x96, 0x12, 0xfe, 0x29, 0x24,
	0xa4, 0xed, 0x45, 0x95, 0x56, 0x95, 0x1c, 0x9f, 0x49, 0x62, 0xe1, 0x63, 0x1b, 0xdb, 0x27, 0x21,
	0x68, 0xa5, 0xd1, 0xb6, 0x49, 0xa3, 0x95, 0xd8, 0x64, 0xb5, 0x49, 0x51, 0x9f, 0xa2, 0x0f, 0xd1,
	0xcb, 0x4a, 0x7d, 0x91, 0x3e, 0x4a, 0x1f, 0xa0, 0xd7, 0x95, 0x7d, 0x92, 0x90, 0xed, 0x86, 0xbd,
	0xca, 0xc9, 0xf8, 0x9b, 0xff, 0x6f, 0x66, 0xc8, 0x8f, 0xa3, 0xc9, 0x64, 0xf4, 0x76, 0x58, 0xdb,
	0x1b, 0x4c, 0x6b, 0xe5, 0x67, 0xfc, 0x7a, 0x57, 0xaf, 0x0d, 0x8f, 0x8e, 0x26, 0x47, 0xd3, 0xda,
	0xf0, 0xb7, 0xd9, 0x70, 0x3c, 0xdd, 0x9f, 0x8c, 0xf1, 0x97, 0xe1, 0x70, 0x80, 0xfb, 0xb3, 0xe1,
	0x01, 0xa6, 0xa7, 0xea, 0xe1, 0xd1, 0x64, 0x36, 0x61, 0x3b, 0xa5, 0x52, 0x75, 0x6f, 0x30, 0xad,
	0x2e, 0xf5, 0xab, 0xef, 0xea, 0xd5, 0x52, 0x7f, 0xeb, 0xd6, 0xc2, 0xfe, 0xe1, 0x7e, 0x6d, 0x6f,
	0x3c, 0x9e, 0xcc, 0xf6, 0x66, 0xfb, 0x93, 0xf1, 0xb4, 0xd4, 0xae, 0xfc, 0x75, 0x91, 0x6c, 0xc1,
	0xc2, 0x43, 0x6b, 0x38, 0x1c, 0xc8, 0xd9, 0xf0, 0x00, 0xa2, 0x26, 0x8c, 0x7f, 0x3d, 0xa8, 0xfc,
	0x7e, 0x91, 0x6c, 0xae, 0x7f, 0x66, 0x97, 0xc9, 0x85, 0x42, 0x7b, 0x0b, 0x42, 0xb6, 0x24, 0x64,
	0xf4, 0x23, 0x76, 0x81, 0x9c, 0x2f, 0xf4, 0x4b, 0x6d, 0x7a, 0x9a, 0x9e, 0x61, 0x9b, 0x84, 0x75,
	0xb9, 0x2a, 0x00, 0x4d, 0x11, 0xd0, 0xb4, 0xd0, 0x71, 0xdd, 0x06, 0xba, 0xc1, 0xae, 0x91, 0x2b,
	0x85, 0x53, 0xa8, 0xa4, 0x0f, 0x18, 0x8c, 0x41, 0x65, 0x74, 0x9b, 0x9e, 0x65, 0x5f, 0x93, 0xaa,
	0xe0, 0x5a, 0x9b, 0x80, 0x1d, 0xde, 0x05, 0x74, 0xe0, 0x83, 0x93, 0x22, 0x48, 0xa3, 0xd1, 0x68,
	0x84, 0xdc, 0x86, 0x3e, 0xb6, 0xc1, 0x60, 0xe0, 0xae, 0x0d, 0x41, 0xea, 0x36, 0xfd, 0x98, 0xed,
	0x90, 0xad, 0xb9, 0x8e, 0x87, 0x80, 0x3d, 0x19, 0x3a, 0xd8, 0x92, 0x9a, 0x2b, 0x2c, 0x9c, 0xf2,
	0xf4, 0x13, 0x76, 0x97, 0xdc, 0xfe, 0xdf, 0x7b, 0x8c, 0x65, 0x05, 0x72, 0x8e, 0xdd, 0x20, 0x57,
	0xa5, 0xee, 0x72, 0x25, 0x33, 0xb4, 0x1d, 0xa3, 0x01, 0x75, 0x91, 0x37, 0xc1, 0xd1, 0xf3, 0xec,
	0x29, 0x79, 0xb8, 0x2a, 0xc1, 0x64, 0xa6, 0xb0, 0xd6, 0xb8, 0x00, 0x19, 0xb6, 0x8c, 0x43, 0x61,
	0x0a, 0x1d, 0x5c, 0x9f, 0x7e, 0xca, 0x9e, 0x93, 0x27, 0x82, 0x3b, 0x27, 0xc1, 0xe1, 0xbc, 0x1e,
	0x02, 0x7d, 0xc7, 0xb8, 0xb0, 0xaa, 0xcc, 0x95, 0x32, 0x3d, 0xc8, 0xe8, 0x67, 0xec, 0x1e, 0xb9,
	0x63, 0x1d, 0xe4, 0xb2, 0xc8, 0xd1, 0xf1, 0x00, 0xeb, 0x40, 0x84, 0x6d, 0x91, 0xcd, 0x4c, 0xfa,
	0xf9, 0xff, 0x05, 0x24, 0xf4, 0x2d, 0xd0, 0x0b, 0xec, 0x31, 0xb9, 0xbf, 0x88, 0x3a, 0x33, 0x39,
	0xf8, 0x20, 0xc5, 0xb1, 0xf0, 0x63, 0x78, 0x39, 0x0f, 0xf4, 0xf3, 0xe8, 0xaa, 0xcb, 0xb5, 0x0c,
	0x7d, 0x3c, 0x91, 0xcc, 0xc2, 0xd5, 0x45, 0x56, 0x21, 0x3b, 0x0b, 0x73, 0x82, 0x2b, 0x85, 0xc2,
	0xe8, 0x2e, 0x38, 0x1f, 0x6b, 0xcf, 0x53, 0x0b, 0xe8, 0xa5, 0x94, 0x62, 0xe1, 0x83, 0xc9, 0xe7,
	0xda, 0xbd, 0x8e, 0x0c, 0x10, 0x9b, 0xb8, 0x28, 0x06, 0x57, 0x2a, 0x38, 0x2e, 0x5e, 0xc6, 0xd6,
	0x5c, 0x8e, 0xd5, 0x5b, 0x95, 0x9c, 0x52, 0x3d, 0xca, 0x5e, 0x90, 0x67, 0x4b, 0xd3, 0xc2, 0x68,
	0x0f, 0x3a, 0x2c, 0x4d, 0xa2, 0x03, 0x61, 0x5c, 0x16, 0x4d, 0x38, 0x78, 0x55, 0x48, 0x07, 0x19,
	0xbd, 0xc2, 0x18, 0xb9, 0xb4, 0x08, 0x98, 0x5b, 0x8b, 0x32, 0xa3, 0x8c, 0x3d, 0x24, 0x95, 0x57,
	0x85, 0x09, 0xe0, 0x51, 0x6a, 0x74, 0xd0, 0x95, 0xd0, 0x43, 0x78, 0x1d, 0x40, 0xa7, 0x3c, 0xbc,
	0x96, 0xd6, 0x42, 0xa0, 0x5f, 0xb0, 0x47, 0xe4, 0x5e, 0xa7, 0x6f, 0x3b, 0xa0, 0x4f, 0x07, 0x5e,
	0x8d, 0x06, 0x4f, 0xbe, 0x9a, 0xc2, 0x09, 0x40, 0xa9, 0x41, 0xc9, 0xb6, 0x6c, 0x2a, 0xa0, 0xd7,
	0x62, 0x33, 0xe6, 0x62, 0xcd, 0x73, 0x58, 0x6b, 0x34, 0xc0, 0xeb, 0x40, 0x37, 0xd9, 0x1d, 0xb2,
	0x2d, 0x75, 0xcc, 0x30, 0x96, 0x4d, 0x07, 0x14, 0x85, 0x73, 0xa0, 0x45, 0x1f, 0x85, 0xc9, 0xc0,
	0xd3, 0xeb, 0x89, 0x73, 0x4e, 0x0a, 0x58, 0x51, 0xed, 0x70, 0x8f, 0x59, 0x61, 0x95, 0x14, 0x3c,
	0x56, 0xae, 0x03, 0x3c, 0x03, 0xe7, 0xe9, 0x0d, 0xf6, 0x2d, 0x79, 0x51, 0x62, 0x65, 0x80, 0x7c,
	0x3d, 0x0c, 0xb9, 0xce, 0x30, 0x03, 0x2f, 0x9c, 0xb4, 0xa9, 0x8d, 0x37, 0xd9, 0x03, 0x72, 0x77,
	0x9d, 0x87, 0x38, 0x88, 0x2d, 0xe8, 0x25, 0x5b, 0x9e, 0x6e, 0xc5, 0xdc, 0x3f, 0x04, 0xcb, 0xb9,
	0xee, 0xcf, 0x71, 0xdb, 0x69, 0x98, 0xf5, 0xfb, 0xbe, 0xa6, 0x81, 0xa7, 0xb7, 0x62, 0x1e, 0x27,
	0xc4, 0xb1, 0x30, 0x1e, 0x14, 0x88, 0x28, 0x51, 0x5c, 0xb7, 0x0b, 0xde, 0x06, 0x7a, 0x9b, 0xdd,
	0x26, 0x37, 0x97, 0x5c, 0x86, 0x6e, 0xf4, 0x69, 0x1d, 0xb4, 0x20, 0x16, 0x06, 0xe8, 0xce, 0xea,
	0x80, 0x7a, 0xd1, 0x81, 0xac, 0x50, 0x80, 0xa0, 0x33, 0x7a, 0x27, 0x3a, 0xc9, 0xe2, 0xf4, 0x04,
	0x99, 0x03, 0xe6, 0x85, 0x0f, 0xd8, 0x4c, 0x4e, 0xb8, 0x48, 0xd4, 0x2a, 0xe5, 0x6f, 0x8c, 0x06,
	0xfa, 0x25, 0xdb, 0x26, 0xd7, 0x97, 0x56, 0xca, 0x06, 0xfb, 0x79, 0x8d, 0xe8, 0xdd, 0xc8, 0x88,
	0xf9, 0x9a, 0x30, 0x16, 0xd2, 0x40, 0x9a, 0xd8, 0xc3, 0xdc, 0x74, 0x23, 0x55, 0x01, 0xb2, 0x94,
	0x2e, 0xad, 0xb0, 0x1f, 0xc8, 0x77, 0xa7, 0xac, 0x84, 0xb4, 0x7f, 0x8e, 0x91, 0x7e, 0x95, 0xe6,
	0xf7, 0x22, 0x4f, 0x84, 0xd1, 0x2d, 0x15, 0xb7, 0x9a, 0x6e, 0x9f, 0x98, 0x34, 0x0f, 0x21, 0xca,
	0x3d, 0xbd, 0x1f, 0xa3, 0x5d, 0xe1, 0x4e, 0xdf, 0x02, 0xe6, 0xd2, 0xe7, 0x3c, 0x88, 0x0e, 0x7d,
	0x10, 0x97, 0xde, 0x0a, 0x1f, 0x8b, 0x66, 0x7a, 0x5f, 0xce, 0xc6, 0xc3, 0xe3, 0xef, 0xe9, 0x71,
	0xa5, 0x15, 0xf4, 0x11, 0xab, 0x93, 0xe7, 0x27, 0xb3, 0x4d, 0x59, 0xa6, 0x04, 0xf2, 0x42, 0x05,
	0x69, 0x15, 0x60, 0xce, 0xad, 0x4d, 0xf1, 0x3c, 0x66, 0x55, 0xf2, 0xf4, 0x34, 0x95, 0x97, 0xd0,
	0x47, 0x1e, 0x82, 0x93, 0xcd, 0x22, 0x80, 0xa7, 0x4f, 0x8e, 0x2d, 0xd5, 0xc4, 0xa2, 0xf9, 0x3a,
	0x7a, 0x1a, 0x97, 0x9a, 0x75, 0x26, 0x37, 0x69, 0xaf, 0x2f, 0x30, 0xb1, 0x51, 0xf4, 0xab, 0x48,
	0xcd, 0x25, 0xbf, 0x32, 0x10, 0x32, 0xe7, 0x0a, 0xad, 0xe2, 0x02, 0x3c, 0xbe, 0x3f, 0x32, 0xcf,
	0x9a, 0xff, 0x9e, 0x21, 0x95, 0x9f, 0x27, 0x07, 0xd5, 0xd3, 0x8f, 0x5e, 0x73, 0x7b, 0xfd, 0xd1,
	0xb2, 0xf1, 0xe6, 0xd9, 0x33, 0x6f, 0xb2, 0xb9, 0xfa, 0x68, 0xf2, 0x76, 0x6f, 0x3c, 0xaa, 0x4e,
	0x8e, 0x46, 0xb5, 0xd1, 0x70, 0x9c, 0x2e, 0xe2, 0xe2, 0x06, 0x1f, 0xee, 0x4f, 0x3f, 0x74, 0x92,
	0xbf, 0x2f, 0x7f, 0xfe, 0xd8, 0x38, 0xdb, 0xe6, 0xfc, 0xcf, 0x8d, 0x9d, 0x76, 0x69, 0x8c, 0x0f,
	0xa6, 0xd5, 0xf2, 0x33, 0x7e, 0x75, 0xeb, 0xd5, 0xe4, 0x72, 0xfa, 0xf7, 0x02, 0xb0, 0xcb, 0x07,
	0xd3, 0xdd, 0x25, 0x60, 0xb7, 0x5b, 0xdf, 0x2d, 0x01, 0xff, 0x6c, 0x54, 0x4a, 0x69, 0xa3, 0xc1,
	0x07, 0xd3, 0x46, 0x63, 0x09, 0x69, 0x34, 0xba, 0xf5, 0x46, 0xa3, 0x04, 0xfd, 0x74, 0x2e, 0x45,
	0xf7, 0xcd, 0x7f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x4a, 0x95, 0x61, 0x9f, 0x2f, 0x08, 0x00, 0x00,
}

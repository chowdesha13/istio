// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/resources/feed_item.proto

package resources // import "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import wrappers "github.com/golang/protobuf/ptypes/wrappers"
import common "google.golang.org/genproto/googleapis/ads/googleads/v1/common"
import enums "google.golang.org/genproto/googleapis/ads/googleads/v1/enums"
import errors "google.golang.org/genproto/googleapis/ads/googleads/v1/errors"
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

// A feed item.
type FeedItem struct {
	// The resource name of the feed item.
	// Feed item resource names have the form:
	//
	// `customers/{customer_id}/feedItems/{feed_id}~{feed_item_id}`
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	// The feed to which this feed item belongs.
	Feed *wrappers.StringValue `protobuf:"bytes,2,opt,name=feed,proto3" json:"feed,omitempty"`
	// The ID of this feed item.
	Id *wrappers.Int64Value `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
	// Start time in which this feed item is effective and can begin serving.
	// The format is "YYYY-MM-DD HH:MM:SS".
	// Examples: "2018-03-05 09:15:00" or "2018-02-01 14:34:30"
	StartDateTime *wrappers.StringValue `protobuf:"bytes,4,opt,name=start_date_time,json=startDateTime,proto3" json:"start_date_time,omitempty"`
	// End time in which this feed item is no longer effective and will stop
	// serving.
	// The format is "YYYY-MM-DD HH:MM:SS".
	// Examples: "2018-03-05 09:15:00" or "2018-02-01 14:34:30"
	EndDateTime *wrappers.StringValue `protobuf:"bytes,5,opt,name=end_date_time,json=endDateTime,proto3" json:"end_date_time,omitempty"`
	// The feed item's attribute values.
	AttributeValues []*FeedItemAttributeValue `protobuf:"bytes,6,rep,name=attribute_values,json=attributeValues,proto3" json:"attribute_values,omitempty"`
	// Geo targeting restriction specifies the type of location that can be used
	// for targeting.
	GeoTargetingRestriction enums.GeoTargetingRestrictionEnum_GeoTargetingRestriction `protobuf:"varint,7,opt,name=geo_targeting_restriction,json=geoTargetingRestriction,proto3,enum=google.ads.googleads.v1.enums.GeoTargetingRestrictionEnum_GeoTargetingRestriction" json:"geo_targeting_restriction,omitempty"`
	// The list of mappings used to substitute custom parameter tags in a
	// `tracking_url_template`, `final_urls`, or `mobile_final_urls`.
	UrlCustomParameters []*common.CustomParameter `protobuf:"bytes,8,rep,name=url_custom_parameters,json=urlCustomParameters,proto3" json:"url_custom_parameters,omitempty"`
	// Status of the feed item.
	// This field is read-only.
	Status enums.FeedItemStatusEnum_FeedItemStatus `protobuf:"varint,9,opt,name=status,proto3,enum=google.ads.googleads.v1.enums.FeedItemStatusEnum_FeedItemStatus" json:"status,omitempty"`
	// List of info about a feed item's validation and approval state for active
	// feed mappings. There will be an entry in the list for each type of feed
	// mapping associated with the feed, e.g. a feed with a sitelink and a call
	// feed mapping would cause every feed item associated with that feed to have
	// an entry in this list for both sitelink and call.
	// This field is read-only.
	PolicyInfos          []*FeedItemPlaceholderPolicyInfo `protobuf:"bytes,10,rep,name=policy_infos,json=policyInfos,proto3" json:"policy_infos,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                         `json:"-"`
	XXX_unrecognized     []byte                           `json:"-"`
	XXX_sizecache        int32                            `json:"-"`
}

func (m *FeedItem) Reset()         { *m = FeedItem{} }
func (m *FeedItem) String() string { return proto.CompactTextString(m) }
func (*FeedItem) ProtoMessage()    {}
func (*FeedItem) Descriptor() ([]byte, []int) {
	return fileDescriptor_feed_item_1965a7177a1e850a, []int{0}
}
func (m *FeedItem) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FeedItem.Unmarshal(m, b)
}
func (m *FeedItem) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FeedItem.Marshal(b, m, deterministic)
}
func (dst *FeedItem) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FeedItem.Merge(dst, src)
}
func (m *FeedItem) XXX_Size() int {
	return xxx_messageInfo_FeedItem.Size(m)
}
func (m *FeedItem) XXX_DiscardUnknown() {
	xxx_messageInfo_FeedItem.DiscardUnknown(m)
}

var xxx_messageInfo_FeedItem proto.InternalMessageInfo

func (m *FeedItem) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *FeedItem) GetFeed() *wrappers.StringValue {
	if m != nil {
		return m.Feed
	}
	return nil
}

func (m *FeedItem) GetId() *wrappers.Int64Value {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *FeedItem) GetStartDateTime() *wrappers.StringValue {
	if m != nil {
		return m.StartDateTime
	}
	return nil
}

func (m *FeedItem) GetEndDateTime() *wrappers.StringValue {
	if m != nil {
		return m.EndDateTime
	}
	return nil
}

func (m *FeedItem) GetAttributeValues() []*FeedItemAttributeValue {
	if m != nil {
		return m.AttributeValues
	}
	return nil
}

func (m *FeedItem) GetGeoTargetingRestriction() enums.GeoTargetingRestrictionEnum_GeoTargetingRestriction {
	if m != nil {
		return m.GeoTargetingRestriction
	}
	return enums.GeoTargetingRestrictionEnum_UNSPECIFIED
}

func (m *FeedItem) GetUrlCustomParameters() []*common.CustomParameter {
	if m != nil {
		return m.UrlCustomParameters
	}
	return nil
}

func (m *FeedItem) GetStatus() enums.FeedItemStatusEnum_FeedItemStatus {
	if m != nil {
		return m.Status
	}
	return enums.FeedItemStatusEnum_UNSPECIFIED
}

func (m *FeedItem) GetPolicyInfos() []*FeedItemPlaceholderPolicyInfo {
	if m != nil {
		return m.PolicyInfos
	}
	return nil
}

// A feed item attribute value.
type FeedItemAttributeValue struct {
	// Id of the feed attribute for which the value is associated with.
	FeedAttributeId *wrappers.Int64Value `protobuf:"bytes,1,opt,name=feed_attribute_id,json=feedAttributeId,proto3" json:"feed_attribute_id,omitempty"`
	// Int64 value. Should be set if feed_attribute_id refers to a feed attribute
	// of type INT64.
	IntegerValue *wrappers.Int64Value `protobuf:"bytes,2,opt,name=integer_value,json=integerValue,proto3" json:"integer_value,omitempty"`
	// Bool value. Should be set if feed_attribute_id refers to a feed attribute
	// of type BOOLEAN.
	BooleanValue *wrappers.BoolValue `protobuf:"bytes,3,opt,name=boolean_value,json=booleanValue,proto3" json:"boolean_value,omitempty"`
	// String value. Should be set if feed_attribute_id refers to a feed attribute
	// of type STRING, URL or DATE_TIME.
	// For STRING the maximum length is 1500 characters. For URL the maximum
	// length is 2076 characters. For DATE_TIME the format of the string must
	// be the same as start and end time for the feed item.
	StringValue *wrappers.StringValue `protobuf:"bytes,4,opt,name=string_value,json=stringValue,proto3" json:"string_value,omitempty"`
	// Double value. Should be set if feed_attribute_id refers to a feed attribute
	// of type DOUBLE.
	DoubleValue *wrappers.DoubleValue `protobuf:"bytes,5,opt,name=double_value,json=doubleValue,proto3" json:"double_value,omitempty"`
	// Price value. Should be set if feed_attribute_id refers to a feed attribute
	// of type PRICE.
	PriceValue *common.Money `protobuf:"bytes,6,opt,name=price_value,json=priceValue,proto3" json:"price_value,omitempty"`
	// Repeated int64 value. Should be set if feed_attribute_id refers to a feed
	// attribute of type INT64_LIST.
	IntegerValues []*wrappers.Int64Value `protobuf:"bytes,7,rep,name=integer_values,json=integerValues,proto3" json:"integer_values,omitempty"`
	// Repeated bool value. Should be set if feed_attribute_id refers to a feed
	// attribute of type BOOLEAN_LIST.
	BooleanValues []*wrappers.BoolValue `protobuf:"bytes,8,rep,name=boolean_values,json=booleanValues,proto3" json:"boolean_values,omitempty"`
	// Repeated string value. Should be set if feed_attribute_id refers to a feed
	// attribute of type STRING_LIST, URL_LIST or DATE_TIME_LIST.
	// For STRING_LIST and URL_LIST the total size of the list in bytes may not
	// exceed 3000. For DATE_TIME_LIST the number of elements may not exceed 200.
	//
	// For STRING_LIST the maximum length of each string element is 1500
	// characters. For URL_LIST the maximum length is 2076 characters. For
	// DATE_TIME the format of the string must be the same as start and end time
	// for the feed item.
	StringValues []*wrappers.StringValue `protobuf:"bytes,9,rep,name=string_values,json=stringValues,proto3" json:"string_values,omitempty"`
	// Repeated double value. Should be set if feed_attribute_id refers to a feed
	// attribute of type DOUBLE_LIST.
	DoubleValues         []*wrappers.DoubleValue `protobuf:"bytes,10,rep,name=double_values,json=doubleValues,proto3" json:"double_values,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *FeedItemAttributeValue) Reset()         { *m = FeedItemAttributeValue{} }
func (m *FeedItemAttributeValue) String() string { return proto.CompactTextString(m) }
func (*FeedItemAttributeValue) ProtoMessage()    {}
func (*FeedItemAttributeValue) Descriptor() ([]byte, []int) {
	return fileDescriptor_feed_item_1965a7177a1e850a, []int{1}
}
func (m *FeedItemAttributeValue) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FeedItemAttributeValue.Unmarshal(m, b)
}
func (m *FeedItemAttributeValue) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FeedItemAttributeValue.Marshal(b, m, deterministic)
}
func (dst *FeedItemAttributeValue) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FeedItemAttributeValue.Merge(dst, src)
}
func (m *FeedItemAttributeValue) XXX_Size() int {
	return xxx_messageInfo_FeedItemAttributeValue.Size(m)
}
func (m *FeedItemAttributeValue) XXX_DiscardUnknown() {
	xxx_messageInfo_FeedItemAttributeValue.DiscardUnknown(m)
}

var xxx_messageInfo_FeedItemAttributeValue proto.InternalMessageInfo

func (m *FeedItemAttributeValue) GetFeedAttributeId() *wrappers.Int64Value {
	if m != nil {
		return m.FeedAttributeId
	}
	return nil
}

func (m *FeedItemAttributeValue) GetIntegerValue() *wrappers.Int64Value {
	if m != nil {
		return m.IntegerValue
	}
	return nil
}

func (m *FeedItemAttributeValue) GetBooleanValue() *wrappers.BoolValue {
	if m != nil {
		return m.BooleanValue
	}
	return nil
}

func (m *FeedItemAttributeValue) GetStringValue() *wrappers.StringValue {
	if m != nil {
		return m.StringValue
	}
	return nil
}

func (m *FeedItemAttributeValue) GetDoubleValue() *wrappers.DoubleValue {
	if m != nil {
		return m.DoubleValue
	}
	return nil
}

func (m *FeedItemAttributeValue) GetPriceValue() *common.Money {
	if m != nil {
		return m.PriceValue
	}
	return nil
}

func (m *FeedItemAttributeValue) GetIntegerValues() []*wrappers.Int64Value {
	if m != nil {
		return m.IntegerValues
	}
	return nil
}

func (m *FeedItemAttributeValue) GetBooleanValues() []*wrappers.BoolValue {
	if m != nil {
		return m.BooleanValues
	}
	return nil
}

func (m *FeedItemAttributeValue) GetStringValues() []*wrappers.StringValue {
	if m != nil {
		return m.StringValues
	}
	return nil
}

func (m *FeedItemAttributeValue) GetDoubleValues() []*wrappers.DoubleValue {
	if m != nil {
		return m.DoubleValues
	}
	return nil
}

// Policy, validation, and quality approval info for a feed item for the
// specified placeholder type.
type FeedItemPlaceholderPolicyInfo struct {
	// The placeholder type.
	PlaceholderType *wrappers.Int32Value `protobuf:"bytes,1,opt,name=placeholder_type,json=placeholderType,proto3" json:"placeholder_type,omitempty"`
	// The FeedMapping that contains the placeholder type.
	FeedMappingResourceName *wrappers.StringValue `protobuf:"bytes,2,opt,name=feed_mapping_resource_name,json=feedMappingResourceName,proto3" json:"feed_mapping_resource_name,omitempty"`
	// Where the placeholder type is in the review process.
	ReviewStatus enums.PolicyReviewStatusEnum_PolicyReviewStatus `protobuf:"varint,3,opt,name=review_status,json=reviewStatus,proto3,enum=google.ads.googleads.v1.enums.PolicyReviewStatusEnum_PolicyReviewStatus" json:"review_status,omitempty"`
	// The overall approval status of the placeholder type, calculated based on
	// the status of its individual policy topic entries.
	ApprovalStatus enums.PolicyApprovalStatusEnum_PolicyApprovalStatus `protobuf:"varint,4,opt,name=approval_status,json=approvalStatus,proto3,enum=google.ads.googleads.v1.enums.PolicyApprovalStatusEnum_PolicyApprovalStatus" json:"approval_status,omitempty"`
	// The list of policy findings for the placeholder type.
	PolicyTopicEntries []*common.PolicyTopicEntry `protobuf:"bytes,5,rep,name=policy_topic_entries,json=policyTopicEntries,proto3" json:"policy_topic_entries,omitempty"`
	// The validation status of the palceholder type.
	ValidationStatus enums.FeedItemValidationStatusEnum_FeedItemValidationStatus `protobuf:"varint,6,opt,name=validation_status,json=validationStatus,proto3,enum=google.ads.googleads.v1.enums.FeedItemValidationStatusEnum_FeedItemValidationStatus" json:"validation_status,omitempty"`
	// List of placeholder type validation errors.
	ValidationErrors []*FeedItemValidationError `protobuf:"bytes,7,rep,name=validation_errors,json=validationErrors,proto3" json:"validation_errors,omitempty"`
	// Placeholder type quality evaluation approval status.
	QualityApprovalStatus enums.FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus `protobuf:"varint,8,opt,name=quality_approval_status,json=qualityApprovalStatus,proto3,enum=google.ads.googleads.v1.enums.FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus" json:"quality_approval_status,omitempty"`
	// List of placeholder type quality evaluation disapproval reasons.
	QualityDisapprovalReasons []enums.FeedItemQualityDisapprovalReasonEnum_FeedItemQualityDisapprovalReason `protobuf:"varint,9,rep,packed,name=quality_disapproval_reasons,json=qualityDisapprovalReasons,proto3,enum=google.ads.googleads.v1.enums.FeedItemQualityDisapprovalReasonEnum_FeedItemQualityDisapprovalReason" json:"quality_disapproval_reasons,omitempty"`
	XXX_NoUnkeyedLiteral      struct{}                                                                      `json:"-"`
	XXX_unrecognized          []byte                                                                        `json:"-"`
	XXX_sizecache             int32                                                                         `json:"-"`
}

func (m *FeedItemPlaceholderPolicyInfo) Reset()         { *m = FeedItemPlaceholderPolicyInfo{} }
func (m *FeedItemPlaceholderPolicyInfo) String() string { return proto.CompactTextString(m) }
func (*FeedItemPlaceholderPolicyInfo) ProtoMessage()    {}
func (*FeedItemPlaceholderPolicyInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_feed_item_1965a7177a1e850a, []int{2}
}
func (m *FeedItemPlaceholderPolicyInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FeedItemPlaceholderPolicyInfo.Unmarshal(m, b)
}
func (m *FeedItemPlaceholderPolicyInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FeedItemPlaceholderPolicyInfo.Marshal(b, m, deterministic)
}
func (dst *FeedItemPlaceholderPolicyInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FeedItemPlaceholderPolicyInfo.Merge(dst, src)
}
func (m *FeedItemPlaceholderPolicyInfo) XXX_Size() int {
	return xxx_messageInfo_FeedItemPlaceholderPolicyInfo.Size(m)
}
func (m *FeedItemPlaceholderPolicyInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_FeedItemPlaceholderPolicyInfo.DiscardUnknown(m)
}

var xxx_messageInfo_FeedItemPlaceholderPolicyInfo proto.InternalMessageInfo

func (m *FeedItemPlaceholderPolicyInfo) GetPlaceholderType() *wrappers.Int32Value {
	if m != nil {
		return m.PlaceholderType
	}
	return nil
}

func (m *FeedItemPlaceholderPolicyInfo) GetFeedMappingResourceName() *wrappers.StringValue {
	if m != nil {
		return m.FeedMappingResourceName
	}
	return nil
}

func (m *FeedItemPlaceholderPolicyInfo) GetReviewStatus() enums.PolicyReviewStatusEnum_PolicyReviewStatus {
	if m != nil {
		return m.ReviewStatus
	}
	return enums.PolicyReviewStatusEnum_UNSPECIFIED
}

func (m *FeedItemPlaceholderPolicyInfo) GetApprovalStatus() enums.PolicyApprovalStatusEnum_PolicyApprovalStatus {
	if m != nil {
		return m.ApprovalStatus
	}
	return enums.PolicyApprovalStatusEnum_UNSPECIFIED
}

func (m *FeedItemPlaceholderPolicyInfo) GetPolicyTopicEntries() []*common.PolicyTopicEntry {
	if m != nil {
		return m.PolicyTopicEntries
	}
	return nil
}

func (m *FeedItemPlaceholderPolicyInfo) GetValidationStatus() enums.FeedItemValidationStatusEnum_FeedItemValidationStatus {
	if m != nil {
		return m.ValidationStatus
	}
	return enums.FeedItemValidationStatusEnum_UNSPECIFIED
}

func (m *FeedItemPlaceholderPolicyInfo) GetValidationErrors() []*FeedItemValidationError {
	if m != nil {
		return m.ValidationErrors
	}
	return nil
}

func (m *FeedItemPlaceholderPolicyInfo) GetQualityApprovalStatus() enums.FeedItemQualityApprovalStatusEnum_FeedItemQualityApprovalStatus {
	if m != nil {
		return m.QualityApprovalStatus
	}
	return enums.FeedItemQualityApprovalStatusEnum_UNSPECIFIED
}

func (m *FeedItemPlaceholderPolicyInfo) GetQualityDisapprovalReasons() []enums.FeedItemQualityDisapprovalReasonEnum_FeedItemQualityDisapprovalReason {
	if m != nil {
		return m.QualityDisapprovalReasons
	}
	return nil
}

// Stores a validation error and the set of offending feed attributes which
// together are responsible for causing a feed item validation error.
type FeedItemValidationError struct {
	// Error code indicating what validation error was triggered. The description
	// of the error can be found in the 'description' field.
	ValidationError errors.FeedItemValidationErrorEnum_FeedItemValidationError `protobuf:"varint,1,opt,name=validation_error,json=validationError,proto3,enum=google.ads.googleads.v1.errors.FeedItemValidationErrorEnum_FeedItemValidationError" json:"validation_error,omitempty"`
	// The description of the validation error.
	Description *wrappers.StringValue `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	// Set of feed attributes in the feed item flagged during validation. If
	// empty, no specific feed attributes can be associated with the error
	// (e.g. error across the entire feed item).
	FeedAttributeIds []*wrappers.Int64Value `protobuf:"bytes,3,rep,name=feed_attribute_ids,json=feedAttributeIds,proto3" json:"feed_attribute_ids,omitempty"`
	// Any extra information related to this error which is not captured by
	// validation_error and feed_attribute_id (e.g. placeholder field IDs when
	// feed_attribute_id is not mapped). Note that extra_info is not localized.
	ExtraInfo            *wrappers.StringValue `protobuf:"bytes,5,opt,name=extra_info,json=extraInfo,proto3" json:"extra_info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *FeedItemValidationError) Reset()         { *m = FeedItemValidationError{} }
func (m *FeedItemValidationError) String() string { return proto.CompactTextString(m) }
func (*FeedItemValidationError) ProtoMessage()    {}
func (*FeedItemValidationError) Descriptor() ([]byte, []int) {
	return fileDescriptor_feed_item_1965a7177a1e850a, []int{3}
}
func (m *FeedItemValidationError) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FeedItemValidationError.Unmarshal(m, b)
}
func (m *FeedItemValidationError) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FeedItemValidationError.Marshal(b, m, deterministic)
}
func (dst *FeedItemValidationError) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FeedItemValidationError.Merge(dst, src)
}
func (m *FeedItemValidationError) XXX_Size() int {
	return xxx_messageInfo_FeedItemValidationError.Size(m)
}
func (m *FeedItemValidationError) XXX_DiscardUnknown() {
	xxx_messageInfo_FeedItemValidationError.DiscardUnknown(m)
}

var xxx_messageInfo_FeedItemValidationError proto.InternalMessageInfo

func (m *FeedItemValidationError) GetValidationError() errors.FeedItemValidationErrorEnum_FeedItemValidationError {
	if m != nil {
		return m.ValidationError
	}
	return errors.FeedItemValidationErrorEnum_UNSPECIFIED
}

func (m *FeedItemValidationError) GetDescription() *wrappers.StringValue {
	if m != nil {
		return m.Description
	}
	return nil
}

func (m *FeedItemValidationError) GetFeedAttributeIds() []*wrappers.Int64Value {
	if m != nil {
		return m.FeedAttributeIds
	}
	return nil
}

func (m *FeedItemValidationError) GetExtraInfo() *wrappers.StringValue {
	if m != nil {
		return m.ExtraInfo
	}
	return nil
}

func init() {
	proto.RegisterType((*FeedItem)(nil), "google.ads.googleads.v1.resources.FeedItem")
	proto.RegisterType((*FeedItemAttributeValue)(nil), "google.ads.googleads.v1.resources.FeedItemAttributeValue")
	proto.RegisterType((*FeedItemPlaceholderPolicyInfo)(nil), "google.ads.googleads.v1.resources.FeedItemPlaceholderPolicyInfo")
	proto.RegisterType((*FeedItemValidationError)(nil), "google.ads.googleads.v1.resources.FeedItemValidationError")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/resources/feed_item.proto", fileDescriptor_feed_item_1965a7177a1e850a)
}

var fileDescriptor_feed_item_1965a7177a1e850a = []byte{
	// 1213 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x57, 0xdb, 0x6e, 0xdc, 0x44,
	0x18, 0xd6, 0x6e, 0xda, 0x34, 0x99, 0x3d, 0x24, 0x1d, 0x28, 0x71, 0xd3, 0x82, 0xd2, 0xa0, 0x48,
	0x91, 0x2a, 0x79, 0xb3, 0xdb, 0x82, 0x60, 0x2b, 0x68, 0x36, 0xe4, 0xd0, 0x20, 0x8a, 0x82, 0x13,
	0x45, 0x80, 0x22, 0xac, 0x59, 0x7b, 0x62, 0x46, 0xb2, 0x3d, 0xce, 0xcc, 0x78, 0xcb, 0xde, 0x20,
	0xf1, 0x02, 0x5c, 0xf2, 0x00, 0x88, 0x2b, 0xee, 0xb8, 0x44, 0xbc, 0x01, 0x6f, 0xc1, 0x2d, 0x8f,
	0xc0, 0x15, 0xf2, 0xcc, 0xd8, 0xeb, 0x3d, 0x78, 0xd7, 0xb9, 0x1b, 0xcf, 0xfc, 0xdf, 0xf7, 0x1f,
	0xe6, 0x3f, 0x8c, 0x41, 0xdb, 0xa3, 0xd4, 0xf3, 0x71, 0x0b, 0xb9, 0xbc, 0xa5, 0x96, 0xc9, 0x6a,
	0xd0, 0x6e, 0x31, 0xcc, 0x69, 0xcc, 0x1c, 0xcc, 0x5b, 0xd7, 0x18, 0xbb, 0x36, 0x11, 0x38, 0x30,
	0x23, 0x46, 0x05, 0x85, 0x4f, 0x94, 0x9c, 0x89, 0x5c, 0x6e, 0x66, 0x10, 0x73, 0xd0, 0x36, 0x33,
	0xc8, 0xe6, 0x07, 0x45, 0xac, 0x0e, 0x0d, 0x02, 0x1a, 0xb6, 0x9c, 0x98, 0x0b, 0x1a, 0xd8, 0x11,
	0x62, 0x28, 0xc0, 0x02, 0x33, 0xc5, 0xbc, 0xb9, 0xb7, 0x00, 0x26, 0x2d, 0x51, 0x6b, 0x8d, 0x78,
	0xba, 0x00, 0x11, 0x51, 0x9f, 0x38, 0x43, 0x2d, 0x7c, 0x54, 0x24, 0x8c, 0xc3, 0x38, 0xc8, 0xf9,
	0x69, 0xdf, 0xc4, 0xc8, 0x27, 0x62, 0x68, 0xa3, 0x28, 0x62, 0x74, 0x80, 0x7c, 0x9b, 0x0b, 0x24,
	0x62, 0xae, 0x69, 0x5e, 0xdd, 0x96, 0xc6, 0x25, 0x3c, 0x63, 0x62, 0x18, 0xf1, 0xcc, 0xfa, 0xe7,
	0x65, 0x99, 0xc6, 0xf4, 0xbf, 0x2c, 0x8b, 0x1a, 0x20, 0x9f, 0xb8, 0x48, 0x10, 0x1a, 0x8e, 0x13,
	0x7c, 0x32, 0x9f, 0xc0, 0xc3, 0xd4, 0x16, 0x88, 0x79, 0x58, 0x90, 0xd0, 0xb3, 0x19, 0xe6, 0x82,
	0x11, 0x27, 0x61, 0xd1, 0xf0, 0xee, 0x7c, 0xb8, 0x0a, 0x79, 0x41, 0xec, 0x3e, 0x2a, 0x85, 0x65,
	0x78, 0x40, 0xf0, 0x9b, 0xb2, 0x5e, 0x33, 0x46, 0x59, 0x81, 0xdb, 0xf2, 0x4c, 0x13, 0xbc, 0xa7,
	0x09, 0xe4, 0x57, 0x3f, 0xbe, 0x6e, 0xbd, 0x61, 0x28, 0x8a, 0x30, 0x4b, 0x15, 0x3c, 0x4e, 0x15,
	0x44, 0xa4, 0x85, 0xc2, 0x90, 0x0a, 0x49, 0xa1, 0x4f, 0xb7, 0xff, 0x58, 0x06, 0x2b, 0xc7, 0x18,
	0xbb, 0xa7, 0x02, 0x07, 0xf0, 0x7d, 0xd0, 0x48, 0x73, 0xdd, 0x0e, 0x51, 0x80, 0x8d, 0xca, 0x56,
	0x65, 0x77, 0xd5, 0xaa, 0xa7, 0x9b, 0x5f, 0xa2, 0x00, 0xc3, 0x3d, 0x70, 0x27, 0xb1, 0xc9, 0xa8,
	0x6e, 0x55, 0x76, 0x6b, 0x9d, 0xc7, 0xba, 0x54, 0xcc, 0x54, 0xbd, 0x79, 0x2e, 0x18, 0x09, 0xbd,
	0x4b, 0xe4, 0xc7, 0xd8, 0x92, 0x92, 0xf0, 0x29, 0xa8, 0x12, 0xd7, 0x58, 0x92, 0xf2, 0x8f, 0xa6,
	0xe4, 0x4f, 0x43, 0xf1, 0xe1, 0x73, 0x25, 0x5e, 0x25, 0x2e, 0x3c, 0x04, 0x6b, 0x5c, 0x20, 0x26,
	0x6c, 0x17, 0x09, 0x6c, 0x0b, 0x12, 0x60, 0xe3, 0x4e, 0x09, 0x4d, 0x0d, 0x09, 0x3a, 0x44, 0x02,
	0x5f, 0x90, 0x00, 0xc3, 0x7d, 0xd0, 0xc0, 0xa1, 0x9b, 0xe3, 0xb8, 0x5b, 0x82, 0xa3, 0x86, 0x43,
	0x37, 0x63, 0x70, 0xc1, 0x3a, 0x12, 0x82, 0x91, 0x7e, 0x2c, 0x70, 0x12, 0xfa, 0x18, 0x73, 0x63,
	0x79, 0x6b, 0x69, 0xb7, 0xd6, 0xf9, 0xd8, 0x5c, 0xd8, 0x28, 0xcc, 0x34, 0xa4, 0xbd, 0x94, 0x42,
	0x69, 0x58, 0x43, 0x63, 0xdf, 0x1c, 0xfe, 0x5c, 0x01, 0x0f, 0x0b, 0xf3, 0xd2, 0xb8, 0xb7, 0x55,
	0xd9, 0x6d, 0x76, 0xac, 0x42, 0x7d, 0x32, 0xb9, 0xcc, 0x13, 0x4c, 0x2f, 0x52, 0xb8, 0x35, 0x42,
	0x1f, 0x85, 0x71, 0x50, 0x74, 0x66, 0x6d, 0x78, 0xb3, 0x0f, 0xa0, 0x03, 0x1e, 0xc4, 0xcc, 0xb7,
	0x27, 0x1b, 0x19, 0x37, 0x56, 0xa4, 0xef, 0xad, 0x42, 0x5b, 0x74, 0xfb, 0xfa, 0x4c, 0x02, 0xcf,
	0x52, 0x9c, 0xf5, 0x56, 0xcc, 0xfc, 0x89, 0x3d, 0x0e, 0xbf, 0x06, 0xcb, 0xaa, 0x06, 0x8c, 0x55,
	0xe9, 0xe1, 0xfe, 0x02, 0x0f, 0xd3, 0x68, 0x9e, 0x4b, 0x90, 0x74, 0x6c, 0x7c, 0xcb, 0xd2, 0x7c,
	0xd0, 0x01, 0x75, 0x5d, 0x6b, 0x24, 0xbc, 0xa6, 0xdc, 0x00, 0xd2, 0xea, 0xfd, 0x5b, 0xdc, 0xd8,
	0x99, 0x8f, 0x1c, 0xfc, 0x3d, 0xf5, 0x5d, 0xcc, 0xce, 0x24, 0xd3, 0x69, 0x78, 0x4d, 0xad, 0x5a,
	0x94, 0xad, 0xf9, 0xf6, 0x5f, 0x77, 0xc1, 0x3b, 0xb3, 0x2f, 0x18, 0x9e, 0x80, 0xfb, 0xb2, 0x60,
	0x47, 0xa9, 0x43, 0x5c, 0x59, 0x45, 0x0b, 0x32, 0x7f, 0x2d, 0x41, 0x65, 0x5c, 0xa7, 0x6e, 0x92,
	0xc0, 0x24, 0x14, 0xd8, 0xc3, 0x4c, 0x25, 0x9f, 0x2e, 0xb7, 0xb9, 0x24, 0x75, 0x8d, 0x50, 0xa6,
	0xbc, 0x04, 0x8d, 0x3e, 0xa5, 0x3e, 0x46, 0xa1, 0x66, 0x50, 0x05, 0xb8, 0x39, 0xc5, 0x70, 0x40,
	0xa9, 0xaf, 0x09, 0x34, 0x20, 0x25, 0xa8, 0x73, 0x59, 0x1d, 0x1a, 0x5f, 0xa6, 0x0c, 0x6b, 0x7c,
	0xf4, 0x91, 0x10, 0xb8, 0x34, 0xee, 0xfb, 0xba, 0x7e, 0x0a, 0x6b, 0xf0, 0x50, 0x0a, 0x69, 0x02,
	0x77, 0xf4, 0x01, 0x8f, 0x41, 0x2d, 0x62, 0xc4, 0x49, 0xf1, 0xcb, 0x12, 0xbf, 0xb3, 0x28, 0x05,
	0x5f, 0xd3, 0x10, 0x0f, 0x2d, 0x20, 0x91, 0x8a, 0xe7, 0x00, 0x34, 0xc7, 0x82, 0xc9, 0x8d, 0x7b,
	0x32, 0x2f, 0xe6, 0x46, 0xb3, 0x91, 0x8f, 0x26, 0x87, 0x3d, 0xd0, 0x1c, 0x0b, 0x67, 0x5a, 0x11,
	0xf3, 0xe2, 0xd9, 0xc8, 0xc7, 0x33, 0xa1, 0x68, 0xe4, 0x03, 0x9a, 0x64, 0xff, 0xd2, 0xc2, 0x88,
	0xd6, 0x73, 0x11, 0x95, 0x14, 0xf9, 0x90, 0xa6, 0x09, 0x3e, 0x3f, 0xa6, 0xf5, 0x5c, 0x4c, 0xf9,
	0xf6, 0x9f, 0x2b, 0xe0, 0xdd, 0xb9, 0xc9, 0x0e, 0x8f, 0xc1, 0x7a, 0x34, 0x3a, 0xb0, 0xc5, 0x30,
	0xc2, 0xf3, 0x72, 0xf8, 0x59, 0x47, 0xe7, 0x70, 0x0e, 0x74, 0x31, 0x8c, 0x30, 0xfc, 0x06, 0x6c,
	0xca, 0x62, 0x08, 0x50, 0x14, 0xe9, 0xd6, 0x96, 0x9b, 0x2d, 0x65, 0xe6, 0xc7, 0x46, 0x82, 0x7f,
	0xad, 0xe0, 0x56, 0x7e, 0x08, 0x05, 0xc9, 0xa4, 0xca, 0x0d, 0x53, 0x99, 0xdc, 0xcd, 0xce, 0xab,
	0x05, 0x8d, 0x44, 0x39, 0x69, 0x49, 0x64, 0xae, 0x99, 0x4c, 0x6f, 0x27, 0x33, 0x6f, 0xf4, 0x05,
	0x63, 0xb0, 0x36, 0x31, 0xf7, 0x65, 0x35, 0x34, 0x3b, 0x5f, 0x94, 0x52, 0xd8, 0xd3, 0xd8, 0x29,
	0x95, 0xe3, 0x07, 0x56, 0x13, 0x8d, 0x7d, 0xc3, 0x3e, 0x78, 0x5b, 0x77, 0x33, 0x41, 0x23, 0xe2,
	0xd8, 0x38, 0x14, 0x8c, 0x60, 0x6e, 0xdc, 0x95, 0x97, 0xbe, 0xb7, 0xa8, 0x10, 0x94, 0x8e, 0x8b,
	0x04, 0x7a, 0x14, 0x0a, 0x36, 0xb4, 0x60, 0x34, 0xbe, 0x43, 0x30, 0x87, 0x3f, 0x55, 0xc0, 0xfd,
	0xa9, 0x07, 0x95, 0x2c, 0xb5, 0x66, 0xe7, 0xa2, 0x64, 0x5f, 0xbe, 0xcc, 0xf0, 0x33, 0x3a, 0xf4,
	0xe4, 0xa1, 0xb5, 0x3e, 0x98, 0xd8, 0x81, 0xde, 0x98, 0x09, 0xea, 0xe1, 0xa3, 0x4b, 0xb4, 0x7b,
	0x8b, 0xd6, 0x3d, 0xd2, 0x74, 0x94, 0x50, 0xe4, 0x15, 0xc9, 0x0d, 0x0e, 0x7f, 0xa9, 0x80, 0x8d,
	0x82, 0x47, 0xb0, 0xb1, 0x22, 0x5d, 0xfe, 0xae, 0xa4, 0xcb, 0x5f, 0x29, 0x96, 0x19, 0x37, 0x3b,
	0x57, 0xc2, 0x7a, 0x70, 0x33, 0x6b, 0x1b, 0xfe, 0x56, 0x01, 0x8f, 0x8a, 0x9f, 0xd5, 0xaa, 0x53,
	0x34, 0x3b, 0xee, 0xed, 0x8c, 0x3b, 0x1c, 0x11, 0x59, 0x92, 0x67, 0x96, 0x7d, 0x53, 0x42, 0xd6,
	0xc3, 0x9b, 0x82, 0x13, 0xbe, 0xfd, 0x4f, 0x15, 0x6c, 0x14, 0x44, 0x1b, 0xfe, 0x08, 0xd6, 0x27,
	0x2f, 0x51, 0x76, 0x8d, 0x66, 0xe7, 0xbc, 0xd8, 0x6c, 0x79, 0x2d, 0x45, 0x17, 0x58, 0x90, 0x46,
	0xea, 0x72, 0xd7, 0x26, 0x2e, 0x17, 0x7e, 0x0a, 0x6a, 0x2e, 0xe6, 0x0e, 0x23, 0x91, 0x7c, 0x3b,
	0x95, 0x69, 0x2f, 0x79, 0x00, 0x3c, 0x05, 0x70, 0x6a, 0x74, 0x27, 0x7d, 0x65, 0xe1, 0xa0, 0x58,
	0x9f, 0x98, 0xdd, 0x1c, 0xbe, 0x00, 0x00, 0xff, 0x20, 0x18, 0x92, 0x8f, 0x90, 0x52, 0x4f, 0xcf,
	0x55, 0x29, 0x9f, 0x74, 0xdf, 0x83, 0xff, 0x2a, 0x60, 0xc7, 0xa1, 0xc1, 0xe2, 0xbc, 0x3f, 0x68,
	0x64, 0x6d, 0x3c, 0xa1, 0x3c, 0xab, 0x7c, 0xfb, 0xb9, 0xc6, 0x78, 0xd4, 0x47, 0xa1, 0x67, 0x52,
	0xe6, 0xb5, 0x3c, 0x1c, 0x4a, 0x85, 0xe9, 0xbf, 0x45, 0x44, 0xf8, 0x9c, 0x7f, 0xe2, 0x17, 0xd9,
	0xea, 0xd7, 0xea, 0xd2, 0x49, 0xaf, 0xf7, 0x7b, 0xf5, 0xc9, 0x89, 0xa2, 0xec, 0xb9, 0xdc, 0x54,
	0xcb, 0x64, 0x75, 0xd9, 0x36, 0xd3, 0x76, 0xcc, 0xff, 0x4e, 0x65, 0xae, 0x7a, 0x2e, 0xbf, 0xca,
	0x64, 0xae, 0x2e, 0xdb, 0x57, 0x99, 0xcc, 0xbf, 0xd5, 0x1d, 0x75, 0xd0, 0xed, 0xf6, 0x5c, 0xde,
	0xed, 0x66, 0x52, 0xdd, 0xee, 0x65, 0xbb, 0xdb, 0xcd, 0xe4, 0xfa, 0xcb, 0xd2, 0xd8, 0x67, 0xff,
	0x07, 0x00, 0x00, 0xff, 0xff, 0x79, 0xc5, 0x0d, 0x5c, 0xbf, 0x0f, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/resources/feed_mapping.proto

package resources // import "google.golang.org/genproto/googleapis/ads/googleads/v0/resources"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import wrappers "github.com/golang/protobuf/ptypes/wrappers"
import enums "google.golang.org/genproto/googleapis/ads/googleads/v0/enums"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// A feed mapping.
type FeedMapping struct {
	// The resource name of the feed mapping.
	// Feed mapping resource names have the form:
	//
	// `customers/{customer_id}/feedMappings/{feed_id}_{feed_mapping_id}`
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	// The feed of this feed mapping.
	Feed *wrappers.StringValue `protobuf:"bytes,2,opt,name=feed,proto3" json:"feed,omitempty"`
	// Feed attributes to field mappings. These mappings are a one-to-many
	// relationship meaning that 1 feed attribute can be used to populate
	// multiple placeholder fields, but 1 placeholder field can only draw
	// data from 1 feed attribute. Ad Customizer is an exception, 1 placeholder
	// field can be mapped to multiple feed attributes. Required.
	AttributeFieldMappings []*AttributeFieldMapping `protobuf:"bytes,5,rep,name=attribute_field_mappings,json=attributeFieldMappings,proto3" json:"attribute_field_mappings,omitempty"`
	// Status of the feed mapping.
	// This field is read-only.
	Status enums.FeedMappingStatusEnum_FeedMappingStatus `protobuf:"varint,6,opt,name=status,proto3,enum=google.ads.googleads.v0.enums.FeedMappingStatusEnum_FeedMappingStatus" json:"status,omitempty"`
	// Feed mapping target. Can be either a placeholder or a criterion. For a
	// given feed, the active FeedMappings must have unique targets. Required.
	//
	// Types that are valid to be assigned to Target:
	//	*FeedMapping_PlaceholderType
	//	*FeedMapping_CriterionType
	Target               isFeedMapping_Target `protobuf_oneof:"target"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *FeedMapping) Reset()         { *m = FeedMapping{} }
func (m *FeedMapping) String() string { return proto.CompactTextString(m) }
func (*FeedMapping) ProtoMessage()    {}
func (*FeedMapping) Descriptor() ([]byte, []int) {
	return fileDescriptor_feed_mapping_334515cabe7cdafe, []int{0}
}
func (m *FeedMapping) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FeedMapping.Unmarshal(m, b)
}
func (m *FeedMapping) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FeedMapping.Marshal(b, m, deterministic)
}
func (dst *FeedMapping) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FeedMapping.Merge(dst, src)
}
func (m *FeedMapping) XXX_Size() int {
	return xxx_messageInfo_FeedMapping.Size(m)
}
func (m *FeedMapping) XXX_DiscardUnknown() {
	xxx_messageInfo_FeedMapping.DiscardUnknown(m)
}

var xxx_messageInfo_FeedMapping proto.InternalMessageInfo

func (m *FeedMapping) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *FeedMapping) GetFeed() *wrappers.StringValue {
	if m != nil {
		return m.Feed
	}
	return nil
}

func (m *FeedMapping) GetAttributeFieldMappings() []*AttributeFieldMapping {
	if m != nil {
		return m.AttributeFieldMappings
	}
	return nil
}

func (m *FeedMapping) GetStatus() enums.FeedMappingStatusEnum_FeedMappingStatus {
	if m != nil {
		return m.Status
	}
	return enums.FeedMappingStatusEnum_UNSPECIFIED
}

type isFeedMapping_Target interface {
	isFeedMapping_Target()
}

type FeedMapping_PlaceholderType struct {
	PlaceholderType enums.PlaceholderTypeEnum_PlaceholderType `protobuf:"varint,3,opt,name=placeholder_type,json=placeholderType,proto3,enum=google.ads.googleads.v0.enums.PlaceholderTypeEnum_PlaceholderType,oneof"`
}

type FeedMapping_CriterionType struct {
	CriterionType enums.FeedMappingCriterionTypeEnum_FeedMappingCriterionType `protobuf:"varint,4,opt,name=criterion_type,json=criterionType,proto3,enum=google.ads.googleads.v0.enums.FeedMappingCriterionTypeEnum_FeedMappingCriterionType,oneof"`
}

func (*FeedMapping_PlaceholderType) isFeedMapping_Target() {}

func (*FeedMapping_CriterionType) isFeedMapping_Target() {}

func (m *FeedMapping) GetTarget() isFeedMapping_Target {
	if m != nil {
		return m.Target
	}
	return nil
}

func (m *FeedMapping) GetPlaceholderType() enums.PlaceholderTypeEnum_PlaceholderType {
	if x, ok := m.GetTarget().(*FeedMapping_PlaceholderType); ok {
		return x.PlaceholderType
	}
	return enums.PlaceholderTypeEnum_UNSPECIFIED
}

func (m *FeedMapping) GetCriterionType() enums.FeedMappingCriterionTypeEnum_FeedMappingCriterionType {
	if x, ok := m.GetTarget().(*FeedMapping_CriterionType); ok {
		return x.CriterionType
	}
	return enums.FeedMappingCriterionTypeEnum_UNSPECIFIED
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*FeedMapping) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _FeedMapping_OneofMarshaler, _FeedMapping_OneofUnmarshaler, _FeedMapping_OneofSizer, []interface{}{
		(*FeedMapping_PlaceholderType)(nil),
		(*FeedMapping_CriterionType)(nil),
	}
}

func _FeedMapping_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*FeedMapping)
	// target
	switch x := m.Target.(type) {
	case *FeedMapping_PlaceholderType:
		b.EncodeVarint(3<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.PlaceholderType))
	case *FeedMapping_CriterionType:
		b.EncodeVarint(4<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.CriterionType))
	case nil:
	default:
		return fmt.Errorf("FeedMapping.Target has unexpected type %T", x)
	}
	return nil
}

func _FeedMapping_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*FeedMapping)
	switch tag {
	case 3: // target.placeholder_type
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Target = &FeedMapping_PlaceholderType{enums.PlaceholderTypeEnum_PlaceholderType(x)}
		return true, err
	case 4: // target.criterion_type
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Target = &FeedMapping_CriterionType{enums.FeedMappingCriterionTypeEnum_FeedMappingCriterionType(x)}
		return true, err
	default:
		return false, nil
	}
}

func _FeedMapping_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*FeedMapping)
	// target
	switch x := m.Target.(type) {
	case *FeedMapping_PlaceholderType:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.PlaceholderType))
	case *FeedMapping_CriterionType:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.CriterionType))
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// Maps from feed attribute id to a placeholder or criterion field id.
type AttributeFieldMapping struct {
	// Feed attribute from which to map.
	FeedAttributeId *wrappers.Int64Value `protobuf:"bytes,1,opt,name=feed_attribute_id,json=feedAttributeId,proto3" json:"feed_attribute_id,omitempty"`
	// The placeholder field ID. If a placeholder field enum is not published in
	// the current API version, then this field will be populated and the field
	// oneof will be empty.
	// This field is read-only.
	FieldId *wrappers.Int64Value `protobuf:"bytes,2,opt,name=field_id,json=fieldId,proto3" json:"field_id,omitempty"`
	// Placeholder or criterion field to be populated using data from
	// the above feed attribute. Required.
	//
	// Types that are valid to be assigned to Field:
	//	*AttributeFieldMapping_SitelinkField
	//	*AttributeFieldMapping_CallField
	//	*AttributeFieldMapping_AppField
	//	*AttributeFieldMapping_CalloutField
	//	*AttributeFieldMapping_StructuredSnippetField
	//	*AttributeFieldMapping_MessageField
	//	*AttributeFieldMapping_PriceField
	//	*AttributeFieldMapping_PromotionField
	//	*AttributeFieldMapping_AdCustomizerField
	//	*AttributeFieldMapping_EducationField
	//	*AttributeFieldMapping_FlightField
	//	*AttributeFieldMapping_CustomField
	//	*AttributeFieldMapping_HotelField
	//	*AttributeFieldMapping_RealEstateField
	//	*AttributeFieldMapping_TravelField
	//	*AttributeFieldMapping_LocalField
	//	*AttributeFieldMapping_JobField
	Field                isAttributeFieldMapping_Field `protobuf_oneof:"field"`
	XXX_NoUnkeyedLiteral struct{}                      `json:"-"`
	XXX_unrecognized     []byte                        `json:"-"`
	XXX_sizecache        int32                         `json:"-"`
}

func (m *AttributeFieldMapping) Reset()         { *m = AttributeFieldMapping{} }
func (m *AttributeFieldMapping) String() string { return proto.CompactTextString(m) }
func (*AttributeFieldMapping) ProtoMessage()    {}
func (*AttributeFieldMapping) Descriptor() ([]byte, []int) {
	return fileDescriptor_feed_mapping_334515cabe7cdafe, []int{1}
}
func (m *AttributeFieldMapping) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AttributeFieldMapping.Unmarshal(m, b)
}
func (m *AttributeFieldMapping) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AttributeFieldMapping.Marshal(b, m, deterministic)
}
func (dst *AttributeFieldMapping) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AttributeFieldMapping.Merge(dst, src)
}
func (m *AttributeFieldMapping) XXX_Size() int {
	return xxx_messageInfo_AttributeFieldMapping.Size(m)
}
func (m *AttributeFieldMapping) XXX_DiscardUnknown() {
	xxx_messageInfo_AttributeFieldMapping.DiscardUnknown(m)
}

var xxx_messageInfo_AttributeFieldMapping proto.InternalMessageInfo

func (m *AttributeFieldMapping) GetFeedAttributeId() *wrappers.Int64Value {
	if m != nil {
		return m.FeedAttributeId
	}
	return nil
}

func (m *AttributeFieldMapping) GetFieldId() *wrappers.Int64Value {
	if m != nil {
		return m.FieldId
	}
	return nil
}

type isAttributeFieldMapping_Field interface {
	isAttributeFieldMapping_Field()
}

type AttributeFieldMapping_SitelinkField struct {
	SitelinkField enums.SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField `protobuf:"varint,3,opt,name=sitelink_field,json=sitelinkField,proto3,enum=google.ads.googleads.v0.enums.SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField,oneof"`
}

type AttributeFieldMapping_CallField struct {
	CallField enums.CallPlaceholderFieldEnum_CallPlaceholderField `protobuf:"varint,4,opt,name=call_field,json=callField,proto3,enum=google.ads.googleads.v0.enums.CallPlaceholderFieldEnum_CallPlaceholderField,oneof"`
}

type AttributeFieldMapping_AppField struct {
	AppField enums.AppPlaceholderFieldEnum_AppPlaceholderField `protobuf:"varint,5,opt,name=app_field,json=appField,proto3,enum=google.ads.googleads.v0.enums.AppPlaceholderFieldEnum_AppPlaceholderField,oneof"`
}

type AttributeFieldMapping_CalloutField struct {
	CalloutField enums.CalloutPlaceholderFieldEnum_CalloutPlaceholderField `protobuf:"varint,8,opt,name=callout_field,json=calloutField,proto3,enum=google.ads.googleads.v0.enums.CalloutPlaceholderFieldEnum_CalloutPlaceholderField,oneof"`
}

type AttributeFieldMapping_StructuredSnippetField struct {
	StructuredSnippetField enums.StructuredSnippetPlaceholderFieldEnum_StructuredSnippetPlaceholderField `protobuf:"varint,9,opt,name=structured_snippet_field,json=structuredSnippetField,proto3,enum=google.ads.googleads.v0.enums.StructuredSnippetPlaceholderFieldEnum_StructuredSnippetPlaceholderField,oneof"`
}

type AttributeFieldMapping_MessageField struct {
	MessageField enums.MessagePlaceholderFieldEnum_MessagePlaceholderField `protobuf:"varint,10,opt,name=message_field,json=messageField,proto3,enum=google.ads.googleads.v0.enums.MessagePlaceholderFieldEnum_MessagePlaceholderField,oneof"`
}

type AttributeFieldMapping_PriceField struct {
	PriceField enums.PricePlaceholderFieldEnum_PricePlaceholderField `protobuf:"varint,11,opt,name=price_field,json=priceField,proto3,enum=google.ads.googleads.v0.enums.PricePlaceholderFieldEnum_PricePlaceholderField,oneof"`
}

type AttributeFieldMapping_PromotionField struct {
	PromotionField enums.PromotionPlaceholderFieldEnum_PromotionPlaceholderField `protobuf:"varint,12,opt,name=promotion_field,json=promotionField,proto3,enum=google.ads.googleads.v0.enums.PromotionPlaceholderFieldEnum_PromotionPlaceholderField,oneof"`
}

type AttributeFieldMapping_AdCustomizerField struct {
	AdCustomizerField enums.AdCustomizerPlaceholderFieldEnum_AdCustomizerPlaceholderField `protobuf:"varint,13,opt,name=ad_customizer_field,json=adCustomizerField,proto3,enum=google.ads.googleads.v0.enums.AdCustomizerPlaceholderFieldEnum_AdCustomizerPlaceholderField,oneof"`
}

type AttributeFieldMapping_EducationField struct {
	EducationField enums.EducationPlaceholderFieldEnum_EducationPlaceholderField `protobuf:"varint,16,opt,name=education_field,json=educationField,proto3,enum=google.ads.googleads.v0.enums.EducationPlaceholderFieldEnum_EducationPlaceholderField,oneof"`
}

type AttributeFieldMapping_FlightField struct {
	FlightField enums.FlightPlaceholderFieldEnum_FlightPlaceholderField `protobuf:"varint,17,opt,name=flight_field,json=flightField,proto3,enum=google.ads.googleads.v0.enums.FlightPlaceholderFieldEnum_FlightPlaceholderField,oneof"`
}

type AttributeFieldMapping_CustomField struct {
	CustomField enums.CustomPlaceholderFieldEnum_CustomPlaceholderField `protobuf:"varint,18,opt,name=custom_field,json=customField,proto3,enum=google.ads.googleads.v0.enums.CustomPlaceholderFieldEnum_CustomPlaceholderField,oneof"`
}

type AttributeFieldMapping_HotelField struct {
	HotelField enums.HotelPlaceholderFieldEnum_HotelPlaceholderField `protobuf:"varint,19,opt,name=hotel_field,json=hotelField,proto3,enum=google.ads.googleads.v0.enums.HotelPlaceholderFieldEnum_HotelPlaceholderField,oneof"`
}

type AttributeFieldMapping_RealEstateField struct {
	RealEstateField enums.RealEstatePlaceholderFieldEnum_RealEstatePlaceholderField `protobuf:"varint,20,opt,name=real_estate_field,json=realEstateField,proto3,enum=google.ads.googleads.v0.enums.RealEstatePlaceholderFieldEnum_RealEstatePlaceholderField,oneof"`
}

type AttributeFieldMapping_TravelField struct {
	TravelField enums.TravelPlaceholderFieldEnum_TravelPlaceholderField `protobuf:"varint,21,opt,name=travel_field,json=travelField,proto3,enum=google.ads.googleads.v0.enums.TravelPlaceholderFieldEnum_TravelPlaceholderField,oneof"`
}

type AttributeFieldMapping_LocalField struct {
	LocalField enums.LocalPlaceholderFieldEnum_LocalPlaceholderField `protobuf:"varint,22,opt,name=local_field,json=localField,proto3,enum=google.ads.googleads.v0.enums.LocalPlaceholderFieldEnum_LocalPlaceholderField,oneof"`
}

type AttributeFieldMapping_JobField struct {
	JobField enums.JobPlaceholderFieldEnum_JobPlaceholderField `protobuf:"varint,23,opt,name=job_field,json=jobField,proto3,enum=google.ads.googleads.v0.enums.JobPlaceholderFieldEnum_JobPlaceholderField,oneof"`
}

func (*AttributeFieldMapping_SitelinkField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_CallField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_AppField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_CalloutField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_StructuredSnippetField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_MessageField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_PriceField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_PromotionField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_AdCustomizerField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_EducationField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_FlightField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_CustomField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_HotelField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_RealEstateField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_TravelField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_LocalField) isAttributeFieldMapping_Field() {}

func (*AttributeFieldMapping_JobField) isAttributeFieldMapping_Field() {}

func (m *AttributeFieldMapping) GetField() isAttributeFieldMapping_Field {
	if m != nil {
		return m.Field
	}
	return nil
}

func (m *AttributeFieldMapping) GetSitelinkField() enums.SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_SitelinkField); ok {
		return x.SitelinkField
	}
	return enums.SitelinkPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetCallField() enums.CallPlaceholderFieldEnum_CallPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_CallField); ok {
		return x.CallField
	}
	return enums.CallPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetAppField() enums.AppPlaceholderFieldEnum_AppPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_AppField); ok {
		return x.AppField
	}
	return enums.AppPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetCalloutField() enums.CalloutPlaceholderFieldEnum_CalloutPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_CalloutField); ok {
		return x.CalloutField
	}
	return enums.CalloutPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetStructuredSnippetField() enums.StructuredSnippetPlaceholderFieldEnum_StructuredSnippetPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_StructuredSnippetField); ok {
		return x.StructuredSnippetField
	}
	return enums.StructuredSnippetPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetMessageField() enums.MessagePlaceholderFieldEnum_MessagePlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_MessageField); ok {
		return x.MessageField
	}
	return enums.MessagePlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetPriceField() enums.PricePlaceholderFieldEnum_PricePlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_PriceField); ok {
		return x.PriceField
	}
	return enums.PricePlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetPromotionField() enums.PromotionPlaceholderFieldEnum_PromotionPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_PromotionField); ok {
		return x.PromotionField
	}
	return enums.PromotionPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetAdCustomizerField() enums.AdCustomizerPlaceholderFieldEnum_AdCustomizerPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_AdCustomizerField); ok {
		return x.AdCustomizerField
	}
	return enums.AdCustomizerPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetEducationField() enums.EducationPlaceholderFieldEnum_EducationPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_EducationField); ok {
		return x.EducationField
	}
	return enums.EducationPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetFlightField() enums.FlightPlaceholderFieldEnum_FlightPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_FlightField); ok {
		return x.FlightField
	}
	return enums.FlightPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetCustomField() enums.CustomPlaceholderFieldEnum_CustomPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_CustomField); ok {
		return x.CustomField
	}
	return enums.CustomPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetHotelField() enums.HotelPlaceholderFieldEnum_HotelPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_HotelField); ok {
		return x.HotelField
	}
	return enums.HotelPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetRealEstateField() enums.RealEstatePlaceholderFieldEnum_RealEstatePlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_RealEstateField); ok {
		return x.RealEstateField
	}
	return enums.RealEstatePlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetTravelField() enums.TravelPlaceholderFieldEnum_TravelPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_TravelField); ok {
		return x.TravelField
	}
	return enums.TravelPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetLocalField() enums.LocalPlaceholderFieldEnum_LocalPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_LocalField); ok {
		return x.LocalField
	}
	return enums.LocalPlaceholderFieldEnum_UNSPECIFIED
}

func (m *AttributeFieldMapping) GetJobField() enums.JobPlaceholderFieldEnum_JobPlaceholderField {
	if x, ok := m.GetField().(*AttributeFieldMapping_JobField); ok {
		return x.JobField
	}
	return enums.JobPlaceholderFieldEnum_UNSPECIFIED
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*AttributeFieldMapping) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _AttributeFieldMapping_OneofMarshaler, _AttributeFieldMapping_OneofUnmarshaler, _AttributeFieldMapping_OneofSizer, []interface{}{
		(*AttributeFieldMapping_SitelinkField)(nil),
		(*AttributeFieldMapping_CallField)(nil),
		(*AttributeFieldMapping_AppField)(nil),
		(*AttributeFieldMapping_CalloutField)(nil),
		(*AttributeFieldMapping_StructuredSnippetField)(nil),
		(*AttributeFieldMapping_MessageField)(nil),
		(*AttributeFieldMapping_PriceField)(nil),
		(*AttributeFieldMapping_PromotionField)(nil),
		(*AttributeFieldMapping_AdCustomizerField)(nil),
		(*AttributeFieldMapping_EducationField)(nil),
		(*AttributeFieldMapping_FlightField)(nil),
		(*AttributeFieldMapping_CustomField)(nil),
		(*AttributeFieldMapping_HotelField)(nil),
		(*AttributeFieldMapping_RealEstateField)(nil),
		(*AttributeFieldMapping_TravelField)(nil),
		(*AttributeFieldMapping_LocalField)(nil),
		(*AttributeFieldMapping_JobField)(nil),
	}
}

func _AttributeFieldMapping_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*AttributeFieldMapping)
	// field
	switch x := m.Field.(type) {
	case *AttributeFieldMapping_SitelinkField:
		b.EncodeVarint(3<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.SitelinkField))
	case *AttributeFieldMapping_CallField:
		b.EncodeVarint(4<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.CallField))
	case *AttributeFieldMapping_AppField:
		b.EncodeVarint(5<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.AppField))
	case *AttributeFieldMapping_CalloutField:
		b.EncodeVarint(8<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.CalloutField))
	case *AttributeFieldMapping_StructuredSnippetField:
		b.EncodeVarint(9<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.StructuredSnippetField))
	case *AttributeFieldMapping_MessageField:
		b.EncodeVarint(10<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.MessageField))
	case *AttributeFieldMapping_PriceField:
		b.EncodeVarint(11<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.PriceField))
	case *AttributeFieldMapping_PromotionField:
		b.EncodeVarint(12<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.PromotionField))
	case *AttributeFieldMapping_AdCustomizerField:
		b.EncodeVarint(13<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.AdCustomizerField))
	case *AttributeFieldMapping_EducationField:
		b.EncodeVarint(16<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.EducationField))
	case *AttributeFieldMapping_FlightField:
		b.EncodeVarint(17<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.FlightField))
	case *AttributeFieldMapping_CustomField:
		b.EncodeVarint(18<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.CustomField))
	case *AttributeFieldMapping_HotelField:
		b.EncodeVarint(19<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.HotelField))
	case *AttributeFieldMapping_RealEstateField:
		b.EncodeVarint(20<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.RealEstateField))
	case *AttributeFieldMapping_TravelField:
		b.EncodeVarint(21<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.TravelField))
	case *AttributeFieldMapping_LocalField:
		b.EncodeVarint(22<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.LocalField))
	case *AttributeFieldMapping_JobField:
		b.EncodeVarint(23<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.JobField))
	case nil:
	default:
		return fmt.Errorf("AttributeFieldMapping.Field has unexpected type %T", x)
	}
	return nil
}

func _AttributeFieldMapping_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*AttributeFieldMapping)
	switch tag {
	case 3: // field.sitelink_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_SitelinkField{enums.SitelinkPlaceholderFieldEnum_SitelinkPlaceholderField(x)}
		return true, err
	case 4: // field.call_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_CallField{enums.CallPlaceholderFieldEnum_CallPlaceholderField(x)}
		return true, err
	case 5: // field.app_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_AppField{enums.AppPlaceholderFieldEnum_AppPlaceholderField(x)}
		return true, err
	case 8: // field.callout_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_CalloutField{enums.CalloutPlaceholderFieldEnum_CalloutPlaceholderField(x)}
		return true, err
	case 9: // field.structured_snippet_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_StructuredSnippetField{enums.StructuredSnippetPlaceholderFieldEnum_StructuredSnippetPlaceholderField(x)}
		return true, err
	case 10: // field.message_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_MessageField{enums.MessagePlaceholderFieldEnum_MessagePlaceholderField(x)}
		return true, err
	case 11: // field.price_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_PriceField{enums.PricePlaceholderFieldEnum_PricePlaceholderField(x)}
		return true, err
	case 12: // field.promotion_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_PromotionField{enums.PromotionPlaceholderFieldEnum_PromotionPlaceholderField(x)}
		return true, err
	case 13: // field.ad_customizer_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_AdCustomizerField{enums.AdCustomizerPlaceholderFieldEnum_AdCustomizerPlaceholderField(x)}
		return true, err
	case 16: // field.education_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_EducationField{enums.EducationPlaceholderFieldEnum_EducationPlaceholderField(x)}
		return true, err
	case 17: // field.flight_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_FlightField{enums.FlightPlaceholderFieldEnum_FlightPlaceholderField(x)}
		return true, err
	case 18: // field.custom_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_CustomField{enums.CustomPlaceholderFieldEnum_CustomPlaceholderField(x)}
		return true, err
	case 19: // field.hotel_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_HotelField{enums.HotelPlaceholderFieldEnum_HotelPlaceholderField(x)}
		return true, err
	case 20: // field.real_estate_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_RealEstateField{enums.RealEstatePlaceholderFieldEnum_RealEstatePlaceholderField(x)}
		return true, err
	case 21: // field.travel_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_TravelField{enums.TravelPlaceholderFieldEnum_TravelPlaceholderField(x)}
		return true, err
	case 22: // field.local_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_LocalField{enums.LocalPlaceholderFieldEnum_LocalPlaceholderField(x)}
		return true, err
	case 23: // field.job_field
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Field = &AttributeFieldMapping_JobField{enums.JobPlaceholderFieldEnum_JobPlaceholderField(x)}
		return true, err
	default:
		return false, nil
	}
}

func _AttributeFieldMapping_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*AttributeFieldMapping)
	// field
	switch x := m.Field.(type) {
	case *AttributeFieldMapping_SitelinkField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.SitelinkField))
	case *AttributeFieldMapping_CallField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.CallField))
	case *AttributeFieldMapping_AppField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.AppField))
	case *AttributeFieldMapping_CalloutField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.CalloutField))
	case *AttributeFieldMapping_StructuredSnippetField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.StructuredSnippetField))
	case *AttributeFieldMapping_MessageField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.MessageField))
	case *AttributeFieldMapping_PriceField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.PriceField))
	case *AttributeFieldMapping_PromotionField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.PromotionField))
	case *AttributeFieldMapping_AdCustomizerField:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.AdCustomizerField))
	case *AttributeFieldMapping_EducationField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.EducationField))
	case *AttributeFieldMapping_FlightField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.FlightField))
	case *AttributeFieldMapping_CustomField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.CustomField))
	case *AttributeFieldMapping_HotelField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.HotelField))
	case *AttributeFieldMapping_RealEstateField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.RealEstateField))
	case *AttributeFieldMapping_TravelField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.TravelField))
	case *AttributeFieldMapping_LocalField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.LocalField))
	case *AttributeFieldMapping_JobField:
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(x.JobField))
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

func init() {
	proto.RegisterType((*FeedMapping)(nil), "google.ads.googleads.v0.resources.FeedMapping")
	proto.RegisterType((*AttributeFieldMapping)(nil), "google.ads.googleads.v0.resources.AttributeFieldMapping")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/resources/feed_mapping.proto", fileDescriptor_feed_mapping_334515cabe7cdafe)
}

var fileDescriptor_feed_mapping_334515cabe7cdafe = []byte{
	// 1134 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x98, 0xdd, 0x6e, 0xdb, 0x36,
	0x14, 0xc7, 0xed, 0x7c, 0x35, 0xa1, 0xf3, 0xa9, 0xae, 0x99, 0xd1, 0x0d, 0x43, 0xda, 0xa1, 0x40,
	0xae, 0x64, 0x23, 0x0b, 0xba, 0xcd, 0xdd, 0x07, 0x9c, 0x20, 0x89, 0x12, 0xb4, 0x45, 0xa0, 0x04,
	0xc1, 0x30, 0x04, 0x33, 0x68, 0x89, 0x51, 0xd4, 0xc9, 0x22, 0x47, 0x51, 0x19, 0x32, 0x60, 0x17,
	0xbb, 0xd9, 0xe5, 0x1e, 0xa2, 0x97, 0xbb, 0xdc, 0x63, 0xec, 0x29, 0x76, 0xbd, 0x77, 0x18, 0x30,
	0x90, 0x47, 0xa2, 0x9d, 0x94, 0xfa, 0xa8, 0xef, 0x14, 0x1e, 0xfe, 0xcf, 0xef, 0xf0, 0xf0, 0x90,
	0x3c, 0x0e, 0xda, 0x0d, 0x28, 0x0d, 0x22, 0xd2, 0xc1, 0x7e, 0xd2, 0x81, 0x4f, 0xf9, 0x75, 0xd3,
	0xed, 0x70, 0x92, 0xd0, 0x94, 0x7b, 0x24, 0xe9, 0x5c, 0x11, 0xe2, 0x0f, 0x46, 0x98, 0xb1, 0x30,
	0x0e, 0x6c, 0xc6, 0xa9, 0xa0, 0xd6, 0x13, 0x98, 0x6a, 0x63, 0x3f, 0xb1, 0xb5, 0xca, 0xbe, 0xe9,
	0xda, 0x5a, 0xf5, 0x78, 0xbf, 0xc8, 0x31, 0x89, 0xd3, 0x51, 0xd2, 0xc1, 0xfe, 0xc0, 0x4b, 0x13,
	0x41, 0x47, 0xe1, 0x2f, 0x84, 0x0f, 0x58, 0x84, 0x3d, 0x72, 0x4d, 0x23, 0x9f, 0xf0, 0xc1, 0x55,
	0x48, 0x22, 0x1f, 0x38, 0x8f, 0xbf, 0xac, 0x70, 0xc2, 0x58, 0xa1, 0xb4, 0x57, 0x2e, 0xf5, 0x70,
	0x14, 0x15, 0x6a, 0xbf, 0xae, 0xd6, 0xd2, 0x54, 0x14, 0xca, 0xbf, 0xaa, 0x90, 0xab, 0x75, 0x17,
	0xaa, 0xbf, 0x2d, 0x57, 0x13, 0x3f, 0xf5, 0xb0, 0x08, 0x69, 0x3c, 0xad, 0x83, 0xc9, 0xed, 0x1c,
	0x78, 0x3c, 0x14, 0x84, 0x4b, 0x6f, 0xe2, 0x96, 0x91, 0xcc, 0xc1, 0xe7, 0xef, 0xe1, 0x20, 0x11,
	0x58, 0xa4, 0x49, 0xbd, 0x85, 0x5f, 0x45, 0x61, 0x70, 0x5d, 0x9c, 0xb6, 0x17, 0xe5, 0xea, 0x6b,
	0x2a, 0x48, 0x34, 0x6d, 0xa5, 0xbc, 0xa1, 0xc3, 0x69, 0xb9, 0x11, 0xf5, 0xf0, 0xd4, 0xa5, 0x32,
	0x22, 0x49, 0x82, 0x03, 0x52, 0x28, 0xdf, 0x2d, 0x97, 0x4f, 0xca, 0x26, 0x36, 0xa8, 0x22, 0x62,
	0xc6, 0x43, 0x8f, 0x4c, 0x5b, 0x1e, 0x8c, 0xd3, 0x11, 0x2d, 0xad, 0xaf, 0x7e, 0xb9, 0x03, 0x4e,
	0x70, 0x34, 0x20, 0xb2, 0x2e, 0x8a, 0x63, 0xf8, 0xa6, 0xdc, 0x45, 0x12, 0x0a, 0x12, 0x85, 0xf1,
	0x8f, 0x85, 0x7a, 0xa7, 0x42, 0x2f, 0x78, 0xea, 0x89, 0x94, 0x13, 0x7f, 0x90, 0xc4, 0x21, 0x63,
	0x64, 0xea, 0xb3, 0x2a, 0x38, 0xbe, 0x29, 0xa9, 0xba, 0x4f, 0x32, 0xb5, 0xfa, 0x6b, 0x98, 0x5e,
	0x75, 0x7e, 0xe6, 0x98, 0x31, 0xc2, 0xb3, 0x03, 0xf1, 0xf4, 0xaf, 0x39, 0xd4, 0x3a, 0x24, 0xc4,
	0x7f, 0x05, 0xa7, 0xc5, 0xfa, 0x14, 0xad, 0xe4, 0x37, 0xe4, 0x20, 0xc6, 0x23, 0xd2, 0x6e, 0x6e,
	0x35, 0xb7, 0x97, 0xdc, 0xe5, 0x7c, 0xf0, 0x35, 0x1e, 0x11, 0xab, 0x8b, 0xe6, 0xe4, 0x11, 0x6b,
	0xcf, 0x6c, 0x35, 0xb7, 0x5b, 0x3b, 0x1f, 0x67, 0x17, 0xac, 0x9d, 0x33, 0xec, 0x33, 0xc1, 0xc3,
	0x38, 0xb8, 0xc0, 0x51, 0x4a, 0x5c, 0x35, 0xd3, 0xe2, 0xa8, 0x8d, 0x85, 0xe0, 0xe1, 0x30, 0x15,
	0x04, 0xe2, 0xcb, 0xcf, 0x67, 0xd2, 0x9e, 0xdf, 0x9a, 0xdd, 0x6e, 0xed, 0x7c, 0x61, 0x57, 0xde,
	0xd8, 0x76, 0x3f, 0x77, 0x71, 0x28, 0x3d, 0x64, 0x21, 0xbb, 0x9b, 0xd8, 0x34, 0x9c, 0x58, 0x3f,
	0xa0, 0x05, 0x38, 0xfb, 0xed, 0x85, 0xad, 0xe6, 0xf6, 0xea, 0xce, 0x61, 0x21, 0x41, 0x65, 0xd2,
	0x9e, 0x48, 0xc3, 0x99, 0xd2, 0x1d, 0xc4, 0xe9, 0xe8, 0xdd, 0x51, 0x37, 0xf3, 0x6a, 0x51, 0xb4,
	0x7e, 0xbf, 0xfa, 0xdb, 0xb3, 0x8a, 0xb4, 0x57, 0x41, 0x3a, 0x1d, 0xcb, 0xce, 0x6f, 0x19, 0x51,
	0x9c, 0x7b, 0x63, 0x4e, 0xc3, 0x5d, 0x63, 0x77, 0x87, 0xac, 0x5f, 0xd1, 0xea, 0xdd, 0xdb, 0xb0,
	0x3d, 0xa7, 0x70, 0xe7, 0xf5, 0x17, 0xb6, 0x9f, 0xeb, 0x35, 0xb7, 0xc8, 0xe8, 0x34, 0xdc, 0x15,
	0x6f, 0x72, 0x60, 0x6f, 0x11, 0x2d, 0x08, 0xcc, 0x03, 0x22, 0x9e, 0xfe, 0xb3, 0x81, 0x1e, 0x19,
	0xf7, 0xc2, 0x3a, 0x42, 0x1b, 0xea, 0xf2, 0x1d, 0x6f, 0x76, 0xe8, 0xab, 0x12, 0x6a, 0xed, 0x7c,
	0xf4, 0x4e, 0x99, 0x1c, 0xc7, 0xe2, 0xf9, 0x2e, 0x54, 0xc9, 0x9a, 0x54, 0x69, 0x97, 0xc7, 0xbe,
	0xf5, 0x1c, 0x2d, 0x42, 0x99, 0x84, 0x79, 0x99, 0x95, 0xea, 0x1f, 0xa8, 0xc9, 0xc7, 0xbe, 0xcc,
	0x91, 0x3e, 0x9b, 0x6a, 0x2c, 0xdb, 0x92, 0xaa, 0x1c, 0x9d, 0x65, 0xa2, 0x89, 0x6d, 0x50, 0x0b,
	0x53, 0x39, 0x2a, 0x32, 0xca, 0x1c, 0xe5, 0x34, 0x35, 0x60, 0x8d, 0x10, 0x52, 0xef, 0x36, 0xa0,
	0x61, 0x7b, 0x5e, 0x56, 0xa0, 0xf7, 0x71, 0x14, 0x19, 0xb1, 0x26, 0x83, 0xd3, 0x70, 0x97, 0x24,
	0x01, 0x70, 0x21, 0x5a, 0x92, 0x1d, 0x06, 0xd0, 0xe6, 0x15, 0xed, 0xa4, 0x82, 0xd6, 0x67, 0xcc,
	0x08, 0x33, 0x8c, 0x3b, 0x0d, 0x77, 0x11, 0x33, 0x06, 0xa8, 0x5b, 0xb4, 0x92, 0x77, 0x15, 0x80,
	0x5b, 0x54, 0x38, 0xb7, 0xc6, 0xe2, 0x68, 0x2a, 0x0a, 0xd7, 0x67, 0xb0, 0x39, 0x0d, 0x77, 0x39,
	0x43, 0x01, 0xfa, 0x6d, 0x13, 0xb5, 0x0d, 0x17, 0x26, 0x84, 0xb1, 0xa4, 0xc2, 0xb8, 0xaa, 0xda,
	0x5e, 0x2d, 0x3f, 0x03, 0xb5, 0x79, 0x9f, 0xab, 0x66, 0x39, 0x0d, 0x77, 0x33, 0xb9, 0x3f, 0x49,
	0xe7, 0x27, 0x7f, 0x4a, 0x21, 0x30, 0x54, 0x2b, 0x3f, 0xaf, 0x40, 0x63, 0x0c, 0xa7, 0xc0, 0x26,
	0xf3, 0x93, 0xa1, 0x00, 0xfd, 0x13, 0x6a, 0xc1, 0x83, 0x0a, 0xe0, 0x96, 0x02, 0xbf, 0xae, 0xba,
	0x83, 0xa4, 0xc2, 0x88, 0x35, 0x5a, 0x9c, 0x86, 0x8b, 0x14, 0x04, 0x90, 0xbf, 0x35, 0xd1, 0xda,
	0xf8, 0x1d, 0x06, 0xee, 0xb2, 0xe2, 0x5e, 0x54, 0x72, 0x33, 0x55, 0x01, 0xbb, 0xc0, 0xea, 0x34,
	0xdc, 0x55, 0x0d, 0x84, 0x18, 0xfe, 0x68, 0xa2, 0x87, 0x77, 0x9b, 0x74, 0x88, 0x63, 0x45, 0xc5,
	0x71, 0x59, 0x75, 0x0e, 0xfc, 0x7d, 0x2d, 0x34, 0x1f, 0x88, 0x92, 0x09, 0x4e, 0xc3, 0xdd, 0xc0,
	0x13, 0xf6, 0x71, 0x52, 0xc6, 0xcd, 0x2f, 0x04, 0xb3, 0x5e, 0x2b, 0x29, 0x07, 0xb9, 0xca, 0x18,
	0x49, 0xa1, 0x55, 0x26, 0x45, 0x03, 0x21, 0x86, 0x14, 0x2d, 0x67, 0x4d, 0x2c, 0xf0, 0x37, 0x14,
	0xff, 0xb4, 0xea, 0x85, 0x50, 0x12, 0x23, 0xdc, 0x6c, 0x72, 0x1a, 0x6e, 0x0b, 0x38, 0x1a, 0x9b,
	0xfd, 0x68, 0x00, 0xac, 0x55, 0x0b, 0x0b, 0x09, 0x34, 0xdf, 0x0d, 0x46, 0x93, 0xc4, 0x02, 0x47,
	0x57, 0x3e, 0x34, 0xdd, 0x40, 0x7d, 0x58, 0xab, 0xf2, 0x1d, 0xa9, 0x30, 0x42, 0x8d, 0x16, 0x59,
	0xf9, 0x0a, 0x02, 0xc8, 0xdf, 0x9b, 0x68, 0x63, 0xb2, 0x81, 0x04, 0xf2, 0x07, 0x8a, 0xfc, 0x5d,
	0x05, 0xd9, 0x25, 0x38, 0x3a, 0x50, 0x32, 0x23, 0xbe, 0xd8, 0x2c, 0xbb, 0x01, 0xae, 0xad, 0x3a,
	0xe5, 0x59, 0xef, 0x07, 0x21, 0x3c, 0xaa, 0x95, 0xf2, 0x73, 0x25, 0x31, 0xe2, 0xcd, 0x26, 0x99,
	0x72, 0xe0, 0xe8, 0x94, 0xc3, 0xef, 0x0d, 0xa0, 0x6e, 0xd6, 0x4a, 0xf9, 0x4b, 0xa9, 0x30, 0x42,
	0x8d, 0x16, 0x99, 0x72, 0x05, 0xd1, 0xaf, 0x9c, 0xfc, 0x75, 0x04, 0xc0, 0x0f, 0x6b, 0xbd, 0x72,
	0x27, 0x74, 0x68, 0xc4, 0x19, 0xc6, 0xe5, 0x2b, 0xf7, 0x86, 0x0e, 0xd5, 0xf7, 0xde, 0x03, 0x34,
	0xaf, 0x30, 0x7b, 0xff, 0x35, 0xd1, 0x33, 0x8f, 0x8e, 0xaa, 0x9b, 0xd2, 0xbd, 0xf5, 0x89, 0x0e,
	0xea, 0x54, 0xb6, 0x26, 0xa7, 0xcd, 0xef, 0x4f, 0x32, 0x59, 0x40, 0x23, 0x1c, 0x07, 0x36, 0xe5,
	0x41, 0x27, 0x20, 0xb1, 0x6a, 0x5c, 0xf2, 0x1e, 0x9e, 0x85, 0x49, 0xc9, 0xbf, 0x34, 0x5e, 0xe8,
	0xaf, 0xb7, 0x33, 0xb3, 0x47, 0xfd, 0xfe, 0x9f, 0x33, 0x4f, 0x8e, 0xc0, 0x65, 0xdf, 0x4f, 0x6c,
	0xf8, 0x94, 0x5f, 0x17, 0x5d, 0xdb, 0xcd, 0x67, 0xfe, 0x9d, 0xcf, 0xb9, 0xec, 0xfb, 0xc9, 0xa5,
	0x9e, 0x73, 0x79, 0xd1, 0xbd, 0xd4, 0x73, 0xfe, 0x9d, 0x79, 0x06, 0x86, 0x5e, 0xaf, 0xef, 0x27,
	0xbd, 0x9e, 0x9e, 0xd5, 0xeb, 0x5d, 0x74, 0x7b, 0x3d, 0x3d, 0x6f, 0xb8, 0xa0, 0x82, 0xfd, 0xec,
	0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x36, 0x06, 0xda, 0xba, 0x7e, 0x11, 0x00, 0x00,
}

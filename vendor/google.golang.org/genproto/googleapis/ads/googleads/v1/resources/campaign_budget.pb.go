// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/resources/campaign_budget.proto

package resources // import "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"

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

// A campaign budget.
type CampaignBudget struct {
	// The resource name of the campaign budget.
	// Campaign budget resource names have the form:
	//
	// `customers/{customer_id}/campaignBudgets/{budget_id}`
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	// The ID of the campaign budget.
	//
	// A campaign budget is created using the CampaignBudgetService create
	// operation and is assigned a budget ID. A budget ID can be shared across
	// different campaigns; the system will then allocate the campaign budget
	// among different campaigns to get optimum results.
	Id *wrappers.Int64Value `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
	// The name of the campaign budget.
	//
	// When creating a campaign budget through CampaignBudgetService, every
	// explicitly shared campaign budget must have a non-null, non-empty name.
	// Campaign budgets that are not explicitly shared derive their name from the
	// attached campaign's name.
	//
	// The length of this string must be between 1 and 255, inclusive,
	// in UTF-8 bytes, (trimmed).
	Name *wrappers.StringValue `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	// The amount of the budget, in the local currency for the account.
	// Amount is specified in micros, where one million is equivalent to one
	// currency unit.
	AmountMicros *wrappers.Int64Value `protobuf:"bytes,5,opt,name=amount_micros,json=amountMicros,proto3" json:"amount_micros,omitempty"`
	// The lifetime amount of the budget, in the local currency for the account.
	// Amount is specified in micros, where one million is equivalent to one
	// currency unit.
	TotalAmountMicros *wrappers.Int64Value `protobuf:"bytes,10,opt,name=total_amount_micros,json=totalAmountMicros,proto3" json:"total_amount_micros,omitempty"`
	// The status of this campaign budget. This field is read-only.
	Status enums.BudgetStatusEnum_BudgetStatus `protobuf:"varint,6,opt,name=status,proto3,enum=google.ads.googleads.v1.enums.BudgetStatusEnum_BudgetStatus" json:"status,omitempty"`
	// The delivery method that determines the rate at which the campaign budget
	// is spent.
	//
	// Defaults to STANDARD if unspecified in a create operation.
	DeliveryMethod enums.BudgetDeliveryMethodEnum_BudgetDeliveryMethod `protobuf:"varint,7,opt,name=delivery_method,json=deliveryMethod,proto3,enum=google.ads.googleads.v1.enums.BudgetDeliveryMethodEnum_BudgetDeliveryMethod" json:"delivery_method,omitempty"`
	// Specifies whether the budget is explicitly shared. Defaults to true if
	// unspecified in a create operation.
	//
	// If true, the budget was created with the purpose of sharing
	// across one or more campaigns.
	//
	// If false, the budget was created with the intention of only being used
	// with a single campaign. The budget's name and status will stay in sync
	// with the campaign's name and status. Attempting to share the budget with a
	// second campaign will result in an error.
	//
	// A non-shared budget can become an explicitly shared. The same operation
	// must also assign the budget a name.
	//
	// A shared campaign budget can never become non-shared.
	ExplicitlyShared *wrappers.BoolValue `protobuf:"bytes,8,opt,name=explicitly_shared,json=explicitlyShared,proto3" json:"explicitly_shared,omitempty"`
	// The number of campaigns actively using the budget.
	//
	// This field is read-only.
	ReferenceCount *wrappers.Int64Value `protobuf:"bytes,9,opt,name=reference_count,json=referenceCount,proto3" json:"reference_count,omitempty"`
	// Indicates whether there is a recommended budget for this campaign budget.
	//
	// This field is read-only.
	HasRecommendedBudget *wrappers.BoolValue `protobuf:"bytes,11,opt,name=has_recommended_budget,json=hasRecommendedBudget,proto3" json:"has_recommended_budget,omitempty"`
	// The recommended budget amount. If no recommendation is available, this will
	// be set to the budget amount.
	// Amount is specified in micros, where one million is equivalent to one
	// currency unit.
	//
	// This field is read-only.
	RecommendedBudgetAmountMicros *wrappers.Int64Value `protobuf:"bytes,12,opt,name=recommended_budget_amount_micros,json=recommendedBudgetAmountMicros,proto3" json:"recommended_budget_amount_micros,omitempty"`
	// Period over which to spend the budget. Defaults to DAILY if not specified.
	Period enums.BudgetPeriodEnum_BudgetPeriod `protobuf:"varint,13,opt,name=period,proto3,enum=google.ads.googleads.v1.enums.BudgetPeriodEnum_BudgetPeriod" json:"period,omitempty"`
	// The estimated change in weekly clicks if the recommended budget is applied.
	//
	// This field is read-only.
	RecommendedBudgetEstimatedChangeWeeklyClicks *wrappers.Int64Value `protobuf:"bytes,14,opt,name=recommended_budget_estimated_change_weekly_clicks,json=recommendedBudgetEstimatedChangeWeeklyClicks,proto3" json:"recommended_budget_estimated_change_weekly_clicks,omitempty"`
	// The estimated change in weekly cost in micros if the recommended budget is
	// applied. One million is equivalent to one currency unit.
	//
	// This field is read-only.
	RecommendedBudgetEstimatedChangeWeeklyCostMicros *wrappers.Int64Value `protobuf:"bytes,15,opt,name=recommended_budget_estimated_change_weekly_cost_micros,json=recommendedBudgetEstimatedChangeWeeklyCostMicros,proto3" json:"recommended_budget_estimated_change_weekly_cost_micros,omitempty"`
	// The estimated change in weekly interactions if the recommended budget is
	// applied.
	//
	// This field is read-only.
	RecommendedBudgetEstimatedChangeWeeklyInteractions *wrappers.Int64Value `protobuf:"bytes,16,opt,name=recommended_budget_estimated_change_weekly_interactions,json=recommendedBudgetEstimatedChangeWeeklyInteractions,proto3" json:"recommended_budget_estimated_change_weekly_interactions,omitempty"`
	// The estimated change in weekly views if the recommended budget is applied.
	//
	// This field is read-only.
	RecommendedBudgetEstimatedChangeWeeklyViews *wrappers.Int64Value `protobuf:"bytes,17,opt,name=recommended_budget_estimated_change_weekly_views,json=recommendedBudgetEstimatedChangeWeeklyViews,proto3" json:"recommended_budget_estimated_change_weekly_views,omitempty"`
	// The type of the campaign budget.
	Type                 enums.BudgetTypeEnum_BudgetType `protobuf:"varint,18,opt,name=type,proto3,enum=google.ads.googleads.v1.enums.BudgetTypeEnum_BudgetType" json:"type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                        `json:"-"`
	XXX_unrecognized     []byte                          `json:"-"`
	XXX_sizecache        int32                           `json:"-"`
}

func (m *CampaignBudget) Reset()         { *m = CampaignBudget{} }
func (m *CampaignBudget) String() string { return proto.CompactTextString(m) }
func (*CampaignBudget) ProtoMessage()    {}
func (*CampaignBudget) Descriptor() ([]byte, []int) {
	return fileDescriptor_campaign_budget_a7f53c1a4a44d279, []int{0}
}
func (m *CampaignBudget) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CampaignBudget.Unmarshal(m, b)
}
func (m *CampaignBudget) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CampaignBudget.Marshal(b, m, deterministic)
}
func (dst *CampaignBudget) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CampaignBudget.Merge(dst, src)
}
func (m *CampaignBudget) XXX_Size() int {
	return xxx_messageInfo_CampaignBudget.Size(m)
}
func (m *CampaignBudget) XXX_DiscardUnknown() {
	xxx_messageInfo_CampaignBudget.DiscardUnknown(m)
}

var xxx_messageInfo_CampaignBudget proto.InternalMessageInfo

func (m *CampaignBudget) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *CampaignBudget) GetId() *wrappers.Int64Value {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *CampaignBudget) GetName() *wrappers.StringValue {
	if m != nil {
		return m.Name
	}
	return nil
}

func (m *CampaignBudget) GetAmountMicros() *wrappers.Int64Value {
	if m != nil {
		return m.AmountMicros
	}
	return nil
}

func (m *CampaignBudget) GetTotalAmountMicros() *wrappers.Int64Value {
	if m != nil {
		return m.TotalAmountMicros
	}
	return nil
}

func (m *CampaignBudget) GetStatus() enums.BudgetStatusEnum_BudgetStatus {
	if m != nil {
		return m.Status
	}
	return enums.BudgetStatusEnum_UNSPECIFIED
}

func (m *CampaignBudget) GetDeliveryMethod() enums.BudgetDeliveryMethodEnum_BudgetDeliveryMethod {
	if m != nil {
		return m.DeliveryMethod
	}
	return enums.BudgetDeliveryMethodEnum_UNSPECIFIED
}

func (m *CampaignBudget) GetExplicitlyShared() *wrappers.BoolValue {
	if m != nil {
		return m.ExplicitlyShared
	}
	return nil
}

func (m *CampaignBudget) GetReferenceCount() *wrappers.Int64Value {
	if m != nil {
		return m.ReferenceCount
	}
	return nil
}

func (m *CampaignBudget) GetHasRecommendedBudget() *wrappers.BoolValue {
	if m != nil {
		return m.HasRecommendedBudget
	}
	return nil
}

func (m *CampaignBudget) GetRecommendedBudgetAmountMicros() *wrappers.Int64Value {
	if m != nil {
		return m.RecommendedBudgetAmountMicros
	}
	return nil
}

func (m *CampaignBudget) GetPeriod() enums.BudgetPeriodEnum_BudgetPeriod {
	if m != nil {
		return m.Period
	}
	return enums.BudgetPeriodEnum_UNSPECIFIED
}

func (m *CampaignBudget) GetRecommendedBudgetEstimatedChangeWeeklyClicks() *wrappers.Int64Value {
	if m != nil {
		return m.RecommendedBudgetEstimatedChangeWeeklyClicks
	}
	return nil
}

func (m *CampaignBudget) GetRecommendedBudgetEstimatedChangeWeeklyCostMicros() *wrappers.Int64Value {
	if m != nil {
		return m.RecommendedBudgetEstimatedChangeWeeklyCostMicros
	}
	return nil
}

func (m *CampaignBudget) GetRecommendedBudgetEstimatedChangeWeeklyInteractions() *wrappers.Int64Value {
	if m != nil {
		return m.RecommendedBudgetEstimatedChangeWeeklyInteractions
	}
	return nil
}

func (m *CampaignBudget) GetRecommendedBudgetEstimatedChangeWeeklyViews() *wrappers.Int64Value {
	if m != nil {
		return m.RecommendedBudgetEstimatedChangeWeeklyViews
	}
	return nil
}

func (m *CampaignBudget) GetType() enums.BudgetTypeEnum_BudgetType {
	if m != nil {
		return m.Type
	}
	return enums.BudgetTypeEnum_UNSPECIFIED
}

func init() {
	proto.RegisterType((*CampaignBudget)(nil), "google.ads.googleads.v1.resources.CampaignBudget")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/resources/campaign_budget.proto", fileDescriptor_campaign_budget_a7f53c1a4a44d279)
}

var fileDescriptor_campaign_budget_a7f53c1a4a44d279 = []byte{
	// 752 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x95, 0x5d, 0x6b, 0x2b, 0x45,
	0x18, 0xc7, 0xd9, 0x9c, 0x5a, 0x3d, 0x73, 0xd2, 0xf4, 0x74, 0x8f, 0xc8, 0x52, 0x8f, 0x92, 0x2a,
	0x85, 0x42, 0x65, 0xb7, 0xa9, 0xd2, 0xca, 0xea, 0x85, 0x49, 0x5a, 0x4a, 0xb5, 0x95, 0xb0, 0x2d,
	0x11, 0x24, 0xb0, 0x4c, 0x77, 0x9e, 0x6e, 0x86, 0xee, 0xce, 0x2c, 0x33, 0xb3, 0xa9, 0xb9, 0x13,
	0xf1, 0x4a, 0x10, 0xfc, 0x0c, 0x5e, 0xfa, 0x51, 0xfc, 0x28, 0x7e, 0x0a, 0xd9, 0xd9, 0x97, 0xe6,
	0xc5, 0xba, 0xc9, 0xdd, 0xbc, 0x3c, 0xff, 0x5f, 0xfe, 0xf3, 0x9f, 0x67, 0x33, 0xe8, 0x34, 0xe4,
	0x3c, 0x8c, 0xc0, 0xc1, 0x44, 0x3a, 0xf9, 0x30, 0x1b, 0x4d, 0x3a, 0x8e, 0x00, 0xc9, 0x53, 0x11,
	0x80, 0x74, 0x02, 0x1c, 0x27, 0x98, 0x86, 0xcc, 0xbf, 0x4b, 0x49, 0x08, 0xca, 0x4e, 0x04, 0x57,
	0xdc, 0xdc, 0xcb, 0xab, 0x6d, 0x4c, 0xa4, 0x5d, 0x09, 0xed, 0x49, 0xc7, 0xae, 0x84, 0xbb, 0xee,
	0x73, 0x6c, 0x60, 0x69, 0x2c, 0x9d, 0x1c, 0xe7, 0x13, 0x88, 0xe8, 0x04, 0xc4, 0xd4, 0x8f, 0x41,
	0x8d, 0x39, 0xc9, 0xf1, 0xbb, 0x9d, 0x95, 0xb4, 0x09, 0x08, 0xba, 0xa6, 0x44, 0x2a, 0xac, 0x52,
	0x59, 0x48, 0x9c, 0x95, 0x24, 0x6a, 0x9a, 0x40, 0x21, 0xf8, 0xb8, 0x10, 0xe8, 0xd9, 0x5d, 0x7a,
	0xef, 0x3c, 0x0a, 0x9c, 0x24, 0x20, 0x4a, 0xe0, 0xdb, 0x12, 0x98, 0x50, 0x07, 0x33, 0xc6, 0x15,
	0x56, 0x94, 0xb3, 0x62, 0xf7, 0x93, 0xdf, 0x9a, 0xa8, 0xd5, 0x2f, 0xd2, 0xec, 0x69, 0xb6, 0xf9,
	0x29, 0xda, 0x2a, 0x03, 0xf3, 0x19, 0x8e, 0xc1, 0x32, 0xda, 0xc6, 0xc1, 0x4b, 0xaf, 0x59, 0x2e,
	0x7e, 0x8f, 0x63, 0x30, 0x0f, 0x51, 0x83, 0x12, 0xeb, 0x45, 0xdb, 0x38, 0x78, 0x75, 0xfc, 0x61,
	0x91, 0xb6, 0x5d, 0x5a, 0xb0, 0x2f, 0x99, 0x3a, 0xf9, 0x62, 0x88, 0xa3, 0x14, 0xbc, 0x06, 0x25,
	0xe6, 0x11, 0xda, 0xd0, 0xa0, 0x0d, 0x5d, 0xfe, 0x76, 0xa9, 0xfc, 0x46, 0x09, 0xca, 0xc2, 0xbc,
	0x5e, 0x57, 0x9a, 0xdf, 0xa0, 0x2d, 0x1c, 0xf3, 0x94, 0x29, 0x3f, 0xa6, 0x81, 0xe0, 0xd2, 0x7a,
	0xa7, 0xfe, 0x97, 0x9a, 0xb9, 0xe2, 0x5a, 0x0b, 0xcc, 0xef, 0xd0, 0x1b, 0xc5, 0x15, 0x8e, 0xfc,
	0x79, 0x0e, 0xaa, 0xe7, 0xec, 0x68, 0x5d, 0x77, 0x16, 0x76, 0x8b, 0x36, 0xf3, 0x4b, 0xb2, 0x36,
	0xdb, 0xc6, 0x41, 0xeb, 0xf8, 0x6b, 0xfb, 0xb9, 0x56, 0xd3, 0xb7, 0x64, 0xe7, 0x49, 0xde, 0x68,
	0xc9, 0x39, 0x4b, 0xe3, 0xb9, 0x05, 0xaf, 0x60, 0x99, 0x29, 0xda, 0x5e, 0xe8, 0x34, 0xeb, 0x5d,
	0x8d, 0xbf, 0x5a, 0x09, 0x7f, 0x56, 0x68, 0xaf, 0xb5, 0x74, 0xe6, 0x67, 0xe6, 0x37, 0xbc, 0x16,
	0x99, 0x9b, 0x9b, 0x17, 0x68, 0x07, 0x7e, 0x4a, 0x22, 0x1a, 0x50, 0x15, 0x4d, 0x7d, 0x39, 0xc6,
	0x02, 0x88, 0xf5, 0x9e, 0xce, 0x65, 0x77, 0x29, 0x97, 0x1e, 0xe7, 0x51, 0x1e, 0xcb, 0xeb, 0x27,
	0xd1, 0x8d, 0xd6, 0x98, 0x67, 0x68, 0x5b, 0xc0, 0x3d, 0x08, 0x60, 0x01, 0xf8, 0x41, 0x16, 0x97,
	0xf5, 0xb2, 0x3e, 0xde, 0x56, 0xa5, 0xe9, 0x67, 0x12, 0x73, 0x80, 0x3e, 0x18, 0x63, 0xe9, 0x0b,
	0x08, 0x78, 0x1c, 0x03, 0x23, 0x40, 0x8a, 0xaf, 0xda, 0x7a, 0x55, 0xeb, 0xe9, 0xfd, 0x31, 0x96,
	0xde, 0x93, 0xb0, 0x68, 0x60, 0x82, 0xda, 0xcb, 0xb4, 0x85, 0x3e, 0x68, 0xd6, 0x1b, 0xfd, 0x48,
	0x2c, 0x92, 0x17, 0x7b, 0x22, 0xff, 0xd6, 0xad, 0xad, 0x35, 0x7a, 0x62, 0xa0, 0x25, 0x33, 0x97,
	0x95, 0x2f, 0x78, 0x05, 0xcb, 0xfc, 0xd5, 0x40, 0x9d, 0xff, 0x30, 0x0f, 0x52, 0xd1, 0x18, 0x2b,
	0x20, 0x7e, 0x30, 0xc6, 0x2c, 0x04, 0xff, 0x11, 0xe0, 0x21, 0x9a, 0xfa, 0x41, 0x44, 0x83, 0x07,
	0x69, 0xb5, 0xea, 0x4f, 0xf3, 0xd9, 0xd2, 0x69, 0xce, 0x4b, 0x66, 0x5f, 0x23, 0x7f, 0xd0, 0xc4,
	0xbe, 0x06, 0x9a, 0xbf, 0x1b, 0xe8, 0x64, 0x1d, 0x1b, 0x5c, 0x56, 0xc9, 0x6e, 0xd7, 0x7b, 0x39,
	0x5a, 0xd1, 0x0b, 0x97, 0x65, 0xd8, 0x7f, 0x18, 0xe8, 0x74, 0x0d, 0x3f, 0x94, 0x29, 0x10, 0x38,
	0xd0, 0x7f, 0x74, 0xd6, 0xeb, 0x7a, 0x43, 0xc7, 0xab, 0x19, 0xba, 0x9c, 0xc1, 0x9a, 0xbf, 0x18,
	0xe8, 0x68, 0x0d, 0x4b, 0x13, 0x0a, 0x8f, 0xd2, 0xda, 0xa9, 0xf7, 0x72, 0xb8, 0x9a, 0x97, 0x61,
	0xc6, 0x33, 0xaf, 0xd0, 0x46, 0xf6, 0x14, 0x58, 0xa6, 0x6e, 0xc1, 0x2f, 0x57, 0x6a, 0xc1, 0xdb,
	0x69, 0x02, 0x33, 0x0d, 0x98, 0x4d, 0x3d, 0x4d, 0xe9, 0xfd, 0xdc, 0x40, 0xfb, 0x01, 0x8f, 0xed,
	0xda, 0x77, 0xb4, 0xf7, 0x66, 0xfe, 0xcd, 0x18, 0x64, 0xe7, 0x18, 0x18, 0x3f, 0x7e, 0x5b, 0x28,
	0x43, 0x1e, 0x61, 0x16, 0xda, 0x5c, 0x84, 0x4e, 0x08, 0x4c, 0x9f, 0xb2, 0x7c, 0xcc, 0x12, 0x2a,
	0xff, 0xe7, 0x65, 0xff, 0xaa, 0x1a, 0xfd, 0xd9, 0x78, 0x71, 0xd1, 0xed, 0xfe, 0xd5, 0xd8, 0xbb,
	0xc8, 0x91, 0x5d, 0x22, 0xed, 0x7c, 0x98, 0x8d, 0x86, 0x1d, 0xdb, 0x2b, 0x2b, 0xff, 0x2e, 0x6b,
	0x46, 0x5d, 0x22, 0x47, 0x55, 0xcd, 0x68, 0xd8, 0x19, 0x55, 0x35, 0xff, 0x34, 0xf6, 0xf3, 0x0d,
	0xd7, 0xed, 0x12, 0xe9, 0xba, 0x55, 0x95, 0xeb, 0x0e, 0x3b, 0xae, 0x5b, 0xd5, 0xdd, 0x6d, 0x6a,
	0xb3, 0x9f, 0xff, 0x1b, 0x00, 0x00, 0xff, 0xff, 0xfe, 0x08, 0x1b, 0x60, 0x85, 0x08, 0x00, 0x00,
}

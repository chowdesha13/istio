// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/resources/campaign_label.proto

package resources // import "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import wrappers "github.com/golang/protobuf/ptypes/wrappers"
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

// Represents a relationship between a campaign and a label.
type CampaignLabel struct {
	// Name of the resource.
	// Campaign label resource names have the form:
	// `customers/{customer_id}/campaignLabels/{campaign_id}~{label_id}`
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	// The campaign to which the label is attached.
	Campaign *wrappers.StringValue `protobuf:"bytes,2,opt,name=campaign,proto3" json:"campaign,omitempty"`
	// The label assigned to the campaign.
	Label                *wrappers.StringValue `protobuf:"bytes,3,opt,name=label,proto3" json:"label,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *CampaignLabel) Reset()         { *m = CampaignLabel{} }
func (m *CampaignLabel) String() string { return proto.CompactTextString(m) }
func (*CampaignLabel) ProtoMessage()    {}
func (*CampaignLabel) Descriptor() ([]byte, []int) {
	return fileDescriptor_campaign_label_46236044c35ac378, []int{0}
}
func (m *CampaignLabel) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CampaignLabel.Unmarshal(m, b)
}
func (m *CampaignLabel) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CampaignLabel.Marshal(b, m, deterministic)
}
func (dst *CampaignLabel) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CampaignLabel.Merge(dst, src)
}
func (m *CampaignLabel) XXX_Size() int {
	return xxx_messageInfo_CampaignLabel.Size(m)
}
func (m *CampaignLabel) XXX_DiscardUnknown() {
	xxx_messageInfo_CampaignLabel.DiscardUnknown(m)
}

var xxx_messageInfo_CampaignLabel proto.InternalMessageInfo

func (m *CampaignLabel) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *CampaignLabel) GetCampaign() *wrappers.StringValue {
	if m != nil {
		return m.Campaign
	}
	return nil
}

func (m *CampaignLabel) GetLabel() *wrappers.StringValue {
	if m != nil {
		return m.Label
	}
	return nil
}

func init() {
	proto.RegisterType((*CampaignLabel)(nil), "google.ads.googleads.v1.resources.CampaignLabel")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/resources/campaign_label.proto", fileDescriptor_campaign_label_46236044c35ac378)
}

var fileDescriptor_campaign_label_46236044c35ac378 = []byte{
	// 323 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x91, 0xcf, 0x4a, 0xc3, 0x30,
	0x1c, 0xc7, 0x69, 0x87, 0xa2, 0xd5, 0x5d, 0x7a, 0x1a, 0x63, 0xc8, 0xa6, 0x0c, 0x76, 0x4a, 0xe8,
	0x04, 0x91, 0x78, 0xea, 0x3c, 0x0c, 0x44, 0x64, 0x4c, 0xe8, 0x41, 0x0a, 0xe3, 0xb7, 0x35, 0x86,
	0x42, 0x9b, 0x84, 0xa4, 0x9d, 0xef, 0xb3, 0xa3, 0x8f, 0xe2, 0xa3, 0xf8, 0x12, 0x4a, 0x9b, 0x26,
	0xe0, 0x45, 0xbd, 0x7d, 0x69, 0x3e, 0xdf, 0x3f, 0x69, 0x82, 0x1b, 0x26, 0x04, 0x2b, 0x28, 0x86,
	0x4c, 0x63, 0x23, 0x1b, 0xb5, 0x8f, 0xb0, 0xa2, 0x5a, 0xd4, 0x6a, 0x47, 0x35, 0xde, 0x41, 0x29,
	0x21, 0x67, 0x7c, 0x53, 0xc0, 0x96, 0x16, 0x48, 0x2a, 0x51, 0x89, 0x70, 0x62, 0x60, 0x04, 0x99,
	0x46, 0xce, 0x87, 0xf6, 0x11, 0x72, 0xbe, 0xe1, 0x45, 0x17, 0xdd, 0x1a, 0xb6, 0xf5, 0x2b, 0x7e,
	0x53, 0x20, 0x25, 0x55, 0xda, 0x44, 0x0c, 0x47, 0xb6, 0x5a, 0xe6, 0x18, 0x38, 0x17, 0x15, 0x54,
	0xb9, 0xe0, 0xdd, 0xe9, 0xe5, 0xc1, 0x0b, 0xfa, 0xf7, 0x5d, 0xf3, 0x63, 0x53, 0x1c, 0x5e, 0x05,
	0x7d, 0x1b, 0xbe, 0xe1, 0x50, 0xd2, 0x81, 0x37, 0xf6, 0x66, 0xa7, 0xeb, 0x73, 0xfb, 0xf1, 0x09,
	0x4a, 0x1a, 0xde, 0x06, 0x27, 0x76, 0xef, 0xc0, 0x1f, 0x7b, 0xb3, 0xb3, 0xf9, 0xa8, 0xdb, 0x87,
	0xec, 0x0e, 0xf4, 0x5c, 0xa9, 0x9c, 0xb3, 0x04, 0x8a, 0x9a, 0xae, 0x1d, 0x1d, 0xce, 0x83, 0xa3,
	0xf6, 0x82, 0x83, 0xde, 0x3f, 0x6c, 0x06, 0x5d, 0x7c, 0x79, 0xc1, 0x74, 0x27, 0x4a, 0xf4, 0xe7,
	0xcf, 0x58, 0x84, 0x3f, 0xee, 0xb2, 0x6a, 0x32, 0x57, 0xde, 0xcb, 0x43, 0x67, 0x64, 0xa2, 0x00,
	0xce, 0x90, 0x50, 0x0c, 0x33, 0xca, 0xdb, 0x46, 0xfb, 0x1a, 0x32, 0xd7, 0xbf, 0x3c, 0xce, 0x9d,
	0x53, 0x07, 0xbf, 0xb7, 0x8c, 0xe3, 0x77, 0x7f, 0xb2, 0x34, 0x91, 0x71, 0xa6, 0x91, 0x91, 0x8d,
	0x4a, 0x22, 0xb4, 0xb6, 0xe4, 0x87, 0x65, 0xd2, 0x38, 0xd3, 0xa9, 0x63, 0xd2, 0x24, 0x4a, 0x1d,
	0xf3, 0xe9, 0x4f, 0xcd, 0x01, 0x21, 0x71, 0xa6, 0x09, 0x71, 0x14, 0x21, 0x49, 0x44, 0x88, 0xe3,
	0xb6, 0xc7, 0xed, 0xd8, 0xeb, 0xef, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7d, 0x26, 0x6c, 0xe5, 0x48,
	0x02, 0x00, 0x00,
}

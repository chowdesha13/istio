// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/services/campaign_budget_service.proto

package services // import "google.golang.org/genproto/googleapis/ads/googleads/v0/services"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/golang/protobuf/ptypes/wrappers"
import resources "google.golang.org/genproto/googleapis/ads/googleads/v0/resources"
import _ "google.golang.org/genproto/googleapis/api/annotations"
import status "google.golang.org/genproto/googleapis/rpc/status"
import field_mask "google.golang.org/genproto/protobuf/field_mask"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Request message for
// [CampaignBudgetService.GetCampaignBudget][google.ads.googleads.v0.services.CampaignBudgetService.GetCampaignBudget].
type GetCampaignBudgetRequest struct {
	// The resource name of the campaign budget to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetCampaignBudgetRequest) Reset()         { *m = GetCampaignBudgetRequest{} }
func (m *GetCampaignBudgetRequest) String() string { return proto.CompactTextString(m) }
func (*GetCampaignBudgetRequest) ProtoMessage()    {}
func (*GetCampaignBudgetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_campaign_budget_service_40b534b534ea287e, []int{0}
}
func (m *GetCampaignBudgetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetCampaignBudgetRequest.Unmarshal(m, b)
}
func (m *GetCampaignBudgetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetCampaignBudgetRequest.Marshal(b, m, deterministic)
}
func (dst *GetCampaignBudgetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetCampaignBudgetRequest.Merge(dst, src)
}
func (m *GetCampaignBudgetRequest) XXX_Size() int {
	return xxx_messageInfo_GetCampaignBudgetRequest.Size(m)
}
func (m *GetCampaignBudgetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetCampaignBudgetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetCampaignBudgetRequest proto.InternalMessageInfo

func (m *GetCampaignBudgetRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

// Request message for
// [CampaignBudgetService.MutateCampaignBudgets][google.ads.googleads.v0.services.CampaignBudgetService.MutateCampaignBudgets].
type MutateCampaignBudgetsRequest struct {
	// The ID of the customer whose campaign budgets are being modified.
	CustomerId string `protobuf:"bytes,1,opt,name=customer_id,json=customerId,proto3" json:"customer_id,omitempty"`
	// The list of operations to perform on individual campaign budgets.
	Operations []*CampaignBudgetOperation `protobuf:"bytes,2,rep,name=operations,proto3" json:"operations,omitempty"`
	// If true, successful operations will be carried out and invalid
	// operations will return errors. If false, all operations will be carried
	// out in one transaction if and only if they are all valid.
	// Default is false.
	PartialFailure bool `protobuf:"varint,3,opt,name=partial_failure,json=partialFailure,proto3" json:"partial_failure,omitempty"`
	// If true, the request is validated but not executed. Only errors are
	// returned, not results.
	ValidateOnly         bool     `protobuf:"varint,4,opt,name=validate_only,json=validateOnly,proto3" json:"validate_only,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MutateCampaignBudgetsRequest) Reset()         { *m = MutateCampaignBudgetsRequest{} }
func (m *MutateCampaignBudgetsRequest) String() string { return proto.CompactTextString(m) }
func (*MutateCampaignBudgetsRequest) ProtoMessage()    {}
func (*MutateCampaignBudgetsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_campaign_budget_service_40b534b534ea287e, []int{1}
}
func (m *MutateCampaignBudgetsRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateCampaignBudgetsRequest.Unmarshal(m, b)
}
func (m *MutateCampaignBudgetsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateCampaignBudgetsRequest.Marshal(b, m, deterministic)
}
func (dst *MutateCampaignBudgetsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateCampaignBudgetsRequest.Merge(dst, src)
}
func (m *MutateCampaignBudgetsRequest) XXX_Size() int {
	return xxx_messageInfo_MutateCampaignBudgetsRequest.Size(m)
}
func (m *MutateCampaignBudgetsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateCampaignBudgetsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MutateCampaignBudgetsRequest proto.InternalMessageInfo

func (m *MutateCampaignBudgetsRequest) GetCustomerId() string {
	if m != nil {
		return m.CustomerId
	}
	return ""
}

func (m *MutateCampaignBudgetsRequest) GetOperations() []*CampaignBudgetOperation {
	if m != nil {
		return m.Operations
	}
	return nil
}

func (m *MutateCampaignBudgetsRequest) GetPartialFailure() bool {
	if m != nil {
		return m.PartialFailure
	}
	return false
}

func (m *MutateCampaignBudgetsRequest) GetValidateOnly() bool {
	if m != nil {
		return m.ValidateOnly
	}
	return false
}

// A single operation (create, update, remove) on a campaign budget.
type CampaignBudgetOperation struct {
	// FieldMask that determines which resource fields are modified in an update.
	UpdateMask *field_mask.FieldMask `protobuf:"bytes,4,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
	// The mutate operation.
	//
	// Types that are valid to be assigned to Operation:
	//	*CampaignBudgetOperation_Create
	//	*CampaignBudgetOperation_Update
	//	*CampaignBudgetOperation_Remove
	Operation            isCampaignBudgetOperation_Operation `protobuf_oneof:"operation"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *CampaignBudgetOperation) Reset()         { *m = CampaignBudgetOperation{} }
func (m *CampaignBudgetOperation) String() string { return proto.CompactTextString(m) }
func (*CampaignBudgetOperation) ProtoMessage()    {}
func (*CampaignBudgetOperation) Descriptor() ([]byte, []int) {
	return fileDescriptor_campaign_budget_service_40b534b534ea287e, []int{2}
}
func (m *CampaignBudgetOperation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CampaignBudgetOperation.Unmarshal(m, b)
}
func (m *CampaignBudgetOperation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CampaignBudgetOperation.Marshal(b, m, deterministic)
}
func (dst *CampaignBudgetOperation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CampaignBudgetOperation.Merge(dst, src)
}
func (m *CampaignBudgetOperation) XXX_Size() int {
	return xxx_messageInfo_CampaignBudgetOperation.Size(m)
}
func (m *CampaignBudgetOperation) XXX_DiscardUnknown() {
	xxx_messageInfo_CampaignBudgetOperation.DiscardUnknown(m)
}

var xxx_messageInfo_CampaignBudgetOperation proto.InternalMessageInfo

func (m *CampaignBudgetOperation) GetUpdateMask() *field_mask.FieldMask {
	if m != nil {
		return m.UpdateMask
	}
	return nil
}

type isCampaignBudgetOperation_Operation interface {
	isCampaignBudgetOperation_Operation()
}

type CampaignBudgetOperation_Create struct {
	Create *resources.CampaignBudget `protobuf:"bytes,1,opt,name=create,proto3,oneof"`
}

type CampaignBudgetOperation_Update struct {
	Update *resources.CampaignBudget `protobuf:"bytes,2,opt,name=update,proto3,oneof"`
}

type CampaignBudgetOperation_Remove struct {
	Remove string `protobuf:"bytes,3,opt,name=remove,proto3,oneof"`
}

func (*CampaignBudgetOperation_Create) isCampaignBudgetOperation_Operation() {}

func (*CampaignBudgetOperation_Update) isCampaignBudgetOperation_Operation() {}

func (*CampaignBudgetOperation_Remove) isCampaignBudgetOperation_Operation() {}

func (m *CampaignBudgetOperation) GetOperation() isCampaignBudgetOperation_Operation {
	if m != nil {
		return m.Operation
	}
	return nil
}

func (m *CampaignBudgetOperation) GetCreate() *resources.CampaignBudget {
	if x, ok := m.GetOperation().(*CampaignBudgetOperation_Create); ok {
		return x.Create
	}
	return nil
}

func (m *CampaignBudgetOperation) GetUpdate() *resources.CampaignBudget {
	if x, ok := m.GetOperation().(*CampaignBudgetOperation_Update); ok {
		return x.Update
	}
	return nil
}

func (m *CampaignBudgetOperation) GetRemove() string {
	if x, ok := m.GetOperation().(*CampaignBudgetOperation_Remove); ok {
		return x.Remove
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*CampaignBudgetOperation) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _CampaignBudgetOperation_OneofMarshaler, _CampaignBudgetOperation_OneofUnmarshaler, _CampaignBudgetOperation_OneofSizer, []interface{}{
		(*CampaignBudgetOperation_Create)(nil),
		(*CampaignBudgetOperation_Update)(nil),
		(*CampaignBudgetOperation_Remove)(nil),
	}
}

func _CampaignBudgetOperation_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*CampaignBudgetOperation)
	// operation
	switch x := m.Operation.(type) {
	case *CampaignBudgetOperation_Create:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Create); err != nil {
			return err
		}
	case *CampaignBudgetOperation_Update:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Update); err != nil {
			return err
		}
	case *CampaignBudgetOperation_Remove:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.Remove)
	case nil:
	default:
		return fmt.Errorf("CampaignBudgetOperation.Operation has unexpected type %T", x)
	}
	return nil
}

func _CampaignBudgetOperation_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*CampaignBudgetOperation)
	switch tag {
	case 1: // operation.create
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.CampaignBudget)
		err := b.DecodeMessage(msg)
		m.Operation = &CampaignBudgetOperation_Create{msg}
		return true, err
	case 2: // operation.update
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.CampaignBudget)
		err := b.DecodeMessage(msg)
		m.Operation = &CampaignBudgetOperation_Update{msg}
		return true, err
	case 3: // operation.remove
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Operation = &CampaignBudgetOperation_Remove{x}
		return true, err
	default:
		return false, nil
	}
}

func _CampaignBudgetOperation_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*CampaignBudgetOperation)
	// operation
	switch x := m.Operation.(type) {
	case *CampaignBudgetOperation_Create:
		s := proto.Size(x.Create)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *CampaignBudgetOperation_Update:
		s := proto.Size(x.Update)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *CampaignBudgetOperation_Remove:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.Remove)))
		n += len(x.Remove)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// Response message for campaign budget mutate.
type MutateCampaignBudgetsResponse struct {
	// Errors that pertain to operation failures in the partial failure mode.
	// Returned only when partial_failure = true and all errors occur inside the
	// operations. If any errors occur outside the operations (e.g. auth errors),
	// we return an RPC level error.
	PartialFailureError *status.Status `protobuf:"bytes,3,opt,name=partial_failure_error,json=partialFailureError,proto3" json:"partial_failure_error,omitempty"`
	// All results for the mutate.
	Results              []*MutateCampaignBudgetResult `protobuf:"bytes,2,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                      `json:"-"`
	XXX_unrecognized     []byte                        `json:"-"`
	XXX_sizecache        int32                         `json:"-"`
}

func (m *MutateCampaignBudgetsResponse) Reset()         { *m = MutateCampaignBudgetsResponse{} }
func (m *MutateCampaignBudgetsResponse) String() string { return proto.CompactTextString(m) }
func (*MutateCampaignBudgetsResponse) ProtoMessage()    {}
func (*MutateCampaignBudgetsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_campaign_budget_service_40b534b534ea287e, []int{3}
}
func (m *MutateCampaignBudgetsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateCampaignBudgetsResponse.Unmarshal(m, b)
}
func (m *MutateCampaignBudgetsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateCampaignBudgetsResponse.Marshal(b, m, deterministic)
}
func (dst *MutateCampaignBudgetsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateCampaignBudgetsResponse.Merge(dst, src)
}
func (m *MutateCampaignBudgetsResponse) XXX_Size() int {
	return xxx_messageInfo_MutateCampaignBudgetsResponse.Size(m)
}
func (m *MutateCampaignBudgetsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateCampaignBudgetsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MutateCampaignBudgetsResponse proto.InternalMessageInfo

func (m *MutateCampaignBudgetsResponse) GetPartialFailureError() *status.Status {
	if m != nil {
		return m.PartialFailureError
	}
	return nil
}

func (m *MutateCampaignBudgetsResponse) GetResults() []*MutateCampaignBudgetResult {
	if m != nil {
		return m.Results
	}
	return nil
}

// The result for the campaign budget mutate.
type MutateCampaignBudgetResult struct {
	// Returned for successful operations.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MutateCampaignBudgetResult) Reset()         { *m = MutateCampaignBudgetResult{} }
func (m *MutateCampaignBudgetResult) String() string { return proto.CompactTextString(m) }
func (*MutateCampaignBudgetResult) ProtoMessage()    {}
func (*MutateCampaignBudgetResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_campaign_budget_service_40b534b534ea287e, []int{4}
}
func (m *MutateCampaignBudgetResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateCampaignBudgetResult.Unmarshal(m, b)
}
func (m *MutateCampaignBudgetResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateCampaignBudgetResult.Marshal(b, m, deterministic)
}
func (dst *MutateCampaignBudgetResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateCampaignBudgetResult.Merge(dst, src)
}
func (m *MutateCampaignBudgetResult) XXX_Size() int {
	return xxx_messageInfo_MutateCampaignBudgetResult.Size(m)
}
func (m *MutateCampaignBudgetResult) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateCampaignBudgetResult.DiscardUnknown(m)
}

var xxx_messageInfo_MutateCampaignBudgetResult proto.InternalMessageInfo

func (m *MutateCampaignBudgetResult) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetCampaignBudgetRequest)(nil), "google.ads.googleads.v0.services.GetCampaignBudgetRequest")
	proto.RegisterType((*MutateCampaignBudgetsRequest)(nil), "google.ads.googleads.v0.services.MutateCampaignBudgetsRequest")
	proto.RegisterType((*CampaignBudgetOperation)(nil), "google.ads.googleads.v0.services.CampaignBudgetOperation")
	proto.RegisterType((*MutateCampaignBudgetsResponse)(nil), "google.ads.googleads.v0.services.MutateCampaignBudgetsResponse")
	proto.RegisterType((*MutateCampaignBudgetResult)(nil), "google.ads.googleads.v0.services.MutateCampaignBudgetResult")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// CampaignBudgetServiceClient is the client API for CampaignBudgetService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CampaignBudgetServiceClient interface {
	// Returns the requested Campaign Budget in full detail.
	GetCampaignBudget(ctx context.Context, in *GetCampaignBudgetRequest, opts ...grpc.CallOption) (*resources.CampaignBudget, error)
	// Creates, updates, or removes campaign budgets. Operation statuses are
	// returned.
	MutateCampaignBudgets(ctx context.Context, in *MutateCampaignBudgetsRequest, opts ...grpc.CallOption) (*MutateCampaignBudgetsResponse, error)
}

type campaignBudgetServiceClient struct {
	cc *grpc.ClientConn
}

func NewCampaignBudgetServiceClient(cc *grpc.ClientConn) CampaignBudgetServiceClient {
	return &campaignBudgetServiceClient{cc}
}

func (c *campaignBudgetServiceClient) GetCampaignBudget(ctx context.Context, in *GetCampaignBudgetRequest, opts ...grpc.CallOption) (*resources.CampaignBudget, error) {
	out := new(resources.CampaignBudget)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v0.services.CampaignBudgetService/GetCampaignBudget", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *campaignBudgetServiceClient) MutateCampaignBudgets(ctx context.Context, in *MutateCampaignBudgetsRequest, opts ...grpc.CallOption) (*MutateCampaignBudgetsResponse, error) {
	out := new(MutateCampaignBudgetsResponse)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v0.services.CampaignBudgetService/MutateCampaignBudgets", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CampaignBudgetServiceServer is the server API for CampaignBudgetService service.
type CampaignBudgetServiceServer interface {
	// Returns the requested Campaign Budget in full detail.
	GetCampaignBudget(context.Context, *GetCampaignBudgetRequest) (*resources.CampaignBudget, error)
	// Creates, updates, or removes campaign budgets. Operation statuses are
	// returned.
	MutateCampaignBudgets(context.Context, *MutateCampaignBudgetsRequest) (*MutateCampaignBudgetsResponse, error)
}

func RegisterCampaignBudgetServiceServer(s *grpc.Server, srv CampaignBudgetServiceServer) {
	s.RegisterService(&_CampaignBudgetService_serviceDesc, srv)
}

func _CampaignBudgetService_GetCampaignBudget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCampaignBudgetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CampaignBudgetServiceServer).GetCampaignBudget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v0.services.CampaignBudgetService/GetCampaignBudget",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CampaignBudgetServiceServer).GetCampaignBudget(ctx, req.(*GetCampaignBudgetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CampaignBudgetService_MutateCampaignBudgets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MutateCampaignBudgetsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CampaignBudgetServiceServer).MutateCampaignBudgets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v0.services.CampaignBudgetService/MutateCampaignBudgets",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CampaignBudgetServiceServer).MutateCampaignBudgets(ctx, req.(*MutateCampaignBudgetsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _CampaignBudgetService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v0.services.CampaignBudgetService",
	HandlerType: (*CampaignBudgetServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCampaignBudget",
			Handler:    _CampaignBudgetService_GetCampaignBudget_Handler,
		},
		{
			MethodName: "MutateCampaignBudgets",
			Handler:    _CampaignBudgetService_MutateCampaignBudgets_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v0/services/campaign_budget_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/services/campaign_budget_service.proto", fileDescriptor_campaign_budget_service_40b534b534ea287e)
}

var fileDescriptor_campaign_budget_service_40b534b534ea287e = []byte{
	// 720 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x55, 0xc1, 0x6b, 0xd4, 0x4c,
	0x14, 0xff, 0x92, 0xfd, 0xe8, 0xf7, 0x75, 0xb6, 0xdf, 0x27, 0x8e, 0x94, 0x86, 0x50, 0x75, 0x89,
	0x05, 0xcb, 0x1e, 0x92, 0xed, 0x56, 0x90, 0xa6, 0xb6, 0x65, 0x57, 0x6c, 0x2b, 0x52, 0x5b, 0x52,
	0x58, 0x50, 0x16, 0xc2, 0x34, 0x99, 0x86, 0xd0, 0x24, 0x13, 0x67, 0x26, 0x2b, 0xa5, 0xf4, 0xa0,
	0xff, 0x82, 0x07, 0xef, 0x1e, 0xbd, 0x7a, 0x16, 0xef, 0x5e, 0x3d, 0x79, 0xf7, 0x20, 0xfe, 0x15,
	0x92, 0x4c, 0x66, 0xed, 0xae, 0x1b, 0x56, 0xeb, 0xed, 0xe5, 0xcd, 0xef, 0xfd, 0xde, 0xfb, 0xcd,
	0x7b, 0x6f, 0x02, 0x36, 0x03, 0x42, 0x82, 0x08, 0x5b, 0xc8, 0x67, 0x96, 0x30, 0x73, 0x6b, 0xd0,
	0xb2, 0x18, 0xa6, 0x83, 0xd0, 0xc3, 0xcc, 0xf2, 0x50, 0x9c, 0xa2, 0x30, 0x48, 0xdc, 0xa3, 0xcc,
	0x0f, 0x30, 0x77, 0xcb, 0x03, 0x33, 0xa5, 0x84, 0x13, 0xd8, 0x10, 0x41, 0x26, 0xf2, 0x99, 0x39,
	0x8c, 0x37, 0x07, 0x2d, 0x53, 0xc6, 0xeb, 0x77, 0xab, 0x32, 0x50, 0xcc, 0x48, 0x46, 0x27, 0xa4,
	0x10, 0xd4, 0xfa, 0xa2, 0x0c, 0x4c, 0x43, 0x0b, 0x25, 0x09, 0xe1, 0x88, 0x87, 0x24, 0x61, 0xe5,
	0x69, 0x99, 0xd8, 0x2a, 0xbe, 0x8e, 0xb2, 0x63, 0xeb, 0x38, 0xc4, 0x91, 0xef, 0xc6, 0x88, 0x9d,
	0x94, 0x88, 0x1b, 0xe3, 0x88, 0xe7, 0x14, 0xa5, 0x29, 0xa6, 0x92, 0x61, 0xa1, 0x3c, 0xa7, 0xa9,
	0x67, 0x31, 0x8e, 0x78, 0x56, 0x1e, 0x18, 0x5b, 0x40, 0xdb, 0xc1, 0xfc, 0x7e, 0x59, 0x54, 0xb7,
	0xa8, 0xc9, 0xc1, 0xcf, 0x32, 0xcc, 0x38, 0xbc, 0x05, 0xfe, 0x93, 0x75, 0xbb, 0x09, 0x8a, 0xb1,
	0xa6, 0x34, 0x94, 0xe5, 0x59, 0x67, 0x4e, 0x3a, 0x1f, 0xa3, 0x18, 0x1b, 0x5f, 0x15, 0xb0, 0xb8,
	0x97, 0x71, 0xc4, 0xf1, 0x28, 0x09, 0x93, 0x2c, 0x37, 0x41, 0xdd, 0xcb, 0x18, 0x27, 0x31, 0xa6,
	0x6e, 0xe8, 0x97, 0x1c, 0x40, 0xba, 0x1e, 0xfa, 0xf0, 0x09, 0x00, 0x24, 0xc5, 0x54, 0x28, 0xd6,
	0xd4, 0x46, 0x6d, 0xb9, 0xde, 0x5e, 0x33, 0xa7, 0xdd, 0xb5, 0x39, 0x9a, 0x6e, 0x5f, 0x32, 0x38,
	0x17, 0xc8, 0xe0, 0x6d, 0x70, 0x25, 0x45, 0x94, 0x87, 0x28, 0x72, 0x8f, 0x51, 0x18, 0x65, 0x14,
	0x6b, 0xb5, 0x86, 0xb2, 0xfc, 0xaf, 0xf3, 0x7f, 0xe9, 0xde, 0x16, 0xde, 0x5c, 0xea, 0x00, 0x45,
	0xa1, 0x8f, 0x38, 0x76, 0x49, 0x12, 0x9d, 0x6a, 0x7f, 0x17, 0xb0, 0x39, 0xe9, 0xdc, 0x4f, 0xa2,
	0x53, 0xe3, 0xb5, 0x0a, 0x16, 0x2a, 0xb2, 0xc2, 0x75, 0x50, 0xcf, 0xd2, 0x22, 0x3c, 0xef, 0x4a,
	0x11, 0x5e, 0x6f, 0xeb, 0x52, 0x85, 0x6c, 0x8b, 0xb9, 0x9d, 0x37, 0x6e, 0x0f, 0xb1, 0x13, 0x07,
	0x08, 0x78, 0x6e, 0xc3, 0x47, 0x60, 0xc6, 0xa3, 0x18, 0x71, 0x71, 0xc3, 0xf5, 0xf6, 0x4a, 0xa5,
	0xfa, 0xe1, 0x1c, 0x8d, 0xc9, 0xdf, 0xfd, 0xcb, 0x29, 0x29, 0x72, 0x32, 0x41, 0xad, 0xa9, 0x7f,
	0x40, 0x26, 0x28, 0xa0, 0x06, 0x66, 0x28, 0x8e, 0xc9, 0x40, 0xdc, 0xdb, 0x6c, 0x7e, 0x22, 0xbe,
	0xbb, 0x75, 0x30, 0x3b, 0xbc, 0x68, 0xe3, 0x83, 0x02, 0xae, 0x57, 0x0c, 0x01, 0x4b, 0x49, 0xc2,
	0x30, 0xdc, 0x06, 0xf3, 0x63, 0x9d, 0x70, 0x31, 0xa5, 0x84, 0x16, 0xbc, 0xf5, 0x36, 0x94, 0x45,
	0xd2, 0xd4, 0x33, 0x0f, 0x8b, 0x01, 0x75, 0xae, 0x8d, 0xf6, 0xe8, 0x41, 0x0e, 0x87, 0x3d, 0xf0,
	0x0f, 0xc5, 0x2c, 0x8b, 0xb8, 0x9c, 0x94, 0x7b, 0xd3, 0x27, 0x65, 0x52, 0x65, 0x4e, 0x41, 0xe2,
	0x48, 0x32, 0xa3, 0x03, 0xf4, 0x6a, 0xd8, 0x2f, 0x6d, 0x42, 0xfb, 0x5d, 0x0d, 0xcc, 0x8f, 0x46,
	0x1f, 0x8a, 0x0a, 0xe0, 0x7b, 0x05, 0x5c, 0xfd, 0x69, 0xcb, 0xa0, 0x3d, 0xbd, 0xf2, 0xaa, 0xd5,
	0xd4, 0x7f, 0xbf, 0xa9, 0xc6, 0xda, 0xcb, 0x4f, 0x5f, 0x5e, 0xa9, 0xab, 0x70, 0x25, 0x7f, 0x8f,
	0xce, 0x46, 0xe4, 0x6c, 0xc8, 0x6d, 0x64, 0x56, 0x73, 0xf8, 0x40, 0x95, 0x1d, 0xb4, 0x9a, 0xe7,
	0xf0, 0xb3, 0x02, 0xe6, 0x27, 0xb6, 0x17, 0x6e, 0x5e, 0xee, 0xf6, 0xe5, 0xe3, 0xa0, 0x6f, 0x5d,
	0x3a, 0x5e, 0xcc, 0x95, 0xb1, 0x55, 0xa8, 0x5a, 0x33, 0xee, 0xe4, 0xaa, 0x7e, 0xc8, 0x38, 0xbb,
	0xf0, 0xe4, 0x6c, 0x34, 0xcf, 0xc7, 0x45, 0xd9, 0x71, 0x41, 0x6a, 0x2b, 0xcd, 0xee, 0x0b, 0x15,
	0x2c, 0x79, 0x24, 0x9e, 0x5a, 0x47, 0x57, 0x9f, 0xd8, 0xdb, 0x83, 0x7c, 0xb3, 0x0f, 0x94, 0xa7,
	0xbb, 0x65, 0x7c, 0x40, 0x22, 0x94, 0x04, 0x26, 0xa1, 0x81, 0x15, 0xe0, 0xa4, 0xd8, 0x7b, 0xf9,
	0x27, 0x48, 0x43, 0x56, 0xfd, 0xeb, 0x59, 0x97, 0xc6, 0x1b, 0xb5, 0xb6, 0xd3, 0xe9, 0xbc, 0x55,
	0x1b, 0x3b, 0x82, 0xb0, 0xe3, 0x33, 0x53, 0x98, 0xb9, 0xd5, 0x6b, 0x99, 0x65, 0x62, 0xf6, 0x51,
	0x42, 0xfa, 0x1d, 0x9f, 0xf5, 0x87, 0x90, 0x7e, 0xaf, 0xd5, 0x97, 0x90, 0x6f, 0xea, 0x92, 0xf0,
	0xdb, 0x76, 0xc7, 0x67, 0xb6, 0x3d, 0x04, 0xd9, 0x76, 0xaf, 0x65, 0xdb, 0x12, 0x76, 0x34, 0x53,
	0xd4, 0xb9, 0xfa, 0x3d, 0x00, 0x00, 0xff, 0xff, 0x9d, 0xd1, 0x43, 0x08, 0x21, 0x07, 0x00, 0x00,
}

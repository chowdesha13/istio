// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/services/customer_feed_service.proto

package services // import "google.golang.org/genproto/googleapis/ads/googleads/v1/services"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/golang/protobuf/ptypes/wrappers"
import resources "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"
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

// Request message for [CustomerFeedService.GetCustomerFeed][google.ads.googleads.v1.services.CustomerFeedService.GetCustomerFeed].
type GetCustomerFeedRequest struct {
	// The resource name of the customer feed to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetCustomerFeedRequest) Reset()         { *m = GetCustomerFeedRequest{} }
func (m *GetCustomerFeedRequest) String() string { return proto.CompactTextString(m) }
func (*GetCustomerFeedRequest) ProtoMessage()    {}
func (*GetCustomerFeedRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_customer_feed_service_75211bb72676f739, []int{0}
}
func (m *GetCustomerFeedRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetCustomerFeedRequest.Unmarshal(m, b)
}
func (m *GetCustomerFeedRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetCustomerFeedRequest.Marshal(b, m, deterministic)
}
func (dst *GetCustomerFeedRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetCustomerFeedRequest.Merge(dst, src)
}
func (m *GetCustomerFeedRequest) XXX_Size() int {
	return xxx_messageInfo_GetCustomerFeedRequest.Size(m)
}
func (m *GetCustomerFeedRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetCustomerFeedRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetCustomerFeedRequest proto.InternalMessageInfo

func (m *GetCustomerFeedRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

// Request message for [CustomerFeedService.MutateCustomerFeeds][google.ads.googleads.v1.services.CustomerFeedService.MutateCustomerFeeds].
type MutateCustomerFeedsRequest struct {
	// The ID of the customer whose customer feeds are being modified.
	CustomerId string `protobuf:"bytes,1,opt,name=customer_id,json=customerId,proto3" json:"customer_id,omitempty"`
	// The list of operations to perform on individual customer feeds.
	Operations []*CustomerFeedOperation `protobuf:"bytes,2,rep,name=operations,proto3" json:"operations,omitempty"`
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

func (m *MutateCustomerFeedsRequest) Reset()         { *m = MutateCustomerFeedsRequest{} }
func (m *MutateCustomerFeedsRequest) String() string { return proto.CompactTextString(m) }
func (*MutateCustomerFeedsRequest) ProtoMessage()    {}
func (*MutateCustomerFeedsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_customer_feed_service_75211bb72676f739, []int{1}
}
func (m *MutateCustomerFeedsRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateCustomerFeedsRequest.Unmarshal(m, b)
}
func (m *MutateCustomerFeedsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateCustomerFeedsRequest.Marshal(b, m, deterministic)
}
func (dst *MutateCustomerFeedsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateCustomerFeedsRequest.Merge(dst, src)
}
func (m *MutateCustomerFeedsRequest) XXX_Size() int {
	return xxx_messageInfo_MutateCustomerFeedsRequest.Size(m)
}
func (m *MutateCustomerFeedsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateCustomerFeedsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MutateCustomerFeedsRequest proto.InternalMessageInfo

func (m *MutateCustomerFeedsRequest) GetCustomerId() string {
	if m != nil {
		return m.CustomerId
	}
	return ""
}

func (m *MutateCustomerFeedsRequest) GetOperations() []*CustomerFeedOperation {
	if m != nil {
		return m.Operations
	}
	return nil
}

func (m *MutateCustomerFeedsRequest) GetPartialFailure() bool {
	if m != nil {
		return m.PartialFailure
	}
	return false
}

func (m *MutateCustomerFeedsRequest) GetValidateOnly() bool {
	if m != nil {
		return m.ValidateOnly
	}
	return false
}

// A single operation (create, update, remove) on a customer feed.
type CustomerFeedOperation struct {
	// FieldMask that determines which resource fields are modified in an update.
	UpdateMask *field_mask.FieldMask `protobuf:"bytes,4,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
	// The mutate operation.
	//
	// Types that are valid to be assigned to Operation:
	//	*CustomerFeedOperation_Create
	//	*CustomerFeedOperation_Update
	//	*CustomerFeedOperation_Remove
	Operation            isCustomerFeedOperation_Operation `protobuf_oneof:"operation"`
	XXX_NoUnkeyedLiteral struct{}                          `json:"-"`
	XXX_unrecognized     []byte                            `json:"-"`
	XXX_sizecache        int32                             `json:"-"`
}

func (m *CustomerFeedOperation) Reset()         { *m = CustomerFeedOperation{} }
func (m *CustomerFeedOperation) String() string { return proto.CompactTextString(m) }
func (*CustomerFeedOperation) ProtoMessage()    {}
func (*CustomerFeedOperation) Descriptor() ([]byte, []int) {
	return fileDescriptor_customer_feed_service_75211bb72676f739, []int{2}
}
func (m *CustomerFeedOperation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CustomerFeedOperation.Unmarshal(m, b)
}
func (m *CustomerFeedOperation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CustomerFeedOperation.Marshal(b, m, deterministic)
}
func (dst *CustomerFeedOperation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CustomerFeedOperation.Merge(dst, src)
}
func (m *CustomerFeedOperation) XXX_Size() int {
	return xxx_messageInfo_CustomerFeedOperation.Size(m)
}
func (m *CustomerFeedOperation) XXX_DiscardUnknown() {
	xxx_messageInfo_CustomerFeedOperation.DiscardUnknown(m)
}

var xxx_messageInfo_CustomerFeedOperation proto.InternalMessageInfo

func (m *CustomerFeedOperation) GetUpdateMask() *field_mask.FieldMask {
	if m != nil {
		return m.UpdateMask
	}
	return nil
}

type isCustomerFeedOperation_Operation interface {
	isCustomerFeedOperation_Operation()
}

type CustomerFeedOperation_Create struct {
	Create *resources.CustomerFeed `protobuf:"bytes,1,opt,name=create,proto3,oneof"`
}

type CustomerFeedOperation_Update struct {
	Update *resources.CustomerFeed `protobuf:"bytes,2,opt,name=update,proto3,oneof"`
}

type CustomerFeedOperation_Remove struct {
	Remove string `protobuf:"bytes,3,opt,name=remove,proto3,oneof"`
}

func (*CustomerFeedOperation_Create) isCustomerFeedOperation_Operation() {}

func (*CustomerFeedOperation_Update) isCustomerFeedOperation_Operation() {}

func (*CustomerFeedOperation_Remove) isCustomerFeedOperation_Operation() {}

func (m *CustomerFeedOperation) GetOperation() isCustomerFeedOperation_Operation {
	if m != nil {
		return m.Operation
	}
	return nil
}

func (m *CustomerFeedOperation) GetCreate() *resources.CustomerFeed {
	if x, ok := m.GetOperation().(*CustomerFeedOperation_Create); ok {
		return x.Create
	}
	return nil
}

func (m *CustomerFeedOperation) GetUpdate() *resources.CustomerFeed {
	if x, ok := m.GetOperation().(*CustomerFeedOperation_Update); ok {
		return x.Update
	}
	return nil
}

func (m *CustomerFeedOperation) GetRemove() string {
	if x, ok := m.GetOperation().(*CustomerFeedOperation_Remove); ok {
		return x.Remove
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*CustomerFeedOperation) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _CustomerFeedOperation_OneofMarshaler, _CustomerFeedOperation_OneofUnmarshaler, _CustomerFeedOperation_OneofSizer, []interface{}{
		(*CustomerFeedOperation_Create)(nil),
		(*CustomerFeedOperation_Update)(nil),
		(*CustomerFeedOperation_Remove)(nil),
	}
}

func _CustomerFeedOperation_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*CustomerFeedOperation)
	// operation
	switch x := m.Operation.(type) {
	case *CustomerFeedOperation_Create:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Create); err != nil {
			return err
		}
	case *CustomerFeedOperation_Update:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Update); err != nil {
			return err
		}
	case *CustomerFeedOperation_Remove:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.Remove)
	case nil:
	default:
		return fmt.Errorf("CustomerFeedOperation.Operation has unexpected type %T", x)
	}
	return nil
}

func _CustomerFeedOperation_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*CustomerFeedOperation)
	switch tag {
	case 1: // operation.create
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.CustomerFeed)
		err := b.DecodeMessage(msg)
		m.Operation = &CustomerFeedOperation_Create{msg}
		return true, err
	case 2: // operation.update
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.CustomerFeed)
		err := b.DecodeMessage(msg)
		m.Operation = &CustomerFeedOperation_Update{msg}
		return true, err
	case 3: // operation.remove
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Operation = &CustomerFeedOperation_Remove{x}
		return true, err
	default:
		return false, nil
	}
}

func _CustomerFeedOperation_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*CustomerFeedOperation)
	// operation
	switch x := m.Operation.(type) {
	case *CustomerFeedOperation_Create:
		s := proto.Size(x.Create)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *CustomerFeedOperation_Update:
		s := proto.Size(x.Update)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *CustomerFeedOperation_Remove:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.Remove)))
		n += len(x.Remove)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// Response message for a customer feed mutate.
type MutateCustomerFeedsResponse struct {
	// Errors that pertain to operation failures in the partial failure mode.
	// Returned only when partial_failure = true and all errors occur inside the
	// operations. If any errors occur outside the operations (e.g. auth errors),
	// we return an RPC level error.
	PartialFailureError *status.Status `protobuf:"bytes,3,opt,name=partial_failure_error,json=partialFailureError,proto3" json:"partial_failure_error,omitempty"`
	// All results for the mutate.
	Results              []*MutateCustomerFeedResult `protobuf:"bytes,2,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                    `json:"-"`
	XXX_unrecognized     []byte                      `json:"-"`
	XXX_sizecache        int32                       `json:"-"`
}

func (m *MutateCustomerFeedsResponse) Reset()         { *m = MutateCustomerFeedsResponse{} }
func (m *MutateCustomerFeedsResponse) String() string { return proto.CompactTextString(m) }
func (*MutateCustomerFeedsResponse) ProtoMessage()    {}
func (*MutateCustomerFeedsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_customer_feed_service_75211bb72676f739, []int{3}
}
func (m *MutateCustomerFeedsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateCustomerFeedsResponse.Unmarshal(m, b)
}
func (m *MutateCustomerFeedsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateCustomerFeedsResponse.Marshal(b, m, deterministic)
}
func (dst *MutateCustomerFeedsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateCustomerFeedsResponse.Merge(dst, src)
}
func (m *MutateCustomerFeedsResponse) XXX_Size() int {
	return xxx_messageInfo_MutateCustomerFeedsResponse.Size(m)
}
func (m *MutateCustomerFeedsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateCustomerFeedsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MutateCustomerFeedsResponse proto.InternalMessageInfo

func (m *MutateCustomerFeedsResponse) GetPartialFailureError() *status.Status {
	if m != nil {
		return m.PartialFailureError
	}
	return nil
}

func (m *MutateCustomerFeedsResponse) GetResults() []*MutateCustomerFeedResult {
	if m != nil {
		return m.Results
	}
	return nil
}

// The result for the customer feed mutate.
type MutateCustomerFeedResult struct {
	// Returned for successful operations.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MutateCustomerFeedResult) Reset()         { *m = MutateCustomerFeedResult{} }
func (m *MutateCustomerFeedResult) String() string { return proto.CompactTextString(m) }
func (*MutateCustomerFeedResult) ProtoMessage()    {}
func (*MutateCustomerFeedResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_customer_feed_service_75211bb72676f739, []int{4}
}
func (m *MutateCustomerFeedResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateCustomerFeedResult.Unmarshal(m, b)
}
func (m *MutateCustomerFeedResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateCustomerFeedResult.Marshal(b, m, deterministic)
}
func (dst *MutateCustomerFeedResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateCustomerFeedResult.Merge(dst, src)
}
func (m *MutateCustomerFeedResult) XXX_Size() int {
	return xxx_messageInfo_MutateCustomerFeedResult.Size(m)
}
func (m *MutateCustomerFeedResult) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateCustomerFeedResult.DiscardUnknown(m)
}

var xxx_messageInfo_MutateCustomerFeedResult proto.InternalMessageInfo

func (m *MutateCustomerFeedResult) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetCustomerFeedRequest)(nil), "google.ads.googleads.v1.services.GetCustomerFeedRequest")
	proto.RegisterType((*MutateCustomerFeedsRequest)(nil), "google.ads.googleads.v1.services.MutateCustomerFeedsRequest")
	proto.RegisterType((*CustomerFeedOperation)(nil), "google.ads.googleads.v1.services.CustomerFeedOperation")
	proto.RegisterType((*MutateCustomerFeedsResponse)(nil), "google.ads.googleads.v1.services.MutateCustomerFeedsResponse")
	proto.RegisterType((*MutateCustomerFeedResult)(nil), "google.ads.googleads.v1.services.MutateCustomerFeedResult")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// CustomerFeedServiceClient is the client API for CustomerFeedService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CustomerFeedServiceClient interface {
	// Returns the requested customer feed in full detail.
	GetCustomerFeed(ctx context.Context, in *GetCustomerFeedRequest, opts ...grpc.CallOption) (*resources.CustomerFeed, error)
	// Creates, updates, or removes customer feeds. Operation statuses are
	// returned.
	MutateCustomerFeeds(ctx context.Context, in *MutateCustomerFeedsRequest, opts ...grpc.CallOption) (*MutateCustomerFeedsResponse, error)
}

type customerFeedServiceClient struct {
	cc *grpc.ClientConn
}

func NewCustomerFeedServiceClient(cc *grpc.ClientConn) CustomerFeedServiceClient {
	return &customerFeedServiceClient{cc}
}

func (c *customerFeedServiceClient) GetCustomerFeed(ctx context.Context, in *GetCustomerFeedRequest, opts ...grpc.CallOption) (*resources.CustomerFeed, error) {
	out := new(resources.CustomerFeed)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.CustomerFeedService/GetCustomerFeed", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *customerFeedServiceClient) MutateCustomerFeeds(ctx context.Context, in *MutateCustomerFeedsRequest, opts ...grpc.CallOption) (*MutateCustomerFeedsResponse, error) {
	out := new(MutateCustomerFeedsResponse)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.CustomerFeedService/MutateCustomerFeeds", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CustomerFeedServiceServer is the server API for CustomerFeedService service.
type CustomerFeedServiceServer interface {
	// Returns the requested customer feed in full detail.
	GetCustomerFeed(context.Context, *GetCustomerFeedRequest) (*resources.CustomerFeed, error)
	// Creates, updates, or removes customer feeds. Operation statuses are
	// returned.
	MutateCustomerFeeds(context.Context, *MutateCustomerFeedsRequest) (*MutateCustomerFeedsResponse, error)
}

func RegisterCustomerFeedServiceServer(s *grpc.Server, srv CustomerFeedServiceServer) {
	s.RegisterService(&_CustomerFeedService_serviceDesc, srv)
}

func _CustomerFeedService_GetCustomerFeed_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCustomerFeedRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CustomerFeedServiceServer).GetCustomerFeed(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.CustomerFeedService/GetCustomerFeed",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CustomerFeedServiceServer).GetCustomerFeed(ctx, req.(*GetCustomerFeedRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CustomerFeedService_MutateCustomerFeeds_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MutateCustomerFeedsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CustomerFeedServiceServer).MutateCustomerFeeds(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.CustomerFeedService/MutateCustomerFeeds",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CustomerFeedServiceServer).MutateCustomerFeeds(ctx, req.(*MutateCustomerFeedsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _CustomerFeedService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v1.services.CustomerFeedService",
	HandlerType: (*CustomerFeedServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCustomerFeed",
			Handler:    _CustomerFeedService_GetCustomerFeed_Handler,
		},
		{
			MethodName: "MutateCustomerFeeds",
			Handler:    _CustomerFeedService_MutateCustomerFeeds_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v1/services/customer_feed_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/services/customer_feed_service.proto", fileDescriptor_customer_feed_service_75211bb72676f739)
}

var fileDescriptor_customer_feed_service_75211bb72676f739 = []byte{
	// 710 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x55, 0xc1, 0x6e, 0xd3, 0x4c,
	0x10, 0xfe, 0xed, 0xfc, 0x2a, 0x74, 0x5d, 0xa8, 0xb4, 0x55, 0xc1, 0x0a, 0x08, 0x22, 0x53, 0x89,
	0x2a, 0x07, 0xaf, 0x12, 0x84, 0x8a, 0xdc, 0x46, 0x28, 0x45, 0xa4, 0xed, 0xa1, 0xb4, 0x72, 0x51,
	0x91, 0x50, 0x24, 0x6b, 0x1b, 0x6f, 0x22, 0xab, 0xb6, 0xd7, 0xec, 0xae, 0x83, 0xaa, 0xaa, 0x17,
	0xde, 0x00, 0xf1, 0x04, 0x70, 0xe4, 0xce, 0x89, 0x37, 0xe0, 0x86, 0x78, 0x85, 0x9e, 0x78, 0x09,
	0x90, 0xbd, 0x5e, 0x93, 0xb4, 0x89, 0x02, 0xbd, 0x8d, 0x67, 0xbf, 0xf9, 0x66, 0x66, 0xbf, 0xd9,
	0x31, 0xd8, 0x18, 0x50, 0x3a, 0x08, 0x09, 0xc2, 0x3e, 0x47, 0xd2, 0xcc, 0xac, 0x61, 0x03, 0x71,
	0xc2, 0x86, 0x41, 0x8f, 0x70, 0xd4, 0x4b, 0xb9, 0xa0, 0x11, 0x61, 0x5e, 0x9f, 0x10, 0xdf, 0x2b,
	0xdc, 0x76, 0xc2, 0xa8, 0xa0, 0xb0, 0x26, 0x43, 0x6c, 0xec, 0x73, 0xbb, 0x8c, 0xb6, 0x87, 0x0d,
	0x5b, 0x45, 0x57, 0x1f, 0x4f, 0xe3, 0x67, 0x84, 0xd3, 0x94, 0x5d, 0x4a, 0x20, 0x89, 0xab, 0x77,
	0x55, 0x58, 0x12, 0x20, 0x1c, 0xc7, 0x54, 0x60, 0x11, 0xd0, 0x98, 0x17, 0xa7, 0x45, 0x5a, 0x94,
	0x7f, 0x1d, 0xa5, 0x7d, 0xd4, 0x0f, 0x48, 0xe8, 0x7b, 0x11, 0xe6, 0xc7, 0x05, 0xe2, 0xde, 0x45,
	0xc4, 0x5b, 0x86, 0x93, 0x84, 0x30, 0xc5, 0x70, 0xbb, 0x38, 0x67, 0x49, 0x0f, 0x71, 0x81, 0x45,
	0x5a, 0x1c, 0x58, 0x2d, 0x70, 0x6b, 0x8b, 0x88, 0x67, 0x45, 0x49, 0x1d, 0x42, 0x7c, 0x97, 0xbc,
	0x49, 0x09, 0x17, 0xf0, 0x01, 0xb8, 0xa1, 0x6a, 0xf6, 0x62, 0x1c, 0x11, 0x53, 0xab, 0x69, 0xab,
	0xf3, 0xee, 0x82, 0x72, 0xbe, 0xc0, 0x11, 0xb1, 0xce, 0x35, 0x50, 0xdd, 0x4d, 0x05, 0x16, 0x64,
	0x94, 0x82, 0x2b, 0x8e, 0xfb, 0xc0, 0x28, 0xbb, 0x0d, 0xfc, 0x82, 0x01, 0x28, 0xd7, 0x8e, 0x0f,
	0x5f, 0x01, 0x40, 0x13, 0xc2, 0x64, 0xb7, 0xa6, 0x5e, 0xab, 0xac, 0x1a, 0xcd, 0x35, 0x7b, 0xd6,
	0x2d, 0xdb, 0xa3, 0xc9, 0xf6, 0x54, 0xbc, 0x3b, 0x42, 0x05, 0x1f, 0x82, 0xc5, 0x04, 0x33, 0x11,
	0xe0, 0xd0, 0xeb, 0xe3, 0x20, 0x4c, 0x19, 0x31, 0x2b, 0x35, 0x6d, 0xf5, 0xba, 0x7b, 0xb3, 0x70,
	0x77, 0xa4, 0x37, 0x6b, 0x73, 0x88, 0xc3, 0xc0, 0xc7, 0x82, 0x78, 0x34, 0x0e, 0x4f, 0xcc, 0xff,
	0x73, 0xd8, 0x82, 0x72, 0xee, 0xc5, 0xe1, 0x89, 0xf5, 0x5e, 0x07, 0xcb, 0x13, 0x73, 0xc2, 0x75,
	0x60, 0xa4, 0x49, 0x1e, 0x9c, 0xa9, 0x91, 0x07, 0x1b, 0xcd, 0xaa, 0xea, 0x40, 0xc9, 0x61, 0x77,
	0x32, 0xc1, 0x76, 0x31, 0x3f, 0x76, 0x81, 0x84, 0x67, 0x36, 0xdc, 0x01, 0x73, 0x3d, 0x46, 0xb0,
	0x90, 0x77, 0x6b, 0x34, 0xd1, 0xd4, 0xce, 0xcb, 0xe9, 0x19, 0x6b, 0x7d, 0xfb, 0x3f, 0xb7, 0x20,
	0xc8, 0xa8, 0x24, 0xb1, 0xa9, 0x5f, 0x99, 0x4a, 0x12, 0x40, 0x13, 0xcc, 0x31, 0x12, 0xd1, 0xa1,
	0xbc, 0xb1, 0xf9, 0xec, 0x44, 0x7e, 0x6f, 0x1a, 0x60, 0xbe, 0xbc, 0x62, 0xeb, 0xab, 0x06, 0xee,
	0x4c, 0x94, 0x9e, 0x27, 0x34, 0xe6, 0x04, 0x76, 0xc0, 0xf2, 0x05, 0x05, 0x3c, 0xc2, 0x18, 0x65,
	0x39, 0xab, 0xd1, 0x84, 0xaa, 0x40, 0x96, 0xf4, 0xec, 0x83, 0x7c, 0x24, 0xdd, 0xa5, 0x71, 0x6d,
	0x9e, 0x67, 0x70, 0xf8, 0x12, 0x5c, 0x63, 0x84, 0xa7, 0xa1, 0x50, 0xf3, 0xe1, 0xcc, 0x9e, 0x8f,
	0xcb, 0x75, 0xb9, 0x39, 0x85, 0xab, 0xa8, 0xac, 0xa7, 0xc0, 0x9c, 0x06, 0xfa, 0xab, 0xc9, 0x6f,
	0x7e, 0xac, 0x80, 0xa5, 0xd1, 0xd8, 0x03, 0x99, 0x1b, 0x7e, 0xd1, 0xc0, 0xe2, 0x85, 0x17, 0x05,
	0x9f, 0xcc, 0xae, 0x78, 0xf2, 0x23, 0xac, 0xfe, 0xab, 0x8c, 0xd6, 0xda, 0xbb, 0x1f, 0xe7, 0x1f,
	0xf4, 0x06, 0x44, 0xd9, 0xce, 0x39, 0x1d, 0x6b, 0xa3, 0xa5, 0xde, 0x1d, 0x47, 0xf5, 0x72, 0x09,
	0xe5, 0x9a, 0xa1, 0xfa, 0x19, 0xfc, 0xae, 0x81, 0xa5, 0x09, 0x72, 0xc2, 0x8d, 0xab, 0xdc, 0xb6,
	0x5a, 0x00, 0xd5, 0xd6, 0x15, 0xa3, 0xe5, 0x0c, 0x59, 0xad, 0xbc, 0x9b, 0x35, 0xab, 0x99, 0x75,
	0xf3, 0xa7, 0xfc, 0xd3, 0x91, 0xa5, 0xd2, 0xaa, 0x9f, 0x8d, 0x37, 0xe3, 0x44, 0x39, 0xa1, 0xa3,
	0xd5, 0x37, 0x7f, 0x69, 0x60, 0xa5, 0x47, 0xa3, 0x99, 0x35, 0x6c, 0x9a, 0x13, 0x94, 0xdc, 0xcf,
	0xde, 0xee, 0xbe, 0xf6, 0x7a, 0xbb, 0x88, 0x1e, 0xd0, 0x10, 0xc7, 0x03, 0x9b, 0xb2, 0x01, 0x1a,
	0x90, 0x38, 0x7f, 0xd9, 0x6a, 0xc3, 0x27, 0x01, 0x9f, 0xfe, 0x43, 0x59, 0x57, 0xc6, 0x27, 0xbd,
	0xb2, 0xd5, 0x6e, 0x7f, 0xd6, 0x6b, 0x5b, 0x92, 0xb0, 0xed, 0x73, 0x5b, 0x9a, 0x99, 0x75, 0xd8,
	0xb0, 0x8b, 0xc4, 0xfc, 0x9b, 0x82, 0x74, 0xdb, 0x3e, 0xef, 0x96, 0x90, 0xee, 0x61, 0xa3, 0xab,
	0x20, 0x3f, 0xf5, 0x15, 0xe9, 0x77, 0x9c, 0xb6, 0xcf, 0x1d, 0xa7, 0x04, 0x39, 0xce, 0x61, 0xc3,
	0x71, 0x14, 0xec, 0x68, 0x2e, 0xaf, 0xf3, 0xd1, 0xef, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x70,
	0x21, 0x28, 0xf7, 0x06, 0x00, 0x00,
}

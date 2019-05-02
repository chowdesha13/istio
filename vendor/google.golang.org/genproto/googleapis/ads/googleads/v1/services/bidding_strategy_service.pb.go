// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/services/bidding_strategy_service.proto

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

// Request message for [BiddingStrategyService.GetBiddingStrategy][google.ads.googleads.v1.services.BiddingStrategyService.GetBiddingStrategy].
type GetBiddingStrategyRequest struct {
	// The resource name of the bidding strategy to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetBiddingStrategyRequest) Reset()         { *m = GetBiddingStrategyRequest{} }
func (m *GetBiddingStrategyRequest) String() string { return proto.CompactTextString(m) }
func (*GetBiddingStrategyRequest) ProtoMessage()    {}
func (*GetBiddingStrategyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_bidding_strategy_service_c8276e79a5566ec3, []int{0}
}
func (m *GetBiddingStrategyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetBiddingStrategyRequest.Unmarshal(m, b)
}
func (m *GetBiddingStrategyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetBiddingStrategyRequest.Marshal(b, m, deterministic)
}
func (dst *GetBiddingStrategyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetBiddingStrategyRequest.Merge(dst, src)
}
func (m *GetBiddingStrategyRequest) XXX_Size() int {
	return xxx_messageInfo_GetBiddingStrategyRequest.Size(m)
}
func (m *GetBiddingStrategyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetBiddingStrategyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetBiddingStrategyRequest proto.InternalMessageInfo

func (m *GetBiddingStrategyRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

// Request message for [BiddingStrategyService.MutateBiddingStrategies][google.ads.googleads.v1.services.BiddingStrategyService.MutateBiddingStrategies].
type MutateBiddingStrategiesRequest struct {
	// The ID of the customer whose bidding strategies are being modified.
	CustomerId string `protobuf:"bytes,1,opt,name=customer_id,json=customerId,proto3" json:"customer_id,omitempty"`
	// The list of operations to perform on individual bidding strategies.
	Operations []*BiddingStrategyOperation `protobuf:"bytes,2,rep,name=operations,proto3" json:"operations,omitempty"`
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

func (m *MutateBiddingStrategiesRequest) Reset()         { *m = MutateBiddingStrategiesRequest{} }
func (m *MutateBiddingStrategiesRequest) String() string { return proto.CompactTextString(m) }
func (*MutateBiddingStrategiesRequest) ProtoMessage()    {}
func (*MutateBiddingStrategiesRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_bidding_strategy_service_c8276e79a5566ec3, []int{1}
}
func (m *MutateBiddingStrategiesRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateBiddingStrategiesRequest.Unmarshal(m, b)
}
func (m *MutateBiddingStrategiesRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateBiddingStrategiesRequest.Marshal(b, m, deterministic)
}
func (dst *MutateBiddingStrategiesRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateBiddingStrategiesRequest.Merge(dst, src)
}
func (m *MutateBiddingStrategiesRequest) XXX_Size() int {
	return xxx_messageInfo_MutateBiddingStrategiesRequest.Size(m)
}
func (m *MutateBiddingStrategiesRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateBiddingStrategiesRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MutateBiddingStrategiesRequest proto.InternalMessageInfo

func (m *MutateBiddingStrategiesRequest) GetCustomerId() string {
	if m != nil {
		return m.CustomerId
	}
	return ""
}

func (m *MutateBiddingStrategiesRequest) GetOperations() []*BiddingStrategyOperation {
	if m != nil {
		return m.Operations
	}
	return nil
}

func (m *MutateBiddingStrategiesRequest) GetPartialFailure() bool {
	if m != nil {
		return m.PartialFailure
	}
	return false
}

func (m *MutateBiddingStrategiesRequest) GetValidateOnly() bool {
	if m != nil {
		return m.ValidateOnly
	}
	return false
}

// A single operation (create, update, remove) on a bidding strategy.
type BiddingStrategyOperation struct {
	// FieldMask that determines which resource fields are modified in an update.
	UpdateMask *field_mask.FieldMask `protobuf:"bytes,4,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
	// The mutate operation.
	//
	// Types that are valid to be assigned to Operation:
	//	*BiddingStrategyOperation_Create
	//	*BiddingStrategyOperation_Update
	//	*BiddingStrategyOperation_Remove
	Operation            isBiddingStrategyOperation_Operation `protobuf_oneof:"operation"`
	XXX_NoUnkeyedLiteral struct{}                             `json:"-"`
	XXX_unrecognized     []byte                               `json:"-"`
	XXX_sizecache        int32                                `json:"-"`
}

func (m *BiddingStrategyOperation) Reset()         { *m = BiddingStrategyOperation{} }
func (m *BiddingStrategyOperation) String() string { return proto.CompactTextString(m) }
func (*BiddingStrategyOperation) ProtoMessage()    {}
func (*BiddingStrategyOperation) Descriptor() ([]byte, []int) {
	return fileDescriptor_bidding_strategy_service_c8276e79a5566ec3, []int{2}
}
func (m *BiddingStrategyOperation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BiddingStrategyOperation.Unmarshal(m, b)
}
func (m *BiddingStrategyOperation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BiddingStrategyOperation.Marshal(b, m, deterministic)
}
func (dst *BiddingStrategyOperation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BiddingStrategyOperation.Merge(dst, src)
}
func (m *BiddingStrategyOperation) XXX_Size() int {
	return xxx_messageInfo_BiddingStrategyOperation.Size(m)
}
func (m *BiddingStrategyOperation) XXX_DiscardUnknown() {
	xxx_messageInfo_BiddingStrategyOperation.DiscardUnknown(m)
}

var xxx_messageInfo_BiddingStrategyOperation proto.InternalMessageInfo

func (m *BiddingStrategyOperation) GetUpdateMask() *field_mask.FieldMask {
	if m != nil {
		return m.UpdateMask
	}
	return nil
}

type isBiddingStrategyOperation_Operation interface {
	isBiddingStrategyOperation_Operation()
}

type BiddingStrategyOperation_Create struct {
	Create *resources.BiddingStrategy `protobuf:"bytes,1,opt,name=create,proto3,oneof"`
}

type BiddingStrategyOperation_Update struct {
	Update *resources.BiddingStrategy `protobuf:"bytes,2,opt,name=update,proto3,oneof"`
}

type BiddingStrategyOperation_Remove struct {
	Remove string `protobuf:"bytes,3,opt,name=remove,proto3,oneof"`
}

func (*BiddingStrategyOperation_Create) isBiddingStrategyOperation_Operation() {}

func (*BiddingStrategyOperation_Update) isBiddingStrategyOperation_Operation() {}

func (*BiddingStrategyOperation_Remove) isBiddingStrategyOperation_Operation() {}

func (m *BiddingStrategyOperation) GetOperation() isBiddingStrategyOperation_Operation {
	if m != nil {
		return m.Operation
	}
	return nil
}

func (m *BiddingStrategyOperation) GetCreate() *resources.BiddingStrategy {
	if x, ok := m.GetOperation().(*BiddingStrategyOperation_Create); ok {
		return x.Create
	}
	return nil
}

func (m *BiddingStrategyOperation) GetUpdate() *resources.BiddingStrategy {
	if x, ok := m.GetOperation().(*BiddingStrategyOperation_Update); ok {
		return x.Update
	}
	return nil
}

func (m *BiddingStrategyOperation) GetRemove() string {
	if x, ok := m.GetOperation().(*BiddingStrategyOperation_Remove); ok {
		return x.Remove
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*BiddingStrategyOperation) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _BiddingStrategyOperation_OneofMarshaler, _BiddingStrategyOperation_OneofUnmarshaler, _BiddingStrategyOperation_OneofSizer, []interface{}{
		(*BiddingStrategyOperation_Create)(nil),
		(*BiddingStrategyOperation_Update)(nil),
		(*BiddingStrategyOperation_Remove)(nil),
	}
}

func _BiddingStrategyOperation_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*BiddingStrategyOperation)
	// operation
	switch x := m.Operation.(type) {
	case *BiddingStrategyOperation_Create:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Create); err != nil {
			return err
		}
	case *BiddingStrategyOperation_Update:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Update); err != nil {
			return err
		}
	case *BiddingStrategyOperation_Remove:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.Remove)
	case nil:
	default:
		return fmt.Errorf("BiddingStrategyOperation.Operation has unexpected type %T", x)
	}
	return nil
}

func _BiddingStrategyOperation_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*BiddingStrategyOperation)
	switch tag {
	case 1: // operation.create
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.BiddingStrategy)
		err := b.DecodeMessage(msg)
		m.Operation = &BiddingStrategyOperation_Create{msg}
		return true, err
	case 2: // operation.update
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.BiddingStrategy)
		err := b.DecodeMessage(msg)
		m.Operation = &BiddingStrategyOperation_Update{msg}
		return true, err
	case 3: // operation.remove
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Operation = &BiddingStrategyOperation_Remove{x}
		return true, err
	default:
		return false, nil
	}
}

func _BiddingStrategyOperation_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*BiddingStrategyOperation)
	// operation
	switch x := m.Operation.(type) {
	case *BiddingStrategyOperation_Create:
		s := proto.Size(x.Create)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *BiddingStrategyOperation_Update:
		s := proto.Size(x.Update)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *BiddingStrategyOperation_Remove:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.Remove)))
		n += len(x.Remove)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// Response message for bidding strategy mutate.
type MutateBiddingStrategiesResponse struct {
	// Errors that pertain to operation failures in the partial failure mode.
	// Returned only when partial_failure = true and all errors occur inside the
	// operations. If any errors occur outside the operations (e.g. auth errors),
	// we return an RPC level error.
	PartialFailureError *status.Status `protobuf:"bytes,3,opt,name=partial_failure_error,json=partialFailureError,proto3" json:"partial_failure_error,omitempty"`
	// All results for the mutate.
	Results              []*MutateBiddingStrategyResult `protobuf:"bytes,2,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                       `json:"-"`
	XXX_unrecognized     []byte                         `json:"-"`
	XXX_sizecache        int32                          `json:"-"`
}

func (m *MutateBiddingStrategiesResponse) Reset()         { *m = MutateBiddingStrategiesResponse{} }
func (m *MutateBiddingStrategiesResponse) String() string { return proto.CompactTextString(m) }
func (*MutateBiddingStrategiesResponse) ProtoMessage()    {}
func (*MutateBiddingStrategiesResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_bidding_strategy_service_c8276e79a5566ec3, []int{3}
}
func (m *MutateBiddingStrategiesResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateBiddingStrategiesResponse.Unmarshal(m, b)
}
func (m *MutateBiddingStrategiesResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateBiddingStrategiesResponse.Marshal(b, m, deterministic)
}
func (dst *MutateBiddingStrategiesResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateBiddingStrategiesResponse.Merge(dst, src)
}
func (m *MutateBiddingStrategiesResponse) XXX_Size() int {
	return xxx_messageInfo_MutateBiddingStrategiesResponse.Size(m)
}
func (m *MutateBiddingStrategiesResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateBiddingStrategiesResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MutateBiddingStrategiesResponse proto.InternalMessageInfo

func (m *MutateBiddingStrategiesResponse) GetPartialFailureError() *status.Status {
	if m != nil {
		return m.PartialFailureError
	}
	return nil
}

func (m *MutateBiddingStrategiesResponse) GetResults() []*MutateBiddingStrategyResult {
	if m != nil {
		return m.Results
	}
	return nil
}

// The result for the bidding strategy mutate.
type MutateBiddingStrategyResult struct {
	// Returned for successful operations.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MutateBiddingStrategyResult) Reset()         { *m = MutateBiddingStrategyResult{} }
func (m *MutateBiddingStrategyResult) String() string { return proto.CompactTextString(m) }
func (*MutateBiddingStrategyResult) ProtoMessage()    {}
func (*MutateBiddingStrategyResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_bidding_strategy_service_c8276e79a5566ec3, []int{4}
}
func (m *MutateBiddingStrategyResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateBiddingStrategyResult.Unmarshal(m, b)
}
func (m *MutateBiddingStrategyResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateBiddingStrategyResult.Marshal(b, m, deterministic)
}
func (dst *MutateBiddingStrategyResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateBiddingStrategyResult.Merge(dst, src)
}
func (m *MutateBiddingStrategyResult) XXX_Size() int {
	return xxx_messageInfo_MutateBiddingStrategyResult.Size(m)
}
func (m *MutateBiddingStrategyResult) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateBiddingStrategyResult.DiscardUnknown(m)
}

var xxx_messageInfo_MutateBiddingStrategyResult proto.InternalMessageInfo

func (m *MutateBiddingStrategyResult) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetBiddingStrategyRequest)(nil), "google.ads.googleads.v1.services.GetBiddingStrategyRequest")
	proto.RegisterType((*MutateBiddingStrategiesRequest)(nil), "google.ads.googleads.v1.services.MutateBiddingStrategiesRequest")
	proto.RegisterType((*BiddingStrategyOperation)(nil), "google.ads.googleads.v1.services.BiddingStrategyOperation")
	proto.RegisterType((*MutateBiddingStrategiesResponse)(nil), "google.ads.googleads.v1.services.MutateBiddingStrategiesResponse")
	proto.RegisterType((*MutateBiddingStrategyResult)(nil), "google.ads.googleads.v1.services.MutateBiddingStrategyResult")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// BiddingStrategyServiceClient is the client API for BiddingStrategyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type BiddingStrategyServiceClient interface {
	// Returns the requested bidding strategy in full detail.
	GetBiddingStrategy(ctx context.Context, in *GetBiddingStrategyRequest, opts ...grpc.CallOption) (*resources.BiddingStrategy, error)
	// Creates, updates, or removes bidding strategies. Operation statuses are
	// returned.
	MutateBiddingStrategies(ctx context.Context, in *MutateBiddingStrategiesRequest, opts ...grpc.CallOption) (*MutateBiddingStrategiesResponse, error)
}

type biddingStrategyServiceClient struct {
	cc *grpc.ClientConn
}

func NewBiddingStrategyServiceClient(cc *grpc.ClientConn) BiddingStrategyServiceClient {
	return &biddingStrategyServiceClient{cc}
}

func (c *biddingStrategyServiceClient) GetBiddingStrategy(ctx context.Context, in *GetBiddingStrategyRequest, opts ...grpc.CallOption) (*resources.BiddingStrategy, error) {
	out := new(resources.BiddingStrategy)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.BiddingStrategyService/GetBiddingStrategy", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *biddingStrategyServiceClient) MutateBiddingStrategies(ctx context.Context, in *MutateBiddingStrategiesRequest, opts ...grpc.CallOption) (*MutateBiddingStrategiesResponse, error) {
	out := new(MutateBiddingStrategiesResponse)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.BiddingStrategyService/MutateBiddingStrategies", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BiddingStrategyServiceServer is the server API for BiddingStrategyService service.
type BiddingStrategyServiceServer interface {
	// Returns the requested bidding strategy in full detail.
	GetBiddingStrategy(context.Context, *GetBiddingStrategyRequest) (*resources.BiddingStrategy, error)
	// Creates, updates, or removes bidding strategies. Operation statuses are
	// returned.
	MutateBiddingStrategies(context.Context, *MutateBiddingStrategiesRequest) (*MutateBiddingStrategiesResponse, error)
}

func RegisterBiddingStrategyServiceServer(s *grpc.Server, srv BiddingStrategyServiceServer) {
	s.RegisterService(&_BiddingStrategyService_serviceDesc, srv)
}

func _BiddingStrategyService_GetBiddingStrategy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBiddingStrategyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BiddingStrategyServiceServer).GetBiddingStrategy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.BiddingStrategyService/GetBiddingStrategy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BiddingStrategyServiceServer).GetBiddingStrategy(ctx, req.(*GetBiddingStrategyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BiddingStrategyService_MutateBiddingStrategies_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MutateBiddingStrategiesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BiddingStrategyServiceServer).MutateBiddingStrategies(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.BiddingStrategyService/MutateBiddingStrategies",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BiddingStrategyServiceServer).MutateBiddingStrategies(ctx, req.(*MutateBiddingStrategiesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _BiddingStrategyService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v1.services.BiddingStrategyService",
	HandlerType: (*BiddingStrategyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetBiddingStrategy",
			Handler:    _BiddingStrategyService_GetBiddingStrategy_Handler,
		},
		{
			MethodName: "MutateBiddingStrategies",
			Handler:    _BiddingStrategyService_MutateBiddingStrategies_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v1/services/bidding_strategy_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/services/bidding_strategy_service.proto", fileDescriptor_bidding_strategy_service_c8276e79a5566ec3)
}

var fileDescriptor_bidding_strategy_service_c8276e79a5566ec3 = []byte{
	// 721 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x95, 0xd1, 0x6a, 0xd4, 0x4c,
	0x14, 0xc7, 0xbf, 0x64, 0x3f, 0xaa, 0x9d, 0x54, 0x85, 0x11, 0x6d, 0xdc, 0x4a, 0xbb, 0xc4, 0x82,
	0x65, 0x2f, 0x12, 0x76, 0x8b, 0x22, 0x59, 0x8a, 0xcd, 0x82, 0x6d, 0x05, 0x6b, 0x4b, 0x0a, 0x15,
	0xca, 0x42, 0x98, 0x6e, 0xa6, 0x21, 0x34, 0xc9, 0xc4, 0x99, 0xc9, 0xca, 0x52, 0x7a, 0xd3, 0x57,
	0xf0, 0xce, 0x4b, 0x2f, 0x7d, 0x0b, 0x7b, 0xe9, 0xad, 0x4f, 0x20, 0x78, 0xa5, 0x2f, 0x21, 0xc9,
	0x64, 0xb6, 0xed, 0xb6, 0x71, 0xa5, 0xbd, 0x3b, 0x39, 0xf3, 0x9f, 0xdf, 0x9c, 0x33, 0xe7, 0xcc,
	0x09, 0x78, 0x19, 0x10, 0x12, 0x44, 0xd8, 0x42, 0x3e, 0xb3, 0x84, 0x99, 0x5b, 0x83, 0x96, 0xc5,
	0x30, 0x1d, 0x84, 0x7d, 0xcc, 0xac, 0xfd, 0xd0, 0xf7, 0xc3, 0x24, 0xf0, 0x18, 0xa7, 0x88, 0xe3,
	0x60, 0xe8, 0x95, 0x2b, 0x66, 0x4a, 0x09, 0x27, 0xb0, 0x21, 0x76, 0x99, 0xc8, 0x67, 0xe6, 0x08,
	0x60, 0x0e, 0x5a, 0xa6, 0x04, 0xd4, 0x5f, 0x54, 0x1d, 0x41, 0x31, 0x23, 0x19, 0xbd, 0xea, 0x0c,
	0xc1, 0xae, 0x3f, 0x96, 0x3b, 0xd3, 0xd0, 0x42, 0x49, 0x42, 0x38, 0xe2, 0x21, 0x49, 0x58, 0xb9,
	0x5a, 0x9e, 0x6c, 0x15, 0x5f, 0xfb, 0xd9, 0x81, 0x75, 0x10, 0xe2, 0xc8, 0xf7, 0x62, 0xc4, 0x0e,
	0x4b, 0xc5, 0xfc, 0xb8, 0xe2, 0x03, 0x45, 0x69, 0x8a, 0xa9, 0x24, 0xcc, 0x96, 0xeb, 0x34, 0xed,
	0x5b, 0x8c, 0x23, 0x9e, 0x95, 0x0b, 0xc6, 0x2a, 0x78, 0xb4, 0x8e, 0x79, 0x57, 0x44, 0xb5, 0x53,
	0x06, 0xe5, 0xe2, 0xf7, 0x19, 0x66, 0x1c, 0x3e, 0x01, 0x77, 0x64, 0xe4, 0x5e, 0x82, 0x62, 0xac,
	0x2b, 0x0d, 0x65, 0x69, 0xda, 0x9d, 0x91, 0xce, 0xb7, 0x28, 0xc6, 0xc6, 0x6f, 0x05, 0xcc, 0x6f,
	0x66, 0x1c, 0x71, 0x7c, 0x91, 0x12, 0x62, 0x26, 0x39, 0x0b, 0x40, 0xeb, 0x67, 0x8c, 0x93, 0x18,
	0x53, 0x2f, 0xf4, 0x4b, 0x0a, 0x90, 0xae, 0xd7, 0x3e, 0xdc, 0x03, 0x80, 0xa4, 0x98, 0x8a, 0xa4,
	0x75, 0xb5, 0x51, 0x5b, 0xd2, 0xda, 0xb6, 0x39, 0xe9, 0xbe, 0xcd, 0xb1, 0xb0, 0xb7, 0x24, 0xc2,
	0x3d, 0x47, 0x83, 0x4f, 0xc1, 0xbd, 0x14, 0x51, 0x1e, 0xa2, 0xc8, 0x3b, 0x40, 0x61, 0x94, 0x51,
	0xac, 0xd7, 0x1a, 0xca, 0xd2, 0x6d, 0xf7, 0x6e, 0xe9, 0x5e, 0x13, 0xde, 0x3c, 0xdb, 0x01, 0x8a,
	0x42, 0x1f, 0x71, 0xec, 0x91, 0x24, 0x1a, 0xea, 0xff, 0x17, 0xb2, 0x19, 0xe9, 0xdc, 0x4a, 0xa2,
	0xa1, 0xf1, 0x49, 0x05, 0x7a, 0xd5, 0xb1, 0xb0, 0x03, 0xb4, 0x2c, 0x2d, 0xf6, 0xe7, 0xa5, 0x29,
	0xf6, 0x6b, 0xed, 0xba, 0xcc, 0x43, 0xd6, 0xc6, 0x5c, 0xcb, 0xab, 0xb7, 0x89, 0xd8, 0xa1, 0x0b,
	0x84, 0x3c, 0xb7, 0xe1, 0x1b, 0x30, 0xd5, 0xa7, 0x18, 0x71, 0x71, 0xcb, 0x5a, 0xbb, 0x5d, 0x99,
	0xff, 0xa8, 0x9b, 0xc6, 0x2f, 0x60, 0xe3, 0x3f, 0xb7, 0x64, 0xe4, 0x34, 0xc1, 0xd6, 0xd5, 0x9b,
	0xd0, 0x04, 0x03, 0xea, 0x60, 0x8a, 0xe2, 0x98, 0x0c, 0xc4, 0xd5, 0x4d, 0xe7, 0x2b, 0xe2, 0xbb,
	0xab, 0x81, 0xe9, 0xd1, 0x5d, 0x1b, 0xa7, 0x0a, 0x58, 0xa8, 0x6c, 0x05, 0x96, 0x92, 0x84, 0x61,
	0xb8, 0x06, 0x1e, 0x8c, 0x95, 0xc3, 0xc3, 0x94, 0x12, 0x5a, 0x90, 0xb5, 0x36, 0x94, 0x71, 0xd2,
	0xb4, 0x6f, 0xee, 0x14, 0x9d, 0xea, 0xde, 0xbf, 0x58, 0xa8, 0x57, 0xb9, 0x1c, 0xbe, 0x03, 0xb7,
	0x28, 0x66, 0x59, 0xc4, 0x65, 0xbf, 0xac, 0x4c, 0xee, 0x97, 0xab, 0x62, 0x1b, 0xba, 0x05, 0xc5,
	0x95, 0x34, 0xa3, 0x0b, 0xe6, 0xfe, 0xa2, 0xfb, 0xa7, 0x37, 0xd1, 0xfe, 0x5a, 0x03, 0x0f, 0xc7,
	0xb6, 0xef, 0x88, 0x20, 0xe0, 0xa9, 0x02, 0xe0, 0xe5, 0x17, 0x07, 0x3b, 0x93, 0xa3, 0xaf, 0x7c,
	0xa7, 0xf5, 0x6b, 0x14, 0xd7, 0xe8, 0x9c, 0x7c, 0xff, 0xf9, 0x51, 0x7d, 0x06, 0x97, 0xf3, 0xf9,
	0x74, 0x74, 0x21, 0xa5, 0x15, 0xf9, 0x32, 0x99, 0xd5, 0x94, 0x03, 0xeb, 0xac, 0x92, 0x56, 0xf3,
	0x18, 0xfe, 0x50, 0xc0, 0x6c, 0x45, 0xa1, 0xe1, 0xea, 0xf5, 0xea, 0x70, 0x36, 0x2e, 0xea, 0xce,
	0x0d, 0x08, 0xa2, 0xcb, 0x0c, 0xa7, 0xc8, 0xae, 0x63, 0x3c, 0xcf, 0xb3, 0x3b, 0x4b, 0xe7, 0xe8,
	0xdc, 0x18, 0x5a, 0x69, 0x1e, 0x5f, 0x4e, 0xce, 0x8e, 0x0b, 0xb0, 0xad, 0x34, 0xbb, 0x27, 0x2a,
	0x58, 0xec, 0x93, 0x78, 0x62, 0x2c, 0xdd, 0xb9, 0xab, 0x2b, 0xbd, 0x9d, 0x3f, 0xf7, 0x6d, 0x65,
	0x6f, 0xa3, 0x04, 0x04, 0x24, 0x42, 0x49, 0x60, 0x12, 0x1a, 0x58, 0x01, 0x4e, 0x8a, 0x61, 0x20,
	0x7f, 0x12, 0x69, 0xc8, 0xaa, 0x7f, 0x4b, 0x1d, 0x69, 0x7c, 0x56, 0x6b, 0xeb, 0x8e, 0xf3, 0x45,
	0x6d, 0xac, 0x0b, 0xa0, 0xe3, 0x33, 0x53, 0x98, 0xb9, 0xb5, 0xdb, 0x32, 0xcb, 0x83, 0xd9, 0x37,
	0x29, 0xe9, 0x39, 0x3e, 0xeb, 0x8d, 0x24, 0xbd, 0xdd, 0x56, 0x4f, 0x4a, 0x7e, 0xa9, 0x8b, 0xc2,
	0x6f, 0xdb, 0x8e, 0xcf, 0x6c, 0x7b, 0x24, 0xb2, 0xed, 0xdd, 0x96, 0x6d, 0x4b, 0xd9, 0xfe, 0x54,
	0x11, 0xe7, 0xf2, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0xd6, 0xf6, 0x59, 0x3d, 0x07, 0x00,
	0x00,
}

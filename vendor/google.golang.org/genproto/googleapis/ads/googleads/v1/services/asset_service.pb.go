// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/services/asset_service.proto

package services // import "google.golang.org/genproto/googleapis/ads/googleads/v1/services"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import resources "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"
import _ "google.golang.org/genproto/googleapis/api/annotations"

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

// Request message for [AssetService.GetAsset][google.ads.googleads.v1.services.AssetService.GetAsset]
type GetAssetRequest struct {
	// The resource name of the asset to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetAssetRequest) Reset()         { *m = GetAssetRequest{} }
func (m *GetAssetRequest) String() string { return proto.CompactTextString(m) }
func (*GetAssetRequest) ProtoMessage()    {}
func (*GetAssetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_asset_service_6973137248fb30b8, []int{0}
}
func (m *GetAssetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetAssetRequest.Unmarshal(m, b)
}
func (m *GetAssetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetAssetRequest.Marshal(b, m, deterministic)
}
func (dst *GetAssetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetAssetRequest.Merge(dst, src)
}
func (m *GetAssetRequest) XXX_Size() int {
	return xxx_messageInfo_GetAssetRequest.Size(m)
}
func (m *GetAssetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetAssetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetAssetRequest proto.InternalMessageInfo

func (m *GetAssetRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

// Request message for [AssetService.MutateAssets][google.ads.googleads.v1.services.AssetService.MutateAssets]
type MutateAssetsRequest struct {
	// The ID of the customer whose assets are being modified.
	CustomerId string `protobuf:"bytes,1,opt,name=customer_id,json=customerId,proto3" json:"customer_id,omitempty"`
	// The list of operations to perform on individual assets.
	Operations           []*AssetOperation `protobuf:"bytes,2,rep,name=operations,proto3" json:"operations,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *MutateAssetsRequest) Reset()         { *m = MutateAssetsRequest{} }
func (m *MutateAssetsRequest) String() string { return proto.CompactTextString(m) }
func (*MutateAssetsRequest) ProtoMessage()    {}
func (*MutateAssetsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_asset_service_6973137248fb30b8, []int{1}
}
func (m *MutateAssetsRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateAssetsRequest.Unmarshal(m, b)
}
func (m *MutateAssetsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateAssetsRequest.Marshal(b, m, deterministic)
}
func (dst *MutateAssetsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateAssetsRequest.Merge(dst, src)
}
func (m *MutateAssetsRequest) XXX_Size() int {
	return xxx_messageInfo_MutateAssetsRequest.Size(m)
}
func (m *MutateAssetsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateAssetsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MutateAssetsRequest proto.InternalMessageInfo

func (m *MutateAssetsRequest) GetCustomerId() string {
	if m != nil {
		return m.CustomerId
	}
	return ""
}

func (m *MutateAssetsRequest) GetOperations() []*AssetOperation {
	if m != nil {
		return m.Operations
	}
	return nil
}

// A single operation to create an asset.
type AssetOperation struct {
	// The mutate operation.
	//
	// Types that are valid to be assigned to Operation:
	//	*AssetOperation_Create
	Operation            isAssetOperation_Operation `protobuf_oneof:"operation"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *AssetOperation) Reset()         { *m = AssetOperation{} }
func (m *AssetOperation) String() string { return proto.CompactTextString(m) }
func (*AssetOperation) ProtoMessage()    {}
func (*AssetOperation) Descriptor() ([]byte, []int) {
	return fileDescriptor_asset_service_6973137248fb30b8, []int{2}
}
func (m *AssetOperation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AssetOperation.Unmarshal(m, b)
}
func (m *AssetOperation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AssetOperation.Marshal(b, m, deterministic)
}
func (dst *AssetOperation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AssetOperation.Merge(dst, src)
}
func (m *AssetOperation) XXX_Size() int {
	return xxx_messageInfo_AssetOperation.Size(m)
}
func (m *AssetOperation) XXX_DiscardUnknown() {
	xxx_messageInfo_AssetOperation.DiscardUnknown(m)
}

var xxx_messageInfo_AssetOperation proto.InternalMessageInfo

type isAssetOperation_Operation interface {
	isAssetOperation_Operation()
}

type AssetOperation_Create struct {
	Create *resources.Asset `protobuf:"bytes,1,opt,name=create,proto3,oneof"`
}

func (*AssetOperation_Create) isAssetOperation_Operation() {}

func (m *AssetOperation) GetOperation() isAssetOperation_Operation {
	if m != nil {
		return m.Operation
	}
	return nil
}

func (m *AssetOperation) GetCreate() *resources.Asset {
	if x, ok := m.GetOperation().(*AssetOperation_Create); ok {
		return x.Create
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*AssetOperation) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _AssetOperation_OneofMarshaler, _AssetOperation_OneofUnmarshaler, _AssetOperation_OneofSizer, []interface{}{
		(*AssetOperation_Create)(nil),
	}
}

func _AssetOperation_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*AssetOperation)
	// operation
	switch x := m.Operation.(type) {
	case *AssetOperation_Create:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Create); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("AssetOperation.Operation has unexpected type %T", x)
	}
	return nil
}

func _AssetOperation_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*AssetOperation)
	switch tag {
	case 1: // operation.create
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.Asset)
		err := b.DecodeMessage(msg)
		m.Operation = &AssetOperation_Create{msg}
		return true, err
	default:
		return false, nil
	}
}

func _AssetOperation_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*AssetOperation)
	// operation
	switch x := m.Operation.(type) {
	case *AssetOperation_Create:
		s := proto.Size(x.Create)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// Response message for an asset mutate.
type MutateAssetsResponse struct {
	// All results for the mutate.
	Results              []*MutateAssetResult `protobuf:"bytes,2,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *MutateAssetsResponse) Reset()         { *m = MutateAssetsResponse{} }
func (m *MutateAssetsResponse) String() string { return proto.CompactTextString(m) }
func (*MutateAssetsResponse) ProtoMessage()    {}
func (*MutateAssetsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_asset_service_6973137248fb30b8, []int{3}
}
func (m *MutateAssetsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateAssetsResponse.Unmarshal(m, b)
}
func (m *MutateAssetsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateAssetsResponse.Marshal(b, m, deterministic)
}
func (dst *MutateAssetsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateAssetsResponse.Merge(dst, src)
}
func (m *MutateAssetsResponse) XXX_Size() int {
	return xxx_messageInfo_MutateAssetsResponse.Size(m)
}
func (m *MutateAssetsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateAssetsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MutateAssetsResponse proto.InternalMessageInfo

func (m *MutateAssetsResponse) GetResults() []*MutateAssetResult {
	if m != nil {
		return m.Results
	}
	return nil
}

// The result for the asset mutate.
type MutateAssetResult struct {
	// The resource name returned for successful operations.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MutateAssetResult) Reset()         { *m = MutateAssetResult{} }
func (m *MutateAssetResult) String() string { return proto.CompactTextString(m) }
func (*MutateAssetResult) ProtoMessage()    {}
func (*MutateAssetResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_asset_service_6973137248fb30b8, []int{4}
}
func (m *MutateAssetResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateAssetResult.Unmarshal(m, b)
}
func (m *MutateAssetResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateAssetResult.Marshal(b, m, deterministic)
}
func (dst *MutateAssetResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateAssetResult.Merge(dst, src)
}
func (m *MutateAssetResult) XXX_Size() int {
	return xxx_messageInfo_MutateAssetResult.Size(m)
}
func (m *MutateAssetResult) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateAssetResult.DiscardUnknown(m)
}

var xxx_messageInfo_MutateAssetResult proto.InternalMessageInfo

func (m *MutateAssetResult) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetAssetRequest)(nil), "google.ads.googleads.v1.services.GetAssetRequest")
	proto.RegisterType((*MutateAssetsRequest)(nil), "google.ads.googleads.v1.services.MutateAssetsRequest")
	proto.RegisterType((*AssetOperation)(nil), "google.ads.googleads.v1.services.AssetOperation")
	proto.RegisterType((*MutateAssetsResponse)(nil), "google.ads.googleads.v1.services.MutateAssetsResponse")
	proto.RegisterType((*MutateAssetResult)(nil), "google.ads.googleads.v1.services.MutateAssetResult")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AssetServiceClient is the client API for AssetService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AssetServiceClient interface {
	// Returns the requested asset in full detail.
	GetAsset(ctx context.Context, in *GetAssetRequest, opts ...grpc.CallOption) (*resources.Asset, error)
	// Creates assets. Operation statuses are returned.
	MutateAssets(ctx context.Context, in *MutateAssetsRequest, opts ...grpc.CallOption) (*MutateAssetsResponse, error)
}

type assetServiceClient struct {
	cc *grpc.ClientConn
}

func NewAssetServiceClient(cc *grpc.ClientConn) AssetServiceClient {
	return &assetServiceClient{cc}
}

func (c *assetServiceClient) GetAsset(ctx context.Context, in *GetAssetRequest, opts ...grpc.CallOption) (*resources.Asset, error) {
	out := new(resources.Asset)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.AssetService/GetAsset", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *assetServiceClient) MutateAssets(ctx context.Context, in *MutateAssetsRequest, opts ...grpc.CallOption) (*MutateAssetsResponse, error) {
	out := new(MutateAssetsResponse)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.AssetService/MutateAssets", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AssetServiceServer is the server API for AssetService service.
type AssetServiceServer interface {
	// Returns the requested asset in full detail.
	GetAsset(context.Context, *GetAssetRequest) (*resources.Asset, error)
	// Creates assets. Operation statuses are returned.
	MutateAssets(context.Context, *MutateAssetsRequest) (*MutateAssetsResponse, error)
}

func RegisterAssetServiceServer(s *grpc.Server, srv AssetServiceServer) {
	s.RegisterService(&_AssetService_serviceDesc, srv)
}

func _AssetService_GetAsset_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAssetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AssetServiceServer).GetAsset(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.AssetService/GetAsset",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AssetServiceServer).GetAsset(ctx, req.(*GetAssetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AssetService_MutateAssets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MutateAssetsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AssetServiceServer).MutateAssets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.AssetService/MutateAssets",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AssetServiceServer).MutateAssets(ctx, req.(*MutateAssetsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AssetService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v1.services.AssetService",
	HandlerType: (*AssetServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAsset",
			Handler:    _AssetService_GetAsset_Handler,
		},
		{
			MethodName: "MutateAssets",
			Handler:    _AssetService_MutateAssets_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v1/services/asset_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/services/asset_service.proto", fileDescriptor_asset_service_6973137248fb30b8)
}

var fileDescriptor_asset_service_6973137248fb30b8 = []byte{
	// 520 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0xbf, 0x6f, 0xd3, 0x40,
	0x14, 0xc6, 0xae, 0x54, 0xe8, 0x25, 0x80, 0x7a, 0x30, 0x54, 0x11, 0x12, 0x91, 0xe9, 0x10, 0x19,
	0x71, 0x8e, 0x53, 0x88, 0xd0, 0xa1, 0x0e, 0xce, 0x92, 0x32, 0x14, 0x22, 0x23, 0x65, 0x40, 0x91,
	0xa2, 0x23, 0x3e, 0x59, 0x96, 0x62, 0x9f, 0xf1, 0x3b, 0x67, 0xa9, 0xba, 0x30, 0xb1, 0x33, 0xb1,
	0x32, 0xb2, 0xf3, 0x4f, 0xb0, 0xf2, 0x1f, 0x20, 0x26, 0xfe, 0x02, 0x46, 0x64, 0x9f, 0xcf, 0x38,
	0x54, 0x51, 0x9a, 0xed, 0xf9, 0xee, 0xfb, 0xbe, 0xf7, 0xbd, 0x1f, 0x67, 0xf4, 0x34, 0x14, 0x22,
	0x5c, 0x72, 0x87, 0x05, 0xe0, 0xa8, 0xb0, 0x88, 0x56, 0xae, 0x03, 0x3c, 0x5b, 0x45, 0x0b, 0x0e,
	0x0e, 0x03, 0xe0, 0x72, 0x5e, 0x7d, 0x92, 0x34, 0x13, 0x52, 0xe0, 0xae, 0x82, 0x12, 0x16, 0x00,
	0xa9, 0x59, 0x64, 0xe5, 0x12, 0xcd, 0xea, 0x3c, 0xd9, 0xa4, 0x9b, 0x71, 0x10, 0x79, 0x56, 0x0b,
	0x2b, 0xc1, 0xce, 0x03, 0x0d, 0x4f, 0x23, 0x87, 0x25, 0x89, 0x90, 0x4c, 0x46, 0x22, 0x01, 0x75,
	0x6b, 0x0d, 0xd1, 0xdd, 0x31, 0x97, 0x5e, 0x81, 0xf7, 0xf9, 0xfb, 0x9c, 0x83, 0xc4, 0x8f, 0xd0,
	0x6d, 0xad, 0x34, 0x4f, 0x58, 0xcc, 0x8f, 0x8c, 0xae, 0xd1, 0x3b, 0xf0, 0xdb, 0xfa, 0xf0, 0x15,
	0x8b, 0xb9, 0xf5, 0xd1, 0x40, 0xf7, 0xce, 0x73, 0xc9, 0x24, 0x2f, 0xb9, 0xa0, 0xc9, 0x0f, 0x51,
	0x6b, 0x91, 0x83, 0x14, 0x31, 0xcf, 0xe6, 0x51, 0x50, 0x51, 0x91, 0x3e, 0x7a, 0x19, 0xe0, 0x09,
	0x42, 0x22, 0xe5, 0x99, 0x32, 0x71, 0x64, 0x76, 0xf7, 0x7a, 0xad, 0x41, 0x9f, 0x6c, 0x2b, 0x9a,
	0x94, 0x59, 0x5e, 0x6b, 0xa2, 0xdf, 0xd0, 0xb0, 0x18, 0xba, 0xb3, 0x7e, 0x8b, 0x47, 0x68, 0x7f,
	0x91, 0x71, 0x26, 0x95, 0xf5, 0xd6, 0xa0, 0xb7, 0x51, 0xbf, 0x6e, 0x99, 0x4a, 0x70, 0x76, 0xc3,
	0xaf, 0x98, 0xa3, 0x16, 0x3a, 0xa8, 0x73, 0x58, 0x1c, 0xdd, 0x5f, 0x2f, 0x16, 0x52, 0x91, 0x00,
	0xc7, 0xe7, 0xe8, 0x66, 0xc6, 0x21, 0x5f, 0x4a, 0x5d, 0xc9, 0xc9, 0xf6, 0x4a, 0x1a, 0x42, 0x7e,
	0xc9, 0xf5, 0xb5, 0x86, 0xf5, 0x1c, 0x1d, 0x5e, 0xb9, 0xbd, 0xd6, 0x38, 0x06, 0x3f, 0x4d, 0xd4,
	0x2e, 0x49, 0x6f, 0x54, 0x1a, 0xfc, 0xd9, 0x40, 0xb7, 0xf4, 0x60, 0xb1, 0xbb, 0xdd, 0xd5, 0x7f,
	0x4b, 0xd0, 0xb9, 0x76, 0xcb, 0xac, 0xfe, 0x87, 0x1f, 0xbf, 0x3e, 0x99, 0x36, 0xee, 0x15, 0x2b,
	0x78, 0xb1, 0x66, 0xf5, 0x54, 0xcf, 0x1d, 0x1c, 0x5b, 0xed, 0x24, 0x38, 0xf6, 0x25, 0xfe, 0x66,
	0xa0, 0x76, 0xb3, 0x9d, 0xf8, 0xd9, 0x4e, 0x5d, 0xd3, 0xbb, 0xd6, 0x19, 0xee, 0x4a, 0x53, 0x53,
	0xb3, 0x86, 0xa5, 0xe3, 0xbe, 0xf5, 0xb8, 0x70, 0xfc, 0xcf, 0xe2, 0x45, 0x63, 0x71, 0x4f, 0xed,
	0xcb, 0xca, 0x30, 0x8d, 0x4b, 0x09, 0x6a, 0xd8, 0xa3, 0x3f, 0x06, 0x3a, 0x5e, 0x88, 0x78, 0x6b,
	0xd6, 0xd1, 0x61, 0x73, 0x14, 0x93, 0xe2, 0x9d, 0x4d, 0x8c, 0xb7, 0x67, 0x15, 0x2d, 0x14, 0x4b,
	0x96, 0x84, 0x44, 0x64, 0xa1, 0x13, 0xf2, 0xa4, 0x7c, 0x85, 0xfa, 0x19, 0xa7, 0x11, 0x6c, 0xfe,
	0x5b, 0xbc, 0xd0, 0xc1, 0x17, 0x73, 0x6f, 0xec, 0x79, 0x5f, 0xcd, 0xee, 0x58, 0x09, 0x7a, 0x01,
	0x10, 0x15, 0x16, 0xd1, 0xd4, 0x25, 0x55, 0x62, 0xf8, 0xae, 0x21, 0x33, 0x2f, 0x80, 0x59, 0x0d,
	0x99, 0x4d, 0xdd, 0x99, 0x86, 0xfc, 0x36, 0x8f, 0xd5, 0x39, 0xa5, 0x5e, 0x00, 0x94, 0xd6, 0x20,
	0x4a, 0xa7, 0x2e, 0xa5, 0x1a, 0xf6, 0x6e, 0xbf, 0xf4, 0x79, 0xf2, 0x37, 0x00, 0x00, 0xff, 0xff,
	0xc0, 0xa5, 0x7e, 0xbf, 0xd4, 0x04, 0x00, 0x00,
}

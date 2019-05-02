// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v0/services/account_budget_service.proto

package services // import "google.golang.org/genproto/googleapis/ads/googleads/v0/services"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import resources "google.golang.org/genproto/googleapis/ads/googleads/v0/resources"
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

// Request message for
// [AccountBudgetService.GetAccountBudget][google.ads.googleads.v0.services.AccountBudgetService.GetAccountBudget].
type GetAccountBudgetRequest struct {
	// The resource name of the account-level budget to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetAccountBudgetRequest) Reset()         { *m = GetAccountBudgetRequest{} }
func (m *GetAccountBudgetRequest) String() string { return proto.CompactTextString(m) }
func (*GetAccountBudgetRequest) ProtoMessage()    {}
func (*GetAccountBudgetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_account_budget_service_18e5ccab714ba478, []int{0}
}
func (m *GetAccountBudgetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetAccountBudgetRequest.Unmarshal(m, b)
}
func (m *GetAccountBudgetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetAccountBudgetRequest.Marshal(b, m, deterministic)
}
func (dst *GetAccountBudgetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetAccountBudgetRequest.Merge(dst, src)
}
func (m *GetAccountBudgetRequest) XXX_Size() int {
	return xxx_messageInfo_GetAccountBudgetRequest.Size(m)
}
func (m *GetAccountBudgetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetAccountBudgetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetAccountBudgetRequest proto.InternalMessageInfo

func (m *GetAccountBudgetRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetAccountBudgetRequest)(nil), "google.ads.googleads.v0.services.GetAccountBudgetRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AccountBudgetServiceClient is the client API for AccountBudgetService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AccountBudgetServiceClient interface {
	// Returns an account-level budget in full detail.
	GetAccountBudget(ctx context.Context, in *GetAccountBudgetRequest, opts ...grpc.CallOption) (*resources.AccountBudget, error)
}

type accountBudgetServiceClient struct {
	cc *grpc.ClientConn
}

func NewAccountBudgetServiceClient(cc *grpc.ClientConn) AccountBudgetServiceClient {
	return &accountBudgetServiceClient{cc}
}

func (c *accountBudgetServiceClient) GetAccountBudget(ctx context.Context, in *GetAccountBudgetRequest, opts ...grpc.CallOption) (*resources.AccountBudget, error) {
	out := new(resources.AccountBudget)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v0.services.AccountBudgetService/GetAccountBudget", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccountBudgetServiceServer is the server API for AccountBudgetService service.
type AccountBudgetServiceServer interface {
	// Returns an account-level budget in full detail.
	GetAccountBudget(context.Context, *GetAccountBudgetRequest) (*resources.AccountBudget, error)
}

func RegisterAccountBudgetServiceServer(s *grpc.Server, srv AccountBudgetServiceServer) {
	s.RegisterService(&_AccountBudgetService_serviceDesc, srv)
}

func _AccountBudgetService_GetAccountBudget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAccountBudgetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountBudgetServiceServer).GetAccountBudget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v0.services.AccountBudgetService/GetAccountBudget",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountBudgetServiceServer).GetAccountBudget(ctx, req.(*GetAccountBudgetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AccountBudgetService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v0.services.AccountBudgetService",
	HandlerType: (*AccountBudgetServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAccountBudget",
			Handler:    _AccountBudgetService_GetAccountBudget_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v0/services/account_budget_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v0/services/account_budget_service.proto", fileDescriptor_account_budget_service_18e5ccab714ba478)
}

var fileDescriptor_account_budget_service_18e5ccab714ba478 = []byte{
	// 363 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0x4f, 0x4a, 0xf3, 0x40,
	0x18, 0xc6, 0x49, 0x3e, 0xf8, 0xc0, 0xa0, 0x20, 0x41, 0x50, 0x8b, 0x8b, 0x52, 0xbb, 0x90, 0x2e,
	0x66, 0x86, 0x0a, 0xa2, 0x23, 0x15, 0xd2, 0x4d, 0x5d, 0x49, 0xa9, 0xd0, 0x85, 0x04, 0xca, 0x34,
	0x19, 0x86, 0x40, 0x33, 0x53, 0xf3, 0x4e, 0xba, 0x11, 0x41, 0xbc, 0x82, 0x37, 0x70, 0xe9, 0x0d,
	0xbc, 0x82, 0x4b, 0xbd, 0x82, 0x2b, 0x4f, 0x21, 0xe9, 0x74, 0x02, 0x51, 0x43, 0x77, 0x0f, 0x6f,
	0x9e, 0xdf, 0xfb, 0xe7, 0xc9, 0x78, 0x3d, 0xa1, 0x94, 0x98, 0x71, 0xcc, 0x62, 0xc0, 0x46, 0x16,
	0x6a, 0x41, 0x30, 0xf0, 0x6c, 0x91, 0x44, 0x1c, 0x30, 0x8b, 0x22, 0x95, 0x4b, 0x3d, 0x99, 0xe6,
	0xb1, 0xe0, 0x7a, 0xb2, 0xaa, 0xa3, 0x79, 0xa6, 0xb4, 0xf2, 0x9b, 0x86, 0x41, 0x2c, 0x06, 0x54,
	0xe2, 0x68, 0x41, 0x90, 0xc5, 0x1b, 0x27, 0x75, 0x03, 0x32, 0x0e, 0x2a, 0xcf, 0x7e, 0x4f, 0x30,
	0x9d, 0x1b, 0x07, 0x96, 0x9b, 0x27, 0x98, 0x49, 0xa9, 0x34, 0xd3, 0x89, 0x92, 0x60, 0xbe, 0xb6,
	0x2e, 0xbc, 0xdd, 0x01, 0xd7, 0x81, 0x01, 0xfb, 0x4b, 0x6e, 0xc4, 0x6f, 0x73, 0x0e, 0xda, 0x3f,
	0xf4, 0xb6, 0x6c, 0xeb, 0x89, 0x64, 0x29, 0xdf, 0x73, 0x9a, 0xce, 0xd1, 0xc6, 0x68, 0xd3, 0x16,
	0xaf, 0x58, 0xca, 0xbb, 0xef, 0x8e, 0xb7, 0x53, 0xa1, 0xaf, 0xcd, 0xbe, 0xfe, 0xab, 0xe3, 0x6d,
	0xff, 0xec, 0xec, 0x9f, 0xa1, 0x75, 0x67, 0xa2, 0x9a, 0x6d, 0x1a, 0xa4, 0x16, 0x2d, 0xef, 0x47,
	0x15, 0xb0, 0x75, 0xfa, 0xf8, 0xf1, 0xf9, 0xe4, 0x76, 0x7d, 0x52, 0x84, 0x74, 0x57, 0x39, 0xa5,
	0x17, 0xe5, 0xa0, 0x55, 0xca, 0x33, 0xc0, 0x1d, 0x9b, 0x9a, 0xa1, 0x00, 0x77, 0xee, 0xfb, 0x0f,
	0xae, 0xd7, 0x8e, 0x54, 0xba, 0x76, 0xd9, 0xfe, 0xfe, 0x5f, 0xa7, 0x0f, 0x8b, 0x60, 0x87, 0xce,
	0xcd, 0xe5, 0x0a, 0x17, 0x6a, 0xc6, 0xa4, 0x40, 0x2a, 0x13, 0x58, 0x70, 0xb9, 0x8c, 0xdd, 0xfe,
	0xc0, 0x79, 0x02, 0xf5, 0x0f, 0xe6, 0xdc, 0x8a, 0x67, 0xf7, 0xdf, 0x20, 0x08, 0x5e, 0xdc, 0xe6,
	0xc0, 0x34, 0x0c, 0x62, 0x40, 0x46, 0x16, 0x6a, 0x4c, 0xd0, 0x6a, 0x30, 0xbc, 0x59, 0x4b, 0x18,
	0xc4, 0x10, 0x96, 0x96, 0x70, 0x4c, 0x42, 0x6b, 0xf9, 0x72, 0xdb, 0xa6, 0x4e, 0x69, 0x10, 0x03,
	0xa5, 0xa5, 0x89, 0xd2, 0x31, 0xa1, 0xd4, 0xda, 0xa6, 0xff, 0x97, 0x7b, 0x1e, 0x7f, 0x07, 0x00,
	0x00, 0xff, 0xff, 0xef, 0xf9, 0x6f, 0x58, 0xd7, 0x02, 0x00, 0x00,
}

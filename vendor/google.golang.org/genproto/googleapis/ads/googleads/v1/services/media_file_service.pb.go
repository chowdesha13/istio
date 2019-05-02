// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/services/media_file_service.proto

package services // import "google.golang.org/genproto/googleapis/ads/googleads/v1/services"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/golang/protobuf/ptypes/wrappers"
import resources "google.golang.org/genproto/googleapis/ads/googleads/v1/resources"
import _ "google.golang.org/genproto/googleapis/api/annotations"
import status "google.golang.org/genproto/googleapis/rpc/status"

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

// Request message for [MediaFileService.GetMediaFile][google.ads.googleads.v1.services.MediaFileService.GetMediaFile]
type GetMediaFileRequest struct {
	// The resource name of the media file to fetch.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetMediaFileRequest) Reset()         { *m = GetMediaFileRequest{} }
func (m *GetMediaFileRequest) String() string { return proto.CompactTextString(m) }
func (*GetMediaFileRequest) ProtoMessage()    {}
func (*GetMediaFileRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_media_file_service_52854e541380429c, []int{0}
}
func (m *GetMediaFileRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetMediaFileRequest.Unmarshal(m, b)
}
func (m *GetMediaFileRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetMediaFileRequest.Marshal(b, m, deterministic)
}
func (dst *GetMediaFileRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetMediaFileRequest.Merge(dst, src)
}
func (m *GetMediaFileRequest) XXX_Size() int {
	return xxx_messageInfo_GetMediaFileRequest.Size(m)
}
func (m *GetMediaFileRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetMediaFileRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetMediaFileRequest proto.InternalMessageInfo

func (m *GetMediaFileRequest) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

// Request message for [MediaFileService.MutateMediaFiles][google.ads.googleads.v1.services.MediaFileService.MutateMediaFiles]
type MutateMediaFilesRequest struct {
	// The ID of the customer whose media files are being modified.
	CustomerId string `protobuf:"bytes,1,opt,name=customer_id,json=customerId,proto3" json:"customer_id,omitempty"`
	// The list of operations to perform on individual media file.
	Operations []*MediaFileOperation `protobuf:"bytes,2,rep,name=operations,proto3" json:"operations,omitempty"`
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

func (m *MutateMediaFilesRequest) Reset()         { *m = MutateMediaFilesRequest{} }
func (m *MutateMediaFilesRequest) String() string { return proto.CompactTextString(m) }
func (*MutateMediaFilesRequest) ProtoMessage()    {}
func (*MutateMediaFilesRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_media_file_service_52854e541380429c, []int{1}
}
func (m *MutateMediaFilesRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateMediaFilesRequest.Unmarshal(m, b)
}
func (m *MutateMediaFilesRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateMediaFilesRequest.Marshal(b, m, deterministic)
}
func (dst *MutateMediaFilesRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateMediaFilesRequest.Merge(dst, src)
}
func (m *MutateMediaFilesRequest) XXX_Size() int {
	return xxx_messageInfo_MutateMediaFilesRequest.Size(m)
}
func (m *MutateMediaFilesRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateMediaFilesRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MutateMediaFilesRequest proto.InternalMessageInfo

func (m *MutateMediaFilesRequest) GetCustomerId() string {
	if m != nil {
		return m.CustomerId
	}
	return ""
}

func (m *MutateMediaFilesRequest) GetOperations() []*MediaFileOperation {
	if m != nil {
		return m.Operations
	}
	return nil
}

func (m *MutateMediaFilesRequest) GetPartialFailure() bool {
	if m != nil {
		return m.PartialFailure
	}
	return false
}

func (m *MutateMediaFilesRequest) GetValidateOnly() bool {
	if m != nil {
		return m.ValidateOnly
	}
	return false
}

// A single operation to create media file.
type MediaFileOperation struct {
	// The mutate operation.
	//
	// Types that are valid to be assigned to Operation:
	//	*MediaFileOperation_Create
	Operation            isMediaFileOperation_Operation `protobuf_oneof:"operation"`
	XXX_NoUnkeyedLiteral struct{}                       `json:"-"`
	XXX_unrecognized     []byte                         `json:"-"`
	XXX_sizecache        int32                          `json:"-"`
}

func (m *MediaFileOperation) Reset()         { *m = MediaFileOperation{} }
func (m *MediaFileOperation) String() string { return proto.CompactTextString(m) }
func (*MediaFileOperation) ProtoMessage()    {}
func (*MediaFileOperation) Descriptor() ([]byte, []int) {
	return fileDescriptor_media_file_service_52854e541380429c, []int{2}
}
func (m *MediaFileOperation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MediaFileOperation.Unmarshal(m, b)
}
func (m *MediaFileOperation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MediaFileOperation.Marshal(b, m, deterministic)
}
func (dst *MediaFileOperation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MediaFileOperation.Merge(dst, src)
}
func (m *MediaFileOperation) XXX_Size() int {
	return xxx_messageInfo_MediaFileOperation.Size(m)
}
func (m *MediaFileOperation) XXX_DiscardUnknown() {
	xxx_messageInfo_MediaFileOperation.DiscardUnknown(m)
}

var xxx_messageInfo_MediaFileOperation proto.InternalMessageInfo

type isMediaFileOperation_Operation interface {
	isMediaFileOperation_Operation()
}

type MediaFileOperation_Create struct {
	Create *resources.MediaFile `protobuf:"bytes,1,opt,name=create,proto3,oneof"`
}

func (*MediaFileOperation_Create) isMediaFileOperation_Operation() {}

func (m *MediaFileOperation) GetOperation() isMediaFileOperation_Operation {
	if m != nil {
		return m.Operation
	}
	return nil
}

func (m *MediaFileOperation) GetCreate() *resources.MediaFile {
	if x, ok := m.GetOperation().(*MediaFileOperation_Create); ok {
		return x.Create
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*MediaFileOperation) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _MediaFileOperation_OneofMarshaler, _MediaFileOperation_OneofUnmarshaler, _MediaFileOperation_OneofSizer, []interface{}{
		(*MediaFileOperation_Create)(nil),
	}
}

func _MediaFileOperation_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*MediaFileOperation)
	// operation
	switch x := m.Operation.(type) {
	case *MediaFileOperation_Create:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Create); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("MediaFileOperation.Operation has unexpected type %T", x)
	}
	return nil
}

func _MediaFileOperation_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*MediaFileOperation)
	switch tag {
	case 1: // operation.create
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(resources.MediaFile)
		err := b.DecodeMessage(msg)
		m.Operation = &MediaFileOperation_Create{msg}
		return true, err
	default:
		return false, nil
	}
}

func _MediaFileOperation_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*MediaFileOperation)
	// operation
	switch x := m.Operation.(type) {
	case *MediaFileOperation_Create:
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

// Response message for a media file mutate.
type MutateMediaFilesResponse struct {
	// Errors that pertain to operation failures in the partial failure mode.
	// Returned only when partial_failure = true and all errors occur inside the
	// operations. If any errors occur outside the operations (e.g. auth errors),
	// we return an RPC level error.
	PartialFailureError *status.Status `protobuf:"bytes,3,opt,name=partial_failure_error,json=partialFailureError,proto3" json:"partial_failure_error,omitempty"`
	// All results for the mutate.
	Results              []*MutateMediaFileResult `protobuf:"bytes,2,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *MutateMediaFilesResponse) Reset()         { *m = MutateMediaFilesResponse{} }
func (m *MutateMediaFilesResponse) String() string { return proto.CompactTextString(m) }
func (*MutateMediaFilesResponse) ProtoMessage()    {}
func (*MutateMediaFilesResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_media_file_service_52854e541380429c, []int{3}
}
func (m *MutateMediaFilesResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateMediaFilesResponse.Unmarshal(m, b)
}
func (m *MutateMediaFilesResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateMediaFilesResponse.Marshal(b, m, deterministic)
}
func (dst *MutateMediaFilesResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateMediaFilesResponse.Merge(dst, src)
}
func (m *MutateMediaFilesResponse) XXX_Size() int {
	return xxx_messageInfo_MutateMediaFilesResponse.Size(m)
}
func (m *MutateMediaFilesResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateMediaFilesResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MutateMediaFilesResponse proto.InternalMessageInfo

func (m *MutateMediaFilesResponse) GetPartialFailureError() *status.Status {
	if m != nil {
		return m.PartialFailureError
	}
	return nil
}

func (m *MutateMediaFilesResponse) GetResults() []*MutateMediaFileResult {
	if m != nil {
		return m.Results
	}
	return nil
}

// The result for the media file mutate.
type MutateMediaFileResult struct {
	// The resource name returned for successful operations.
	ResourceName         string   `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MutateMediaFileResult) Reset()         { *m = MutateMediaFileResult{} }
func (m *MutateMediaFileResult) String() string { return proto.CompactTextString(m) }
func (*MutateMediaFileResult) ProtoMessage()    {}
func (*MutateMediaFileResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_media_file_service_52854e541380429c, []int{4}
}
func (m *MutateMediaFileResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MutateMediaFileResult.Unmarshal(m, b)
}
func (m *MutateMediaFileResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MutateMediaFileResult.Marshal(b, m, deterministic)
}
func (dst *MutateMediaFileResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MutateMediaFileResult.Merge(dst, src)
}
func (m *MutateMediaFileResult) XXX_Size() int {
	return xxx_messageInfo_MutateMediaFileResult.Size(m)
}
func (m *MutateMediaFileResult) XXX_DiscardUnknown() {
	xxx_messageInfo_MutateMediaFileResult.DiscardUnknown(m)
}

var xxx_messageInfo_MutateMediaFileResult proto.InternalMessageInfo

func (m *MutateMediaFileResult) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetMediaFileRequest)(nil), "google.ads.googleads.v1.services.GetMediaFileRequest")
	proto.RegisterType((*MutateMediaFilesRequest)(nil), "google.ads.googleads.v1.services.MutateMediaFilesRequest")
	proto.RegisterType((*MediaFileOperation)(nil), "google.ads.googleads.v1.services.MediaFileOperation")
	proto.RegisterType((*MutateMediaFilesResponse)(nil), "google.ads.googleads.v1.services.MutateMediaFilesResponse")
	proto.RegisterType((*MutateMediaFileResult)(nil), "google.ads.googleads.v1.services.MutateMediaFileResult")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MediaFileServiceClient is the client API for MediaFileService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MediaFileServiceClient interface {
	// Returns the requested media file in full detail.
	GetMediaFile(ctx context.Context, in *GetMediaFileRequest, opts ...grpc.CallOption) (*resources.MediaFile, error)
	// Creates media files. Operation statuses are returned.
	MutateMediaFiles(ctx context.Context, in *MutateMediaFilesRequest, opts ...grpc.CallOption) (*MutateMediaFilesResponse, error)
}

type mediaFileServiceClient struct {
	cc *grpc.ClientConn
}

func NewMediaFileServiceClient(cc *grpc.ClientConn) MediaFileServiceClient {
	return &mediaFileServiceClient{cc}
}

func (c *mediaFileServiceClient) GetMediaFile(ctx context.Context, in *GetMediaFileRequest, opts ...grpc.CallOption) (*resources.MediaFile, error) {
	out := new(resources.MediaFile)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.MediaFileService/GetMediaFile", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mediaFileServiceClient) MutateMediaFiles(ctx context.Context, in *MutateMediaFilesRequest, opts ...grpc.CallOption) (*MutateMediaFilesResponse, error) {
	out := new(MutateMediaFilesResponse)
	err := c.cc.Invoke(ctx, "/google.ads.googleads.v1.services.MediaFileService/MutateMediaFiles", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MediaFileServiceServer is the server API for MediaFileService service.
type MediaFileServiceServer interface {
	// Returns the requested media file in full detail.
	GetMediaFile(context.Context, *GetMediaFileRequest) (*resources.MediaFile, error)
	// Creates media files. Operation statuses are returned.
	MutateMediaFiles(context.Context, *MutateMediaFilesRequest) (*MutateMediaFilesResponse, error)
}

func RegisterMediaFileServiceServer(s *grpc.Server, srv MediaFileServiceServer) {
	s.RegisterService(&_MediaFileService_serviceDesc, srv)
}

func _MediaFileService_GetMediaFile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetMediaFileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MediaFileServiceServer).GetMediaFile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.MediaFileService/GetMediaFile",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MediaFileServiceServer).GetMediaFile(ctx, req.(*GetMediaFileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MediaFileService_MutateMediaFiles_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MutateMediaFilesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MediaFileServiceServer).MutateMediaFiles(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.ads.googleads.v1.services.MediaFileService/MutateMediaFiles",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MediaFileServiceServer).MutateMediaFiles(ctx, req.(*MutateMediaFilesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _MediaFileService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.ads.googleads.v1.services.MediaFileService",
	HandlerType: (*MediaFileServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetMediaFile",
			Handler:    _MediaFileService_GetMediaFile_Handler,
		},
		{
			MethodName: "MutateMediaFiles",
			Handler:    _MediaFileService_MutateMediaFiles_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/ads/googleads/v1/services/media_file_service.proto",
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/services/media_file_service.proto", fileDescriptor_media_file_service_52854e541380429c)
}

var fileDescriptor_media_file_service_52854e541380429c = []byte{
	// 646 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x54, 0xcd, 0x6e, 0xd3, 0x4c,
	0x14, 0xfd, 0x9c, 0x7c, 0x2a, 0x74, 0x52, 0xa0, 0x9a, 0xaa, 0x6a, 0x14, 0x21, 0x88, 0x4c, 0x25,
	0xaa, 0xa8, 0x1a, 0x2b, 0xa1, 0x08, 0x75, 0xa0, 0x8b, 0x54, 0x22, 0x2d, 0x8b, 0xd2, 0xe2, 0xa2,
	0x2e, 0x50, 0x24, 0x6b, 0x6a, 0x4f, 0xad, 0x91, 0x6c, 0x8f, 0x99, 0x19, 0x07, 0x55, 0x55, 0x37,
	0x2c, 0x78, 0x01, 0xde, 0x80, 0x1d, 0xec, 0x79, 0x04, 0x36, 0x6c, 0xd9, 0xb3, 0x62, 0xc5, 0x33,
	0xb0, 0x40, 0xf6, 0x78, 0xdc, 0xa4, 0x3f, 0x6a, 0xcb, 0xee, 0xfa, 0xde, 0x73, 0xee, 0x3d, 0xf7,
	0xc7, 0x03, 0x56, 0x43, 0xce, 0xc3, 0x88, 0x3a, 0x24, 0x90, 0x8e, 0x36, 0x73, 0x6b, 0xd4, 0x75,
	0x24, 0x15, 0x23, 0xe6, 0x53, 0xe9, 0xc4, 0x34, 0x60, 0xc4, 0x3b, 0x60, 0x11, 0xf5, 0x4a, 0x1f,
	0x4a, 0x05, 0x57, 0x1c, 0xb6, 0x35, 0x1e, 0x91, 0x40, 0xa2, 0x8a, 0x8a, 0x46, 0x5d, 0x64, 0xa8,
	0xad, 0xde, 0x45, 0xc9, 0x05, 0x95, 0x3c, 0x13, 0x93, 0xd9, 0x75, 0xd6, 0xd6, 0x5d, 0xc3, 0x49,
	0x99, 0x43, 0x92, 0x84, 0x2b, 0xa2, 0x18, 0x4f, 0x64, 0x19, 0xbd, 0x57, 0x46, 0x8b, 0xaf, 0xfd,
	0xec, 0xc0, 0x79, 0x27, 0x48, 0x9a, 0x52, 0x61, 0xe2, 0x0b, 0x65, 0x5c, 0xa4, 0xbe, 0x23, 0x15,
	0x51, 0x59, 0x19, 0xb0, 0x31, 0x98, 0xdb, 0xa0, 0x6a, 0x2b, 0xaf, 0x36, 0x60, 0x11, 0x75, 0xe9,
	0xdb, 0x8c, 0x4a, 0x05, 0x1f, 0x80, 0x5b, 0x46, 0x8b, 0x97, 0x90, 0x98, 0x36, 0xad, 0xb6, 0xb5,
	0x34, 0xed, 0xce, 0x18, 0xe7, 0x4b, 0x12, 0x53, 0xfb, 0xa7, 0x05, 0x16, 0xb6, 0x32, 0x45, 0x14,
	0xad, 0xf8, 0xd2, 0x24, 0xb8, 0x0f, 0x1a, 0x7e, 0x26, 0x15, 0x8f, 0xa9, 0xf0, 0x58, 0x50, 0xd2,
	0x81, 0x71, 0xbd, 0x08, 0xe0, 0x6b, 0x00, 0x78, 0x4a, 0x85, 0xee, 0xa2, 0x59, 0x6b, 0xd7, 0x97,
	0x1a, 0xbd, 0x15, 0x74, 0xd9, 0xe8, 0x50, 0x55, 0x69, 0xdb, 0x90, 0xdd, 0xb1, 0x3c, 0xf0, 0x21,
	0xb8, 0x93, 0x12, 0xa1, 0x18, 0x89, 0xbc, 0x03, 0xc2, 0xa2, 0x4c, 0xd0, 0x66, 0xbd, 0x6d, 0x2d,
	0xdd, 0x74, 0x6f, 0x97, 0xee, 0x81, 0xf6, 0xe6, 0x0d, 0x8e, 0x48, 0xc4, 0x02, 0xa2, 0xa8, 0xc7,
	0x93, 0xe8, 0xb0, 0xf9, 0x7f, 0x01, 0x9b, 0x31, 0xce, 0xed, 0x24, 0x3a, 0xb4, 0x19, 0x80, 0x67,
	0xeb, 0xc1, 0x01, 0x98, 0xf2, 0x05, 0x25, 0x4a, 0x0f, 0xa5, 0xd1, 0x5b, 0xbe, 0x50, 0x75, 0xb5,
	0xce, 0x13, 0xd9, 0x9b, 0xff, 0xb9, 0x25, 0x7b, 0xbd, 0x01, 0xa6, 0x2b, 0xe5, 0xf6, 0x57, 0x0b,
	0x34, 0xcf, 0xce, 0x52, 0xa6, 0x3c, 0x91, 0x14, 0x0e, 0xc0, 0xfc, 0xa9, 0xae, 0x3c, 0x2a, 0x04,
	0x17, 0x45, 0x6f, 0x8d, 0x1e, 0x34, 0x02, 0x44, 0xea, 0xa3, 0xdd, 0x62, 0xbb, 0xee, 0xdc, 0x64,
	0xbf, 0xcf, 0x73, 0x38, 0x7c, 0x05, 0x6e, 0x08, 0x2a, 0xb3, 0x48, 0x99, 0x81, 0x3f, 0xb9, 0xc2,
	0xc0, 0x27, 0x45, 0xb9, 0x05, 0xdf, 0x35, 0x79, 0xec, 0x67, 0x60, 0xfe, 0x5c, 0xc4, 0x95, 0x2e,
	0xa8, 0xf7, 0xa1, 0x0e, 0x66, 0x2b, 0xe2, 0xae, 0x2e, 0x09, 0x3f, 0x5b, 0x60, 0x66, 0xfc, 0x26,
	0xe1, 0xe3, 0xcb, 0x55, 0x9e, 0x73, 0xc3, 0xad, 0x6b, 0xed, 0xc5, 0x5e, 0x79, 0xff, 0xe3, 0xd7,
	0xc7, 0x1a, 0x82, 0xcb, 0xf9, 0x7f, 0x78, 0x34, 0x21, 0x7d, 0xcd, 0x9c, 0xad, 0x74, 0x3a, 0xfa,
	0xc7, 0x2c, 0xd6, 0xe3, 0x74, 0x8e, 0xe1, 0x37, 0x0b, 0xcc, 0x9e, 0x5e, 0x1b, 0x5c, 0xbd, 0xf6,
	0x54, 0xcd, 0x6f, 0xd3, 0xc2, 0xff, 0x42, 0xd5, 0x57, 0x62, 0xe3, 0xa2, 0x83, 0x15, 0xdb, 0xc9,
	0x3b, 0x38, 0x91, 0x7c, 0x34, 0xf6, 0x1f, 0xae, 0x75, 0x8e, 0xc7, 0x1a, 0xc0, 0x71, 0x91, 0x0a,
	0x5b, 0x9d, 0xf5, 0x3f, 0x16, 0x58, 0xf4, 0x79, 0x7c, 0x69, 0xf5, 0xf5, 0xf9, 0xd3, 0xeb, 0xda,
	0xc9, 0x9f, 0x91, 0x1d, 0xeb, 0xcd, 0x66, 0x49, 0x0d, 0x79, 0x44, 0x92, 0x10, 0x71, 0x11, 0x3a,
	0x21, 0x4d, 0x8a, 0x47, 0xc6, 0xbc, 0x71, 0x29, 0x93, 0x17, 0xbf, 0xa7, 0x4f, 0x8d, 0xf1, 0xa9,
	0x56, 0xdf, 0xe8, 0xf7, 0xbf, 0xd4, 0xda, 0x1b, 0x3a, 0x61, 0x3f, 0x90, 0x48, 0x9b, 0xb9, 0xb5,
	0xd7, 0x45, 0x65, 0x61, 0xf9, 0xdd, 0x40, 0x86, 0xfd, 0x40, 0x0e, 0x2b, 0xc8, 0x70, 0xaf, 0x3b,
	0x34, 0x90, 0xdf, 0xb5, 0x45, 0xed, 0xc7, 0xb8, 0x1f, 0x48, 0x8c, 0x2b, 0x10, 0xc6, 0x7b, 0x5d,
	0x8c, 0x0d, 0x6c, 0x7f, 0xaa, 0xd0, 0xf9, 0xe8, 0x6f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xf1, 0x84,
	0xc8, 0x18, 0xf6, 0x05, 0x00, 0x00,
}

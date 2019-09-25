// Code generated by protoc-gen-go. DO NOT EDIT.
// source: security/proto/providers/google/meshca.proto

package google_security_meshca_v1beta1

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Certificate request message.
type MeshCertificateRequest struct {
	// PEM-encoded certificate request.
	Csr string `protobuf:"bytes,1,opt,name=csr,proto3" json:"csr,omitempty"`
	// Optional subject ID field.
	SubjectId string `protobuf:"bytes,2,opt,name=subject_id,json=subjectId,proto3" json:"subject_id,omitempty"`
	// Optional: requested certificate validity period, in seconds.
	ValidityDuration     int64    `protobuf:"varint,3,opt,name=validity_duration,json=validityDuration,proto3" json:"validity_duration,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MeshCertificateRequest) Reset()         { *m = MeshCertificateRequest{} }
func (m *MeshCertificateRequest) String() string { return proto.CompactTextString(m) }
func (*MeshCertificateRequest) ProtoMessage()    {}
func (*MeshCertificateRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_c0b192e3de918f2a, []int{0}
}

func (m *MeshCertificateRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MeshCertificateRequest.Unmarshal(m, b)
}
func (m *MeshCertificateRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MeshCertificateRequest.Marshal(b, m, deterministic)
}
func (m *MeshCertificateRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MeshCertificateRequest.Merge(m, src)
}
func (m *MeshCertificateRequest) XXX_Size() int {
	return xxx_messageInfo_MeshCertificateRequest.Size(m)
}
func (m *MeshCertificateRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MeshCertificateRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MeshCertificateRequest proto.InternalMessageInfo

func (m *MeshCertificateRequest) GetCsr() string {
	if m != nil {
		return m.Csr
	}
	return ""
}

func (m *MeshCertificateRequest) GetSubjectId() string {
	if m != nil {
		return m.SubjectId
	}
	return ""
}

func (m *MeshCertificateRequest) GetValidityDuration() int64 {
	if m != nil {
		return m.ValidityDuration
	}
	return 0
}

// Certificate response message.
type MeshCertificateResponse struct {
	// PEM-encoded certificate chain.
	// Leaf cert is element '0'. Root cert is element 'n'.
	CertChain            []string `protobuf:"bytes,1,rep,name=cert_chain,json=certChain,proto3" json:"cert_chain,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MeshCertificateResponse) Reset()         { *m = MeshCertificateResponse{} }
func (m *MeshCertificateResponse) String() string { return proto.CompactTextString(m) }
func (*MeshCertificateResponse) ProtoMessage()    {}
func (*MeshCertificateResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_c0b192e3de918f2a, []int{1}
}

func (m *MeshCertificateResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MeshCertificateResponse.Unmarshal(m, b)
}
func (m *MeshCertificateResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MeshCertificateResponse.Marshal(b, m, deterministic)
}
func (m *MeshCertificateResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MeshCertificateResponse.Merge(m, src)
}
func (m *MeshCertificateResponse) XXX_Size() int {
	return xxx_messageInfo_MeshCertificateResponse.Size(m)
}
func (m *MeshCertificateResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MeshCertificateResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MeshCertificateResponse proto.InternalMessageInfo

func (m *MeshCertificateResponse) GetCertChain() []string {
	if m != nil {
		return m.CertChain
	}
	return nil
}

func init() {
	proto.RegisterType((*MeshCertificateRequest)(nil), "google.security.meshca.v1beta1.MeshCertificateRequest")
	proto.RegisterType((*MeshCertificateResponse)(nil), "google.security.meshca.v1beta1.MeshCertificateResponse")
}

func init() {
	proto.RegisterFile("security/proto/providers/google/meshca.proto", fileDescriptor_c0b192e3de918f2a)
}

var fileDescriptor_c0b192e3de918f2a = []byte{
	// 255 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x90, 0xc1, 0x4a, 0xc4, 0x30,
	0x14, 0x45, 0x8d, 0x05, 0x61, 0xb2, 0x9a, 0xc9, 0x42, 0x8b, 0xa0, 0x94, 0xae, 0x06, 0x94, 0x94,
	0x51, 0x50, 0xf7, 0x75, 0xe3, 0xc2, 0x4d, 0xfd, 0x80, 0x92, 0x26, 0xcf, 0xe9, 0x93, 0xb1, 0x19,
	0x93, 0xd7, 0xc0, 0xfc, 0x80, 0xff, 0xe1, 0x9f, 0x4a, 0x3a, 0x1d, 0x10, 0x2a, 0x82, 0x9b, 0x10,
	0xce, 0xe1, 0x72, 0x93, 0xcb, 0xaf, 0x3d, 0xe8, 0xde, 0x21, 0xed, 0x8a, 0xad, 0xb3, 0x64, 0xe3,
	0x19, 0xd0, 0x80, 0xf3, 0xc5, 0xda, 0xda, 0xf5, 0x06, 0x8a, 0x77, 0xf0, 0xad, 0x56, 0x72, 0xb0,
	0xe2, 0x72, 0x0f, 0xe5, 0x21, 0x24, 0x47, 0x1b, 0x56, 0x0d, 0x90, 0x5a, 0xe5, 0x81, 0x9f, 0x3e,
	0x83, 0x6f, 0x4b, 0x70, 0x84, 0xaf, 0xa8, 0x15, 0x41, 0x05, 0x1f, 0x3d, 0x78, 0x12, 0x73, 0x9e,
	0x68, 0xef, 0x52, 0x96, 0xb1, 0xe5, 0xac, 0x8a, 0x57, 0x71, 0xc1, 0xb9, 0xef, 0x9b, 0x37, 0xd0,
	0x54, 0xa3, 0x49, 0x8f, 0x07, 0x31, 0x1b, 0xc9, 0x93, 0x11, 0x57, 0x7c, 0x11, 0xd4, 0x06, 0x0d,
	0xd2, 0xae, 0x36, 0xbd, 0x53, 0x84, 0xb6, 0x4b, 0x93, 0x8c, 0x2d, 0x93, 0x6a, 0x7e, 0x10, 0x8f,
	0x23, 0xcf, 0x1f, 0xf8, 0xd9, 0xa4, 0xd7, 0x6f, 0x6d, 0xe7, 0x21, 0xd6, 0x68, 0x70, 0x54, 0xeb,
	0x56, 0x61, 0x97, 0xb2, 0x2c, 0x89, 0x35, 0x91, 0x94, 0x11, 0xdc, 0x7c, 0xb1, 0xc9, 0x93, 0x5f,
	0xc0, 0x05, 0xd4, 0x20, 0x3e, 0x19, 0x5f, 0x94, 0x0e, 0x14, 0xc1, 0x0f, 0x29, 0xee, 0xe4, 0xdf,
	0x1b, 0xc8, 0xdf, 0x07, 0x38, 0xbf, 0xff, 0x77, 0x6e, 0xff, 0x81, 0xfc, 0xa8, 0x39, 0x19, 0xc6,
	0xbf, 0xfd, 0x0e, 0x00, 0x00, 0xff, 0xff, 0x1d, 0x10, 0xa5, 0x3b, 0xac, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MeshCertificateServiceClient is the client API for MeshCertificateService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MeshCertificateServiceClient interface {
	// Using provided CSR, returns a signed certificate that represents a GCP
	// service account identity.
	CreateCertificate(ctx context.Context, in *MeshCertificateRequest, opts ...grpc.CallOption) (*MeshCertificateResponse, error)
}

type meshCertificateServiceClient struct {
	cc *grpc.ClientConn
}

func NewMeshCertificateServiceClient(cc *grpc.ClientConn) MeshCertificateServiceClient {
	return &meshCertificateServiceClient{cc}
}

func (c *meshCertificateServiceClient) CreateCertificate(ctx context.Context, in *MeshCertificateRequest, opts ...grpc.CallOption) (*MeshCertificateResponse, error) {
	out := new(MeshCertificateResponse)
	err := c.cc.Invoke(ctx, "/google.security.meshca.v1beta1.MeshCertificateService/CreateCertificate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MeshCertificateServiceServer is the server API for MeshCertificateService service.
type MeshCertificateServiceServer interface {
	// Using provided CSR, returns a signed certificate that represents a GCP
	// service account identity.
	CreateCertificate(context.Context, *MeshCertificateRequest) (*MeshCertificateResponse, error)
}

// UnimplementedMeshCertificateServiceServer can be embedded to have forward compatible implementations.
type UnimplementedMeshCertificateServiceServer struct {
}

func (*UnimplementedMeshCertificateServiceServer) CreateCertificate(ctx context.Context, req *MeshCertificateRequest) (*MeshCertificateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateCertificate not implemented")
}

func RegisterMeshCertificateServiceServer(s *grpc.Server, srv MeshCertificateServiceServer) {
	s.RegisterService(&_MeshCertificateService_serviceDesc, srv)
}

func _MeshCertificateService_CreateCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MeshCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MeshCertificateServiceServer).CreateCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.security.meshca.v1beta1.MeshCertificateService/CreateCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MeshCertificateServiceServer).CreateCertificate(ctx, req.(*MeshCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _MeshCertificateService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.security.meshca.v1beta1.MeshCertificateService",
	HandlerType: (*MeshCertificateServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateCertificate",
			Handler:    _MeshCertificateService_CreateCertificate_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "security/proto/providers/google/meshca.proto",
}

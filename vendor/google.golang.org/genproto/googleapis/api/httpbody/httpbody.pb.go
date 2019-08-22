// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/api/httpbody.proto

package httpbody // import "google.golang.org/genproto/googleapis/api/httpbody"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import any "github.com/golang/protobuf/ptypes/any"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Message that represents an arbitrary HTTP body. It should only be used for
// payload formats that can't be represented as JSON, such as raw binary or
// an HTML page.
//
//
// This message can be used both in streaming and non-streaming API methods in
// the request as well as the response.
//
// It can be used as a top-level request field, which is convenient if one
// wants to extract parameters from either the URL or HTTP template into the
// request fields and also want access to the raw HTTP body.
//
// Example:
//
//     message GetResourceRequest {
//       // A unique request id.
//       string request_id = 1;
//
//       // The raw HTTP body is bound to this field.
//       google.api.HttpBody http_body = 2;
//     }
//
//     service ResourceService {
//       rpc GetResource(GetResourceRequest) returns (google.api.HttpBody);
//       rpc UpdateResource(google.api.HttpBody) returns
//       (google.protobuf.Empty);
//     }
//
// Example with streaming methods:
//
//     service CaldavService {
//       rpc GetCalendar(stream google.api.HttpBody)
//         returns (stream google.api.HttpBody);
//       rpc UpdateCalendar(stream google.api.HttpBody)
//         returns (stream google.api.HttpBody);
//     }
//
// Use of this type only changes how the request and response bodies are
// handled, all other features will continue to work unchanged.
type HttpBody struct {
	// The HTTP Content-Type header value specifying the content type of the body.
	ContentType string `protobuf:"bytes,1,opt,name=content_type,json=contentType,proto3" json:"content_type,omitempty"`
	// The HTTP request/response body as raw binary.
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	// Application specific response metadata. Must be set in the first response
	// for streaming APIs.
	Extensions           []*any.Any `protobuf:"bytes,3,rep,name=extensions,proto3" json:"extensions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *HttpBody) Reset()         { *m = HttpBody{} }
func (m *HttpBody) String() string { return proto.CompactTextString(m) }
func (*HttpBody) ProtoMessage()    {}
func (*HttpBody) Descriptor() ([]byte, []int) {
	return fileDescriptor_httpbody_4b22a683a4267e55, []int{0}
}
func (m *HttpBody) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HttpBody.Unmarshal(m, b)
}
func (m *HttpBody) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HttpBody.Marshal(b, m, deterministic)
}
func (dst *HttpBody) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HttpBody.Merge(dst, src)
}
func (m *HttpBody) XXX_Size() int {
	return xxx_messageInfo_HttpBody.Size(m)
}
func (m *HttpBody) XXX_DiscardUnknown() {
	xxx_messageInfo_HttpBody.DiscardUnknown(m)
}

var xxx_messageInfo_HttpBody proto.InternalMessageInfo

func (m *HttpBody) GetContentType() string {
	if m != nil {
		return m.ContentType
	}
	return ""
}

func (m *HttpBody) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *HttpBody) GetExtensions() []*any.Any {
	if m != nil {
		return m.Extensions
	}
	return nil
}

func init() {
	proto.RegisterType((*HttpBody)(nil), "google.api.HttpBody")
}

func init() { proto.RegisterFile("google/api/httpbody.proto", fileDescriptor_httpbody_4b22a683a4267e55) }

var fileDescriptor_httpbody_4b22a683a4267e55 = []byte{
	// 229 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0x8f, 0x31, 0x4f, 0xc3, 0x30,
	0x10, 0x85, 0xe5, 0xb6, 0x42, 0x70, 0x2d, 0x0c, 0x16, 0x43, 0x60, 0x0a, 0x4c, 0x99, 0x6c, 0x09,
	0xd8, 0x3a, 0x35, 0x0b, 0xb0, 0x45, 0x11, 0x13, 0x0b, 0x72, 0x1a, 0xe3, 0x46, 0x2a, 0x77, 0xa7,
	0xe6, 0x10, 0xf8, 0xef, 0xf0, 0x2b, 0x19, 0x11, 0x69, 0x2c, 0xe8, 0xf6, 0xe4, 0xef, 0x3d, 0xbf,
	0x77, 0x70, 0x11, 0x88, 0xc2, 0xd6, 0x5b, 0xc7, 0x9d, 0xdd, 0x88, 0x70, 0x43, 0x6d, 0x34, 0xbc,
	0x23, 0x21, 0x0d, 0x7b, 0x64, 0x1c, 0x77, 0x97, 0xc9, 0x36, 0x90, 0xe6, 0xfd, 0xd5, 0x3a, 0x1c,
	0x6d, 0xd7, 0x1f, 0x70, 0xfc, 0x20, 0xc2, 0x25, 0xb5, 0x51, 0x5f, 0xc1, 0x62, 0x4d, 0x28, 0x1e,
	0xe5, 0x45, 0x22, 0xfb, 0x4c, 0xe5, 0xaa, 0x38, 0xa9, 0xe7, 0xe3, 0xdb, 0x53, 0x64, 0xaf, 0x35,
	0xcc, 0x5a, 0x27, 0x2e, 0x9b, 0xe4, 0xaa, 0x58, 0xd4, 0x83, 0xd6, 0x77, 0x00, 0xfe, 0x53, 0x3c,
	0xf6, 0x1d, 0x61, 0x9f, 0x4d, 0xf3, 0x69, 0x31, 0xbf, 0x39, 0x37, 0x63, 0x7d, 0xaa, 0x34, 0x2b,
	0x8c, 0xf5, 0x3f, 0x5f, 0xb9, 0x81, 0xb3, 0x35, 0xbd, 0x99, 0xbf, 0x95, 0xe5, 0x69, 0x1a, 0x52,
	0xfd, 0x66, 0x2a, 0xf5, 0xbc, 0x1c, 0x61, 0xa0, 0xad, 0xc3, 0x60, 0x68, 0x17, 0x6c, 0xf0, 0x38,
	0xfc, 0x68, 0xf7, 0xc8, 0x71, 0xd7, 0x1f, 0x1c, 0xbf, 0x4c, 0xe2, 0x5b, 0xa9, 0xaf, 0xc9, 0xec,
	0x7e, 0x55, 0x3d, 0x36, 0x47, 0x43, 0xe2, 0xf6, 0x27, 0x00, 0x00, 0xff, 0xff, 0x78, 0xb9, 0x16,
	0x2b, 0x2d, 0x01, 0x00, 0x00,
}

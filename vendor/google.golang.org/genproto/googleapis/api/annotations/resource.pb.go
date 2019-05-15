// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/api/resource.proto

package annotations // import "google.golang.org/genproto/googleapis/api/annotations"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import descriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// An annotation designating that this field designates a resource.
//
// Example:
//
//     message Topic {
//       string name = 1 [(google.api.resource) = {
//         name: "projects/{project}/topics/{topic}"
//       }];
//     }
type Resource struct {
	// Required. The resource's name template.
	//
	// Examples:
	//   - "projects/{project}/topics/{topic}"
	//   - "projects/{project}/knowledgeBases/{knowledge_base}"
	Pattern string `protobuf:"bytes,1,opt,name=pattern,proto3" json:"pattern,omitempty"`
	// The name that should be used in code to describe the resource,
	// in PascalCase.
	//
	// If omitted, this is inferred from the name of the message.
	// This is required if the resource is being defined without the context
	// of a message (see `resource_definition`, below).
	//
	// Example:
	//   option (google.api.resource_definition) = {
	//     pattern: "projects/{project}"
	//     symbol: "Project"
	//   };
	Symbol               string   `protobuf:"bytes,2,opt,name=symbol,proto3" json:"symbol,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Resource) Reset()         { *m = Resource{} }
func (m *Resource) String() string { return proto.CompactTextString(m) }
func (*Resource) ProtoMessage()    {}
func (*Resource) Descriptor() ([]byte, []int) {
	return fileDescriptor_resource_232de5e6fd811932, []int{0}
}
func (m *Resource) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Resource.Unmarshal(m, b)
}
func (m *Resource) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Resource.Marshal(b, m, deterministic)
}
func (dst *Resource) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Resource.Merge(dst, src)
}
func (m *Resource) XXX_Size() int {
	return xxx_messageInfo_Resource.Size(m)
}
func (m *Resource) XXX_DiscardUnknown() {
	xxx_messageInfo_Resource.DiscardUnknown(m)
}

var xxx_messageInfo_Resource proto.InternalMessageInfo

func (m *Resource) GetPattern() string {
	if m != nil {
		return m.Pattern
	}
	return ""
}

func (m *Resource) GetSymbol() string {
	if m != nil {
		return m.Symbol
	}
	return ""
}

var E_Resource = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*Resource)(nil),
	Field:         1053,
	Name:          "google.api.resource",
	Tag:           "bytes,1053,opt,name=resource",
	Filename:      "google/api/resource.proto",
}

var E_ResourceReference = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         1055,
	Name:          "google.api.resource_reference",
	Tag:           "bytes,1055,opt,name=resource_reference,json=resourceReference",
	Filename:      "google/api/resource.proto",
}

var E_ResourceDefinition = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FileOptions)(nil),
	ExtensionType: ([]*Resource)(nil),
	Field:         1053,
	Name:          "google.api.resource_definition",
	Tag:           "bytes,1053,rep,name=resource_definition,json=resourceDefinition",
	Filename:      "google/api/resource.proto",
}

func init() {
	proto.RegisterType((*Resource)(nil), "google.api.Resource")
	proto.RegisterExtension(E_Resource)
	proto.RegisterExtension(E_ResourceReference)
	proto.RegisterExtension(E_ResourceDefinition)
}

func init() { proto.RegisterFile("google/api/resource.proto", fileDescriptor_resource_232de5e6fd811932) }

var fileDescriptor_resource_232de5e6fd811932 = []byte{
	// 334 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xc1, 0x4a, 0xeb, 0x40,
	0x18, 0x85, 0x49, 0xef, 0xa5, 0xcd, 0x9d, 0xab, 0x82, 0xa3, 0x48, 0x94, 0x16, 0x8a, 0xab, 0x2e,
	0x64, 0x06, 0x74, 0x57, 0xdd, 0xa4, 0x88, 0xe2, 0x42, 0x1a, 0xb2, 0x74, 0x23, 0xd3, 0x64, 0x3a,
	0x8c, 0xa4, 0xf3, 0x0f, 0x93, 0xe9, 0x42, 0x4b, 0x1f, 0x45, 0x04, 0x1f, 0xc3, 0x47, 0xea, 0x53,
	0x48, 0x27, 0x99, 0x98, 0x85, 0xe2, 0xee, 0x3f, 0x9c, 0x39, 0xe7, 0x3b, 0x81, 0xa0, 0x63, 0x01,
	0x20, 0x0a, 0x4e, 0x99, 0x96, 0xd4, 0xf0, 0x12, 0x96, 0x26, 0xe3, 0x44, 0x1b, 0xb0, 0x80, 0x51,
	0x65, 0x11, 0xa6, 0xe5, 0xc9, 0xb0, 0x7e, 0xe6, 0x9c, 0xd9, 0x72, 0x4e, 0x73, 0x5e, 0x66, 0x46,
	0x6a, 0x0b, 0xa6, 0x7a, 0x7d, 0x7a, 0x85, 0xc2, 0xb4, 0xce, 0xe3, 0x08, 0xf5, 0x34, 0xb3, 0x96,
	0x1b, 0x15, 0x05, 0xc3, 0x60, 0xf4, 0x2f, 0xf5, 0x12, 0x1f, 0xa1, 0x6e, 0xf9, 0xbc, 0x98, 0x41,
	0x11, 0x75, 0x9c, 0x51, 0xab, 0x71, 0x82, 0x42, 0x4f, 0xc7, 0x03, 0x52, 0x83, 0x3d, 0x8c, 0xdc,
	0x48, 0x5e, 0xe4, 0x53, 0x6d, 0x25, 0xa8, 0x32, 0x7a, 0x0d, 0x87, 0xc1, 0xe8, 0xff, 0xf9, 0x21,
	0xf9, 0x9a, 0x47, 0x3c, 0x39, 0x6d, 0x5a, 0xc6, 0xf7, 0x08, 0xfb, 0xfb, 0xd1, 0xf0, 0x39, 0x37,
	0x5c, 0xfd, 0xde, 0xfd, 0x16, 0xba, 0x55, 0xfb, 0x3e, 0x99, 0xfa, 0xe0, 0x38, 0x47, 0x07, 0x4d,
	0x5d, 0xce, 0xe7, 0x52, 0xc9, 0x6d, 0x02, 0xf7, 0xbf, 0xe9, 0x2b, 0x78, 0x6b, 0xea, 0x9f, 0x1f,
	0xa7, 0x36, 0xf3, 0xae, 0x9b, 0xba, 0xc9, 0x47, 0xb0, 0x89, 0x07, 0x08, 0x6b, 0x03, 0x4f, 0x3c,
	0xb3, 0x25, 0x5d, 0xd5, 0xd7, 0x1a, 0xf7, 0x92, 0xea, 0xda, 0xc4, 0x67, 0xa8, 0x0f, 0x46, 0x30,
	0x25, 0x5f, 0x98, 0xa3, 0xd0, 0x55, 0x5b, 0xae, 0xf1, 0xce, 0xb4, 0x25, 0xd1, 0x5e, 0x06, 0x8b,
	0x16, 0x7e, 0xb2, 0xeb, 0xf9, 0xc9, 0x76, 0x70, 0x12, 0x3c, 0xc4, 0xb5, 0x29, 0xa0, 0x60, 0x4a,
	0x10, 0x30, 0x82, 0x0a, 0xae, 0xdc, 0xe7, 0xd0, 0xca, 0x62, 0x5a, 0x96, 0xee, 0xff, 0x60, 0x4a,
	0x81, 0xad, 0xa0, 0x97, 0xad, 0xfb, 0xbd, 0xf3, 0xf7, 0x36, 0x4e, 0xee, 0x66, 0x5d, 0x17, 0xba,
	0xf8, 0x0c, 0x00, 0x00, 0xff, 0xff, 0xcf, 0x7e, 0x96, 0xa2, 0x53, 0x02, 0x00, 0x00,
}

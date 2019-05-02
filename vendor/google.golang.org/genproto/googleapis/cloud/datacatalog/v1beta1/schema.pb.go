// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/cloud/datacatalog/v1beta1/schema.proto

package datacatalog // import "google.golang.org/genproto/googleapis/cloud/datacatalog/v1beta1"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Represents a schema (e.g. BigQuery, GoogleSQL, Avro schema).
type Schema struct {
	// Schema of columns. A maximum of 10,000 columns and sub-columns can be
	// specified.
	Columns              []*ColumnSchema `protobuf:"bytes,2,rep,name=columns,proto3" json:"columns,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *Schema) Reset()         { *m = Schema{} }
func (m *Schema) String() string { return proto.CompactTextString(m) }
func (*Schema) ProtoMessage()    {}
func (*Schema) Descriptor() ([]byte, []int) {
	return fileDescriptor_schema_3cda8417f7d2d075, []int{0}
}
func (m *Schema) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Schema.Unmarshal(m, b)
}
func (m *Schema) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Schema.Marshal(b, m, deterministic)
}
func (dst *Schema) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Schema.Merge(dst, src)
}
func (m *Schema) XXX_Size() int {
	return xxx_messageInfo_Schema.Size(m)
}
func (m *Schema) XXX_DiscardUnknown() {
	xxx_messageInfo_Schema.DiscardUnknown(m)
}

var xxx_messageInfo_Schema proto.InternalMessageInfo

func (m *Schema) GetColumns() []*ColumnSchema {
	if m != nil {
		return m.Columns
	}
	return nil
}

// Representation of a column within a schema. Columns could be nested inside
// other columns.
type ColumnSchema struct {
	// Required. Name of the column.
	Column string `protobuf:"bytes,6,opt,name=column,proto3" json:"column,omitempty"`
	// Required. Type of the column.
	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// Description of the column.
	Description string `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	// A column's mode indicates whether the values in this column are
	// required, nullable, etc. Only 'NULLABLE', 'REQUIRED' and 'REPEATED' are
	// supported, default mode is 'NULLABLE'.
	Mode string `protobuf:"bytes,3,opt,name=mode,proto3" json:"mode,omitempty"`
	// Schema of sub-columns.
	Subcolumns           []*ColumnSchema `protobuf:"bytes,7,rep,name=subcolumns,proto3" json:"subcolumns,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *ColumnSchema) Reset()         { *m = ColumnSchema{} }
func (m *ColumnSchema) String() string { return proto.CompactTextString(m) }
func (*ColumnSchema) ProtoMessage()    {}
func (*ColumnSchema) Descriptor() ([]byte, []int) {
	return fileDescriptor_schema_3cda8417f7d2d075, []int{1}
}
func (m *ColumnSchema) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ColumnSchema.Unmarshal(m, b)
}
func (m *ColumnSchema) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ColumnSchema.Marshal(b, m, deterministic)
}
func (dst *ColumnSchema) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ColumnSchema.Merge(dst, src)
}
func (m *ColumnSchema) XXX_Size() int {
	return xxx_messageInfo_ColumnSchema.Size(m)
}
func (m *ColumnSchema) XXX_DiscardUnknown() {
	xxx_messageInfo_ColumnSchema.DiscardUnknown(m)
}

var xxx_messageInfo_ColumnSchema proto.InternalMessageInfo

func (m *ColumnSchema) GetColumn() string {
	if m != nil {
		return m.Column
	}
	return ""
}

func (m *ColumnSchema) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *ColumnSchema) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func (m *ColumnSchema) GetMode() string {
	if m != nil {
		return m.Mode
	}
	return ""
}

func (m *ColumnSchema) GetSubcolumns() []*ColumnSchema {
	if m != nil {
		return m.Subcolumns
	}
	return nil
}

func init() {
	proto.RegisterType((*Schema)(nil), "google.cloud.datacatalog.v1beta1.Schema")
	proto.RegisterType((*ColumnSchema)(nil), "google.cloud.datacatalog.v1beta1.ColumnSchema")
}

func init() {
	proto.RegisterFile("google/cloud/datacatalog/v1beta1/schema.proto", fileDescriptor_schema_3cda8417f7d2d075)
}

var fileDescriptor_schema_3cda8417f7d2d075 = []byte{
	// 251 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x91, 0x31, 0x4b, 0x04, 0x31,
	0x10, 0x85, 0xc9, 0x9d, 0xec, 0xe1, 0x9c, 0x55, 0x0a, 0x49, 0x61, 0xb1, 0x5c, 0x75, 0x8d, 0x09,
	0xa7, 0xa5, 0x9d, 0x36, 0x82, 0x20, 0xb2, 0x76, 0x76, 0xd9, 0x6c, 0x88, 0x0b, 0xd9, 0x4c, 0xd8,
	0x64, 0x05, 0xff, 0x9d, 0x3f, 0xcb, 0x52, 0x2e, 0xd9, 0x83, 0x34, 0x8b, 0x70, 0xdd, 0xe4, 0xbd,
	0xf7, 0x3d, 0x86, 0x0c, 0xdc, 0x1a, 0x44, 0x63, 0xb5, 0x50, 0x16, 0xa7, 0x4e, 0x74, 0x32, 0x4a,
	0x25, 0xa3, 0xb4, 0x68, 0xc4, 0xd7, 0xa1, 0xd5, 0x51, 0x1e, 0x44, 0x50, 0x9f, 0x7a, 0x90, 0xdc,
	0x8f, 0x18, 0x91, 0xd6, 0x39, 0xce, 0x53, 0x9c, 0x17, 0x71, 0x3e, 0xc7, 0x77, 0x0d, 0x54, 0xef,
	0x89, 0xa0, 0xcf, 0xb0, 0x51, 0x68, 0xa7, 0xc1, 0x05, 0xb6, 0xaa, 0xd7, 0xfb, 0xed, 0x1d, 0xe7,
	0xff, 0xd1, 0xfc, 0x29, 0x01, 0xb9, 0xa0, 0x39, 0xe1, 0xbb, 0x1f, 0x02, 0x57, 0xa5, 0x43, 0xaf,
	0xa1, 0xca, 0x1e, 0xab, 0x6a, 0xb2, 0xbf, 0x6c, 0xe6, 0x17, 0xa5, 0x70, 0x11, 0xbf, 0xbd, 0x66,
	0x24, 0xa9, 0x69, 0xa6, 0x35, 0x6c, 0x3b, 0x1d, 0xd4, 0xd8, 0xfb, 0xd8, 0xa3, 0x63, 0xab, 0x64,
	0x95, 0xd2, 0x91, 0x1a, 0xb0, 0xd3, 0x6c, 0x9d, 0xa9, 0xe3, 0x4c, 0x5f, 0x01, 0xc2, 0xd4, 0x9e,
	0xf6, 0xdf, 0x9c, 0xb5, 0x7f, 0xd1, 0xf0, 0xe8, 0xe1, 0x46, 0xe1, 0xb0, 0x58, 0xf0, 0x46, 0x3e,
	0x5e, 0x66, 0xcf, 0xa0, 0x95, 0xce, 0x70, 0x1c, 0x8d, 0x30, 0xda, 0xa5, 0x6f, 0x17, 0xd9, 0x92,
	0xbe, 0x0f, 0xcb, 0x87, 0x7a, 0x28, 0xb4, 0x5f, 0x42, 0xda, 0x2a, 0xa1, 0xf7, 0x7f, 0x01, 0x00,
	0x00, 0xff, 0xff, 0x28, 0x89, 0x34, 0x94, 0xe2, 0x01, 0x00, 0x00,
}

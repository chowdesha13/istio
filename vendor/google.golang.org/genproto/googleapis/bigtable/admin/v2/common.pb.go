// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/bigtable/admin/v2/common.proto

package admin // import "google.golang.org/genproto/googleapis/bigtable/admin/v2"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/golang/protobuf/ptypes/timestamp"
import _ "google.golang.org/genproto/googleapis/api/annotations"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Storage media types for persisting Bigtable data.
type StorageType int32

const (
	// The user did not specify a storage type.
	StorageType_STORAGE_TYPE_UNSPECIFIED StorageType = 0
	// Flash (SSD) storage should be used.
	StorageType_SSD StorageType = 1
	// Magnetic drive (HDD) storage should be used.
	StorageType_HDD StorageType = 2
)

var StorageType_name = map[int32]string{
	0: "STORAGE_TYPE_UNSPECIFIED",
	1: "SSD",
	2: "HDD",
}
var StorageType_value = map[string]int32{
	"STORAGE_TYPE_UNSPECIFIED": 0,
	"SSD":                      1,
	"HDD":                      2,
}

func (x StorageType) String() string {
	return proto.EnumName(StorageType_name, int32(x))
}
func (StorageType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_common_aea695cda7095808, []int{0}
}

func init() {
	proto.RegisterEnum("google.bigtable.admin.v2.StorageType", StorageType_name, StorageType_value)
}

func init() {
	proto.RegisterFile("google/bigtable/admin/v2/common.proto", fileDescriptor_common_aea695cda7095808)
}

var fileDescriptor_common_aea695cda7095808 = []byte{
	// 270 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0xd0, 0xcf, 0x4b, 0xc3, 0x30,
	0x14, 0x07, 0x70, 0x3b, 0x41, 0x21, 0xbb, 0x94, 0x9e, 0xc6, 0x28, 0x7a, 0xf2, 0xe2, 0x21, 0x81,
	0x7a, 0x94, 0x1d, 0xd6, 0x1f, 0xce, 0x5d, 0xb4, 0x98, 0x3a, 0x50, 0x0a, 0x23, 0xdd, 0x62, 0x08,
	0x34, 0x79, 0xa1, 0xcd, 0x06, 0xfe, 0x4b, 0x1e, 0xfc, 0x43, 0xfc, 0xab, 0x64, 0x49, 0x7b, 0x12,
	0x6f, 0x2f, 0xbc, 0xcf, 0xcb, 0xf7, 0x25, 0xe8, 0x46, 0x00, 0x88, 0x96, 0x93, 0x46, 0x0a, 0xcb,
	0x9a, 0x96, 0x13, 0xb6, 0x57, 0x52, 0x93, 0x63, 0x42, 0x76, 0xa0, 0x14, 0x68, 0x6c, 0x3a, 0xb0,
	0x10, 0xcd, 0x3c, 0xc3, 0x23, 0xc3, 0x8e, 0xe1, 0x63, 0x32, 0x8f, 0x87, 0x0b, 0x98, 0x91, 0x84,
	0x69, 0x0d, 0x96, 0x59, 0x09, 0xba, 0xf7, 0x73, 0xf3, 0xeb, 0xa1, 0xeb, 0x4e, 0xcd, 0xe1, 0x83,
	0x58, 0xa9, 0x78, 0x6f, 0x99, 0x32, 0x1e, 0xdc, 0x2e, 0xd0, 0x94, 0x5a, 0xe8, 0x98, 0xe0, 0xd5,
	0xa7, 0xe1, 0x51, 0x8c, 0x66, 0xb4, 0x7a, 0x7e, 0x59, 0xae, 0x8a, 0x6d, 0xf5, 0x56, 0x16, 0xdb,
	0xd7, 0x27, 0x5a, 0x16, 0xd9, 0xfa, 0x61, 0x5d, 0xe4, 0xe1, 0x59, 0x74, 0x89, 0xce, 0x29, 0xcd,
	0xc3, 0xe0, 0x54, 0x3c, 0xe6, 0x79, 0x38, 0x49, 0xbf, 0x03, 0x14, 0xef, 0x40, 0xe1, 0xff, 0xd6,
	0x4b, 0xa7, 0x99, 0x7b, 0x46, 0x79, 0x0a, 0x2b, 0x83, 0xf7, 0xc5, 0x00, 0x05, 0xb4, 0x4c, 0x0b,
	0x0c, 0x9d, 0x20, 0x82, 0x6b, 0xb7, 0x0a, 0xf1, 0x2d, 0x66, 0x64, 0xff, 0xf7, 0x37, 0xee, 0x5d,
	0xf1, 0x35, 0xb9, 0x5a, 0xf9, 0xf9, 0xac, 0x85, 0xc3, 0x1e, 0xa7, 0x63, 0xdc, 0xd2, 0xc5, 0x6d,
	0x92, 0x9f, 0x11, 0xd4, 0x0e, 0xd4, 0x23, 0xa8, 0x1d, 0xa8, 0x37, 0x49, 0x73, 0xe1, 0xb2, 0xee,
	0x7e, 0x03, 0x00, 0x00, 0xff, 0xff, 0xaf, 0x9e, 0x61, 0x6a, 0x78, 0x01, 0x00, 0x00,
}

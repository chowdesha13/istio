// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/errors/media_bundle_error.proto

package errors // import "google.golang.org/genproto/googleapis/ads/googleads/v1/errors"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
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

// Enum describing possible media bundle errors.
type MediaBundleErrorEnum_MediaBundleError int32

const (
	// Enum unspecified.
	MediaBundleErrorEnum_UNSPECIFIED MediaBundleErrorEnum_MediaBundleError = 0
	// The received error code is not known in this version.
	MediaBundleErrorEnum_UNKNOWN MediaBundleErrorEnum_MediaBundleError = 1
	// There was a problem with the request.
	MediaBundleErrorEnum_BAD_REQUEST MediaBundleErrorEnum_MediaBundleError = 3
	// HTML5 ads using DoubleClick Studio created ZIP files are not supported.
	MediaBundleErrorEnum_DOUBLECLICK_BUNDLE_NOT_ALLOWED MediaBundleErrorEnum_MediaBundleError = 4
	// Cannot reference URL external to the media bundle.
	MediaBundleErrorEnum_EXTERNAL_URL_NOT_ALLOWED MediaBundleErrorEnum_MediaBundleError = 5
	// Media bundle file is too large.
	MediaBundleErrorEnum_FILE_TOO_LARGE MediaBundleErrorEnum_MediaBundleError = 6
	// ZIP file from Google Web Designer is not published.
	MediaBundleErrorEnum_GOOGLE_WEB_DESIGNER_ZIP_FILE_NOT_PUBLISHED MediaBundleErrorEnum_MediaBundleError = 7
	// Input was invalid.
	MediaBundleErrorEnum_INVALID_INPUT MediaBundleErrorEnum_MediaBundleError = 8
	// There was a problem with the media bundle.
	MediaBundleErrorEnum_INVALID_MEDIA_BUNDLE MediaBundleErrorEnum_MediaBundleError = 9
	// There was a problem with one or more of the media bundle entries.
	MediaBundleErrorEnum_INVALID_MEDIA_BUNDLE_ENTRY MediaBundleErrorEnum_MediaBundleError = 10
	// The media bundle contains a file with an unknown mime type
	MediaBundleErrorEnum_INVALID_MIME_TYPE MediaBundleErrorEnum_MediaBundleError = 11
	// The media bundle contain an invalid asset path.
	MediaBundleErrorEnum_INVALID_PATH MediaBundleErrorEnum_MediaBundleError = 12
	// HTML5 ad is trying to reference an asset not in .ZIP file
	MediaBundleErrorEnum_INVALID_URL_REFERENCE MediaBundleErrorEnum_MediaBundleError = 13
	// Media data is too large.
	MediaBundleErrorEnum_MEDIA_DATA_TOO_LARGE MediaBundleErrorEnum_MediaBundleError = 14
	// The media bundle contains no primary entry.
	MediaBundleErrorEnum_MISSING_PRIMARY_MEDIA_BUNDLE_ENTRY MediaBundleErrorEnum_MediaBundleError = 15
	// There was an error on the server.
	MediaBundleErrorEnum_SERVER_ERROR MediaBundleErrorEnum_MediaBundleError = 16
	// The image could not be stored.
	MediaBundleErrorEnum_STORAGE_ERROR MediaBundleErrorEnum_MediaBundleError = 17
	// Media bundle created with the Swiffy tool is not allowed.
	MediaBundleErrorEnum_SWIFFY_BUNDLE_NOT_ALLOWED MediaBundleErrorEnum_MediaBundleError = 18
	// The media bundle contains too many files.
	MediaBundleErrorEnum_TOO_MANY_FILES MediaBundleErrorEnum_MediaBundleError = 19
	// The media bundle is not of legal dimensions.
	MediaBundleErrorEnum_UNEXPECTED_SIZE MediaBundleErrorEnum_MediaBundleError = 20
	// Google Web Designer not created for "Google Ads" environment.
	MediaBundleErrorEnum_UNSUPPORTED_GOOGLE_WEB_DESIGNER_ENVIRONMENT MediaBundleErrorEnum_MediaBundleError = 21
	// Unsupported HTML5 feature in HTML5 asset.
	MediaBundleErrorEnum_UNSUPPORTED_HTML5_FEATURE MediaBundleErrorEnum_MediaBundleError = 22
	// URL in HTML5 entry is not ssl compliant.
	MediaBundleErrorEnum_URL_IN_MEDIA_BUNDLE_NOT_SSL_COMPLIANT MediaBundleErrorEnum_MediaBundleError = 23
	// Custom exits not allowed in HTML5 entry.
	MediaBundleErrorEnum_CUSTOM_EXIT_NOT_ALLOWED MediaBundleErrorEnum_MediaBundleError = 24
)

var MediaBundleErrorEnum_MediaBundleError_name = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "UNKNOWN",
	3:  "BAD_REQUEST",
	4:  "DOUBLECLICK_BUNDLE_NOT_ALLOWED",
	5:  "EXTERNAL_URL_NOT_ALLOWED",
	6:  "FILE_TOO_LARGE",
	7:  "GOOGLE_WEB_DESIGNER_ZIP_FILE_NOT_PUBLISHED",
	8:  "INVALID_INPUT",
	9:  "INVALID_MEDIA_BUNDLE",
	10: "INVALID_MEDIA_BUNDLE_ENTRY",
	11: "INVALID_MIME_TYPE",
	12: "INVALID_PATH",
	13: "INVALID_URL_REFERENCE",
	14: "MEDIA_DATA_TOO_LARGE",
	15: "MISSING_PRIMARY_MEDIA_BUNDLE_ENTRY",
	16: "SERVER_ERROR",
	17: "STORAGE_ERROR",
	18: "SWIFFY_BUNDLE_NOT_ALLOWED",
	19: "TOO_MANY_FILES",
	20: "UNEXPECTED_SIZE",
	21: "UNSUPPORTED_GOOGLE_WEB_DESIGNER_ENVIRONMENT",
	22: "UNSUPPORTED_HTML5_FEATURE",
	23: "URL_IN_MEDIA_BUNDLE_NOT_SSL_COMPLIANT",
	24: "CUSTOM_EXIT_NOT_ALLOWED",
}
var MediaBundleErrorEnum_MediaBundleError_value = map[string]int32{
	"UNSPECIFIED":                    0,
	"UNKNOWN":                        1,
	"BAD_REQUEST":                    3,
	"DOUBLECLICK_BUNDLE_NOT_ALLOWED": 4,
	"EXTERNAL_URL_NOT_ALLOWED":       5,
	"FILE_TOO_LARGE":                 6,
	"GOOGLE_WEB_DESIGNER_ZIP_FILE_NOT_PUBLISHED": 7,
	"INVALID_INPUT":                               8,
	"INVALID_MEDIA_BUNDLE":                        9,
	"INVALID_MEDIA_BUNDLE_ENTRY":                  10,
	"INVALID_MIME_TYPE":                           11,
	"INVALID_PATH":                                12,
	"INVALID_URL_REFERENCE":                       13,
	"MEDIA_DATA_TOO_LARGE":                        14,
	"MISSING_PRIMARY_MEDIA_BUNDLE_ENTRY":          15,
	"SERVER_ERROR":                                16,
	"STORAGE_ERROR":                               17,
	"SWIFFY_BUNDLE_NOT_ALLOWED":                   18,
	"TOO_MANY_FILES":                              19,
	"UNEXPECTED_SIZE":                             20,
	"UNSUPPORTED_GOOGLE_WEB_DESIGNER_ENVIRONMENT": 21,
	"UNSUPPORTED_HTML5_FEATURE":                   22,
	"URL_IN_MEDIA_BUNDLE_NOT_SSL_COMPLIANT":       23,
	"CUSTOM_EXIT_NOT_ALLOWED":                     24,
}

func (x MediaBundleErrorEnum_MediaBundleError) String() string {
	return proto.EnumName(MediaBundleErrorEnum_MediaBundleError_name, int32(x))
}
func (MediaBundleErrorEnum_MediaBundleError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_media_bundle_error_f3b259602be58c27, []int{0, 0}
}

// Container for enum describing possible media bundle errors.
type MediaBundleErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MediaBundleErrorEnum) Reset()         { *m = MediaBundleErrorEnum{} }
func (m *MediaBundleErrorEnum) String() string { return proto.CompactTextString(m) }
func (*MediaBundleErrorEnum) ProtoMessage()    {}
func (*MediaBundleErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_media_bundle_error_f3b259602be58c27, []int{0}
}
func (m *MediaBundleErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MediaBundleErrorEnum.Unmarshal(m, b)
}
func (m *MediaBundleErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MediaBundleErrorEnum.Marshal(b, m, deterministic)
}
func (dst *MediaBundleErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MediaBundleErrorEnum.Merge(dst, src)
}
func (m *MediaBundleErrorEnum) XXX_Size() int {
	return xxx_messageInfo_MediaBundleErrorEnum.Size(m)
}
func (m *MediaBundleErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_MediaBundleErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_MediaBundleErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*MediaBundleErrorEnum)(nil), "google.ads.googleads.v1.errors.MediaBundleErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.errors.MediaBundleErrorEnum_MediaBundleError", MediaBundleErrorEnum_MediaBundleError_name, MediaBundleErrorEnum_MediaBundleError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/errors/media_bundle_error.proto", fileDescriptor_media_bundle_error_f3b259602be58c27)
}

var fileDescriptor_media_bundle_error_f3b259602be58c27 = []byte{
	// 641 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x53, 0xdd, 0x6a, 0x13, 0x41,
	0x14, 0xb6, 0xad, 0x6d, 0x75, 0xfa, 0x37, 0x9d, 0x36, 0xf6, 0xc7, 0x9a, 0x8b, 0x80, 0x82, 0x0a,
	0x1b, 0x82, 0x88, 0xb0, 0x5e, 0xcd, 0x66, 0x4f, 0xb6, 0x43, 0x67, 0x67, 0xd6, 0x99, 0xd9, 0xa4,
	0x29, 0x81, 0x21, 0x35, 0x21, 0x04, 0xda, 0x6c, 0xc9, 0xb6, 0x7d, 0x1d, 0xc1, 0x4b, 0x9f, 0xc0,
	0x67, 0xf0, 0x51, 0xbc, 0xf2, 0x11, 0x64, 0xb2, 0x4d, 0x68, 0x4b, 0xf4, 0x6a, 0x0e, 0xdf, 0xf9,
	0xbe, 0xef, 0xfc, 0x30, 0x07, 0x7d, 0x1a, 0x64, 0xd9, 0xe0, 0xa2, 0x5f, 0xed, 0xf6, 0xf2, 0x6a,
	0x11, 0xba, 0xe8, 0xb6, 0x56, 0xed, 0x8f, 0xc7, 0xd9, 0x38, 0xaf, 0x5e, 0xf6, 0x7b, 0xc3, 0xae,
	0x3d, 0xbf, 0x19, 0xf5, 0x2e, 0xfa, 0x76, 0x82, 0x79, 0x57, 0xe3, 0xec, 0x3a, 0x23, 0xe5, 0x82,
	0xed, 0x75, 0x7b, 0xb9, 0x37, 0x13, 0x7a, 0xb7, 0x35, 0xaf, 0x10, 0x1e, 0x1e, 0x4d, 0x8d, 0xaf,
	0x86, 0xd5, 0xee, 0x68, 0x94, 0x5d, 0x77, 0xaf, 0x87, 0xd9, 0x28, 0x2f, 0xd4, 0x95, 0x9f, 0xcb,
	0x68, 0x37, 0x76, 0xd6, 0xc1, 0xc4, 0x19, 0x9c, 0x06, 0x46, 0x37, 0x97, 0x95, 0x6f, 0xcb, 0x08,
	0x3f, 0x4e, 0x90, 0x2d, 0xb4, 0x96, 0x0a, 0x9d, 0x40, 0x9d, 0x35, 0x18, 0x84, 0xf8, 0x09, 0x59,
	0x43, 0xab, 0xa9, 0x38, 0x11, 0xb2, 0x25, 0xf0, 0x82, 0xcb, 0x06, 0x34, 0xb4, 0x0a, 0xbe, 0xa4,
	0xa0, 0x0d, 0x5e, 0x22, 0x15, 0x54, 0x0e, 0x65, 0x1a, 0x70, 0xa8, 0x73, 0x56, 0x3f, 0xb1, 0x41,
	0x2a, 0x42, 0x0e, 0x56, 0x48, 0x63, 0x29, 0xe7, 0xb2, 0x05, 0x21, 0x7e, 0x4a, 0x8e, 0xd0, 0x3e,
	0x9c, 0x1a, 0x50, 0x82, 0x72, 0x9b, 0x2a, 0xfe, 0x20, 0xbb, 0x4c, 0x08, 0xda, 0x6c, 0x30, 0x0e,
	0xd6, 0x48, 0x69, 0x39, 0x55, 0x11, 0xe0, 0x15, 0xe2, 0xa1, 0x77, 0x91, 0x94, 0x11, 0x07, 0xdb,
	0x82, 0xc0, 0x86, 0xa0, 0x59, 0x24, 0x40, 0xd9, 0x33, 0x96, 0xd8, 0x09, 0xd7, 0x39, 0x24, 0x69,
	0xc0, 0x99, 0x3e, 0x86, 0x10, 0xaf, 0x92, 0x6d, 0xb4, 0xc1, 0x44, 0x93, 0x72, 0x16, 0x5a, 0x26,
	0x92, 0xd4, 0xe0, 0x67, 0x64, 0x1f, 0xed, 0x4e, 0xa1, 0x18, 0x42, 0x46, 0xef, 0x5a, 0xc3, 0xcf,
	0x49, 0x19, 0x1d, 0xce, 0xcb, 0x58, 0x10, 0x46, 0xb5, 0x31, 0x22, 0x25, 0xb4, 0x3d, 0xcb, 0xb3,
	0x18, 0xac, 0x69, 0x27, 0x80, 0xd7, 0x08, 0x46, 0xeb, 0x53, 0x38, 0xa1, 0xe6, 0x18, 0xaf, 0x93,
	0x03, 0x54, 0x9a, 0x22, 0x6e, 0x2c, 0x05, 0x0d, 0x50, 0x20, 0xea, 0x80, 0x37, 0x5c, 0xf5, 0xc2,
	0x3b, 0xa4, 0x86, 0xde, 0x1b, 0x6d, 0x93, 0xbc, 0x41, 0x95, 0x98, 0x69, 0xcd, 0x44, 0x64, 0x13,
	0xc5, 0x62, 0xaa, 0xda, 0xf3, 0xba, 0xd8, 0x72, 0xe5, 0x34, 0xa8, 0x26, 0x28, 0x0b, 0x4a, 0x49,
	0x85, 0xb1, 0x1b, 0x52, 0x1b, 0xa9, 0x68, 0x04, 0x77, 0xd0, 0x36, 0x79, 0x85, 0x0e, 0x74, 0x8b,
	0x35, 0x1a, 0xed, 0x79, 0x8b, 0x27, 0x6e, 0xb5, 0xae, 0x74, 0x4c, 0x45, 0x7b, 0xb2, 0x37, 0x8d,
	0x77, 0xc8, 0x0e, 0xda, 0x4a, 0x05, 0x9c, 0x26, 0x50, 0x37, 0x10, 0x5a, 0xcd, 0xce, 0x00, 0xef,
	0x92, 0x2a, 0x7a, 0x9f, 0x0a, 0x9d, 0x26, 0x89, 0x54, 0x0e, 0x9d, 0xb7, 0x7b, 0x10, 0x4d, 0xa6,
	0xa4, 0x88, 0x41, 0x18, 0x5c, 0x72, 0x85, 0xef, 0x0b, 0x8e, 0x4d, 0xcc, 0x3f, 0xda, 0x06, 0x50,
	0x93, 0x2a, 0xc0, 0x2f, 0xc8, 0x5b, 0xf4, 0xda, 0x6d, 0x84, 0x89, 0x87, 0xb3, 0xb9, 0xee, 0xb4,
	0xe6, 0xb6, 0x2e, 0xe3, 0x84, 0x33, 0x2a, 0x0c, 0xde, 0x23, 0x2f, 0xd1, 0x5e, 0x3d, 0xd5, 0x46,
	0xc6, 0x16, 0x4e, 0x99, 0x79, 0x30, 0xc0, 0x7e, 0xf0, 0x67, 0x01, 0x55, 0xbe, 0x66, 0x97, 0xde,
	0xff, 0xff, 0x7f, 0x50, 0x7a, 0xfc, 0x8b, 0x13, 0xf7, 0xf1, 0x93, 0x85, 0xb3, 0xf0, 0x4e, 0x38,
	0xc8, 0x2e, 0xba, 0xa3, 0x81, 0x97, 0x8d, 0x07, 0xd5, 0x41, 0x7f, 0x34, 0x39, 0x8b, 0xe9, 0x05,
	0x5e, 0x0d, 0xf3, 0x7f, 0x1d, 0xe4, 0xe7, 0xe2, 0xf9, 0xbe, 0xb8, 0x14, 0x51, 0xfa, 0x63, 0xb1,
	0x1c, 0x15, 0x66, 0xb4, 0x97, 0x7b, 0x45, 0xe8, 0xa2, 0x66, 0xcd, 0x9b, 0x94, 0xcc, 0x7f, 0x4d,
	0x09, 0x1d, 0xda, 0xcb, 0x3b, 0x33, 0x42, 0xa7, 0x59, 0xeb, 0x14, 0x84, 0xdf, 0x8b, 0x95, 0x02,
	0xf5, 0x7d, 0xda, 0xcb, 0x7d, 0x7f, 0x46, 0xf1, 0xfd, 0x66, 0xcd, 0xf7, 0x0b, 0xd2, 0xf9, 0xca,
	0xa4, 0xbb, 0x0f, 0x7f, 0x03, 0x00, 0x00, 0xff, 0xff, 0xf9, 0x49, 0xe4, 0x52, 0x2d, 0x04, 0x00,
	0x00,
}

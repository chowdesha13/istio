// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/api/launch_stage.proto

package api // import "google.golang.org/genproto/googleapis/api"

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

// The launch stage as defined by [Google Cloud Platform
// Launch Stages](http://cloud.google.com/terms/launch-stages).
type LaunchStage int32

const (
	// Do not use this default value.
	LaunchStage_LAUNCH_STAGE_UNSPECIFIED LaunchStage = 0
	// Early Access features are limited to a closed group of testers. To use
	// these features, you must sign up in advance and sign a Trusted Tester
	// agreement (which includes confidentiality provisions). These features may
	// be unstable, changed in backward-incompatible ways, and are not
	// guaranteed to be released.
	LaunchStage_EARLY_ACCESS LaunchStage = 1
	// Alpha is a limited availability test for releases before they are cleared
	// for widespread use. By Alpha, all significant design issues are resolved
	// and we are in the process of verifying functionality. Alpha customers
	// need to apply for access, agree to applicable terms, and have their
	// projects whitelisted. Alpha releases don’t have to be feature complete,
	// no SLAs are provided, and there are no technical support obligations, but
	// they will be far enough along that customers can actually use them in
	// test environments or for limited-use tests -- just like they would in
	// normal production cases.
	LaunchStage_ALPHA LaunchStage = 2
	// Beta is the point at which we are ready to open a release for any
	// customer to use. There are no SLA or technical support obligations in a
	// Beta release. Products will be complete from a feature perspective, but
	// may have some open outstanding issues. Beta releases are suitable for
	// limited production use cases.
	LaunchStage_BETA LaunchStage = 3
	// GA features are open to all developers and are considered stable and
	// fully qualified for production use.
	LaunchStage_GA LaunchStage = 4
	// Deprecated features are scheduled to be shut down and removed. For more
	// information, see the “Deprecation Policy” section of our [Terms of
	// Service](https://cloud.google.com/terms/)
	// and the [Google Cloud Platform Subject to the Deprecation
	// Policy](https://cloud.google.com/terms/deprecation) documentation.
	LaunchStage_DEPRECATED LaunchStage = 5
)

var LaunchStage_name = map[int32]string{
	0: "LAUNCH_STAGE_UNSPECIFIED",
	1: "EARLY_ACCESS",
	2: "ALPHA",
	3: "BETA",
	4: "GA",
	5: "DEPRECATED",
}
var LaunchStage_value = map[string]int32{
	"LAUNCH_STAGE_UNSPECIFIED": 0,
	"EARLY_ACCESS":             1,
	"ALPHA":                    2,
	"BETA":                     3,
	"GA":                       4,
	"DEPRECATED":               5,
}

func (x LaunchStage) String() string {
	return proto.EnumName(LaunchStage_name, int32(x))
}
func (LaunchStage) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_launch_stage_a5005a4ee2700165, []int{0}
}

func init() {
	proto.RegisterEnum("google.api.LaunchStage", LaunchStage_name, LaunchStage_value)
}

func init() {
	proto.RegisterFile("google/api/launch_stage.proto", fileDescriptor_launch_stage_a5005a4ee2700165)
}

var fileDescriptor_launch_stage_a5005a4ee2700165 = []byte{
	// 225 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x8f, 0xc1, 0x4a, 0xc3, 0x40,
	0x14, 0x45, 0x6d, 0x4c, 0x8b, 0x3e, 0xa5, 0x3c, 0x66, 0xe5, 0x42, 0x7f, 0x40, 0x30, 0x59, 0xb8,
	0x74, 0xf5, 0x32, 0x79, 0xa6, 0x81, 0x50, 0x86, 0x4e, 0xba, 0xb0, 0x9b, 0x30, 0x96, 0x30, 0x8e,
	0xc4, 0xcc, 0xd0, 0xd6, 0x1f, 0xf2, 0x4b, 0x25, 0x89, 0x60, 0xd7, 0xe7, 0xc0, 0x3d, 0x17, 0x1e,
	0xac, 0xf7, 0xb6, 0x6b, 0x53, 0x13, 0x5c, 0xda, 0x99, 0xef, 0x7e, 0xff, 0xd1, 0x1c, 0x4f, 0xc6,
	0xb6, 0x49, 0x38, 0xf8, 0x93, 0x17, 0x30, 0xe1, 0xc4, 0x04, 0xf7, 0xf8, 0x09, 0x37, 0xd5, 0x68,
	0xe8, 0x41, 0x10, 0xf7, 0x70, 0x57, 0xd1, 0x76, 0x2d, 0x57, 0x8d, 0xae, 0xa9, 0xe0, 0x66, 0xbb,
	0xd6, 0x8a, 0x65, 0xf9, 0x5a, 0x72, 0x8e, 0x17, 0x02, 0xe1, 0x96, 0x69, 0x53, 0xbd, 0x35, 0x24,
	0x25, 0x6b, 0x8d, 0x33, 0x71, 0x0d, 0x73, 0xaa, 0xd4, 0x8a, 0x30, 0x12, 0x57, 0x10, 0x67, 0x5c,
	0x13, 0x5e, 0x8a, 0x05, 0x44, 0x05, 0x61, 0x2c, 0x96, 0x00, 0x39, 0xab, 0x0d, 0x4b, 0xaa, 0x39,
	0xc7, 0x79, 0xb6, 0x83, 0xe5, 0xde, 0x7f, 0x25, 0xff, 0xeb, 0x19, 0x9e, 0x6d, 0xab, 0xa1, 0x4d,
	0xcd, 0x76, 0x4f, 0x7f, 0xdc, 0xfa, 0xce, 0xf4, 0x36, 0xf1, 0x07, 0x9b, 0xda, 0xb6, 0x1f, 0xcb,
	0xd3, 0x09, 0x99, 0xe0, 0x8e, 0xc3, 0xb7, 0x17, 0x13, 0xdc, 0x4f, 0x14, 0x17, 0xa4, 0xca, 0xf7,
	0xc5, 0x28, 0x3c, 0xff, 0x06, 0x00, 0x00, 0xff, 0xff, 0x8e, 0xd5, 0x39, 0x1a, 0xfb, 0x00, 0x00,
	0x00,
}

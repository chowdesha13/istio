// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/adapter/model/v1beta1/extensions.proto

package v1beta1

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/gogo/protobuf/protoc-gen-gogo/descriptor"

import strconv "strconv"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// The available varieties of templates, controlling the semantics of what an adapter does with each instance.
type TemplateVariety int32

const (
	// Makes the template applicable for Mixer's check calls. Instances of such template are created during
	// check calls in Mixer and passed to the handlers based on the rule configurations.
	TEMPLATE_VARIETY_CHECK TemplateVariety = 0
	// Makes the template applicable for Mixer's report calls. Instances of such template are created during
	// report calls in Mixer and passed to the handlers based on the rule configurations.
	TEMPLATE_VARIETY_REPORT TemplateVariety = 1
	// Makes the template applicable for Mixer's quota calls. Instances of such template are created during
	// quota check calls in Mixer and passed to the handlers based on the rule configurations.
	TEMPLATE_VARIETY_QUOTA TemplateVariety = 2
	// Makes the template applicable for Mixer's attribute generation phase. Instances of such template are created during
	// pre-processing attribute generation phase and passed to the handlers based on the rule configurations.
	TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR TemplateVariety = 3
	// Makes the template applicable for Mixer's check calls. Instances of such template are created during
	// check calls in Mixer and passed to the handlers that produce values.
	TEMPLATE_VARIETY_CHECK_WITH_OUTPUT TemplateVariety = 4
)

var TemplateVariety_name = map[int32]string{
	0: "TEMPLATE_VARIETY_CHECK",
	1: "TEMPLATE_VARIETY_REPORT",
	2: "TEMPLATE_VARIETY_QUOTA",
	3: "TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR",
	4: "TEMPLATE_VARIETY_CHECK_WITH_OUTPUT",
}
var TemplateVariety_value = map[string]int32{
	"TEMPLATE_VARIETY_CHECK":               0,
	"TEMPLATE_VARIETY_REPORT":              1,
	"TEMPLATE_VARIETY_QUOTA":               2,
	"TEMPLATE_VARIETY_ATTRIBUTE_GENERATOR": 3,
	"TEMPLATE_VARIETY_CHECK_WITH_OUTPUT":   4,
}

func (TemplateVariety) EnumDescriptor() ([]byte, []int) { return fileDescriptorExtensions, []int{0} }

var E_TemplateVariety = &proto.ExtensionDesc{
	ExtendedType:  (*google_protobuf.FileOptions)(nil),
	ExtensionType: (*TemplateVariety)(nil),
	Field:         72295727,
	Name:          "istio.mixer.adapter.model.v1beta1.template_variety",
	Tag:           "varint,72295727,opt,name=template_variety,json=templateVariety,enum=istio.mixer.adapter.model.v1beta1.TemplateVariety",
	Filename:      "mixer/adapter/model/v1beta1/extensions.proto",
}

var E_TemplateName = &proto.ExtensionDesc{
	ExtendedType:  (*google_protobuf.FileOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         72295888,
	Name:          "istio.mixer.adapter.model.v1beta1.template_name",
	Tag:           "bytes,72295888,opt,name=template_name,json=templateName",
	Filename:      "mixer/adapter/model/v1beta1/extensions.proto",
}

func init() {
	proto.RegisterEnum("istio.mixer.adapter.model.v1beta1.TemplateVariety", TemplateVariety_name, TemplateVariety_value)
	proto.RegisterExtension(E_TemplateVariety)
	proto.RegisterExtension(E_TemplateName)
}
func (x TemplateVariety) String() string {
	s, ok := TemplateVariety_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}

func init() {
	proto.RegisterFile("mixer/adapter/model/v1beta1/extensions.proto", fileDescriptorExtensions)
}

var fileDescriptorExtensions = []byte{
	// 382 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0xc9, 0xcd, 0xac, 0x48,
	0x2d, 0xd2, 0x4f, 0x4c, 0x49, 0x2c, 0x28, 0x49, 0x2d, 0xd2, 0xcf, 0xcd, 0x4f, 0x49, 0xcd, 0xd1,
	0x2f, 0x33, 0x4c, 0x4a, 0x2d, 0x49, 0x34, 0xd4, 0x4f, 0xad, 0x28, 0x49, 0xcd, 0x2b, 0xce, 0xcc,
	0xcf, 0x2b, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x52, 0xcc, 0x2c, 0x2e, 0xc9, 0xcc, 0xd7,
	0x03, 0xeb, 0xd1, 0x83, 0xea, 0xd1, 0x03, 0xeb, 0xd1, 0x83, 0xea, 0x91, 0x52, 0x48, 0xcf, 0xcf,
	0x4f, 0xcf, 0x49, 0xd5, 0x07, 0x6b, 0x48, 0x2a, 0x4d, 0xd3, 0x4f, 0x49, 0x2d, 0x4e, 0x2e, 0xca,
	0x2c, 0x28, 0xc9, 0x2f, 0x82, 0x18, 0xa2, 0xb5, 0x83, 0x91, 0x8b, 0x3f, 0x24, 0x35, 0xb7, 0x20,
	0x27, 0xb1, 0x24, 0x35, 0x2c, 0xb1, 0x28, 0x33, 0xb5, 0xa4, 0x52, 0x48, 0x8a, 0x4b, 0x2c, 0xc4,
	0xd5, 0x37, 0xc0, 0xc7, 0x31, 0xc4, 0x35, 0x3e, 0xcc, 0x31, 0xc8, 0xd3, 0x35, 0x24, 0x32, 0xde,
	0xd9, 0xc3, 0xd5, 0xd9, 0x5b, 0x80, 0x41, 0x48, 0x9a, 0x4b, 0x1c, 0x43, 0x2e, 0xc8, 0x35, 0xc0,
	0x3f, 0x28, 0x44, 0x80, 0x11, 0xab, 0xc6, 0xc0, 0x50, 0xff, 0x10, 0x47, 0x01, 0x26, 0x21, 0x0d,
	0x2e, 0x15, 0x0c, 0x39, 0xc7, 0x90, 0x90, 0x20, 0x4f, 0xa7, 0xd0, 0x10, 0xd7, 0x78, 0x77, 0x57,
	0x3f, 0xd7, 0x20, 0xc7, 0x10, 0xff, 0x20, 0x01, 0x66, 0x21, 0x35, 0x2e, 0x25, 0xec, 0xd6, 0xc7,
	0x87, 0x7b, 0x86, 0x78, 0xc4, 0xfb, 0x87, 0x86, 0x04, 0x84, 0x86, 0x08, 0xb0, 0x58, 0xd5, 0x71,
	0x09, 0x94, 0x40, 0x5d, 0x1e, 0x5f, 0x06, 0x75, 0xba, 0x8c, 0x1e, 0xc4, 0xc7, 0x7a, 0x30, 0x1f,
	0xeb, 0xb9, 0x65, 0xe6, 0xa4, 0xfa, 0x17, 0x94, 0x80, 0xc2, 0x4d, 0x62, 0xfd, 0xa9, 0x3d, 0x4a,
	0x0a, 0x8c, 0x1a, 0x7c, 0x46, 0x46, 0x7a, 0x04, 0xc3, 0x4e, 0x0f, 0x2d, 0x54, 0x82, 0xf8, 0x4b,
	0x50, 0x05, 0xac, 0x5c, 0xb8, 0x78, 0xe1, 0xf6, 0xe7, 0x25, 0xe6, 0xa6, 0x12, 0xb0, 0xfc, 0xc2,
	0x69, 0xb0, 0xe5, 0x9c, 0x41, 0x3c, 0x30, 0x5d, 0x7e, 0x89, 0xb9, 0xa9, 0x4e, 0x61, 0x17, 0x1e,
	0xca, 0x31, 0xdc, 0x78, 0x28, 0xc7, 0xf0, 0xe1, 0xa1, 0x1c, 0x63, 0xc3, 0x23, 0x39, 0xc6, 0x15,
	0x8f, 0xe4, 0x18, 0x4f, 0x3c, 0x92, 0x63, 0xbc, 0xf0, 0x48, 0x8e, 0xf1, 0xc1, 0x23, 0x39, 0xc6,
	0x17, 0x8f, 0xe4, 0x18, 0x3e, 0x3c, 0x92, 0x63, 0x9c, 0xf0, 0x58, 0x8e, 0x21, 0x4a, 0x03, 0xe2,
	0xee, 0xcc, 0x7c, 0xfd, 0xc4, 0x82, 0x4c, 0x7d, 0x3c, 0xc9, 0x25, 0x89, 0x0d, 0xec, 0x08, 0x63,
	0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0xfd, 0x93, 0x1c, 0x86, 0x54, 0x02, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/api/logging.proto

package serviceconfig // import "google.golang.org/genproto/googleapis/api/serviceconfig"

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

// Logging configuration of the service.
//
// The following example shows how to configure logs to be sent to the
// producer and consumer projects. In the example, the `activity_history`
// log is sent to both the producer and consumer projects, whereas the
// `purchase_history` log is only sent to the producer project.
//
//     monitored_resources:
//     - type: library.googleapis.com/branch
//       labels:
//       - key: /city
//         description: The city where the library branch is located in.
//       - key: /name
//         description: The name of the branch.
//     logs:
//     - name: activity_history
//       labels:
//       - key: /customer_id
//     - name: purchase_history
//     logging:
//       producer_destinations:
//       - monitored_resource: library.googleapis.com/branch
//         logs:
//         - activity_history
//         - purchase_history
//       consumer_destinations:
//       - monitored_resource: library.googleapis.com/branch
//         logs:
//         - activity_history
type Logging struct {
	// Logging configurations for sending logs to the producer project.
	// There can be multiple producer destinations, each one must have a
	// different monitored resource type. A log can be used in at most
	// one producer destination.
	ProducerDestinations []*Logging_LoggingDestination `protobuf:"bytes,1,rep,name=producer_destinations,json=producerDestinations,proto3" json:"producer_destinations,omitempty"`
	// Logging configurations for sending logs to the consumer project.
	// There can be multiple consumer destinations, each one must have a
	// different monitored resource type. A log can be used in at most
	// one consumer destination.
	ConsumerDestinations []*Logging_LoggingDestination `protobuf:"bytes,2,rep,name=consumer_destinations,json=consumerDestinations,proto3" json:"consumer_destinations,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                      `json:"-"`
	XXX_unrecognized     []byte                        `json:"-"`
	XXX_sizecache        int32                         `json:"-"`
}

func (m *Logging) Reset()         { *m = Logging{} }
func (m *Logging) String() string { return proto.CompactTextString(m) }
func (*Logging) ProtoMessage()    {}
func (*Logging) Descriptor() ([]byte, []int) {
	return fileDescriptor_logging_75c6d16b6d5e00f3, []int{0}
}
func (m *Logging) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Logging.Unmarshal(m, b)
}
func (m *Logging) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Logging.Marshal(b, m, deterministic)
}
func (dst *Logging) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Logging.Merge(dst, src)
}
func (m *Logging) XXX_Size() int {
	return xxx_messageInfo_Logging.Size(m)
}
func (m *Logging) XXX_DiscardUnknown() {
	xxx_messageInfo_Logging.DiscardUnknown(m)
}

var xxx_messageInfo_Logging proto.InternalMessageInfo

func (m *Logging) GetProducerDestinations() []*Logging_LoggingDestination {
	if m != nil {
		return m.ProducerDestinations
	}
	return nil
}

func (m *Logging) GetConsumerDestinations() []*Logging_LoggingDestination {
	if m != nil {
		return m.ConsumerDestinations
	}
	return nil
}

// Configuration of a specific logging destination (the producer project
// or the consumer project).
type Logging_LoggingDestination struct {
	// The monitored resource type. The type must be defined in the
	// [Service.monitored_resources][google.api.Service.monitored_resources]
	// section.
	MonitoredResource string `protobuf:"bytes,3,opt,name=monitored_resource,json=monitoredResource,proto3" json:"monitored_resource,omitempty"`
	// Names of the logs to be sent to this destination. Each name must
	// be defined in the [Service.logs][google.api.Service.logs] section. If the
	// log name is not a domain scoped name, it will be automatically prefixed
	// with the service name followed by "/".
	Logs                 []string `protobuf:"bytes,1,rep,name=logs,proto3" json:"logs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Logging_LoggingDestination) Reset()         { *m = Logging_LoggingDestination{} }
func (m *Logging_LoggingDestination) String() string { return proto.CompactTextString(m) }
func (*Logging_LoggingDestination) ProtoMessage()    {}
func (*Logging_LoggingDestination) Descriptor() ([]byte, []int) {
	return fileDescriptor_logging_75c6d16b6d5e00f3, []int{0, 0}
}
func (m *Logging_LoggingDestination) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Logging_LoggingDestination.Unmarshal(m, b)
}
func (m *Logging_LoggingDestination) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Logging_LoggingDestination.Marshal(b, m, deterministic)
}
func (dst *Logging_LoggingDestination) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Logging_LoggingDestination.Merge(dst, src)
}
func (m *Logging_LoggingDestination) XXX_Size() int {
	return xxx_messageInfo_Logging_LoggingDestination.Size(m)
}
func (m *Logging_LoggingDestination) XXX_DiscardUnknown() {
	xxx_messageInfo_Logging_LoggingDestination.DiscardUnknown(m)
}

var xxx_messageInfo_Logging_LoggingDestination proto.InternalMessageInfo

func (m *Logging_LoggingDestination) GetMonitoredResource() string {
	if m != nil {
		return m.MonitoredResource
	}
	return ""
}

func (m *Logging_LoggingDestination) GetLogs() []string {
	if m != nil {
		return m.Logs
	}
	return nil
}

func init() {
	proto.RegisterType((*Logging)(nil), "google.api.Logging")
	proto.RegisterType((*Logging_LoggingDestination)(nil), "google.api.Logging.LoggingDestination")
}

func init() { proto.RegisterFile("google/api/logging.proto", fileDescriptor_logging_75c6d16b6d5e00f3) }

var fileDescriptor_logging_75c6d16b6d5e00f3 = []byte{
	// 270 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x90, 0x4f, 0x4b, 0xc4, 0x30,
	0x10, 0xc5, 0x69, 0x77, 0x51, 0x36, 0x8a, 0x60, 0x50, 0x28, 0x8b, 0x87, 0xc5, 0x83, 0xec, 0xc5,
	0x14, 0xf4, 0xe8, 0xc9, 0x45, 0x11, 0xc1, 0x43, 0xe9, 0x45, 0xd0, 0xc3, 0x12, 0xd3, 0x38, 0x04,
	0xda, 0x99, 0x90, 0xa4, 0x7e, 0x1a, 0x4f, 0x7e, 0x52, 0xd9, 0xa6, 0x75, 0xab, 0x9e, 0xf6, 0x94,
	0x3f, 0xef, 0xbd, 0x5f, 0x32, 0x8f, 0x65, 0x40, 0x04, 0xb5, 0xce, 0xa5, 0x35, 0x79, 0x4d, 0x00,
	0x06, 0x41, 0x58, 0x47, 0x81, 0x38, 0x8b, 0x8a, 0x90, 0xd6, 0xcc, 0xcf, 0x46, 0x2e, 0x89, 0x48,
	0x41, 0x06, 0x43, 0xe8, 0xa3, 0xf3, 0xfc, 0x33, 0x65, 0xfb, 0x4f, 0x31, 0xcb, 0x5f, 0xd9, 0xa9,
	0x75, 0x54, 0xb5, 0x4a, 0xbb, 0x75, 0xa5, 0x7d, 0x30, 0x18, 0xad, 0x59, 0xb2, 0x98, 0x2c, 0x0f,
	0xae, 0x2e, 0xc4, 0x96, 0x2a, 0xfa, 0xcc, 0xb0, 0xde, 0x6d, 0xed, 0xe5, 0xc9, 0x00, 0x19, 0x5d,
	0xfa, 0x0d, 0x5c, 0x11, 0xfa, 0xb6, 0xf9, 0x0b, 0x4f, 0x77, 0x83, 0x0f, 0x90, 0x31, 0x7c, 0xfe,
	0xcc, 0xf8, 0x7f, 0x2f, 0xbf, 0x64, 0xbc, 0x21, 0x34, 0x81, 0x9c, 0xae, 0xd6, 0x4e, 0x7b, 0x6a,
	0x9d, 0xd2, 0xd9, 0x64, 0x91, 0x2c, 0x67, 0xe5, 0xf1, 0x8f, 0x52, 0xf6, 0x02, 0xe7, 0x6c, 0x5a,
	0x13, 0xc4, 0x69, 0x67, 0x65, 0xb7, 0x5f, 0x21, 0x3b, 0x52, 0xd4, 0x8c, 0xfe, 0xb6, 0x3a, 0xec,
	0x1f, 0x2a, 0x36, 0xf5, 0x15, 0xc9, 0xcb, 0x7d, 0xaf, 0x01, 0xd5, 0x12, 0x41, 0x90, 0x83, 0x1c,
	0x34, 0x76, 0xe5, 0xe6, 0x51, 0x92, 0xd6, 0xf8, 0xae, 0x7d, 0xaf, 0xdd, 0x87, 0x51, 0x5a, 0x11,
	0xbe, 0x1b, 0xb8, 0xf9, 0x75, 0xfa, 0x4a, 0xa7, 0x0f, 0xb7, 0xc5, 0xe3, 0xdb, 0x5e, 0x17, 0xbc,
	0xfe, 0x0e, 0x00, 0x00, 0xff, 0xff, 0x73, 0x4f, 0x86, 0x6e, 0xdb, 0x01, 0x00, 0x00,
}

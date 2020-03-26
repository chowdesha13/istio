// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/adapter/solarwinds/config/config.proto

// The `solarwinds` adapter enables Istio to deliver log and metric data to the
// [Papertrail](https://www.papertrailapp.com) logging backend and the
// [AppOptics](https://www.appoptics.com) monitoring backend.
//
// This adapter supports the [metric template](https://istio.io/docs/reference/config/policy-and-telemetry/templates/metric/)
// and the [logentry template](https://istio.io/docs/reference/config/policy-and-telemetry/templates/metric/).

package config

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_gogo_protobuf_sortkeys "github.com/gogo/protobuf/sortkeys"
	_ "github.com/gogo/protobuf/types"
	github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
	time "time"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Configuration format for the `solarwinds` adapter.
//
// Example config usage:
// ```yaml
// apiVersion: "config.istio.io/v1alpha2"
// kind: handler
// metadata:
//   name: solarwinds
//   namespace: istio-system
// spec:
//   compiledAdapter: solarwinds
//   params:
//     appoptics_access_token: <APPOPTICS SAMPLE TOKEN>
//     papertrail_url: <PAPERTRAIL URL>
//     papertrail_local_retention_duration: <RETENTION PERIOD FOR LOGS LOCALLY, Optional>
//     metrics:
//       requestcount.metric.istio-system:
//         label_names:
//         - source_service
//         - source_version
//         - destination_service
//         - destination_version
//         - response_code
//       requestduration.metric.istio-system:
//         label_names:
//         - source_service
//         - source_version
//         - destination_service
//         - destination_version
//         - response_code
//       requestsize.metric.istio-system:
//         label_names:
//         - source_service
//         - source_version
//         - destination_service
//         - destination_version
//         - response_code
//       responsesize.metric.istio-system:
//         label_names:
//         - source_service
//         - source_version
//         - destination_service
//         - destination_version
//         - response_code
//       tcpbytesent.metric.istio-system:
//         label_names:
//         - source_service
//         - source_version
//         - destination_service
//         - destination_version
//       tcpbytereceived.metric.istio-system:
//         label_names:
//         - source_service
//         - source_version
//         - destination_service
//         - destination_version
//     logs:
//       solarwindslogentry.logentry.istio-system:
//         payloadTemplate: '{{or (.originIp) "-"}} - {{or (.sourceUser) "-"}} [{{or (.timestamp.Format "2006-01-02T15:04:05Z07:00") "-"}}] "{{or (.method) "-"}} {{or (.url) "-"}} {{or (.protocol) "-"}}" {{or (.responseCode) "-"}} {{or (.responseSize) "-"}}'
// ```
type Params struct {
	// AppOptics Access Token needed to send metrics to AppOptics. If no access token is given then metrics
	// will NOT be shipped to AppOptics
	AppopticsAccessToken string `protobuf:"bytes,1,opt,name=appoptics_access_token,json=appopticsAccessToken,proto3" json:"appoptics_access_token,omitempty"`
	// Optional. Max batch size of metrics to be sent to AppOptics.
	// AppOptics does not allow batch size greater than 1000.
	// If this is unspecified or given a value 0 explicitly, a default batch size of 1000 will be used.
	AppopticsBatchSize int32 `protobuf:"varint,2,opt,name=appoptics_batch_size,json=appopticsBatchSize,proto3" json:"appoptics_batch_size,omitempty"`
	// Papertrail url to ship logs to. If no papertrail url is given then the logs will NOT be shipped but rather
	// dropped.
	PapertrailUrl string `protobuf:"bytes,3,opt,name=papertrail_url,json=papertrailUrl,proto3" json:"papertrail_url,omitempty"`
	// This is the duration for which logs will be persisted locally until it is shipped to papertrail in the event
	// of a network failure. Default value is 1 hour.
	PapertrailLocalRetentionDuration *time.Duration `protobuf:"bytes,4,opt,name=papertrail_local_retention_duration,json=papertrailLocalRetentionDuration,proto3,stdduration" json:"papertrail_local_retention_duration,omitempty"`
	// A map of Istio metric name to solarwinds metric info.
	Metrics map[string]*Params_MetricInfo `protobuf:"bytes,5,rep,name=metrics,proto3" json:"metrics,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// A map of Istio logentry name to solarwinds log info.
	Logs map[string]*Params_LogInfo `protobuf:"bytes,6,rep,name=logs,proto3" json:"logs,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *Params) Reset()      { *m = Params{} }
func (*Params) ProtoMessage() {}
func (*Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe020fae3853bd8, []int{0}
}
func (m *Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params.Merge(m, src)
}
func (m *Params) XXX_Size() int {
	return m.Size()
}
func (m *Params) XXX_DiscardUnknown() {
	xxx_messageInfo_Params.DiscardUnknown(m)
}

var xxx_messageInfo_Params proto.InternalMessageInfo

// Describes how to represent an Istio metric in Solarwinds AppOptics
type Params_MetricInfo struct {
	// The names of labels to use: these need to match the dimensions of the Istio metric.
	LabelNames []string `protobuf:"bytes,1,rep,name=label_names,json=labelNames,proto3" json:"label_names,omitempty"`
}

func (m *Params_MetricInfo) Reset()      { *m = Params_MetricInfo{} }
func (*Params_MetricInfo) ProtoMessage() {}
func (*Params_MetricInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe020fae3853bd8, []int{0, 0}
}
func (m *Params_MetricInfo) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params_MetricInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params_MetricInfo.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params_MetricInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params_MetricInfo.Merge(m, src)
}
func (m *Params_MetricInfo) XXX_Size() int {
	return m.Size()
}
func (m *Params_MetricInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_Params_MetricInfo.DiscardUnknown(m)
}

var xxx_messageInfo_Params_MetricInfo proto.InternalMessageInfo

// Describes how to represent an Istio log entry in Solarwinds AppOptics
type Params_LogInfo struct {
	// Optional. A golang text/template template (more details about golang text/template's templating can be
	// found here: https://golang.org/pkg/text/template/) that will be executed to construct the payload for
	// this log entry.
	// An example template that could be used:
	// {{or (.originIp) "-"}} - {{or (.sourceUser) "-"}} [{{or (.timestamp.Format "2006-01-02T15:04:05Z07:00") "-"}}] "{{or (.method) "-"}} {{or (.url) "-"}} {{or (.protocol) "-"}}" {{or (.responseCode) "-"}} {{or (.responseSize) "-"}}
	// A sample log that will be created after parsing the template with appropriate variables will look like this:
	// Jan 23 21:53:02 istio-mixer-57d88dc4b4-rbgmc istio: 10.32.0.15 - kubernetes://istio-ingress-78545c5bc9-wbr6g.istio-system [2018-01-24T02:53:02Z] "GET /productpage http" 200 5599
	// It will be given the full set of variables for the log to use to construct its result.
	// If it is not provided, a default template in place will be used.
	PayloadTemplate string `protobuf:"bytes,1,opt,name=payload_template,json=payloadTemplate,proto3" json:"payload_template,omitempty"`
}

func (m *Params_LogInfo) Reset()      { *m = Params_LogInfo{} }
func (*Params_LogInfo) ProtoMessage() {}
func (*Params_LogInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe020fae3853bd8, []int{0, 2}
}
func (m *Params_LogInfo) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params_LogInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params_LogInfo.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params_LogInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params_LogInfo.Merge(m, src)
}
func (m *Params_LogInfo) XXX_Size() int {
	return m.Size()
}
func (m *Params_LogInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_Params_LogInfo.DiscardUnknown(m)
}

var xxx_messageInfo_Params_LogInfo proto.InternalMessageInfo

func init() {
	proto.RegisterType((*Params)(nil), "adapter.solarwinds.config.Params")
	proto.RegisterMapType((map[string]*Params_LogInfo)(nil), "adapter.solarwinds.config.Params.LogsEntry")
	proto.RegisterMapType((map[string]*Params_MetricInfo)(nil), "adapter.solarwinds.config.Params.MetricsEntry")
	proto.RegisterType((*Params_MetricInfo)(nil), "adapter.solarwinds.config.Params.MetricInfo")
	proto.RegisterType((*Params_LogInfo)(nil), "adapter.solarwinds.config.Params.LogInfo")
}

func init() {
	proto.RegisterFile("mixer/adapter/solarwinds/config/config.proto", fileDescriptor_ffe020fae3853bd8)
}

var fileDescriptor_ffe020fae3853bd8 = []byte{
	// 527 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x41, 0x6f, 0xd3, 0x3e,
	0x1c, 0x8d, 0xd7, 0xb5, 0xfb, 0xd7, 0xfd, 0x03, 0x93, 0x35, 0xa1, 0x2c, 0x07, 0x37, 0x02, 0x21,
	0x75, 0x62, 0x38, 0xa8, 0xec, 0x80, 0xb8, 0x0c, 0x2a, 0x90, 0x40, 0x2a, 0x08, 0x85, 0x71, 0xe1,
	0x12, 0xb9, 0xa9, 0x9b, 0x45, 0x73, 0xe3, 0xc8, 0x76, 0x81, 0xee, 0xc4, 0x47, 0xe0, 0xc8, 0x47,
	0xe0, 0xa3, 0x94, 0x5b, 0x8f, 0x3b, 0x01, 0x4d, 0x2f, 0x1c, 0xf7, 0x11, 0x50, 0xe2, 0xa4, 0x1d,
	0x08, 0xc4, 0x4e, 0x75, 0xdf, 0x7b, 0xbf, 0xe7, 0xf7, 0x7e, 0x0e, 0xdc, 0x1f, 0xc7, 0xef, 0x99,
	0xf4, 0xe8, 0x90, 0xa6, 0x9a, 0x49, 0x4f, 0x09, 0x4e, 0xe5, 0xbb, 0x38, 0x19, 0x2a, 0x2f, 0x14,
	0xc9, 0x28, 0x8e, 0xca, 0x1f, 0x92, 0x4a, 0xa1, 0x05, 0xda, 0x2d, 0x75, 0x64, 0xad, 0x23, 0x46,
	0xe0, 0xec, 0x44, 0x22, 0x12, 0x85, 0xca, 0xcb, 0x4f, 0x66, 0xc0, 0xc1, 0x91, 0x10, 0x11, 0x67,
	0x5e, 0xf1, 0x6f, 0x30, 0x19, 0x79, 0xc3, 0x89, 0xa4, 0x3a, 0x16, 0x89, 0xe1, 0x6f, 0x7c, 0xa9,
	0xc3, 0xc6, 0x4b, 0x2a, 0xe9, 0x58, 0xa1, 0x03, 0x78, 0x9d, 0xa6, 0xa9, 0x48, 0x75, 0x1c, 0xaa,
	0x80, 0x86, 0x21, 0x53, 0x2a, 0xd0, 0xe2, 0x84, 0x25, 0x36, 0x70, 0x41, 0xa7, 0xe9, 0xef, 0xac,
	0xd8, 0x47, 0x05, 0x79, 0x94, 0x73, 0xe8, 0x2e, 0x5c, 0xe3, 0xc1, 0x80, 0xea, 0xf0, 0x38, 0x50,
	0xf1, 0x29, 0xb3, 0x37, 0x5c, 0xd0, 0xa9, 0xfb, 0x68, 0xc5, 0xf5, 0x72, 0xea, 0x55, 0x7c, 0xca,
	0xd0, 0x2d, 0x78, 0x35, 0xa5, 0x29, 0x93, 0x5a, 0xd2, 0x98, 0x07, 0x13, 0xc9, 0xed, 0x5a, 0xe1,
	0x7f, 0x65, 0x8d, 0xbe, 0x96, 0x1c, 0x49, 0x78, 0xf3, 0x82, 0x8c, 0x8b, 0x90, 0xf2, 0x40, 0x32,
	0xcd, 0x92, 0x3c, 0x7d, 0x50, 0xd5, 0xb0, 0x37, 0x5d, 0xd0, 0x69, 0x75, 0x77, 0x89, 0xe9, 0x49,
	0xaa, 0x9e, 0xe4, 0x71, 0x29, 0xe8, 0xfd, 0x37, 0xfb, 0xda, 0x06, 0x9f, 0xbe, 0xb5, 0x81, 0xef,
	0xae, 0xfd, 0xfa, 0xb9, 0x9d, 0x5f, 0xb9, 0x55, 0x5a, 0xf4, 0x14, 0x6e, 0x8d, 0x99, 0x96, 0x71,
	0xa8, 0xec, 0xba, 0x5b, 0xeb, 0xb4, 0xba, 0x84, 0xfc, 0x75, 0xe1, 0xc4, 0xac, 0x8d, 0x3c, 0x37,
	0x03, 0x4f, 0x12, 0x2d, 0xa7, 0x7e, 0x35, 0x8e, 0x0e, 0xe1, 0x26, 0x17, 0x91, 0xb2, 0x1b, 0x85,
	0xcd, 0xed, 0x7f, 0xdb, 0xf4, 0x45, 0x54, 0x7a, 0x14, 0x83, 0xce, 0x1d, 0x08, 0x8d, 0xf3, 0xb3,
	0x64, 0x24, 0x50, 0x1b, 0xb6, 0x38, 0x1d, 0x30, 0x1e, 0x24, 0x74, 0xcc, 0x94, 0x0d, 0xdc, 0x5a,
	0xa7, 0xe9, 0xc3, 0x02, 0x7a, 0x91, 0x23, 0xce, 0x31, 0xfc, 0xff, 0x62, 0x10, 0xb4, 0x0d, 0x6b,
	0x27, 0x6c, 0x5a, 0xbe, 0x5c, 0x7e, 0x44, 0x3d, 0x58, 0x7f, 0x4b, 0xf9, 0xc4, 0xbc, 0x4c, 0xab,
	0xbb, 0x7f, 0xd9, 0x66, 0xf9, 0xfd, 0xbe, 0x19, 0x7d, 0xb0, 0x71, 0x1f, 0x38, 0x07, 0x70, 0xab,
	0x2f, 0xa2, 0x22, 0xd5, 0x1e, 0xdc, 0x4e, 0xe9, 0x94, 0x0b, 0x3a, 0x0c, 0x34, 0x1b, 0xa7, 0x9c,
	0x6a, 0x56, 0xde, 0x78, 0xad, 0xc4, 0x8f, 0x4a, 0xd8, 0x19, 0xc0, 0xe6, 0xaa, 0xe1, 0x1f, 0xc2,
	0x1d, 0xfe, 0x1a, 0x6e, 0xef, 0x52, 0xfb, 0xfa, 0x2d, 0x59, 0xef, 0xe1, 0x6c, 0x81, 0xad, 0xf9,
	0x02, 0x5b, 0x67, 0x0b, 0x6c, 0x9d, 0x2f, 0xb0, 0xf5, 0x21, 0xc3, 0xe0, 0x73, 0x86, 0xad, 0x59,
	0x86, 0xc1, 0x3c, 0xc3, 0xe0, 0x7b, 0x86, 0xc1, 0x8f, 0x0c, 0x5b, 0xe7, 0x19, 0x06, 0x1f, 0x97,
	0xd8, 0x9a, 0x2f, 0xb1, 0x75, 0xb6, 0xc4, 0xd6, 0x9b, 0x86, 0xf1, 0x1e, 0x34, 0x8a, 0xcf, 0xe7,
	0xde, 0xcf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0f, 0x60, 0xbc, 0xf8, 0x95, 0x03, 0x00, 0x00,
}

func (m *Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Params) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Logs) > 0 {
		for k := range m.Logs {
			v := m.Logs[k]
			baseI := i
			if v != nil {
				{
					size, err := v.MarshalToSizedBuffer(dAtA[:i])
					if err != nil {
						return 0, err
					}
					i -= size
					i = encodeVarintConfig(dAtA, i, uint64(size))
				}
				i--
				dAtA[i] = 0x12
			}
			i -= len(k)
			copy(dAtA[i:], k)
			i = encodeVarintConfig(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = encodeVarintConfig(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x32
		}
	}
	if len(m.Metrics) > 0 {
		for k := range m.Metrics {
			v := m.Metrics[k]
			baseI := i
			if v != nil {
				{
					size, err := v.MarshalToSizedBuffer(dAtA[:i])
					if err != nil {
						return 0, err
					}
					i -= size
					i = encodeVarintConfig(dAtA, i, uint64(size))
				}
				i--
				dAtA[i] = 0x12
			}
			i -= len(k)
			copy(dAtA[i:], k)
			i = encodeVarintConfig(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = encodeVarintConfig(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x2a
		}
	}
	if m.PapertrailLocalRetentionDuration != nil {
		n3, err3 := github_com_gogo_protobuf_types.StdDurationMarshalTo(*m.PapertrailLocalRetentionDuration, dAtA[i-github_com_gogo_protobuf_types.SizeOfStdDuration(*m.PapertrailLocalRetentionDuration):])
		if err3 != nil {
			return 0, err3
		}
		i -= n3
		i = encodeVarintConfig(dAtA, i, uint64(n3))
		i--
		dAtA[i] = 0x22
	}
	if len(m.PapertrailUrl) > 0 {
		i -= len(m.PapertrailUrl)
		copy(dAtA[i:], m.PapertrailUrl)
		i = encodeVarintConfig(dAtA, i, uint64(len(m.PapertrailUrl)))
		i--
		dAtA[i] = 0x1a
	}
	if m.AppopticsBatchSize != 0 {
		i = encodeVarintConfig(dAtA, i, uint64(m.AppopticsBatchSize))
		i--
		dAtA[i] = 0x10
	}
	if len(m.AppopticsAccessToken) > 0 {
		i -= len(m.AppopticsAccessToken)
		copy(dAtA[i:], m.AppopticsAccessToken)
		i = encodeVarintConfig(dAtA, i, uint64(len(m.AppopticsAccessToken)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Params_MetricInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_MetricInfo) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Params_MetricInfo) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.LabelNames) > 0 {
		for iNdEx := len(m.LabelNames) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.LabelNames[iNdEx])
			copy(dAtA[i:], m.LabelNames[iNdEx])
			i = encodeVarintConfig(dAtA, i, uint64(len(m.LabelNames[iNdEx])))
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *Params_LogInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_LogInfo) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Params_LogInfo) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.PayloadTemplate) > 0 {
		i -= len(m.PayloadTemplate)
		copy(dAtA[i:], m.PayloadTemplate)
		i = encodeVarintConfig(dAtA, i, uint64(len(m.PayloadTemplate)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintConfig(dAtA []byte, offset int, v uint64) int {
	offset -= sovConfig(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Params) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.AppopticsAccessToken)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.AppopticsBatchSize != 0 {
		n += 1 + sovConfig(uint64(m.AppopticsBatchSize))
	}
	l = len(m.PapertrailUrl)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.PapertrailLocalRetentionDuration != nil {
		l = github_com_gogo_protobuf_types.SizeOfStdDuration(*m.PapertrailLocalRetentionDuration)
		n += 1 + l + sovConfig(uint64(l))
	}
	if len(m.Metrics) > 0 {
		for k, v := range m.Metrics {
			_ = k
			_ = v
			l = 0
			if v != nil {
				l = v.Size()
				l += 1 + sovConfig(uint64(l))
			}
			mapEntrySize := 1 + len(k) + sovConfig(uint64(len(k))) + l
			n += mapEntrySize + 1 + sovConfig(uint64(mapEntrySize))
		}
	}
	if len(m.Logs) > 0 {
		for k, v := range m.Logs {
			_ = k
			_ = v
			l = 0
			if v != nil {
				l = v.Size()
				l += 1 + sovConfig(uint64(l))
			}
			mapEntrySize := 1 + len(k) + sovConfig(uint64(len(k))) + l
			n += mapEntrySize + 1 + sovConfig(uint64(mapEntrySize))
		}
	}
	return n
}

func (m *Params_MetricInfo) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.LabelNames) > 0 {
		for _, s := range m.LabelNames {
			l = len(s)
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	return n
}

func (m *Params_LogInfo) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.PayloadTemplate)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	return n
}

func sovConfig(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozConfig(x uint64) (n int) {
	return sovConfig(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *Params) String() string {
	if this == nil {
		return "nil"
	}
	keysForMetrics := make([]string, 0, len(this.Metrics))
	for k, _ := range this.Metrics {
		keysForMetrics = append(keysForMetrics, k)
	}
	github_com_gogo_protobuf_sortkeys.Strings(keysForMetrics)
	mapStringForMetrics := "map[string]*Params_MetricInfo{"
	for _, k := range keysForMetrics {
		mapStringForMetrics += fmt.Sprintf("%v: %v,", k, this.Metrics[k])
	}
	mapStringForMetrics += "}"
	keysForLogs := make([]string, 0, len(this.Logs))
	for k, _ := range this.Logs {
		keysForLogs = append(keysForLogs, k)
	}
	github_com_gogo_protobuf_sortkeys.Strings(keysForLogs)
	mapStringForLogs := "map[string]*Params_LogInfo{"
	for _, k := range keysForLogs {
		mapStringForLogs += fmt.Sprintf("%v: %v,", k, this.Logs[k])
	}
	mapStringForLogs += "}"
	s := strings.Join([]string{`&Params{`,
		`AppopticsAccessToken:` + fmt.Sprintf("%v", this.AppopticsAccessToken) + `,`,
		`AppopticsBatchSize:` + fmt.Sprintf("%v", this.AppopticsBatchSize) + `,`,
		`PapertrailUrl:` + fmt.Sprintf("%v", this.PapertrailUrl) + `,`,
		`PapertrailLocalRetentionDuration:` + strings.Replace(fmt.Sprintf("%v", this.PapertrailLocalRetentionDuration), "Duration", "types.Duration", 1) + `,`,
		`Metrics:` + mapStringForMetrics + `,`,
		`Logs:` + mapStringForLogs + `,`,
		`}`,
	}, "")
	return s
}
func (this *Params_MetricInfo) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Params_MetricInfo{`,
		`LabelNames:` + fmt.Sprintf("%v", this.LabelNames) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Params_LogInfo) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Params_LogInfo{`,
		`PayloadTemplate:` + fmt.Sprintf("%v", this.PayloadTemplate) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringConfig(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *Params) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Params: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Params: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AppopticsAccessToken", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AppopticsAccessToken = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AppopticsBatchSize", wireType)
			}
			m.AppopticsBatchSize = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.AppopticsBatchSize |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PapertrailUrl", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PapertrailUrl = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PapertrailLocalRetentionDuration", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.PapertrailLocalRetentionDuration == nil {
				m.PapertrailLocalRetentionDuration = new(time.Duration)
			}
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(m.PapertrailLocalRetentionDuration, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metrics", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Metrics == nil {
				m.Metrics = make(map[string]*Params_MetricInfo)
			}
			var mapkey string
			var mapvalue *Params_MetricInfo
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowConfig
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					wire |= uint64(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				fieldNum := int32(wire >> 3)
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowConfig
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = string(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var mapmsglen int
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowConfig
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						mapmsglen |= int(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					if mapmsglen < 0 {
						return ErrInvalidLengthConfig
					}
					postmsgIndex := iNdEx + mapmsglen
					if postmsgIndex < 0 {
						return ErrInvalidLengthConfig
					}
					if postmsgIndex > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = &Params_MetricInfo{}
					if err := mapvalue.Unmarshal(dAtA[iNdEx:postmsgIndex]); err != nil {
						return err
					}
					iNdEx = postmsgIndex
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipConfig(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if skippy < 0 {
						return ErrInvalidLengthConfig
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.Metrics[mapkey] = mapvalue
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Logs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Logs == nil {
				m.Logs = make(map[string]*Params_LogInfo)
			}
			var mapkey string
			var mapvalue *Params_LogInfo
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowConfig
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					wire |= uint64(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				fieldNum := int32(wire >> 3)
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowConfig
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = string(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var mapmsglen int
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowConfig
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						mapmsglen |= int(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					if mapmsglen < 0 {
						return ErrInvalidLengthConfig
					}
					postmsgIndex := iNdEx + mapmsglen
					if postmsgIndex < 0 {
						return ErrInvalidLengthConfig
					}
					if postmsgIndex > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = &Params_LogInfo{}
					if err := mapvalue.Unmarshal(dAtA[iNdEx:postmsgIndex]); err != nil {
						return err
					}
					iNdEx = postmsgIndex
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipConfig(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if skippy < 0 {
						return ErrInvalidLengthConfig
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.Logs[mapkey] = mapvalue
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Params_MetricInfo) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MetricInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MetricInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LabelNames", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.LabelNames = append(m.LabelNames, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Params_LogInfo) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: LogInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: LogInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PayloadTemplate", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PayloadTemplate = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipConfig(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthConfig
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupConfig
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthConfig
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthConfig        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConfig          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupConfig = fmt.Errorf("proto: unexpected end of group")
)

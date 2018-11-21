// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/adapter/solarwinds/config/config.proto

package config

/*
	The `solarwinds` adapter enables Istio to deliver log and metric data to the
	[Papertrail](https://www.papertrailapp.com) logging backend and the
	[AppOptics](https://www.appoptics.com) monitoring backend.

	This adapter supports the [metric template](https://istio.io/docs/reference/config/policy-and-telemetry/templates/metric/)
	and the [logentry template](https://istio.io/docs/reference/config/policy-and-telemetry/templates/metric/).
*/

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "github.com/gogo/protobuf/types"

import time "time"

import github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"

import strings "strings"
import reflect "reflect"
import github_com_gogo_protobuf_sortkeys "github.com/gogo/protobuf/sortkeys"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// Configuration format for the `solarwinds` adapter.
//
// Example config usage:
// ```yaml
// apiVersion: "config.istio.io/v1alpha2"
// kind: solarwinds
// metadata:
//   name: handler
//   namespace: istio-system
// spec:
//   appoptics_access_token: <APPOPTICS SAMPLE TOKEN>
//   papertrail_url: <PAPERTRAIL URL>
//   papertrail_local_retention_duration: <RETENTION PERIOD FOR LOGS LOCALLY, Optional>
//   metrics:
//     requestcount.metric.istio-system:
//       label_names:
//       - source_service
//       - source_version
//       - destination_service
//       - destination_version
//       - response_code
//     requestduration.metric.istio-system:
//       label_names:
//       - source_service
//       - source_version
//       - destination_service
//       - destination_version
//       - response_code
//     requestsize.metric.istio-system:
//       label_names:
//       - source_service
//       - source_version
//       - destination_service
//       - destination_version
//       - response_code
//     responsesize.metric.istio-system:
//       label_names:
//       - source_service
//       - source_version
//       - destination_service
//       - destination_version
//       - response_code
//     tcpbytesent.metric.istio-system:
//       label_names:
//       - source_service
//       - source_version
//       - destination_service
//       - destination_version
//     tcpbytereceived.metric.istio-system:
//       label_names:
//       - source_service
//       - source_version
//       - destination_service
//       - destination_version
//   logs:
//     solarwindslogentry.logentry.istio-system:
//       payloadTemplate: '{{or (.originIp) "-"}} - {{or (.sourceUser) "-"}} [{{or (.timestamp.Format "2006-01-02T15:04:05Z07:00") "-"}}] "{{or (.method) "-"}} {{or (.url) "-"}} {{or (.protocol) "-"}}" {{or (.responseCode) "-"}} {{or (.responseSize) "-"}}'
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
	PapertrailLocalRetentionDuration *time.Duration `protobuf:"bytes,4,opt,name=papertrail_local_retention_duration,json=papertrailLocalRetentionDuration,stdduration" json:"papertrail_local_retention_duration,omitempty"`
	// A map of Istio metric name to solarwinds metric info.
	Metrics map[string]*Params_MetricInfo `protobuf:"bytes,5,rep,name=metrics" json:"metrics,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value"`
	// A map of Istio logentry name to solarwinds log info.
	Logs                 map[string]*Params_LogInfo `protobuf:"bytes,6,rep,name=logs" json:"logs,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *Params) Reset()      { *m = Params{} }
func (*Params) ProtoMessage() {}
func (*Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_d6743aa11a2059e6, []int{0}
}
func (m *Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params.Merge(dst, src)
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
	LabelNames           []string `protobuf:"bytes,1,rep,name=label_names,json=labelNames" json:"label_names,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Params_MetricInfo) Reset()      { *m = Params_MetricInfo{} }
func (*Params_MetricInfo) ProtoMessage() {}
func (*Params_MetricInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_d6743aa11a2059e6, []int{0, 0}
}
func (m *Params_MetricInfo) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params_MetricInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params_MetricInfo.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *Params_MetricInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params_MetricInfo.Merge(dst, src)
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
	PayloadTemplate      string   `protobuf:"bytes,1,opt,name=payload_template,json=payloadTemplate,proto3" json:"payload_template,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Params_LogInfo) Reset()      { *m = Params_LogInfo{} }
func (*Params_LogInfo) ProtoMessage() {}
func (*Params_LogInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_d6743aa11a2059e6, []int{0, 2}
}
func (m *Params_LogInfo) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params_LogInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params_LogInfo.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *Params_LogInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params_LogInfo.Merge(dst, src)
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
func (m *Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.AppopticsAccessToken) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.AppopticsAccessToken)))
		i += copy(dAtA[i:], m.AppopticsAccessToken)
	}
	if m.AppopticsBatchSize != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.AppopticsBatchSize))
	}
	if len(m.PapertrailUrl) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.PapertrailUrl)))
		i += copy(dAtA[i:], m.PapertrailUrl)
	}
	if m.PapertrailLocalRetentionDuration != nil {
		dAtA[i] = 0x22
		i++
		i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(*m.PapertrailLocalRetentionDuration)))
		n1, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(*m.PapertrailLocalRetentionDuration, dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if len(m.Metrics) > 0 {
		for k, _ := range m.Metrics {
			dAtA[i] = 0x2a
			i++
			v := m.Metrics[k]
			msgSize := 0
			if v != nil {
				msgSize = v.Size()
				msgSize += 1 + sovConfig(uint64(msgSize))
			}
			mapSize := 1 + len(k) + sovConfig(uint64(len(k))) + msgSize
			i = encodeVarintConfig(dAtA, i, uint64(mapSize))
			dAtA[i] = 0xa
			i++
			i = encodeVarintConfig(dAtA, i, uint64(len(k)))
			i += copy(dAtA[i:], k)
			if v != nil {
				dAtA[i] = 0x12
				i++
				i = encodeVarintConfig(dAtA, i, uint64(v.Size()))
				n2, err := v.MarshalTo(dAtA[i:])
				if err != nil {
					return 0, err
				}
				i += n2
			}
		}
	}
	if len(m.Logs) > 0 {
		for k, _ := range m.Logs {
			dAtA[i] = 0x32
			i++
			v := m.Logs[k]
			msgSize := 0
			if v != nil {
				msgSize = v.Size()
				msgSize += 1 + sovConfig(uint64(msgSize))
			}
			mapSize := 1 + len(k) + sovConfig(uint64(len(k))) + msgSize
			i = encodeVarintConfig(dAtA, i, uint64(mapSize))
			dAtA[i] = 0xa
			i++
			i = encodeVarintConfig(dAtA, i, uint64(len(k)))
			i += copy(dAtA[i:], k)
			if v != nil {
				dAtA[i] = 0x12
				i++
				i = encodeVarintConfig(dAtA, i, uint64(v.Size()))
				n3, err := v.MarshalTo(dAtA[i:])
				if err != nil {
					return 0, err
				}
				i += n3
			}
		}
	}
	return i, nil
}

func (m *Params_MetricInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_MetricInfo) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.LabelNames) > 0 {
		for _, s := range m.LabelNames {
			dAtA[i] = 0xa
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	return i, nil
}

func (m *Params_LogInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_LogInfo) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.PayloadTemplate) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.PayloadTemplate)))
		i += copy(dAtA[i:], m.PayloadTemplate)
	}
	return i, nil
}

func encodeVarintConfig(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *Params) Size() (n int) {
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
	var l int
	_ = l
	l = len(m.PayloadTemplate)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	return n
}

func sovConfig(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
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
			wire |= (uint64(b) & 0x7F) << shift
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
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
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
				m.AppopticsBatchSize |= (int32(b) & 0x7F) << shift
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
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
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
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
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
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
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
					wire |= (uint64(b) & 0x7F) << shift
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
						stringLenmapkey |= (uint64(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
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
						mapmsglen |= (int(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					if mapmsglen < 0 {
						return ErrInvalidLengthConfig
					}
					postmsgIndex := iNdEx + mapmsglen
					if mapmsglen < 0 {
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
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
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
					wire |= (uint64(b) & 0x7F) << shift
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
						stringLenmapkey |= (uint64(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
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
						mapmsglen |= (int(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					if mapmsglen < 0 {
						return ErrInvalidLengthConfig
					}
					postmsgIndex := iNdEx + mapmsglen
					if mapmsglen < 0 {
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
			wire |= (uint64(b) & 0x7F) << shift
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
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
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
			wire |= (uint64(b) & 0x7F) << shift
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
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
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
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
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
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthConfig
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowConfig
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipConfig(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthConfig = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConfig   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("mixer/adapter/solarwinds/config/config.proto", fileDescriptor_config_d6743aa11a2059e6)
}

var fileDescriptor_config_d6743aa11a2059e6 = []byte{
	// 519 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x4f, 0x6f, 0xd3, 0x30,
	0x1c, 0x8d, 0xd7, 0xb5, 0xa3, 0x2e, 0x7f, 0x26, 0x6b, 0x42, 0x59, 0x0e, 0x6e, 0x04, 0x42, 0xea,
	0xc4, 0x70, 0x50, 0xd9, 0x61, 0xe2, 0x32, 0x51, 0x81, 0x04, 0x52, 0x41, 0x28, 0x8c, 0x0b, 0x97,
	0xc8, 0x4d, 0xdd, 0x2c, 0x9a, 0x13, 0x47, 0xb6, 0x0b, 0x74, 0x27, 0x3e, 0x02, 0x47, 0x3e, 0x02,
	0x1f, 0xa5, 0xdc, 0x76, 0xe4, 0x04, 0x34, 0x5c, 0x38, 0xee, 0x23, 0xa0, 0xc4, 0x49, 0x3b, 0x10,
	0x68, 0x3b, 0xd5, 0x7d, 0xef, 0xfd, 0x9e, 0xdf, 0xfb, 0x39, 0x70, 0x37, 0x89, 0xdf, 0x33, 0xe9,
	0xd1, 0x31, 0xcd, 0x34, 0x93, 0x9e, 0x12, 0x9c, 0xca, 0x77, 0x71, 0x3a, 0x56, 0x5e, 0x28, 0xd2,
	0x49, 0x1c, 0x55, 0x3f, 0x24, 0x93, 0x42, 0x0b, 0xb4, 0x5d, 0xe9, 0xc8, 0x4a, 0x47, 0x8c, 0xc0,
	0xd9, 0x8a, 0x44, 0x24, 0x4a, 0x95, 0x57, 0x9c, 0xcc, 0x80, 0x83, 0x23, 0x21, 0x22, 0xce, 0xbc,
	0xf2, 0xdf, 0x68, 0x3a, 0xf1, 0xc6, 0x53, 0x49, 0x75, 0x2c, 0x52, 0xc3, 0xdf, 0xfa, 0xd2, 0x84,
	0xad, 0x97, 0x54, 0xd2, 0x44, 0xa1, 0x3d, 0x78, 0x93, 0x66, 0x99, 0xc8, 0x74, 0x1c, 0xaa, 0x80,
	0x86, 0x21, 0x53, 0x2a, 0xd0, 0xe2, 0x98, 0xa5, 0x36, 0x70, 0x41, 0xaf, 0xed, 0x6f, 0x2d, 0xd9,
	0x47, 0x25, 0x79, 0x58, 0x70, 0xe8, 0x3e, 0x5c, 0xe1, 0xc1, 0x88, 0xea, 0xf0, 0x28, 0x50, 0xf1,
	0x09, 0xb3, 0xd7, 0x5c, 0xd0, 0x6b, 0xfa, 0x68, 0xc9, 0x0d, 0x0a, 0xea, 0x55, 0x7c, 0xc2, 0xd0,
	0x1d, 0x78, 0x3d, 0xa3, 0x19, 0x93, 0x5a, 0xd2, 0x98, 0x07, 0x53, 0xc9, 0xed, 0x46, 0xe9, 0x7f,
	0x6d, 0x85, 0xbe, 0x96, 0x1c, 0x49, 0x78, 0xfb, 0x9c, 0x8c, 0x8b, 0x90, 0xf2, 0x40, 0x32, 0xcd,
	0xd2, 0x22, 0x7d, 0x50, 0xd7, 0xb0, 0xd7, 0x5d, 0xd0, 0xeb, 0xf4, 0xb7, 0x89, 0xe9, 0x49, 0xea,
	0x9e, 0xe4, 0x71, 0x25, 0x18, 0x5c, 0x99, 0x7f, 0xeb, 0x82, 0x4f, 0xdf, 0xbb, 0xc0, 0x77, 0x57,
	0x7e, 0xc3, 0xc2, 0xce, 0xaf, 0xdd, 0x6a, 0x2d, 0x7a, 0x0a, 0x37, 0x12, 0xa6, 0x65, 0x1c, 0x2a,
	0xbb, 0xe9, 0x36, 0x7a, 0x9d, 0x3e, 0x21, 0xff, 0x5d, 0x38, 0x31, 0x6b, 0x23, 0xcf, 0xcd, 0xc0,
	0x93, 0x54, 0xcb, 0x99, 0x5f, 0x8f, 0xa3, 0x03, 0xb8, 0xce, 0x45, 0xa4, 0xec, 0x56, 0x69, 0x73,
	0xf7, 0x62, 0x9b, 0xa1, 0x88, 0x2a, 0x8f, 0x72, 0xd0, 0xb9, 0x07, 0xa1, 0x71, 0x7e, 0x96, 0x4e,
	0x04, 0xea, 0xc2, 0x0e, 0xa7, 0x23, 0xc6, 0x83, 0x94, 0x26, 0x4c, 0xd9, 0xc0, 0x6d, 0xf4, 0xda,
	0x3e, 0x2c, 0xa1, 0x17, 0x05, 0xe2, 0x1c, 0xc1, 0xab, 0xe7, 0x83, 0xa0, 0x4d, 0xd8, 0x38, 0x66,
	0xb3, 0xea, 0xe5, 0x8a, 0x23, 0x1a, 0xc0, 0xe6, 0x5b, 0xca, 0xa7, 0xe6, 0x65, 0x3a, 0xfd, 0xdd,
	0xcb, 0x36, 0x2b, 0xee, 0xf7, 0xcd, 0xe8, 0xc3, 0xb5, 0x7d, 0xe0, 0xec, 0xc1, 0x8d, 0xa1, 0x88,
	0xca, 0x54, 0x3b, 0x70, 0x33, 0xa3, 0x33, 0x2e, 0xe8, 0x38, 0xd0, 0x2c, 0xc9, 0x38, 0xd5, 0xac,
	0xba, 0xf1, 0x46, 0x85, 0x1f, 0x56, 0xb0, 0x33, 0x82, 0xed, 0x65, 0xc3, 0x7f, 0x84, 0x3b, 0xf8,
	0x33, 0xdc, 0xce, 0xa5, 0xf6, 0xf5, 0x57, 0xb2, 0xc1, 0xfe, 0x7c, 0x81, 0xad, 0xd3, 0x05, 0xb6,
	0xbe, 0x2e, 0xb0, 0x75, 0xb6, 0xc0, 0xd6, 0x87, 0x1c, 0x83, 0xcf, 0x39, 0xb6, 0xe6, 0x39, 0x06,
	0xa7, 0x39, 0x06, 0x3f, 0x72, 0x0c, 0x7e, 0xe5, 0xd8, 0x3a, 0xcb, 0x31, 0xf8, 0xf8, 0x13, 0x5b,
	0x6f, 0x5a, 0xc6, 0x73, 0xd4, 0x2a, 0x3f, 0x9b, 0x07, 0xbf, 0x03, 0x00, 0x00, 0xff, 0xff, 0x19,
	0x6c, 0xf1, 0x09, 0x8d, 0x03, 0x00, 0x00,
}

// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/api/v2/endpoint/load_report.proto

package endpoint

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
import _ "github.com/lyft/protoc-gen-validate/validate"
import _ "github.com/gogo/protobuf/gogoproto"

import binary "encoding/binary"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// These are stats Envoy reports to GLB every so often. Report frequency is
// defined by
// :ref:`LoadStatsResponse.load_reporting_interval<envoy_api_field_load_stats.LoadStatsResponse.load_reporting_interval>`.
// Stats per upstream region/zone and optionally per subzone.
// [#not-implemented-hide:] Not configuration. TBD how to doc proto APIs.
type UpstreamLocalityStats struct {
	// Name of zone, region and optionally endpoint group these metrics were
	// collected from. Zone and region names could be empty if unknown.
	Locality *envoy_api_v2_core.Locality `protobuf:"bytes,1,opt,name=locality" json:"locality,omitempty"`
	// The total number of requests sent by this Envoy since the last report. A
	// single HTTP or gRPC request or stream is counted as one request. A TCP
	// connection is also treated as one request. There is no explicit
	// total_requests field below for a locality, but it may be inferred from:
	//
	// .. code-block:: none
	//
	//   total_requests = total_successful_requests + total_requests_in_progress +
	//     total_error_requests
	//
	// The total number of requests successfully completed by the endpoints in the
	// locality. These include non-5xx responses for HTTP, where errors
	// originate at the client and the endpoint responded successfully. For gRPC,
	// the grpc-status values are those not covered by total_error_requests below.
	TotalSuccessfulRequests uint64 `protobuf:"varint,2,opt,name=total_successful_requests,json=totalSuccessfulRequests,proto3" json:"total_successful_requests,omitempty"`
	// The total number of unfinished requests
	TotalRequestsInProgress uint64 `protobuf:"varint,3,opt,name=total_requests_in_progress,json=totalRequestsInProgress,proto3" json:"total_requests_in_progress,omitempty"`
	// The total number of requests that failed due to errors at the endpoint.
	// For HTTP these are responses with 5xx status codes and for gRPC the
	// grpc-status values:
	//
	//   - DeadlineExceeded
	//   - Unimplemented
	//   - Internal
	//   - Unavailable
	//   - Unknown
	//   - DataLoss
	TotalErrorRequests uint64 `protobuf:"varint,4,opt,name=total_error_requests,json=totalErrorRequests,proto3" json:"total_error_requests,omitempty"`
	// Stats for multi-dimensional load balancing.
	LoadMetricStats []*EndpointLoadMetricStats `protobuf:"bytes,5,rep,name=load_metric_stats,json=loadMetricStats" json:"load_metric_stats,omitempty"`
	// [#not-implemented-hide:] The priority of the endpoint group these metrics
	// were collected from.
	Priority uint32 `protobuf:"varint,6,opt,name=priority,proto3" json:"priority,omitempty"`
}

func (m *UpstreamLocalityStats) Reset()                    { *m = UpstreamLocalityStats{} }
func (m *UpstreamLocalityStats) String() string            { return proto.CompactTextString(m) }
func (*UpstreamLocalityStats) ProtoMessage()               {}
func (*UpstreamLocalityStats) Descriptor() ([]byte, []int) { return fileDescriptorLoadReport, []int{0} }

func (m *UpstreamLocalityStats) GetLocality() *envoy_api_v2_core.Locality {
	if m != nil {
		return m.Locality
	}
	return nil
}

func (m *UpstreamLocalityStats) GetTotalSuccessfulRequests() uint64 {
	if m != nil {
		return m.TotalSuccessfulRequests
	}
	return 0
}

func (m *UpstreamLocalityStats) GetTotalRequestsInProgress() uint64 {
	if m != nil {
		return m.TotalRequestsInProgress
	}
	return 0
}

func (m *UpstreamLocalityStats) GetTotalErrorRequests() uint64 {
	if m != nil {
		return m.TotalErrorRequests
	}
	return 0
}

func (m *UpstreamLocalityStats) GetLoadMetricStats() []*EndpointLoadMetricStats {
	if m != nil {
		return m.LoadMetricStats
	}
	return nil
}

func (m *UpstreamLocalityStats) GetPriority() uint32 {
	if m != nil {
		return m.Priority
	}
	return 0
}

// [#not-implemented-hide:] Not configuration. TBD how to doc proto APIs.
type EndpointLoadMetricStats struct {
	// Name of the metric; may be empty.
	MetricName string `protobuf:"bytes,1,opt,name=metric_name,json=metricName,proto3" json:"metric_name,omitempty"`
	// Number of calls that finished and included this metric.
	NumRequestsFinishedWithMetric uint64 `protobuf:"varint,2,opt,name=num_requests_finished_with_metric,json=numRequestsFinishedWithMetric,proto3" json:"num_requests_finished_with_metric,omitempty"`
	// Sum of metric values across all calls that finished with this metric for
	// load_reporting_interval.
	TotalMetricValue float64 `protobuf:"fixed64,3,opt,name=total_metric_value,json=totalMetricValue,proto3" json:"total_metric_value,omitempty"`
}

func (m *EndpointLoadMetricStats) Reset()         { *m = EndpointLoadMetricStats{} }
func (m *EndpointLoadMetricStats) String() string { return proto.CompactTextString(m) }
func (*EndpointLoadMetricStats) ProtoMessage()    {}
func (*EndpointLoadMetricStats) Descriptor() ([]byte, []int) {
	return fileDescriptorLoadReport, []int{1}
}

func (m *EndpointLoadMetricStats) GetMetricName() string {
	if m != nil {
		return m.MetricName
	}
	return ""
}

func (m *EndpointLoadMetricStats) GetNumRequestsFinishedWithMetric() uint64 {
	if m != nil {
		return m.NumRequestsFinishedWithMetric
	}
	return 0
}

func (m *EndpointLoadMetricStats) GetTotalMetricValue() float64 {
	if m != nil {
		return m.TotalMetricValue
	}
	return 0
}

// Per cluster load stats. Envoy reports these stats a management server in a
// :ref:`LoadStatsRequest<envoy_api_msg_load_stats.LoadStatsRequest>`
// [#not-implemented-hide:] Not configuration. TBD how to doc proto APIs.
type ClusterStats struct {
	// The name of the cluster.
	ClusterName string `protobuf:"bytes,1,opt,name=cluster_name,json=clusterName,proto3" json:"cluster_name,omitempty"`
	// Need at least one.
	UpstreamLocalityStats []*UpstreamLocalityStats `protobuf:"bytes,2,rep,name=upstream_locality_stats,json=upstreamLocalityStats" json:"upstream_locality_stats,omitempty"`
	// Cluster-level stats such as total_successful_requests may be computed by
	// summing upstream_locality_stats. In addition, below there are additional
	// cluster-wide stats. The following total_requests equality holds at the
	// cluster-level:
	//
	// .. code-block:: none
	//
	//   sum_locality(total_successful_requests) + sum_locality(total_requests_in_progress) +
	//     sum_locality(total_error_requests) + total_dropped_requests`
	//
	// The total number of dropped requests. This covers requests
	// deliberately dropped by the drop_overload policy and circuit breaking.
	TotalDroppedRequests uint64 `protobuf:"varint,3,opt,name=total_dropped_requests,json=totalDroppedRequests,proto3" json:"total_dropped_requests,omitempty"`
}

func (m *ClusterStats) Reset()                    { *m = ClusterStats{} }
func (m *ClusterStats) String() string            { return proto.CompactTextString(m) }
func (*ClusterStats) ProtoMessage()               {}
func (*ClusterStats) Descriptor() ([]byte, []int) { return fileDescriptorLoadReport, []int{2} }

func (m *ClusterStats) GetClusterName() string {
	if m != nil {
		return m.ClusterName
	}
	return ""
}

func (m *ClusterStats) GetUpstreamLocalityStats() []*UpstreamLocalityStats {
	if m != nil {
		return m.UpstreamLocalityStats
	}
	return nil
}

func (m *ClusterStats) GetTotalDroppedRequests() uint64 {
	if m != nil {
		return m.TotalDroppedRequests
	}
	return 0
}

func init() {
	proto.RegisterType((*UpstreamLocalityStats)(nil), "envoy.api.v2.endpoint.UpstreamLocalityStats")
	proto.RegisterType((*EndpointLoadMetricStats)(nil), "envoy.api.v2.endpoint.EndpointLoadMetricStats")
	proto.RegisterType((*ClusterStats)(nil), "envoy.api.v2.endpoint.ClusterStats")
}
func (m *UpstreamLocalityStats) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *UpstreamLocalityStats) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Locality != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(m.Locality.Size()))
		n1, err := m.Locality.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.TotalSuccessfulRequests != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(m.TotalSuccessfulRequests))
	}
	if m.TotalRequestsInProgress != 0 {
		dAtA[i] = 0x18
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(m.TotalRequestsInProgress))
	}
	if m.TotalErrorRequests != 0 {
		dAtA[i] = 0x20
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(m.TotalErrorRequests))
	}
	if len(m.LoadMetricStats) > 0 {
		for _, msg := range m.LoadMetricStats {
			dAtA[i] = 0x2a
			i++
			i = encodeVarintLoadReport(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if m.Priority != 0 {
		dAtA[i] = 0x30
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(m.Priority))
	}
	return i, nil
}

func (m *EndpointLoadMetricStats) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *EndpointLoadMetricStats) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.MetricName) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(len(m.MetricName)))
		i += copy(dAtA[i:], m.MetricName)
	}
	if m.NumRequestsFinishedWithMetric != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(m.NumRequestsFinishedWithMetric))
	}
	if m.TotalMetricValue != 0 {
		dAtA[i] = 0x19
		i++
		binary.LittleEndian.PutUint64(dAtA[i:], uint64(math.Float64bits(float64(m.TotalMetricValue))))
		i += 8
	}
	return i, nil
}

func (m *ClusterStats) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterStats) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.ClusterName) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(len(m.ClusterName)))
		i += copy(dAtA[i:], m.ClusterName)
	}
	if len(m.UpstreamLocalityStats) > 0 {
		for _, msg := range m.UpstreamLocalityStats {
			dAtA[i] = 0x12
			i++
			i = encodeVarintLoadReport(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if m.TotalDroppedRequests != 0 {
		dAtA[i] = 0x18
		i++
		i = encodeVarintLoadReport(dAtA, i, uint64(m.TotalDroppedRequests))
	}
	return i, nil
}

func encodeVarintLoadReport(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *UpstreamLocalityStats) Size() (n int) {
	var l int
	_ = l
	if m.Locality != nil {
		l = m.Locality.Size()
		n += 1 + l + sovLoadReport(uint64(l))
	}
	if m.TotalSuccessfulRequests != 0 {
		n += 1 + sovLoadReport(uint64(m.TotalSuccessfulRequests))
	}
	if m.TotalRequestsInProgress != 0 {
		n += 1 + sovLoadReport(uint64(m.TotalRequestsInProgress))
	}
	if m.TotalErrorRequests != 0 {
		n += 1 + sovLoadReport(uint64(m.TotalErrorRequests))
	}
	if len(m.LoadMetricStats) > 0 {
		for _, e := range m.LoadMetricStats {
			l = e.Size()
			n += 1 + l + sovLoadReport(uint64(l))
		}
	}
	if m.Priority != 0 {
		n += 1 + sovLoadReport(uint64(m.Priority))
	}
	return n
}

func (m *EndpointLoadMetricStats) Size() (n int) {
	var l int
	_ = l
	l = len(m.MetricName)
	if l > 0 {
		n += 1 + l + sovLoadReport(uint64(l))
	}
	if m.NumRequestsFinishedWithMetric != 0 {
		n += 1 + sovLoadReport(uint64(m.NumRequestsFinishedWithMetric))
	}
	if m.TotalMetricValue != 0 {
		n += 9
	}
	return n
}

func (m *ClusterStats) Size() (n int) {
	var l int
	_ = l
	l = len(m.ClusterName)
	if l > 0 {
		n += 1 + l + sovLoadReport(uint64(l))
	}
	if len(m.UpstreamLocalityStats) > 0 {
		for _, e := range m.UpstreamLocalityStats {
			l = e.Size()
			n += 1 + l + sovLoadReport(uint64(l))
		}
	}
	if m.TotalDroppedRequests != 0 {
		n += 1 + sovLoadReport(uint64(m.TotalDroppedRequests))
	}
	return n
}

func sovLoadReport(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozLoadReport(x uint64) (n int) {
	return sovLoadReport(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *UpstreamLocalityStats) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowLoadReport
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
			return fmt.Errorf("proto: UpstreamLocalityStats: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: UpstreamLocalityStats: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Locality", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
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
				return ErrInvalidLengthLoadReport
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Locality == nil {
				m.Locality = &envoy_api_v2_core.Locality{}
			}
			if err := m.Locality.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TotalSuccessfulRequests", wireType)
			}
			m.TotalSuccessfulRequests = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TotalSuccessfulRequests |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TotalRequestsInProgress", wireType)
			}
			m.TotalRequestsInProgress = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TotalRequestsInProgress |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TotalErrorRequests", wireType)
			}
			m.TotalErrorRequests = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TotalErrorRequests |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LoadMetricStats", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
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
				return ErrInvalidLengthLoadReport
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.LoadMetricStats = append(m.LoadMetricStats, &EndpointLoadMetricStats{})
			if err := m.LoadMetricStats[len(m.LoadMetricStats)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Priority", wireType)
			}
			m.Priority = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Priority |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipLoadReport(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthLoadReport
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
func (m *EndpointLoadMetricStats) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowLoadReport
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
			return fmt.Errorf("proto: EndpointLoadMetricStats: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: EndpointLoadMetricStats: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MetricName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
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
				return ErrInvalidLengthLoadReport
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.MetricName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NumRequestsFinishedWithMetric", wireType)
			}
			m.NumRequestsFinishedWithMetric = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.NumRequestsFinishedWithMetric |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 1 {
				return fmt.Errorf("proto: wrong wireType = %d for field TotalMetricValue", wireType)
			}
			var v uint64
			if (iNdEx + 8) > l {
				return io.ErrUnexpectedEOF
			}
			v = uint64(binary.LittleEndian.Uint64(dAtA[iNdEx:]))
			iNdEx += 8
			m.TotalMetricValue = float64(math.Float64frombits(v))
		default:
			iNdEx = preIndex
			skippy, err := skipLoadReport(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthLoadReport
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
func (m *ClusterStats) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowLoadReport
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
			return fmt.Errorf("proto: ClusterStats: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterStats: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClusterName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
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
				return ErrInvalidLengthLoadReport
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClusterName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UpstreamLocalityStats", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
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
				return ErrInvalidLengthLoadReport
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.UpstreamLocalityStats = append(m.UpstreamLocalityStats, &UpstreamLocalityStats{})
			if err := m.UpstreamLocalityStats[len(m.UpstreamLocalityStats)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TotalDroppedRequests", wireType)
			}
			m.TotalDroppedRequests = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLoadReport
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TotalDroppedRequests |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipLoadReport(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthLoadReport
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
func skipLoadReport(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowLoadReport
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
					return 0, ErrIntOverflowLoadReport
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
					return 0, ErrIntOverflowLoadReport
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
				return 0, ErrInvalidLengthLoadReport
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowLoadReport
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
				next, err := skipLoadReport(dAtA[start:])
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
	ErrInvalidLengthLoadReport = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowLoadReport   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("envoy/api/v2/endpoint/load_report.proto", fileDescriptorLoadReport) }

var fileDescriptorLoadReport = []byte{
	// 520 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x93, 0xc1, 0x8e, 0xd3, 0x30,
	0x10, 0x86, 0xe5, 0xb6, 0xbb, 0xea, 0xba, 0x45, 0x80, 0xb5, 0xa5, 0xa5, 0x40, 0x09, 0xbd, 0xd0,
	0x43, 0x95, 0xa0, 0x82, 0x84, 0x04, 0xb7, 0xc2, 0x22, 0x90, 0x16, 0x84, 0xb2, 0x02, 0x24, 0x2e,
	0x91, 0x37, 0x99, 0x6d, 0x2d, 0x25, 0xb1, 0xb1, 0x9d, 0xa0, 0x7d, 0x0d, 0x1e, 0x85, 0x23, 0x27,
	0x8e, 0x1c, 0x79, 0x04, 0x54, 0x71, 0xe1, 0xcc, 0x0b, 0xac, 0x62, 0x3b, 0xed, 0x56, 0xea, 0xde,
	0xc6, 0xf3, 0xcf, 0x9f, 0x99, 0xf9, 0x34, 0xc1, 0x0f, 0x21, 0x2f, 0xf9, 0x79, 0x40, 0x05, 0x0b,
	0xca, 0x59, 0x00, 0x79, 0x22, 0x38, 0xcb, 0x75, 0x90, 0x72, 0x9a, 0x44, 0x12, 0x04, 0x97, 0xda,
	0x17, 0x92, 0x6b, 0x4e, 0x7a, 0xa6, 0xd0, 0xa7, 0x82, 0xf9, 0xe5, 0xcc, 0xaf, 0x0b, 0x87, 0x77,
	0xb7, 0xfc, 0x31, 0x97, 0x10, 0x9c, 0x52, 0x05, 0xd6, 0x34, 0xec, 0x97, 0x34, 0x65, 0x09, 0xd5,
	0x10, 0xd4, 0x81, 0x13, 0x0e, 0x17, 0x7c, 0xc1, 0x4d, 0x18, 0x54, 0x91, 0xcd, 0x8e, 0xff, 0x37,
	0x70, 0xef, 0x83, 0x50, 0x5a, 0x02, 0xcd, 0x8e, 0x79, 0x4c, 0x53, 0xa6, 0xcf, 0x4f, 0x34, 0xd5,
	0x8a, 0x3c, 0xc5, 0xed, 0xd4, 0x25, 0x06, 0xc8, 0x43, 0x93, 0xce, 0xec, 0x8e, 0xbf, 0x35, 0x50,
	0xd5, 0xd9, 0xaf, 0x3d, 0xe1, 0xba, 0x98, 0x3c, 0xc3, 0xb7, 0x35, 0xd7, 0x34, 0x8d, 0x54, 0x11,
	0xc7, 0xa0, 0xd4, 0x59, 0x91, 0x46, 0x12, 0xbe, 0x14, 0xa0, 0xb4, 0x1a, 0x34, 0x3c, 0x34, 0x69,
	0x85, 0x7d, 0x53, 0x70, 0xb2, 0xd6, 0x43, 0x27, 0x93, 0xe7, 0x78, 0x68, 0xbd, 0xb5, 0x21, 0x62,
	0x79, 0x24, 0x24, 0x5f, 0x48, 0x50, 0x6a, 0xd0, 0xbc, 0x64, 0xae, 0x2d, 0x6f, 0xf2, 0xf7, 0x4e,
	0x26, 0x8f, 0xf0, 0xa1, 0x35, 0x83, 0x94, 0x5c, 0x6e, 0x7a, 0xb6, 0x8c, 0x8d, 0x18, 0xed, 0xa8,
	0x92, 0xd6, 0xed, 0x3e, 0xe3, 0x9b, 0x06, 0x7b, 0x06, 0x5a, 0xb2, 0x38, 0x52, 0xd5, 0xe2, 0x83,
	0x3d, 0xaf, 0x39, 0xe9, 0xcc, 0x7c, 0x7f, 0x27, 0x7d, 0xff, 0xc8, 0x05, 0xc7, 0x9c, 0x26, 0x6f,
	0x8d, 0xcd, 0xe0, 0x0a, 0xaf, 0xa7, 0xdb, 0x09, 0x32, 0xc4, 0x6d, 0x21, 0x19, 0x97, 0x15, 0xbf,
	0x7d, 0x0f, 0x4d, 0xae, 0x85, 0xeb, 0xf7, 0xf8, 0x3b, 0xc2, 0xfd, 0x2b, 0x3e, 0x44, 0xee, 0xe3,
	0x8e, 0x1b, 0x27, 0xa7, 0x19, 0x18, 0xf4, 0x07, 0x21, 0xb6, 0xa9, 0x77, 0x34, 0x03, 0xf2, 0x1a,
	0x3f, 0xc8, 0x8b, 0x6c, 0x43, 0xe8, 0x8c, 0xe5, 0x4c, 0x2d, 0x21, 0x89, 0xbe, 0x32, 0xbd, 0x74,
	0xab, 0x38, 0xce, 0xf7, 0xf2, 0x22, 0xab, 0x97, 0x7d, 0xe5, 0xca, 0x3e, 0x31, 0xbd, 0xb4, 0xfd,
	0xc8, 0x14, 0x5b, 0x28, 0xf5, 0xfe, 0x25, 0x4d, 0x0b, 0x30, 0x94, 0x51, 0x78, 0xc3, 0x28, 0xb6,
	0xf0, 0x63, 0x95, 0x1f, 0xff, 0x45, 0xb8, 0xfb, 0x22, 0x2d, 0x94, 0x06, 0x69, 0x27, 0x9d, 0xe2,
	0x6e, 0x6c, 0xdf, 0x97, 0x46, 0x9d, 0x1f, 0xfc, 0xf8, 0xf7, 0xb3, 0xd9, 0x92, 0x0d, 0x0f, 0x85,
	0x1d, 0x27, 0x9b, 0xb1, 0x05, 0xee, 0x17, 0xee, 0xd0, 0xa2, 0xfa, 0x56, 0x1c, 0xf1, 0x86, 0x21,
	0x3e, 0xbd, 0x82, 0xf8, 0xce, 0xf3, 0x9c, 0xe3, 0xaa, 0xcd, 0xde, 0x37, 0xd4, 0x68, 0xa3, 0xb0,
	0x57, 0xec, 0xbc, 0xe0, 0x27, 0xf8, 0x96, 0x5d, 0x2f, 0x91, 0x5c, 0x08, 0x48, 0x36, 0x17, 0x61,
	0x0f, 0xc9, 0x5e, 0xcb, 0x4b, 0x2b, 0xd6, 0x98, 0xe6, 0xdd, 0x5f, 0xab, 0x11, 0xfa, 0xbd, 0x1a,
	0xa1, 0x3f, 0xab, 0x11, 0x3a, 0xdd, 0x37, 0xbf, 0xc9, 0xe3, 0x8b, 0x00, 0x00, 0x00, 0xff, 0xff,
	0xfa, 0x65, 0x57, 0xf9, 0xb5, 0x03, 0x00, 0x00,
}

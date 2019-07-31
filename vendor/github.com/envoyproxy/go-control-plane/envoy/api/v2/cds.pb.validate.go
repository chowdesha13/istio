// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/api/v2/cds.proto

package v2

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gogo/protobuf/types"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = types.DynamicAny{}
)

// Validate checks the field values on Cluster with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Cluster) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetName()) < 1 {
		return ClusterValidationError{
			field:  "Name",
			reason: "value length must be at least 1 bytes",
		}
	}

	// no validation rules for AltStatName

	if v, ok := interface{}(m.GetEdsClusterConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "EdsClusterConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if d := m.GetConnectTimeout(); d != nil {
		dur := *d

		gt := time.Duration(0*time.Second + 0*time.Nanosecond)

		if dur <= gt {
			return ClusterValidationError{
				field:  "ConnectTimeout",
				reason: "value must be greater than 0s",
			}
		}

	}

	if v, ok := interface{}(m.GetPerConnectionBufferLimitBytes()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "PerConnectionBufferLimitBytes",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if _, ok := Cluster_LbPolicy_name[int32(m.GetLbPolicy())]; !ok {
		return ClusterValidationError{
			field:  "LbPolicy",
			reason: "value must be one of the defined enum values",
		}
	}

	for idx, item := range m.GetHosts() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  fmt.Sprintf("Hosts[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetLoadAssignment()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "LoadAssignment",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	for idx, item := range m.GetHealthChecks() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  fmt.Sprintf("HealthChecks[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetMaxRequestsPerConnection()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "MaxRequestsPerConnection",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetCircuitBreakers()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "CircuitBreakers",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetTlsContext()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "TlsContext",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetCommonHttpProtocolOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "CommonHttpProtocolOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetHttpProtocolOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "HttpProtocolOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetHttp2ProtocolOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "Http2ProtocolOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for ExtensionProtocolOptions

	// no validation rules for TypedExtensionProtocolOptions

	if d := m.GetDnsRefreshRate(); d != nil {
		dur := *d

		gt := time.Duration(0*time.Second + 0*time.Nanosecond)

		if dur <= gt {
			return ClusterValidationError{
				field:  "DnsRefreshRate",
				reason: "value must be greater than 0s",
			}
		}

	}

	// no validation rules for RespectDnsTtl

	if _, ok := Cluster_DnsLookupFamily_name[int32(m.GetDnsLookupFamily())]; !ok {
		return ClusterValidationError{
			field:  "DnsLookupFamily",
			reason: "value must be one of the defined enum values",
		}
	}

	for idx, item := range m.GetDnsResolvers() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  fmt.Sprintf("DnsResolvers[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetOutlierDetection()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "OutlierDetection",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if d := m.GetCleanupInterval(); d != nil {
		dur := *d

		gt := time.Duration(0*time.Second + 0*time.Nanosecond)

		if dur <= gt {
			return ClusterValidationError{
				field:  "CleanupInterval",
				reason: "value must be greater than 0s",
			}
		}

	}

	if v, ok := interface{}(m.GetUpstreamBindConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "UpstreamBindConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetLbSubsetConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "LbSubsetConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetCommonLbConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "CommonLbConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetTransportSocket()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "TransportSocket",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetMetadata()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "Metadata",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for ProtocolSelection

	if v, ok := interface{}(m.GetUpstreamConnectionOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterValidationError{
				field:  "UpstreamConnectionOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for CloseConnectionsOnHostHealthFailure

	// no validation rules for DrainConnectionsOnHostRemoval

	for idx, item := range m.GetFilters() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  fmt.Sprintf("Filters[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	switch m.ClusterDiscoveryType.(type) {

	case *Cluster_Type:

		if _, ok := Cluster_DiscoveryType_name[int32(m.GetType())]; !ok {
			return ClusterValidationError{
				field:  "Type",
				reason: "value must be one of the defined enum values",
			}
		}

	case *Cluster_ClusterType:

		if v, ok := interface{}(m.GetClusterType()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  "ClusterType",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	switch m.LbConfig.(type) {

	case *Cluster_RingHashLbConfig_:

		if v, ok := interface{}(m.GetRingHashLbConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  "RingHashLbConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *Cluster_OriginalDstLbConfig_:

		if v, ok := interface{}(m.GetOriginalDstLbConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  "OriginalDstLbConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *Cluster_LeastRequestLbConfig_:

		if v, ok := interface{}(m.GetLeastRequestLbConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterValidationError{
					field:  "LeastRequestLbConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// ClusterValidationError is the validation error returned by Cluster.Validate
// if the designated constraints aren't met.
type ClusterValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ClusterValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ClusterValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ClusterValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ClusterValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ClusterValidationError) ErrorName() string { return "ClusterValidationError" }

// Error satisfies the builtin error interface
func (e ClusterValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ClusterValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ClusterValidationError{}

// Validate checks the field values on UpstreamBindConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *UpstreamBindConfig) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetSourceAddress()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return UpstreamBindConfigValidationError{
				field:  "SourceAddress",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// UpstreamBindConfigValidationError is the validation error returned by
// UpstreamBindConfig.Validate if the designated constraints aren't met.
type UpstreamBindConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UpstreamBindConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UpstreamBindConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UpstreamBindConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UpstreamBindConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UpstreamBindConfigValidationError) ErrorName() string {
	return "UpstreamBindConfigValidationError"
}

// Error satisfies the builtin error interface
func (e UpstreamBindConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpstreamBindConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UpstreamBindConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UpstreamBindConfigValidationError{}

// Validate checks the field values on UpstreamConnectionOptions with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *UpstreamConnectionOptions) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetTcpKeepalive()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return UpstreamConnectionOptionsValidationError{
				field:  "TcpKeepalive",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// UpstreamConnectionOptionsValidationError is the validation error returned by
// UpstreamConnectionOptions.Validate if the designated constraints aren't met.
type UpstreamConnectionOptionsValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UpstreamConnectionOptionsValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UpstreamConnectionOptionsValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UpstreamConnectionOptionsValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UpstreamConnectionOptionsValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UpstreamConnectionOptionsValidationError) ErrorName() string {
	return "UpstreamConnectionOptionsValidationError"
}

// Error satisfies the builtin error interface
func (e UpstreamConnectionOptionsValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpstreamConnectionOptions.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UpstreamConnectionOptionsValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UpstreamConnectionOptionsValidationError{}

// Validate checks the field values on Cluster_CustomClusterType with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Cluster_CustomClusterType) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetName()) < 1 {
		return Cluster_CustomClusterTypeValidationError{
			field:  "Name",
			reason: "value length must be at least 1 bytes",
		}
	}

	if v, ok := interface{}(m.GetTypedConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Cluster_CustomClusterTypeValidationError{
				field:  "TypedConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// Cluster_CustomClusterTypeValidationError is the validation error returned by
// Cluster_CustomClusterType.Validate if the designated constraints aren't met.
type Cluster_CustomClusterTypeValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_CustomClusterTypeValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_CustomClusterTypeValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_CustomClusterTypeValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_CustomClusterTypeValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_CustomClusterTypeValidationError) ErrorName() string {
	return "Cluster_CustomClusterTypeValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_CustomClusterTypeValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_CustomClusterType.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_CustomClusterTypeValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_CustomClusterTypeValidationError{}

// Validate checks the field values on Cluster_EdsClusterConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Cluster_EdsClusterConfig) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetEdsConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Cluster_EdsClusterConfigValidationError{
				field:  "EdsConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for ServiceName

	return nil
}

// Cluster_EdsClusterConfigValidationError is the validation error returned by
// Cluster_EdsClusterConfig.Validate if the designated constraints aren't met.
type Cluster_EdsClusterConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_EdsClusterConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_EdsClusterConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_EdsClusterConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_EdsClusterConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_EdsClusterConfigValidationError) ErrorName() string {
	return "Cluster_EdsClusterConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_EdsClusterConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_EdsClusterConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_EdsClusterConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_EdsClusterConfigValidationError{}

// Validate checks the field values on Cluster_LbSubsetConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Cluster_LbSubsetConfig) Validate() error {
	if m == nil {
		return nil
	}

	if _, ok := Cluster_LbSubsetConfig_LbSubsetFallbackPolicy_name[int32(m.GetFallbackPolicy())]; !ok {
		return Cluster_LbSubsetConfigValidationError{
			field:  "FallbackPolicy",
			reason: "value must be one of the defined enum values",
		}
	}

	if v, ok := interface{}(m.GetDefaultSubset()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Cluster_LbSubsetConfigValidationError{
				field:  "DefaultSubset",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	for idx, item := range m.GetSubsetSelectors() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Cluster_LbSubsetConfigValidationError{
					field:  fmt.Sprintf("SubsetSelectors[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for LocalityWeightAware

	// no validation rules for ScaleLocalityWeight

	// no validation rules for PanicModeAny

	// no validation rules for ListAsAny

	return nil
}

// Cluster_LbSubsetConfigValidationError is the validation error returned by
// Cluster_LbSubsetConfig.Validate if the designated constraints aren't met.
type Cluster_LbSubsetConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_LbSubsetConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_LbSubsetConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_LbSubsetConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_LbSubsetConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_LbSubsetConfigValidationError) ErrorName() string {
	return "Cluster_LbSubsetConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_LbSubsetConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_LbSubsetConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_LbSubsetConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_LbSubsetConfigValidationError{}

// Validate checks the field values on Cluster_LeastRequestLbConfig with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Cluster_LeastRequestLbConfig) Validate() error {
	if m == nil {
		return nil
	}

	if wrapper := m.GetChoiceCount(); wrapper != nil {

		if wrapper.GetValue() < 2 {
			return Cluster_LeastRequestLbConfigValidationError{
				field:  "ChoiceCount",
				reason: "value must be greater than or equal to 2",
			}
		}

	}

	return nil
}

// Cluster_LeastRequestLbConfigValidationError is the validation error returned
// by Cluster_LeastRequestLbConfig.Validate if the designated constraints
// aren't met.
type Cluster_LeastRequestLbConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_LeastRequestLbConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_LeastRequestLbConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_LeastRequestLbConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_LeastRequestLbConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_LeastRequestLbConfigValidationError) ErrorName() string {
	return "Cluster_LeastRequestLbConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_LeastRequestLbConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_LeastRequestLbConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_LeastRequestLbConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_LeastRequestLbConfigValidationError{}

// Validate checks the field values on Cluster_RingHashLbConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Cluster_RingHashLbConfig) Validate() error {
	if m == nil {
		return nil
	}

	if wrapper := m.GetMinimumRingSize(); wrapper != nil {

		if wrapper.GetValue() > 8388608 {
			return Cluster_RingHashLbConfigValidationError{
				field:  "MinimumRingSize",
				reason: "value must be less than or equal to 8388608",
			}
		}

	}

	if _, ok := Cluster_RingHashLbConfig_HashFunction_name[int32(m.GetHashFunction())]; !ok {
		return Cluster_RingHashLbConfigValidationError{
			field:  "HashFunction",
			reason: "value must be one of the defined enum values",
		}
	}

	if wrapper := m.GetMaximumRingSize(); wrapper != nil {

		if wrapper.GetValue() > 8388608 {
			return Cluster_RingHashLbConfigValidationError{
				field:  "MaximumRingSize",
				reason: "value must be less than or equal to 8388608",
			}
		}

	}

	return nil
}

// Cluster_RingHashLbConfigValidationError is the validation error returned by
// Cluster_RingHashLbConfig.Validate if the designated constraints aren't met.
type Cluster_RingHashLbConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_RingHashLbConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_RingHashLbConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_RingHashLbConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_RingHashLbConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_RingHashLbConfigValidationError) ErrorName() string {
	return "Cluster_RingHashLbConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_RingHashLbConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_RingHashLbConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_RingHashLbConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_RingHashLbConfigValidationError{}

// Validate checks the field values on Cluster_OriginalDstLbConfig with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Cluster_OriginalDstLbConfig) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for UseHttpHeader

	return nil
}

// Cluster_OriginalDstLbConfigValidationError is the validation error returned
// by Cluster_OriginalDstLbConfig.Validate if the designated constraints
// aren't met.
type Cluster_OriginalDstLbConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_OriginalDstLbConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_OriginalDstLbConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_OriginalDstLbConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_OriginalDstLbConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_OriginalDstLbConfigValidationError) ErrorName() string {
	return "Cluster_OriginalDstLbConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_OriginalDstLbConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_OriginalDstLbConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_OriginalDstLbConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_OriginalDstLbConfigValidationError{}

// Validate checks the field values on Cluster_CommonLbConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Cluster_CommonLbConfig) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetHealthyPanicThreshold()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Cluster_CommonLbConfigValidationError{
				field:  "HealthyPanicThreshold",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetUpdateMergeWindow()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Cluster_CommonLbConfigValidationError{
				field:  "UpdateMergeWindow",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for IgnoreNewHostsUntilFirstHc

	switch m.LocalityConfigSpecifier.(type) {

	case *Cluster_CommonLbConfig_ZoneAwareLbConfig_:

		if v, ok := interface{}(m.GetZoneAwareLbConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Cluster_CommonLbConfigValidationError{
					field:  "ZoneAwareLbConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *Cluster_CommonLbConfig_LocalityWeightedLbConfig_:

		if v, ok := interface{}(m.GetLocalityWeightedLbConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Cluster_CommonLbConfigValidationError{
					field:  "LocalityWeightedLbConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// Cluster_CommonLbConfigValidationError is the validation error returned by
// Cluster_CommonLbConfig.Validate if the designated constraints aren't met.
type Cluster_CommonLbConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_CommonLbConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_CommonLbConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_CommonLbConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_CommonLbConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_CommonLbConfigValidationError) ErrorName() string {
	return "Cluster_CommonLbConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_CommonLbConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_CommonLbConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_CommonLbConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_CommonLbConfigValidationError{}

// Validate checks the field values on Cluster_LbSubsetConfig_LbSubsetSelector
// with the rules defined in the proto definition for this message. If any
// rules are violated, an error is returned.
func (m *Cluster_LbSubsetConfig_LbSubsetSelector) Validate() error {
	if m == nil {
		return nil
	}

	if _, ok := Cluster_LbSubsetConfig_LbSubsetSelector_LbSubsetSelectorFallbackPolicy_name[int32(m.GetFallbackPolicy())]; !ok {
		return Cluster_LbSubsetConfig_LbSubsetSelectorValidationError{
			field:  "FallbackPolicy",
			reason: "value must be one of the defined enum values",
		}
	}

	return nil
}

// Cluster_LbSubsetConfig_LbSubsetSelectorValidationError is the validation
// error returned by Cluster_LbSubsetConfig_LbSubsetSelector.Validate if the
// designated constraints aren't met.
type Cluster_LbSubsetConfig_LbSubsetSelectorValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_LbSubsetConfig_LbSubsetSelectorValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_LbSubsetConfig_LbSubsetSelectorValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_LbSubsetConfig_LbSubsetSelectorValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_LbSubsetConfig_LbSubsetSelectorValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_LbSubsetConfig_LbSubsetSelectorValidationError) ErrorName() string {
	return "Cluster_LbSubsetConfig_LbSubsetSelectorValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_LbSubsetConfig_LbSubsetSelectorValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_LbSubsetConfig_LbSubsetSelector.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_LbSubsetConfig_LbSubsetSelectorValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_LbSubsetConfig_LbSubsetSelectorValidationError{}

// Validate checks the field values on Cluster_CommonLbConfig_ZoneAwareLbConfig
// with the rules defined in the proto definition for this message. If any
// rules are violated, an error is returned.
func (m *Cluster_CommonLbConfig_ZoneAwareLbConfig) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetRoutingEnabled()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError{
				field:  "RoutingEnabled",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetMinClusterSize()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError{
				field:  "MinClusterSize",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError is the validation
// error returned by Cluster_CommonLbConfig_ZoneAwareLbConfig.Validate if the
// designated constraints aren't met.
type Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError) ErrorName() string {
	return "Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_CommonLbConfig_ZoneAwareLbConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_CommonLbConfig_ZoneAwareLbConfigValidationError{}

// Validate checks the field values on
// Cluster_CommonLbConfig_LocalityWeightedLbConfig with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *Cluster_CommonLbConfig_LocalityWeightedLbConfig) Validate() error {
	if m == nil {
		return nil
	}

	return nil
}

// Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError is the
// validation error returned by
// Cluster_CommonLbConfig_LocalityWeightedLbConfig.Validate if the designated
// constraints aren't met.
type Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError) Reason() string {
	return e.reason
}

// Cause function returns cause value.
func (e Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError) ErrorName() string {
	return "Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError"
}

// Error satisfies the builtin error interface
func (e Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCluster_CommonLbConfig_LocalityWeightedLbConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Cluster_CommonLbConfig_LocalityWeightedLbConfigValidationError{}

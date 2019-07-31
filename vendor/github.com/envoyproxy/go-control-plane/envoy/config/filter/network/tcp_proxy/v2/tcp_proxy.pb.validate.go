// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/filter/network/tcp_proxy/v2/tcp_proxy.proto

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

// Validate checks the field values on TcpProxy with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *TcpProxy) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetStatPrefix()) < 1 {
		return TcpProxyValidationError{
			field:  "StatPrefix",
			reason: "value length must be at least 1 bytes",
		}
	}

	if v, ok := interface{}(m.GetMetadataMatch()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return TcpProxyValidationError{
				field:  "MetadataMatch",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if d := m.GetIdleTimeout(); d != nil {
		dur := *d

		gt := time.Duration(0*time.Second + 0*time.Nanosecond)

		if dur <= gt {
			return TcpProxyValidationError{
				field:  "IdleTimeout",
				reason: "value must be greater than 0s",
			}
		}

	}

	if v, ok := interface{}(m.GetDownstreamIdleTimeout()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return TcpProxyValidationError{
				field:  "DownstreamIdleTimeout",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetUpstreamIdleTimeout()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return TcpProxyValidationError{
				field:  "UpstreamIdleTimeout",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	for idx, item := range m.GetAccessLog() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return TcpProxyValidationError{
					field:  fmt.Sprintf("AccessLog[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetDeprecatedV1()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return TcpProxyValidationError{
				field:  "DeprecatedV1",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if wrapper := m.GetMaxConnectAttempts(); wrapper != nil {

		if wrapper.GetValue() < 1 {
			return TcpProxyValidationError{
				field:  "MaxConnectAttempts",
				reason: "value must be greater than or equal to 1",
			}
		}

	}

	switch m.ClusterSpecifier.(type) {

	case *TcpProxy_Cluster:
		// no validation rules for Cluster

	case *TcpProxy_WeightedClusters:

		if v, ok := interface{}(m.GetWeightedClusters()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return TcpProxyValidationError{
					field:  "WeightedClusters",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		return TcpProxyValidationError{
			field:  "ClusterSpecifier",
			reason: "value is required",
		}

	}

	return nil
}

// TcpProxyValidationError is the validation error returned by
// TcpProxy.Validate if the designated constraints aren't met.
type TcpProxyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TcpProxyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TcpProxyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TcpProxyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TcpProxyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TcpProxyValidationError) ErrorName() string { return "TcpProxyValidationError" }

// Error satisfies the builtin error interface
func (e TcpProxyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTcpProxy.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TcpProxyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TcpProxyValidationError{}

// Validate checks the field values on TcpProxy_DeprecatedV1 with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *TcpProxy_DeprecatedV1) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetRoutes()) < 1 {
		return TcpProxy_DeprecatedV1ValidationError{
			field:  "Routes",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetRoutes() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return TcpProxy_DeprecatedV1ValidationError{
					field:  fmt.Sprintf("Routes[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// TcpProxy_DeprecatedV1ValidationError is the validation error returned by
// TcpProxy_DeprecatedV1.Validate if the designated constraints aren't met.
type TcpProxy_DeprecatedV1ValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TcpProxy_DeprecatedV1ValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TcpProxy_DeprecatedV1ValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TcpProxy_DeprecatedV1ValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TcpProxy_DeprecatedV1ValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TcpProxy_DeprecatedV1ValidationError) ErrorName() string {
	return "TcpProxy_DeprecatedV1ValidationError"
}

// Error satisfies the builtin error interface
func (e TcpProxy_DeprecatedV1ValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTcpProxy_DeprecatedV1.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TcpProxy_DeprecatedV1ValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TcpProxy_DeprecatedV1ValidationError{}

// Validate checks the field values on TcpProxy_WeightedCluster with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *TcpProxy_WeightedCluster) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetClusters()) < 1 {
		return TcpProxy_WeightedClusterValidationError{
			field:  "Clusters",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetClusters() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return TcpProxy_WeightedClusterValidationError{
					field:  fmt.Sprintf("Clusters[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// TcpProxy_WeightedClusterValidationError is the validation error returned by
// TcpProxy_WeightedCluster.Validate if the designated constraints aren't met.
type TcpProxy_WeightedClusterValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TcpProxy_WeightedClusterValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TcpProxy_WeightedClusterValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TcpProxy_WeightedClusterValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TcpProxy_WeightedClusterValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TcpProxy_WeightedClusterValidationError) ErrorName() string {
	return "TcpProxy_WeightedClusterValidationError"
}

// Error satisfies the builtin error interface
func (e TcpProxy_WeightedClusterValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTcpProxy_WeightedCluster.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TcpProxy_WeightedClusterValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TcpProxy_WeightedClusterValidationError{}

// Validate checks the field values on TcpProxy_DeprecatedV1_TCPRoute with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *TcpProxy_DeprecatedV1_TCPRoute) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetCluster()) < 1 {
		return TcpProxy_DeprecatedV1_TCPRouteValidationError{
			field:  "Cluster",
			reason: "value length must be at least 1 bytes",
		}
	}

	for idx, item := range m.GetDestinationIpList() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return TcpProxy_DeprecatedV1_TCPRouteValidationError{
					field:  fmt.Sprintf("DestinationIpList[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for DestinationPorts

	for idx, item := range m.GetSourceIpList() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return TcpProxy_DeprecatedV1_TCPRouteValidationError{
					field:  fmt.Sprintf("SourceIpList[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for SourcePorts

	return nil
}

// TcpProxy_DeprecatedV1_TCPRouteValidationError is the validation error
// returned by TcpProxy_DeprecatedV1_TCPRoute.Validate if the designated
// constraints aren't met.
type TcpProxy_DeprecatedV1_TCPRouteValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TcpProxy_DeprecatedV1_TCPRouteValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TcpProxy_DeprecatedV1_TCPRouteValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TcpProxy_DeprecatedV1_TCPRouteValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TcpProxy_DeprecatedV1_TCPRouteValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TcpProxy_DeprecatedV1_TCPRouteValidationError) ErrorName() string {
	return "TcpProxy_DeprecatedV1_TCPRouteValidationError"
}

// Error satisfies the builtin error interface
func (e TcpProxy_DeprecatedV1_TCPRouteValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTcpProxy_DeprecatedV1_TCPRoute.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TcpProxy_DeprecatedV1_TCPRouteValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TcpProxy_DeprecatedV1_TCPRouteValidationError{}

// Validate checks the field values on TcpProxy_WeightedCluster_ClusterWeight
// with the rules defined in the proto definition for this message. If any
// rules are violated, an error is returned.
func (m *TcpProxy_WeightedCluster_ClusterWeight) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetName()) < 1 {
		return TcpProxy_WeightedCluster_ClusterWeightValidationError{
			field:  "Name",
			reason: "value length must be at least 1 bytes",
		}
	}

	if m.GetWeight() < 1 {
		return TcpProxy_WeightedCluster_ClusterWeightValidationError{
			field:  "Weight",
			reason: "value must be greater than or equal to 1",
		}
	}

	return nil
}

// TcpProxy_WeightedCluster_ClusterWeightValidationError is the validation
// error returned by TcpProxy_WeightedCluster_ClusterWeight.Validate if the
// designated constraints aren't met.
type TcpProxy_WeightedCluster_ClusterWeightValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TcpProxy_WeightedCluster_ClusterWeightValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TcpProxy_WeightedCluster_ClusterWeightValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TcpProxy_WeightedCluster_ClusterWeightValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TcpProxy_WeightedCluster_ClusterWeightValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TcpProxy_WeightedCluster_ClusterWeightValidationError) ErrorName() string {
	return "TcpProxy_WeightedCluster_ClusterWeightValidationError"
}

// Error satisfies the builtin error interface
func (e TcpProxy_WeightedCluster_ClusterWeightValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTcpProxy_WeightedCluster_ClusterWeight.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TcpProxy_WeightedCluster_ClusterWeightValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TcpProxy_WeightedCluster_ClusterWeightValidationError{}

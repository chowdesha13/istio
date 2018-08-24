// Code generated by protoc-gen-validate
// source: envoy/api/v2/endpoint/load_report.proto
// DO NOT EDIT!!!

package endpoint

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

// Validate checks the field values on UpstreamLocalityStats with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *UpstreamLocalityStats) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetLocality()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return UpstreamLocalityStatsValidationError{
				Field:  "Locality",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	// no validation rules for TotalSuccessfulRequests

	// no validation rules for TotalRequestsInProgress

	// no validation rules for TotalErrorRequests

	for idx, item := range m.GetLoadMetricStats() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return UpstreamLocalityStatsValidationError{
					Field:  fmt.Sprintf("LoadMetricStats[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetUpstreamEndpointStats() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return UpstreamLocalityStatsValidationError{
					Field:  fmt.Sprintf("UpstreamEndpointStats[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	// no validation rules for Priority

	return nil
}

// UpstreamLocalityStatsValidationError is the validation error returned by
// UpstreamLocalityStats.Validate if the designated constraints aren't met.
type UpstreamLocalityStatsValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e UpstreamLocalityStatsValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpstreamLocalityStats.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = UpstreamLocalityStatsValidationError{}

// Validate checks the field values on UpstreamEndpointStats with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *UpstreamEndpointStats) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetAddress()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return UpstreamEndpointStatsValidationError{
				Field:  "Address",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	// no validation rules for TotalSuccessfulRequests

	// no validation rules for TotalRequestsInProgress

	// no validation rules for TotalErrorRequests

	for idx, item := range m.GetLoadMetricStats() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return UpstreamEndpointStatsValidationError{
					Field:  fmt.Sprintf("LoadMetricStats[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// UpstreamEndpointStatsValidationError is the validation error returned by
// UpstreamEndpointStats.Validate if the designated constraints aren't met.
type UpstreamEndpointStatsValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e UpstreamEndpointStatsValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpstreamEndpointStats.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = UpstreamEndpointStatsValidationError{}

// Validate checks the field values on EndpointLoadMetricStats with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *EndpointLoadMetricStats) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for MetricName

	// no validation rules for NumRequestsFinishedWithMetric

	// no validation rules for TotalMetricValue

	return nil
}

// EndpointLoadMetricStatsValidationError is the validation error returned by
// EndpointLoadMetricStats.Validate if the designated constraints aren't met.
type EndpointLoadMetricStatsValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e EndpointLoadMetricStatsValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sEndpointLoadMetricStats.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = EndpointLoadMetricStatsValidationError{}

// Validate checks the field values on ClusterStats with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *ClusterStats) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetClusterName()) < 1 {
		return ClusterStatsValidationError{
			Field:  "ClusterName",
			Reason: "value length must be at least 1 bytes",
		}
	}

	if len(m.GetUpstreamLocalityStats()) < 1 {
		return ClusterStatsValidationError{
			Field:  "UpstreamLocalityStats",
			Reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetUpstreamLocalityStats() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return ClusterStatsValidationError{
					Field:  fmt.Sprintf("UpstreamLocalityStats[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	// no validation rules for TotalDroppedRequests

	for idx, item := range m.GetDroppedRequests() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return ClusterStatsValidationError{
					Field:  fmt.Sprintf("DroppedRequests[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetLoadReportInterval()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return ClusterStatsValidationError{
				Field:  "LoadReportInterval",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// ClusterStatsValidationError is the validation error returned by
// ClusterStats.Validate if the designated constraints aren't met.
type ClusterStatsValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e ClusterStatsValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sClusterStats.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = ClusterStatsValidationError{}

// Validate checks the field values on ClusterStats_DroppedRequests with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ClusterStats_DroppedRequests) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetCategory()) < 1 {
		return ClusterStats_DroppedRequestsValidationError{
			Field:  "Category",
			Reason: "value length must be at least 1 bytes",
		}
	}

	// no validation rules for DroppedCount

	return nil
}

// ClusterStats_DroppedRequestsValidationError is the validation error returned
// by ClusterStats_DroppedRequests.Validate if the designated constraints
// aren't met.
type ClusterStats_DroppedRequestsValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e ClusterStats_DroppedRequestsValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sClusterStats_DroppedRequests.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = ClusterStats_DroppedRequestsValidationError{}

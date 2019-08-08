// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/filter/http/fault/v2/fault.proto

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

// Validate checks the field values on FaultAbort with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *FaultAbort) Validate() error {
	if m == nil {
		return nil
	}

	{
		tmp := m.GetPercentage()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return FaultAbortValidationError{
					field:  "Percentage",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	switch m.ErrorType.(type) {

	case *FaultAbort_HttpStatus:

		if val := m.GetHttpStatus(); val < 200 || val >= 600 {
			return FaultAbortValidationError{
				field:  "HttpStatus",
				reason: "value must be inside range [200, 600)",
			}
		}

	default:
		return FaultAbortValidationError{
			field:  "ErrorType",
			reason: "value is required",
		}

	}

	return nil
}

// FaultAbortValidationError is the validation error returned by
// FaultAbort.Validate if the designated constraints aren't met.
type FaultAbortValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e FaultAbortValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e FaultAbortValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e FaultAbortValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e FaultAbortValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e FaultAbortValidationError) ErrorName() string { return "FaultAbortValidationError" }

// Error satisfies the builtin error interface
func (e FaultAbortValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sFaultAbort.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = FaultAbortValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = FaultAbortValidationError{}

// Validate checks the field values on HTTPFault with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *HTTPFault) Validate() error {
	if m == nil {
		return nil
	}

	{
		tmp := m.GetDelay()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return HTTPFaultValidationError{
					field:  "Delay",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	{
		tmp := m.GetAbort()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return HTTPFaultValidationError{
					field:  "Abort",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	// no validation rules for UpstreamCluster

	for idx, item := range m.GetHeaders() {
		_, _ = idx, item

		{
			tmp := item

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return HTTPFaultValidationError{
						field:  fmt.Sprintf("Headers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	{
		tmp := m.GetMaxActiveFaults()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return HTTPFaultValidationError{
					field:  "MaxActiveFaults",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	{
		tmp := m.GetResponseRateLimit()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return HTTPFaultValidationError{
					field:  "ResponseRateLimit",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	// no validation rules for DelayPercentRuntime

	// no validation rules for AbortPercentRuntime

	// no validation rules for DelayDurationRuntime

	// no validation rules for AbortHttpStatusRuntime

	// no validation rules for MaxActiveFaultsRuntime

	// no validation rules for ResponseRateLimitPercentRuntime

	return nil
}

// HTTPFaultValidationError is the validation error returned by
// HTTPFault.Validate if the designated constraints aren't met.
type HTTPFaultValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HTTPFaultValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HTTPFaultValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HTTPFaultValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HTTPFaultValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HTTPFaultValidationError) ErrorName() string { return "HTTPFaultValidationError" }

// Error satisfies the builtin error interface
func (e HTTPFaultValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHTTPFault.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HTTPFaultValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HTTPFaultValidationError{}

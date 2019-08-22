// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/accesslog/v2/als.proto

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

// Validate checks the field values on HttpGrpcAccessLogConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *HttpGrpcAccessLogConfig) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetCommonConfig() == nil {
		return HttpGrpcAccessLogConfigValidationError{
			field:  "CommonConfig",
			reason: "value is required",
		}
	}

	{
		tmp := m.GetCommonConfig()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return HttpGrpcAccessLogConfigValidationError{
					field:  "CommonConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	return nil
}

// HttpGrpcAccessLogConfigValidationError is the validation error returned by
// HttpGrpcAccessLogConfig.Validate if the designated constraints aren't met.
type HttpGrpcAccessLogConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpGrpcAccessLogConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpGrpcAccessLogConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpGrpcAccessLogConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpGrpcAccessLogConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpGrpcAccessLogConfigValidationError) ErrorName() string {
	return "HttpGrpcAccessLogConfigValidationError"
}

// Error satisfies the builtin error interface
func (e HttpGrpcAccessLogConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpGrpcAccessLogConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpGrpcAccessLogConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpGrpcAccessLogConfigValidationError{}

// Validate checks the field values on TcpGrpcAccessLogConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *TcpGrpcAccessLogConfig) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetCommonConfig() == nil {
		return TcpGrpcAccessLogConfigValidationError{
			field:  "CommonConfig",
			reason: "value is required",
		}
	}

	{
		tmp := m.GetCommonConfig()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return TcpGrpcAccessLogConfigValidationError{
					field:  "CommonConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	return nil
}

// TcpGrpcAccessLogConfigValidationError is the validation error returned by
// TcpGrpcAccessLogConfig.Validate if the designated constraints aren't met.
type TcpGrpcAccessLogConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TcpGrpcAccessLogConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TcpGrpcAccessLogConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TcpGrpcAccessLogConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TcpGrpcAccessLogConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TcpGrpcAccessLogConfigValidationError) ErrorName() string {
	return "TcpGrpcAccessLogConfigValidationError"
}

// Error satisfies the builtin error interface
func (e TcpGrpcAccessLogConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTcpGrpcAccessLogConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TcpGrpcAccessLogConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TcpGrpcAccessLogConfigValidationError{}

// Validate checks the field values on CommonGrpcAccessLogConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *CommonGrpcAccessLogConfig) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetLogName()) < 1 {
		return CommonGrpcAccessLogConfigValidationError{
			field:  "LogName",
			reason: "value length must be at least 1 bytes",
		}
	}

	if m.GetGrpcService() == nil {
		return CommonGrpcAccessLogConfigValidationError{
			field:  "GrpcService",
			reason: "value is required",
		}
	}

	{
		tmp := m.GetGrpcService()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return CommonGrpcAccessLogConfigValidationError{
					field:  "GrpcService",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	if d := m.GetBufferFlushInterval(); d != nil {
		dur, err := types.DurationFromProto(d)
		if err != nil {
			return CommonGrpcAccessLogConfigValidationError{
				field:  "BufferFlushInterval",
				reason: "value is not a valid duration",
				cause:  err,
			}
		}

		gt := time.Duration(0*time.Second + 0*time.Nanosecond)

		if dur <= gt {
			return CommonGrpcAccessLogConfigValidationError{
				field:  "BufferFlushInterval",
				reason: "value must be greater than 0s",
			}
		}

	}

	{
		tmp := m.GetBufferSizeBytes()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return CommonGrpcAccessLogConfigValidationError{
					field:  "BufferSizeBytes",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	return nil
}

// CommonGrpcAccessLogConfigValidationError is the validation error returned by
// CommonGrpcAccessLogConfig.Validate if the designated constraints aren't met.
type CommonGrpcAccessLogConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CommonGrpcAccessLogConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CommonGrpcAccessLogConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CommonGrpcAccessLogConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CommonGrpcAccessLogConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CommonGrpcAccessLogConfigValidationError) ErrorName() string {
	return "CommonGrpcAccessLogConfigValidationError"
}

// Error satisfies the builtin error interface
func (e CommonGrpcAccessLogConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCommonGrpcAccessLogConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CommonGrpcAccessLogConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CommonGrpcAccessLogConfigValidationError{}

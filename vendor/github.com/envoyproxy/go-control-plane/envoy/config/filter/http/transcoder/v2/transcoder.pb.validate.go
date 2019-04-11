// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/filter/http/transcoder/v2/transcoder.proto

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

// Validate checks the field values on GrpcJsonTranscoder with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *GrpcJsonTranscoder) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetServices()) < 1 {
		return GrpcJsonTranscoderValidationError{
			field:  "Services",
			reason: "value must contain at least 1 item(s)",
		}
	}

	{
		tmp := m.GetPrintOptions()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return GrpcJsonTranscoderValidationError{
					field:  "PrintOptions",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	// no validation rules for MatchIncomingRequestRoute

	switch m.DescriptorSet.(type) {

	case *GrpcJsonTranscoder_ProtoDescriptor:
		// no validation rules for ProtoDescriptor

	case *GrpcJsonTranscoder_ProtoDescriptorBin:
		// no validation rules for ProtoDescriptorBin

	default:
		return GrpcJsonTranscoderValidationError{
			field:  "DescriptorSet",
			reason: "value is required",
		}

	}

	return nil
}

// GrpcJsonTranscoderValidationError is the validation error returned by
// GrpcJsonTranscoder.Validate if the designated constraints aren't met.
type GrpcJsonTranscoderValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GrpcJsonTranscoderValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GrpcJsonTranscoderValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GrpcJsonTranscoderValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GrpcJsonTranscoderValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GrpcJsonTranscoderValidationError) ErrorName() string {
	return "GrpcJsonTranscoderValidationError"
}

// Error satisfies the builtin error interface
func (e GrpcJsonTranscoderValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGrpcJsonTranscoder.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GrpcJsonTranscoderValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GrpcJsonTranscoderValidationError{}

// Validate checks the field values on GrpcJsonTranscoder_PrintOptions with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *GrpcJsonTranscoder_PrintOptions) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for AddWhitespace

	// no validation rules for AlwaysPrintPrimitiveFields

	// no validation rules for AlwaysPrintEnumsAsInts

	// no validation rules for PreserveProtoFieldNames

	return nil
}

// GrpcJsonTranscoder_PrintOptionsValidationError is the validation error
// returned by GrpcJsonTranscoder_PrintOptions.Validate if the designated
// constraints aren't met.
type GrpcJsonTranscoder_PrintOptionsValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GrpcJsonTranscoder_PrintOptionsValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GrpcJsonTranscoder_PrintOptionsValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GrpcJsonTranscoder_PrintOptionsValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GrpcJsonTranscoder_PrintOptionsValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GrpcJsonTranscoder_PrintOptionsValidationError) ErrorName() string {
	return "GrpcJsonTranscoder_PrintOptionsValidationError"
}

// Error satisfies the builtin error interface
func (e GrpcJsonTranscoder_PrintOptionsValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGrpcJsonTranscoder_PrintOptions.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GrpcJsonTranscoder_PrintOptionsValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GrpcJsonTranscoder_PrintOptionsValidationError{}

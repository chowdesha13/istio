// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/filter/http/rate_limit/v2/rate_limit.proto

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

// Validate checks the field values on RateLimit with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *RateLimit) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetDomain()) < 1 {
		return RateLimitValidationError{
			field:  "Domain",
			reason: "value length must be at least 1 bytes",
		}
	}

	if m.GetStage() > 10 {
		return RateLimitValidationError{
			field:  "Stage",
			reason: "value must be less than or equal to 10",
		}
	}

	// no validation rules for RequestType

	{
		tmp := m.GetTimeout()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return RateLimitValidationError{
					field:  "Timeout",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	// no validation rules for FailureModeDeny

	// no validation rules for RateLimitedAsResourceExhausted

	if m.GetRateLimitService() == nil {
		return RateLimitValidationError{
			field:  "RateLimitService",
			reason: "value is required",
		}
	}

	{
		tmp := m.GetRateLimitService()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return RateLimitValidationError{
					field:  "RateLimitService",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	return nil
}

// RateLimitValidationError is the validation error returned by
// RateLimit.Validate if the designated constraints aren't met.
type RateLimitValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RateLimitValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RateLimitValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RateLimitValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RateLimitValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RateLimitValidationError) ErrorName() string { return "RateLimitValidationError" }

// Error satisfies the builtin error interface
func (e RateLimitValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRateLimit.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RateLimitValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RateLimitValidationError{}

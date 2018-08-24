// Code generated by protoc-gen-validate
// source: envoy/config/metrics/v2/stats.proto
// DO NOT EDIT!!!

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

// Validate checks the field values on StatsSink with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *StatsSink) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Name

	if v, ok := interface{}(m.GetConfig()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return StatsSinkValidationError{
				Field:  "Config",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// StatsSinkValidationError is the validation error returned by
// StatsSink.Validate if the designated constraints aren't met.
type StatsSinkValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e StatsSinkValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sStatsSink.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = StatsSinkValidationError{}

// Validate checks the field values on StatsConfig with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *StatsConfig) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetStatsTags() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return StatsConfigValidationError{
					Field:  fmt.Sprintf("StatsTags[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetUseAllDefaultTags()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return StatsConfigValidationError{
				Field:  "UseAllDefaultTags",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// StatsConfigValidationError is the validation error returned by
// StatsConfig.Validate if the designated constraints aren't met.
type StatsConfigValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e StatsConfigValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sStatsConfig.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = StatsConfigValidationError{}

// Validate checks the field values on TagSpecifier with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *TagSpecifier) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for TagName

	switch m.TagValue.(type) {

	case *TagSpecifier_Regex:

		if len(m.GetRegex()) > 1024 {
			return TagSpecifierValidationError{
				Field:  "Regex",
				Reason: "value length must be at most 1024 bytes",
			}
		}

	case *TagSpecifier_FixedValue:
		// no validation rules for FixedValue

	}

	return nil
}

// TagSpecifierValidationError is the validation error returned by
// TagSpecifier.Validate if the designated constraints aren't met.
type TagSpecifierValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e TagSpecifierValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTagSpecifier.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = TagSpecifierValidationError{}

// Validate checks the field values on StatsdSink with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *StatsdSink) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Prefix

	switch m.StatsdSpecifier.(type) {

	case *StatsdSink_Address:

		if v, ok := interface{}(m.GetAddress()).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return StatsdSinkValidationError{
					Field:  "Address",
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	case *StatsdSink_TcpClusterName:
		// no validation rules for TcpClusterName

	default:
		return StatsdSinkValidationError{
			Field:  "StatsdSpecifier",
			Reason: "value is required",
		}

	}

	return nil
}

// StatsdSinkValidationError is the validation error returned by
// StatsdSink.Validate if the designated constraints aren't met.
type StatsdSinkValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e StatsdSinkValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sStatsdSink.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = StatsdSinkValidationError{}

// Validate checks the field values on DogStatsdSink with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *DogStatsdSink) Validate() error {
	if m == nil {
		return nil
	}

	switch m.DogStatsdSpecifier.(type) {

	case *DogStatsdSink_Address:

		if v, ok := interface{}(m.GetAddress()).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return DogStatsdSinkValidationError{
					Field:  "Address",
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	default:
		return DogStatsdSinkValidationError{
			Field:  "DogStatsdSpecifier",
			Reason: "value is required",
		}

	}

	return nil
}

// DogStatsdSinkValidationError is the validation error returned by
// DogStatsdSink.Validate if the designated constraints aren't met.
type DogStatsdSinkValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e DogStatsdSinkValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDogStatsdSink.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = DogStatsdSinkValidationError{}

// Validate checks the field values on HystrixSink with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *HystrixSink) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for NumBuckets

	return nil
}

// HystrixSinkValidationError is the validation error returned by
// HystrixSink.Validate if the designated constraints aren't met.
type HystrixSinkValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e HystrixSinkValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHystrixSink.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = HystrixSinkValidationError{}

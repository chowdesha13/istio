// Code generated by protoc-gen-validate
// source: envoy/type/matcher/metadata.proto
// DO NOT EDIT!!!

package matcher

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

// Validate checks the field values on MetadataMatcher with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *MetadataMatcher) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetFilter()) < 1 {
		return MetadataMatcherValidationError{
			Field:  "Filter",
			Reason: "value length must be at least 1 bytes",
		}
	}

	if len(m.GetPath()) < 1 {
		return MetadataMatcherValidationError{
			Field:  "Path",
			Reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetPath() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return MetadataMatcherValidationError{
					Field:  fmt.Sprintf("Path[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	if m.GetValue() == nil {
		return MetadataMatcherValidationError{
			Field:  "Value",
			Reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetValue()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return MetadataMatcherValidationError{
				Field:  "Value",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// MetadataMatcherValidationError is the validation error returned by
// MetadataMatcher.Validate if the designated constraints aren't met.
type MetadataMatcherValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e MetadataMatcherValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMetadataMatcher.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = MetadataMatcherValidationError{}

// Validate checks the field values on MetadataMatcher_PathSegment with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *MetadataMatcher_PathSegment) Validate() error {
	if m == nil {
		return nil
	}

	switch m.Segment.(type) {

	case *MetadataMatcher_PathSegment_Key:

		if len(m.GetKey()) < 1 {
			return MetadataMatcher_PathSegmentValidationError{
				Field:  "Key",
				Reason: "value length must be at least 1 bytes",
			}
		}

	default:
		return MetadataMatcher_PathSegmentValidationError{
			Field:  "Segment",
			Reason: "value is required",
		}

	}

	return nil
}

// MetadataMatcher_PathSegmentValidationError is the validation error returned
// by MetadataMatcher_PathSegment.Validate if the designated constraints
// aren't met.
type MetadataMatcher_PathSegmentValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e MetadataMatcher_PathSegmentValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMetadataMatcher_PathSegment.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = MetadataMatcher_PathSegmentValidationError{}

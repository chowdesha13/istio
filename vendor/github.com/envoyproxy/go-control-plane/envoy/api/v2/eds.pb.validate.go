// Code generated by protoc-gen-validate
// source: envoy/api/v2/eds.proto
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

// Validate checks the field values on ClusterLoadAssignment with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ClusterLoadAssignment) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetClusterName()) < 1 {
		return ClusterLoadAssignmentValidationError{
			Field:  "ClusterName",
			Reason: "value length must be at least 1 bytes",
		}
	}

	for idx, item := range m.GetEndpoints() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterLoadAssignmentValidationError{
					Field:  fmt.Sprintf("Endpoints[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetPolicy()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterLoadAssignmentValidationError{
				Field:  "Policy",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// ClusterLoadAssignmentValidationError is the validation error returned by
// ClusterLoadAssignment.Validate if the designated constraints aren't met.
type ClusterLoadAssignmentValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e ClusterLoadAssignmentValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sClusterLoadAssignment.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = ClusterLoadAssignmentValidationError{}

// Validate checks the field values on ClusterLoadAssignment_Policy with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ClusterLoadAssignment_Policy) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetDropOverloads() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterLoadAssignment_PolicyValidationError{
					Field:  fmt.Sprintf("DropOverloads[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// ClusterLoadAssignment_PolicyValidationError is the validation error returned
// by ClusterLoadAssignment_Policy.Validate if the designated constraints
// aren't met.
type ClusterLoadAssignment_PolicyValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e ClusterLoadAssignment_PolicyValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sClusterLoadAssignment_Policy.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = ClusterLoadAssignment_PolicyValidationError{}

// Validate checks the field values on
// ClusterLoadAssignment_Policy_DropOverload with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *ClusterLoadAssignment_Policy_DropOverload) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetCategory()) < 1 {
		return ClusterLoadAssignment_Policy_DropOverloadValidationError{
			Field:  "Category",
			Reason: "value length must be at least 1 bytes",
		}
	}

	if v, ok := interface{}(m.GetDropPercentage()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ClusterLoadAssignment_Policy_DropOverloadValidationError{
				Field:  "DropPercentage",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// ClusterLoadAssignment_Policy_DropOverloadValidationError is the validation
// error returned by ClusterLoadAssignment_Policy_DropOverload.Validate if the
// designated constraints aren't met.
type ClusterLoadAssignment_Policy_DropOverloadValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e ClusterLoadAssignment_Policy_DropOverloadValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sClusterLoadAssignment_Policy_DropOverload.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = ClusterLoadAssignment_Policy_DropOverloadValidationError{}

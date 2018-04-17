// Code generated by protoc-gen-validate
// source: envoy/admin/v2/config_dump.proto
// DO NOT EDIT!!!

package envoy_admin_v2

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

// Validate checks the field values on ConfigDump with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *ConfigDump) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Configs

	return nil
}

// ConfigDumpValidationError is the validation error returned by
// ConfigDump.Validate if the designated constraints aren't met.
type ConfigDumpValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e ConfigDumpValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sConfigDump.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = ConfigDumpValidationError{}

// Validate checks the field values on RouteConfigDump with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *RouteConfigDump) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetStaticRouteConfigs() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RouteConfigDumpValidationError{
					Field:  fmt.Sprintf("StaticRouteConfigs[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetDynamicRouteConfigs() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RouteConfigDumpValidationError{
					Field:  fmt.Sprintf("DynamicRouteConfigs[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// RouteConfigDumpValidationError is the validation error returned by
// RouteConfigDump.Validate if the designated constraints aren't met.
type RouteConfigDumpValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e RouteConfigDumpValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRouteConfigDump.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = RouteConfigDumpValidationError{}

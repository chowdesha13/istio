// Code generated by protoc-gen-validate
// source: envoy/config/filter/network/rbac/v2/rbac.proto
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

// Validate checks the field values on RBAC with the rules defined in the proto
// definition for this message. If any rules are violated, an error is returned.
func (m *RBAC) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetRules()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return RBACValidationError{
				Field:  "Rules",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetShadowRules()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return RBACValidationError{
				Field:  "ShadowRules",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	if len(m.GetStatPrefix()) < 1 {
		return RBACValidationError{
			Field:  "StatPrefix",
			Reason: "value length must be at least 1 bytes",
		}
	}

	return nil
}

// RBACValidationError is the validation error returned by RBAC.Validate if the
// designated constraints aren't met.
type RBACValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e RBACValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRBAC.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = RBACValidationError{}

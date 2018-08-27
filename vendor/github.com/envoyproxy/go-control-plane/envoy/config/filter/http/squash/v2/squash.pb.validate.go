// Code generated by protoc-gen-validate
// source: envoy/config/filter/http/squash/v2/squash.proto
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

// Validate checks the field values on Squash with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Squash) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetCluster()) < 1 {
		return SquashValidationError{
			Field:  "Cluster",
			Reason: "value length must be at least 1 bytes",
		}
	}

	if v, ok := interface{}(m.GetAttachmentTemplate()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return SquashValidationError{
				Field:  "AttachmentTemplate",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetRequestTimeout()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return SquashValidationError{
				Field:  "RequestTimeout",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetAttachmentTimeout()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return SquashValidationError{
				Field:  "AttachmentTimeout",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetAttachmentPollPeriod()).(interface {
		Validate() error
	}); ok {
		if err := v.Validate(); err != nil {
			return SquashValidationError{
				Field:  "AttachmentPollPeriod",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// SquashValidationError is the validation error returned by Squash.Validate if
// the designated constraints aren't met.
type SquashValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e SquashValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sSquash.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = SquashValidationError{}

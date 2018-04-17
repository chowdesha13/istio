// Code generated by protoc-gen-validate
// source: envoy/config/filter/network/mongo_proxy/v2/mongo_proxy.proto
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

// Validate checks the field values on MongoProxy with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *MongoProxy) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetStatPrefix()) < 1 {
		return MongoProxyValidationError{
			Field:  "StatPrefix",
			Reason: "value length must be at least 1 bytes",
		}
	}

	// no validation rules for AccessLog

	if v, ok := interface{}(m.GetDelay()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return MongoProxyValidationError{
				Field:  "Delay",
				Reason: "embedded message failed validation",
				Cause:  err,
			}
		}
	}

	return nil
}

// MongoProxyValidationError is the validation error returned by
// MongoProxy.Validate if the designated constraints aren't met.
type MongoProxyValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e MongoProxyValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMongoProxy.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = MongoProxyValidationError{}

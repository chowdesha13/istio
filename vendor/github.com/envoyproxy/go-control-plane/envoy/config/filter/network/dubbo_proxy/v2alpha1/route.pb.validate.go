// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/filter/network/dubbo_proxy/v2alpha1/route.proto

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

// Validate checks the field values on RouteConfiguration with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *RouteConfiguration) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Name

	// no validation rules for Interface

	// no validation rules for Group

	// no validation rules for Version

	for idx, item := range m.GetRoutes() {
		_, _ = idx, item

		{
			tmp := item

			if v, ok := interface{}(&tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return RouteConfigurationValidationError{
						field:  fmt.Sprintf("Routes[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	return nil
}

// RouteConfigurationValidationError is the validation error returned by
// RouteConfiguration.Validate if the designated constraints aren't met.
type RouteConfigurationValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RouteConfigurationValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RouteConfigurationValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RouteConfigurationValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RouteConfigurationValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RouteConfigurationValidationError) ErrorName() string {
	return "RouteConfigurationValidationError"
}

// Error satisfies the builtin error interface
func (e RouteConfigurationValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRouteConfiguration.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RouteConfigurationValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RouteConfigurationValidationError{}

// Validate checks the field values on Route with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Route) Validate() error {
	if m == nil {
		return nil
	}

	{
		tmp := m.GetMatch()

		if v, ok := interface{}(&tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return RouteValidationError{
					field:  "Match",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	{
		tmp := m.GetRoute()

		if v, ok := interface{}(&tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return RouteValidationError{
					field:  "Route",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	return nil
}

// RouteValidationError is the validation error returned by Route.Validate if
// the designated constraints aren't met.
type RouteValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RouteValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RouteValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RouteValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RouteValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RouteValidationError) ErrorName() string { return "RouteValidationError" }

// Error satisfies the builtin error interface
func (e RouteValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRoute.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RouteValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RouteValidationError{}

// Validate checks the field values on MethodMatch with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *MethodMatch) Validate() error {
	if m == nil {
		return nil
	}

	{
		tmp := m.GetName()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return MethodMatchValidationError{
					field:  "Name",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	// no validation rules for ParamsMatch

	return nil
}

// MethodMatchValidationError is the validation error returned by
// MethodMatch.Validate if the designated constraints aren't met.
type MethodMatchValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MethodMatchValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MethodMatchValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MethodMatchValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MethodMatchValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MethodMatchValidationError) ErrorName() string { return "MethodMatchValidationError" }

// Error satisfies the builtin error interface
func (e MethodMatchValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMethodMatch.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MethodMatchValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MethodMatchValidationError{}

// Validate checks the field values on RouteMatch with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *RouteMatch) Validate() error {
	if m == nil {
		return nil
	}

	{
		tmp := m.GetMethod()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return RouteMatchValidationError{
					field:  "Method",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	for idx, item := range m.GetHeaders() {
		_, _ = idx, item

		{
			tmp := item

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return RouteMatchValidationError{
						field:  fmt.Sprintf("Headers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	return nil
}

// RouteMatchValidationError is the validation error returned by
// RouteMatch.Validate if the designated constraints aren't met.
type RouteMatchValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RouteMatchValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RouteMatchValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RouteMatchValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RouteMatchValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RouteMatchValidationError) ErrorName() string { return "RouteMatchValidationError" }

// Error satisfies the builtin error interface
func (e RouteMatchValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRouteMatch.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RouteMatchValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RouteMatchValidationError{}

// Validate checks the field values on RouteAction with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *RouteAction) Validate() error {
	if m == nil {
		return nil
	}

	switch m.ClusterSpecifier.(type) {

	case *RouteAction_Cluster:
		// no validation rules for Cluster

	case *RouteAction_WeightedClusters:

		{
			tmp := m.GetWeightedClusters()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return RouteActionValidationError{
						field:  "WeightedClusters",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	default:
		return RouteActionValidationError{
			field:  "ClusterSpecifier",
			reason: "value is required",
		}

	}

	return nil
}

// RouteActionValidationError is the validation error returned by
// RouteAction.Validate if the designated constraints aren't met.
type RouteActionValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RouteActionValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RouteActionValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RouteActionValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RouteActionValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RouteActionValidationError) ErrorName() string { return "RouteActionValidationError" }

// Error satisfies the builtin error interface
func (e RouteActionValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRouteAction.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RouteActionValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RouteActionValidationError{}

// Validate checks the field values on MethodMatch_ParameterMatchSpecifier with
// the rules defined in the proto definition for this message. If any rules
// are violated, an error is returned.
func (m *MethodMatch_ParameterMatchSpecifier) Validate() error {
	if m == nil {
		return nil
	}

	switch m.ParameterMatchSpecifier.(type) {

	case *MethodMatch_ParameterMatchSpecifier_ExactMatch:
		// no validation rules for ExactMatch

	case *MethodMatch_ParameterMatchSpecifier_RangeMatch:

		{
			tmp := m.GetRangeMatch()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return MethodMatch_ParameterMatchSpecifierValidationError{
						field:  "RangeMatch",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	return nil
}

// MethodMatch_ParameterMatchSpecifierValidationError is the validation error
// returned by MethodMatch_ParameterMatchSpecifier.Validate if the designated
// constraints aren't met.
type MethodMatch_ParameterMatchSpecifierValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MethodMatch_ParameterMatchSpecifierValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MethodMatch_ParameterMatchSpecifierValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MethodMatch_ParameterMatchSpecifierValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MethodMatch_ParameterMatchSpecifierValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MethodMatch_ParameterMatchSpecifierValidationError) ErrorName() string {
	return "MethodMatch_ParameterMatchSpecifierValidationError"
}

// Error satisfies the builtin error interface
func (e MethodMatch_ParameterMatchSpecifierValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMethodMatch_ParameterMatchSpecifier.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MethodMatch_ParameterMatchSpecifierValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MethodMatch_ParameterMatchSpecifierValidationError{}

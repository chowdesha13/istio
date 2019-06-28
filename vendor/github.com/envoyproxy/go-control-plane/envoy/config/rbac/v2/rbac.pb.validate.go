// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/rbac/v2/rbac.proto

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

	// no validation rules for Action

	// no validation rules for Policies

	return nil
}

// RBACValidationError is the validation error returned by RBAC.Validate if the
// designated constraints aren't met.
type RBACValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RBACValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RBACValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RBACValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RBACValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RBACValidationError) ErrorName() string { return "RBACValidationError" }

// Error satisfies the builtin error interface
func (e RBACValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRBAC.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RBACValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RBACValidationError{}

// Validate checks the field values on Policy with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Policy) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetPermissions()) < 1 {
		return PolicyValidationError{
			field:  "Permissions",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetPermissions() {
		_, _ = idx, item

		{
			tmp := item

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PolicyValidationError{
						field:  fmt.Sprintf("Permissions[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	if len(m.GetPrincipals()) < 1 {
		return PolicyValidationError{
			field:  "Principals",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetPrincipals() {
		_, _ = idx, item

		{
			tmp := item

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PolicyValidationError{
						field:  fmt.Sprintf("Principals[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	return nil
}

// PolicyValidationError is the validation error returned by Policy.Validate if
// the designated constraints aren't met.
type PolicyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e PolicyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e PolicyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e PolicyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e PolicyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e PolicyValidationError) ErrorName() string { return "PolicyValidationError" }

// Error satisfies the builtin error interface
func (e PolicyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPolicy.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = PolicyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = PolicyValidationError{}

// Validate checks the field values on Permission with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Permission) Validate() error {
	if m == nil {
		return nil
	}

	switch m.Rule.(type) {

	case *Permission_AndRules:

		{
			tmp := m.GetAndRules()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PermissionValidationError{
						field:  "AndRules",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Permission_OrRules:

		{
			tmp := m.GetOrRules()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PermissionValidationError{
						field:  "OrRules",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Permission_Any:

		if m.GetAny() != true {
			return PermissionValidationError{
				field:  "Any",
				reason: "value must equal true",
			}
		}

	case *Permission_Header:

		{
			tmp := m.GetHeader()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PermissionValidationError{
						field:  "Header",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Permission_DestinationIp:

		{
			tmp := m.GetDestinationIp()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PermissionValidationError{
						field:  "DestinationIp",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Permission_DestinationPort:

		if m.GetDestinationPort() > 65535 {
			return PermissionValidationError{
				field:  "DestinationPort",
				reason: "value must be less than or equal to 65535",
			}
		}

	case *Permission_Metadata:

		{
			tmp := m.GetMetadata()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PermissionValidationError{
						field:  "Metadata",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Permission_NotRule:

		{
			tmp := m.GetNotRule()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PermissionValidationError{
						field:  "NotRule",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Permission_RequestedServerName:

		{
			tmp := m.GetRequestedServerName()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PermissionValidationError{
						field:  "RequestedServerName",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	default:
		return PermissionValidationError{
			field:  "Rule",
			reason: "value is required",
		}

	}

	return nil
}

// PermissionValidationError is the validation error returned by
// Permission.Validate if the designated constraints aren't met.
type PermissionValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e PermissionValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e PermissionValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e PermissionValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e PermissionValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e PermissionValidationError) ErrorName() string { return "PermissionValidationError" }

// Error satisfies the builtin error interface
func (e PermissionValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPermission.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = PermissionValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = PermissionValidationError{}

// Validate checks the field values on Principal with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Principal) Validate() error {
	if m == nil {
		return nil
	}

	switch m.Identifier.(type) {

	case *Principal_AndIds:

		{
			tmp := m.GetAndIds()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PrincipalValidationError{
						field:  "AndIds",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Principal_OrIds:

		{
			tmp := m.GetOrIds()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PrincipalValidationError{
						field:  "OrIds",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Principal_Any:

		if m.GetAny() != true {
			return PrincipalValidationError{
				field:  "Any",
				reason: "value must equal true",
			}
		}

	case *Principal_Authenticated_:

		{
			tmp := m.GetAuthenticated()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PrincipalValidationError{
						field:  "Authenticated",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Principal_SourceIp:

		{
			tmp := m.GetSourceIp()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PrincipalValidationError{
						field:  "SourceIp",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Principal_Header:

		{
			tmp := m.GetHeader()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PrincipalValidationError{
						field:  "Header",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Principal_Metadata:

		{
			tmp := m.GetMetadata()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PrincipalValidationError{
						field:  "Metadata",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	case *Principal_NotId:

		{
			tmp := m.GetNotId()

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return PrincipalValidationError{
						field:  "NotId",
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	default:
		return PrincipalValidationError{
			field:  "Identifier",
			reason: "value is required",
		}

	}

	return nil
}

// PrincipalValidationError is the validation error returned by
// Principal.Validate if the designated constraints aren't met.
type PrincipalValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e PrincipalValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e PrincipalValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e PrincipalValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e PrincipalValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e PrincipalValidationError) ErrorName() string { return "PrincipalValidationError" }

// Error satisfies the builtin error interface
func (e PrincipalValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPrincipal.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = PrincipalValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = PrincipalValidationError{}

// Validate checks the field values on Permission_Set with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *Permission_Set) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetRules()) < 1 {
		return Permission_SetValidationError{
			field:  "Rules",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetRules() {
		_, _ = idx, item

		{
			tmp := item

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return Permission_SetValidationError{
						field:  fmt.Sprintf("Rules[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	return nil
}

// Permission_SetValidationError is the validation error returned by
// Permission_Set.Validate if the designated constraints aren't met.
type Permission_SetValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Permission_SetValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Permission_SetValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Permission_SetValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Permission_SetValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Permission_SetValidationError) ErrorName() string { return "Permission_SetValidationError" }

// Error satisfies the builtin error interface
func (e Permission_SetValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPermission_Set.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Permission_SetValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Permission_SetValidationError{}

// Validate checks the field values on Principal_Set with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *Principal_Set) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetIds()) < 1 {
		return Principal_SetValidationError{
			field:  "Ids",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetIds() {
		_, _ = idx, item

		{
			tmp := item

			if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

				if err := v.Validate(); err != nil {
					return Principal_SetValidationError{
						field:  fmt.Sprintf("Ids[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}
		}

	}

	return nil
}

// Principal_SetValidationError is the validation error returned by
// Principal_Set.Validate if the designated constraints aren't met.
type Principal_SetValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Principal_SetValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Principal_SetValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Principal_SetValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Principal_SetValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Principal_SetValidationError) ErrorName() string { return "Principal_SetValidationError" }

// Error satisfies the builtin error interface
func (e Principal_SetValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPrincipal_Set.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Principal_SetValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Principal_SetValidationError{}

// Validate checks the field values on Principal_Authenticated with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *Principal_Authenticated) Validate() error {
	if m == nil {
		return nil
	}

	{
		tmp := m.GetPrincipalName()

		if v, ok := interface{}(tmp).(interface{ Validate() error }); ok {

			if err := v.Validate(); err != nil {
				return Principal_AuthenticatedValidationError{
					field:  "PrincipalName",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}
	}

	return nil
}

// Principal_AuthenticatedValidationError is the validation error returned by
// Principal_Authenticated.Validate if the designated constraints aren't met.
type Principal_AuthenticatedValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Principal_AuthenticatedValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Principal_AuthenticatedValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Principal_AuthenticatedValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Principal_AuthenticatedValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Principal_AuthenticatedValidationError) ErrorName() string {
	return "Principal_AuthenticatedValidationError"
}

// Error satisfies the builtin error interface
func (e Principal_AuthenticatedValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPrincipal_Authenticated.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Principal_AuthenticatedValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Principal_AuthenticatedValidationError{}

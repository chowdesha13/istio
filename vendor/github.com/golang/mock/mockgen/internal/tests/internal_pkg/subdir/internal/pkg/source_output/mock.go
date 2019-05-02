// Code generated by MockGen. DO NOT EDIT.
// Source: subdir/internal/pkg/input.go

// Package mock_pkg is a generated GoMock package.
package mock_pkg

import (
	gomock "github.com/golang/mock/gomock"
	pkg "github.com/golang/mock/mockgen/internal/tests/internal_pkg/subdir/internal/pkg"
	reflect "reflect"
)

// MockArg is a mock of Arg interface
type MockArg struct {
	ctrl     *gomock.Controller
	recorder *MockArgMockRecorder
}

// MockArgMockRecorder is the mock recorder for MockArg
type MockArgMockRecorder struct {
	mock *MockArg
}

// NewMockArg creates a new mock instance
func NewMockArg(ctrl *gomock.Controller) *MockArg {
	mock := &MockArg{ctrl: ctrl}
	mock.recorder = &MockArgMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockArg) EXPECT() *MockArgMockRecorder {
	return m.recorder
}

// Foo mocks base method
func (m *MockArg) Foo() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Foo")
	ret0, _ := ret[0].(int)
	return ret0
}

// Foo indicates an expected call of Foo
func (mr *MockArgMockRecorder) Foo() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Foo", reflect.TypeOf((*MockArg)(nil).Foo))
}

// MockIntf is a mock of Intf interface
type MockIntf struct {
	ctrl     *gomock.Controller
	recorder *MockIntfMockRecorder
}

// MockIntfMockRecorder is the mock recorder for MockIntf
type MockIntfMockRecorder struct {
	mock *MockIntf
}

// NewMockIntf creates a new mock instance
func NewMockIntf(ctrl *gomock.Controller) *MockIntf {
	mock := &MockIntf{ctrl: ctrl}
	mock.recorder = &MockIntfMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockIntf) EXPECT() *MockIntfMockRecorder {
	return m.recorder
}

// F mocks base method
func (m *MockIntf) F() pkg.Arg {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "F")
	ret0, _ := ret[0].(pkg.Arg)
	return ret0
}

// F indicates an expected call of F
func (mr *MockIntfMockRecorder) F() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "F", reflect.TypeOf((*MockIntf)(nil).F))
}

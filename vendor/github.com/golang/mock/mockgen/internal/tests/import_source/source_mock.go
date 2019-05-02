// Code generated by MockGen. DO NOT EDIT.
// Source: source.go

// Package mock_source is a generated GoMock package.
package mock_source

import (
	gomock "github.com/golang/mock/gomock"
	definition "github.com/golang/mock/mockgen/internal/tests/import_source/definition"
	reflect "reflect"
)

// MockS is a mock of S interface
type MockS struct {
	ctrl     *gomock.Controller
	recorder *MockSMockRecorder
}

// MockSMockRecorder is the mock recorder for MockS
type MockSMockRecorder struct {
	mock *MockS
}

// NewMockS creates a new mock instance
func NewMockS(ctrl *gomock.Controller) *MockS {
	mock := &MockS{ctrl: ctrl}
	mock.recorder = &MockSMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockS) EXPECT() *MockSMockRecorder {
	return m.recorder
}

// F mocks base method
func (m *MockS) F(arg0 definition.X) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "F", arg0)
}

// F indicates an expected call of F
func (mr *MockSMockRecorder) F(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "F", reflect.TypeOf((*MockS)(nil).F), arg0)
}

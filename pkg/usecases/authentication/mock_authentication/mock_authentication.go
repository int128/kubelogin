// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/pkg/usecases/authentication (interfaces: Interface)

// Package mock_authentication is a generated GoMock package.
package mock_authentication

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	authentication "github.com/pipedrive/kubelogin/pkg/usecases/authentication"
	reflect "reflect"
)

// MockInterface is a mock of Interface interface
type MockInterface struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceMockRecorder
}

// MockInterfaceMockRecorder is the mock recorder for MockInterface
type MockInterfaceMockRecorder struct {
	mock *MockInterface
}

// NewMockInterface creates a new mock instance
func NewMockInterface(ctrl *gomock.Controller) *MockInterface {
	mock := &MockInterface{ctrl: ctrl}
	mock.recorder = &MockInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockInterface) EXPECT() *MockInterfaceMockRecorder {
	return m.recorder
}

// Do mocks base method
func (m *MockInterface) Do(arg0 context.Context, arg1 authentication.Input) (*authentication.Output, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Do", arg0, arg1)
	ret0, _ := ret[0].(*authentication.Output)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Do indicates an expected call of Do
func (mr *MockInterfaceMockRecorder) Do(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Do", reflect.TypeOf((*MockInterface)(nil).Do), arg0, arg1)
}

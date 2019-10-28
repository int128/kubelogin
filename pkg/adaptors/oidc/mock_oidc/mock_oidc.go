// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/pkg/adaptors/oidc (interfaces: FactoryInterface,Interface)

// Package mock_oidc is a generated GoMock package.
package mock_oidc

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	oidc "github.com/int128/kubelogin/pkg/adaptors/oidc"
	reflect "reflect"
)

// MockFactoryInterface is a mock of FactoryInterface interface
type MockFactoryInterface struct {
	ctrl     *gomock.Controller
	recorder *MockFactoryInterfaceMockRecorder
}

// MockFactoryInterfaceMockRecorder is the mock recorder for MockFactoryInterface
type MockFactoryInterfaceMockRecorder struct {
	mock *MockFactoryInterface
}

// NewMockFactoryInterface creates a new mock instance
func NewMockFactoryInterface(ctrl *gomock.Controller) *MockFactoryInterface {
	mock := &MockFactoryInterface{ctrl: ctrl}
	mock.recorder = &MockFactoryInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockFactoryInterface) EXPECT() *MockFactoryInterfaceMockRecorder {
	return m.recorder
}

// New mocks base method
func (m *MockFactoryInterface) New(arg0 context.Context, arg1 oidc.ClientConfig) (oidc.Interface, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", arg0, arg1)
	ret0, _ := ret[0].(oidc.Interface)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// New indicates an expected call of New
func (mr *MockFactoryInterfaceMockRecorder) New(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockFactoryInterface)(nil).New), arg0, arg1)
}

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

// AuthenticateByCode mocks base method
func (m *MockInterface) AuthenticateByCode(arg0 context.Context, arg1 []string, arg2 chan<- string) (*oidc.TokenSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateByCode", arg0, arg1, arg2)
	ret0, _ := ret[0].(*oidc.TokenSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateByCode indicates an expected call of AuthenticateByCode
func (mr *MockInterfaceMockRecorder) AuthenticateByCode(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateByCode", reflect.TypeOf((*MockInterface)(nil).AuthenticateByCode), arg0, arg1, arg2)
}

// AuthenticateByPassword mocks base method
func (m *MockInterface) AuthenticateByPassword(arg0 context.Context, arg1, arg2 string) (*oidc.TokenSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateByPassword", arg0, arg1, arg2)
	ret0, _ := ret[0].(*oidc.TokenSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateByPassword indicates an expected call of AuthenticateByPassword
func (mr *MockInterfaceMockRecorder) AuthenticateByPassword(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateByPassword", reflect.TypeOf((*MockInterface)(nil).AuthenticateByPassword), arg0, arg1, arg2)
}

// Refresh mocks base method
func (m *MockInterface) Refresh(arg0 context.Context, arg1 string) (*oidc.TokenSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Refresh", arg0, arg1)
	ret0, _ := ret[0].(*oidc.TokenSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Refresh indicates an expected call of Refresh
func (mr *MockInterfaceMockRecorder) Refresh(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Refresh", reflect.TypeOf((*MockInterface)(nil).Refresh), arg0, arg1)
}

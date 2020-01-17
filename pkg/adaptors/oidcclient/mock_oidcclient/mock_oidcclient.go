// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/pkg/adaptors/oidcclient (interfaces: Interface)

// Package mock_oidcclient is a generated GoMock package.
package mock_oidcclient

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	oidcclient "github.com/int128/kubelogin/pkg/adaptors/oidcclient"
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

// ExchangeAuthCode mocks base method
func (m *MockInterface) ExchangeAuthCode(arg0 context.Context, arg1 oidcclient.ExchangeAuthCodeInput) (*oidcclient.TokenSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExchangeAuthCode", arg0, arg1)
	ret0, _ := ret[0].(*oidcclient.TokenSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExchangeAuthCode indicates an expected call of ExchangeAuthCode
func (mr *MockInterfaceMockRecorder) ExchangeAuthCode(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExchangeAuthCode", reflect.TypeOf((*MockInterface)(nil).ExchangeAuthCode), arg0, arg1)
}

// GetAuthCodeURL mocks base method
func (m *MockInterface) GetAuthCodeURL(arg0 oidcclient.AuthCodeURLInput) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAuthCodeURL", arg0)
	ret0, _ := ret[0].(string)
	return ret0
}

// GetAuthCodeURL indicates an expected call of GetAuthCodeURL
func (mr *MockInterfaceMockRecorder) GetAuthCodeURL(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAuthCodeURL", reflect.TypeOf((*MockInterface)(nil).GetAuthCodeURL), arg0)
}

// GetTokenByAuthCode mocks base method
func (m *MockInterface) GetTokenByAuthCode(arg0 context.Context, arg1 oidcclient.GetTokenByAuthCodeInput, arg2 chan<- string) (*oidcclient.TokenSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTokenByAuthCode", arg0, arg1, arg2)
	ret0, _ := ret[0].(*oidcclient.TokenSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTokenByAuthCode indicates an expected call of GetTokenByAuthCode
func (mr *MockInterfaceMockRecorder) GetTokenByAuthCode(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTokenByAuthCode", reflect.TypeOf((*MockInterface)(nil).GetTokenByAuthCode), arg0, arg1, arg2)
}

// GetTokenByROPC mocks base method
func (m *MockInterface) GetTokenByROPC(arg0 context.Context, arg1, arg2 string) (*oidcclient.TokenSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTokenByROPC", arg0, arg1, arg2)
	ret0, _ := ret[0].(*oidcclient.TokenSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTokenByROPC indicates an expected call of GetTokenByROPC
func (mr *MockInterfaceMockRecorder) GetTokenByROPC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTokenByROPC", reflect.TypeOf((*MockInterface)(nil).GetTokenByROPC), arg0, arg1, arg2)
}

// Refresh mocks base method
func (m *MockInterface) Refresh(arg0 context.Context, arg1 string) (*oidcclient.TokenSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Refresh", arg0, arg1)
	ret0, _ := ret[0].(*oidcclient.TokenSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Refresh indicates an expected call of Refresh
func (mr *MockInterfaceMockRecorder) Refresh(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Refresh", reflect.TypeOf((*MockInterface)(nil).Refresh), arg0, arg1)
}

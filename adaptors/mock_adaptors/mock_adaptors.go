// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/adaptors (interfaces: KubeConfig,HTTP,OIDC,Logger)

// Package mock_adaptors is a generated GoMock package.
package mock_adaptors

import (
	context "context"
	go_oidc "github.com/coreos/go-oidc"
	gomock "github.com/golang/mock/gomock"
	adaptors "github.com/int128/kubelogin/adaptors"
	kubeconfig "github.com/int128/kubelogin/kubeconfig"
	http "net/http"
	reflect "reflect"
)

// MockKubeConfig is a mock of KubeConfig interface
type MockKubeConfig struct {
	ctrl     *gomock.Controller
	recorder *MockKubeConfigMockRecorder
}

// MockKubeConfigMockRecorder is the mock recorder for MockKubeConfig
type MockKubeConfigMockRecorder struct {
	mock *MockKubeConfig
}

// NewMockKubeConfig creates a new mock instance
func NewMockKubeConfig(ctrl *gomock.Controller) *MockKubeConfig {
	mock := &MockKubeConfig{ctrl: ctrl}
	mock.recorder = &MockKubeConfigMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockKubeConfig) EXPECT() *MockKubeConfigMockRecorder {
	return m.recorder
}

// LoadByDefaultRules mocks base method
func (m *MockKubeConfig) LoadByDefaultRules(arg0 string) (*kubeconfig.Config, error) {
	ret := m.ctrl.Call(m, "LoadByDefaultRules", arg0)
	ret0, _ := ret[0].(*kubeconfig.Config)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LoadByDefaultRules indicates an expected call of LoadByDefaultRules
func (mr *MockKubeConfigMockRecorder) LoadByDefaultRules(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadByDefaultRules", reflect.TypeOf((*MockKubeConfig)(nil).LoadByDefaultRules), arg0)
}

// LoadFromFile mocks base method
func (m *MockKubeConfig) LoadFromFile(arg0 string) (*kubeconfig.Config, error) {
	ret := m.ctrl.Call(m, "LoadFromFile", arg0)
	ret0, _ := ret[0].(*kubeconfig.Config)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LoadFromFile indicates an expected call of LoadFromFile
func (mr *MockKubeConfigMockRecorder) LoadFromFile(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadFromFile", reflect.TypeOf((*MockKubeConfig)(nil).LoadFromFile), arg0)
}

// WriteToFile mocks base method
func (m *MockKubeConfig) WriteToFile(arg0 *kubeconfig.Config, arg1 string) error {
	ret := m.ctrl.Call(m, "WriteToFile", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// WriteToFile indicates an expected call of WriteToFile
func (mr *MockKubeConfigMockRecorder) WriteToFile(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteToFile", reflect.TypeOf((*MockKubeConfig)(nil).WriteToFile), arg0, arg1)
}

// MockHTTP is a mock of HTTP interface
type MockHTTP struct {
	ctrl     *gomock.Controller
	recorder *MockHTTPMockRecorder
}

// MockHTTPMockRecorder is the mock recorder for MockHTTP
type MockHTTPMockRecorder struct {
	mock *MockHTTP
}

// NewMockHTTP creates a new mock instance
func NewMockHTTP(ctrl *gomock.Controller) *MockHTTP {
	mock := &MockHTTP{ctrl: ctrl}
	mock.recorder = &MockHTTPMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockHTTP) EXPECT() *MockHTTPMockRecorder {
	return m.recorder
}

// NewClient mocks base method
func (m *MockHTTP) NewClient(arg0 adaptors.HTTPClientConfig) (*http.Client, error) {
	ret := m.ctrl.Call(m, "NewClient", arg0)
	ret0, _ := ret[0].(*http.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewClient indicates an expected call of NewClient
func (mr *MockHTTPMockRecorder) NewClient(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewClient", reflect.TypeOf((*MockHTTP)(nil).NewClient), arg0)
}

// MockOIDC is a mock of OIDC interface
type MockOIDC struct {
	ctrl     *gomock.Controller
	recorder *MockOIDCMockRecorder
}

// MockOIDCMockRecorder is the mock recorder for MockOIDC
type MockOIDCMockRecorder struct {
	mock *MockOIDC
}

// NewMockOIDC creates a new mock instance
func NewMockOIDC(ctrl *gomock.Controller) *MockOIDC {
	mock := &MockOIDC{ctrl: ctrl}
	mock.recorder = &MockOIDCMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOIDC) EXPECT() *MockOIDCMockRecorder {
	return m.recorder
}

// AuthenticateByCode mocks base method
func (m *MockOIDC) AuthenticateByCode(arg0 context.Context, arg1 adaptors.OIDCAuthenticateByCodeIn, arg2 adaptors.OIDCAuthenticateCallback) (*adaptors.OIDCAuthenticateOut, error) {
	ret := m.ctrl.Call(m, "AuthenticateByCode", arg0, arg1, arg2)
	ret0, _ := ret[0].(*adaptors.OIDCAuthenticateOut)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateByCode indicates an expected call of AuthenticateByCode
func (mr *MockOIDCMockRecorder) AuthenticateByCode(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateByCode", reflect.TypeOf((*MockOIDC)(nil).AuthenticateByCode), arg0, arg1, arg2)
}

// AuthenticateByPassword mocks base method
func (m *MockOIDC) AuthenticateByPassword(arg0 context.Context, arg1 adaptors.OIDCAuthenticateByPasswordIn) (*adaptors.OIDCAuthenticateOut, error) {
	ret := m.ctrl.Call(m, "AuthenticateByPassword", arg0, arg1)
	ret0, _ := ret[0].(*adaptors.OIDCAuthenticateOut)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateByPassword indicates an expected call of AuthenticateByPassword
func (mr *MockOIDCMockRecorder) AuthenticateByPassword(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateByPassword", reflect.TypeOf((*MockOIDC)(nil).AuthenticateByPassword), arg0, arg1)
}

// Verify mocks base method
func (m *MockOIDC) Verify(arg0 context.Context, arg1 adaptors.OIDCVerifyIn) (*go_oidc.IDToken, error) {
	ret := m.ctrl.Call(m, "Verify", arg0, arg1)
	ret0, _ := ret[0].(*go_oidc.IDToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify
func (mr *MockOIDCMockRecorder) Verify(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockOIDC)(nil).Verify), arg0, arg1)
}

// MockLogger is a mock of Logger interface
type MockLogger struct {
	ctrl     *gomock.Controller
	recorder *MockLoggerMockRecorder
}

// MockLoggerMockRecorder is the mock recorder for MockLogger
type MockLoggerMockRecorder struct {
	mock *MockLogger
}

// NewMockLogger creates a new mock instance
func NewMockLogger(ctrl *gomock.Controller) *MockLogger {
	mock := &MockLogger{ctrl: ctrl}
	mock.recorder = &MockLoggerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockLogger) EXPECT() *MockLoggerMockRecorder {
	return m.recorder
}

// Debugf mocks base method
func (m *MockLogger) Debugf(arg0 adaptors.LogLevel, arg1 string, arg2 ...interface{}) {
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Debugf", varargs...)
}

// Debugf indicates an expected call of Debugf
func (mr *MockLoggerMockRecorder) Debugf(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Debugf", reflect.TypeOf((*MockLogger)(nil).Debugf), varargs...)
}

// IsEnabled mocks base method
func (m *MockLogger) IsEnabled(arg0 adaptors.LogLevel) bool {
	ret := m.ctrl.Call(m, "IsEnabled", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsEnabled indicates an expected call of IsEnabled
func (mr *MockLoggerMockRecorder) IsEnabled(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsEnabled", reflect.TypeOf((*MockLogger)(nil).IsEnabled), arg0)
}

// Printf mocks base method
func (m *MockLogger) Printf(arg0 string, arg1 ...interface{}) {
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Printf", varargs...)
}

// Printf indicates an expected call of Printf
func (mr *MockLoggerMockRecorder) Printf(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Printf", reflect.TypeOf((*MockLogger)(nil).Printf), varargs...)
}

// SetLevel mocks base method
func (m *MockLogger) SetLevel(arg0 adaptors.LogLevel) {
	m.ctrl.Call(m, "SetLevel", arg0)
}

// SetLevel indicates an expected call of SetLevel
func (mr *MockLoggerMockRecorder) SetLevel(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetLevel", reflect.TypeOf((*MockLogger)(nil).SetLevel), arg0)
}

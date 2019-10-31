// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/e2e_test/idp (interfaces: Service)

// Package mock_idp is a generated GoMock package.
package mock_idp

import (
	gomock "github.com/golang/mock/gomock"
	idp "github.com/int128/kubelogin/e2e_test/idp"
	reflect "reflect"
)

// MockService is a mock of Service interface
type MockService struct {
	ctrl     *gomock.Controller
	recorder *MockServiceMockRecorder
}

// MockServiceMockRecorder is the mock recorder for MockService
type MockServiceMockRecorder struct {
	mock *MockService
}

// NewMockService creates a new mock instance
func NewMockService(ctrl *gomock.Controller) *MockService {
	mock := &MockService{ctrl: ctrl}
	mock.recorder = &MockServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockService) EXPECT() *MockServiceMockRecorder {
	return m.recorder
}

// AuthenticateCode mocks base method
func (m *MockService) AuthenticateCode(arg0, arg1 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateCode", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateCode indicates an expected call of AuthenticateCode
func (mr *MockServiceMockRecorder) AuthenticateCode(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateCode", reflect.TypeOf((*MockService)(nil).AuthenticateCode), arg0, arg1)
}

// AuthenticatePassword mocks base method
func (m *MockService) AuthenticatePassword(arg0, arg1, arg2 string) (*idp.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticatePassword", arg0, arg1, arg2)
	ret0, _ := ret[0].(*idp.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticatePassword indicates an expected call of AuthenticatePassword
func (mr *MockServiceMockRecorder) AuthenticatePassword(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticatePassword", reflect.TypeOf((*MockService)(nil).AuthenticatePassword), arg0, arg1, arg2)
}

// Discovery mocks base method
func (m *MockService) Discovery() *idp.DiscoveryResponse {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Discovery")
	ret0, _ := ret[0].(*idp.DiscoveryResponse)
	return ret0
}

// Discovery indicates an expected call of Discovery
func (mr *MockServiceMockRecorder) Discovery() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Discovery", reflect.TypeOf((*MockService)(nil).Discovery))
}

// Exchange mocks base method
func (m *MockService) Exchange(arg0 string) (*idp.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exchange", arg0)
	ret0, _ := ret[0].(*idp.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exchange indicates an expected call of Exchange
func (mr *MockServiceMockRecorder) Exchange(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exchange", reflect.TypeOf((*MockService)(nil).Exchange), arg0)
}

// GetCertificates mocks base method
func (m *MockService) GetCertificates() *idp.CertificatesResponse {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCertificates")
	ret0, _ := ret[0].(*idp.CertificatesResponse)
	return ret0
}

// GetCertificates indicates an expected call of GetCertificates
func (mr *MockServiceMockRecorder) GetCertificates() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCertificates", reflect.TypeOf((*MockService)(nil).GetCertificates))
}

// Refresh mocks base method
func (m *MockService) Refresh(arg0 string) (*idp.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Refresh", arg0)
	ret0, _ := ret[0].(*idp.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Refresh indicates an expected call of Refresh
func (mr *MockServiceMockRecorder) Refresh(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Refresh", reflect.TypeOf((*MockService)(nil).Refresh), arg0)
}

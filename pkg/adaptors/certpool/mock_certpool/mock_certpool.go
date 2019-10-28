// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/pkg/adaptors/certpool (interfaces: FactoryInterface,Interface)

// Package mock_certpool is a generated GoMock package.
package mock_certpool

import (
	x509 "crypto/x509"
	gomock "github.com/golang/mock/gomock"
	certpool "github.com/int128/kubelogin/pkg/adaptors/certpool"
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
func (m *MockFactoryInterface) New() certpool.Interface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New")
	ret0, _ := ret[0].(certpool.Interface)
	return ret0
}

// New indicates an expected call of New
func (mr *MockFactoryInterfaceMockRecorder) New() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockFactoryInterface)(nil).New))
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

// GetX509CertPool mocks base method
func (m *MockInterface) GetX509CertPool() *x509.CertPool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetX509CertPool")
	ret0, _ := ret[0].(*x509.CertPool)
	return ret0
}

// GetX509CertPool indicates an expected call of GetX509CertPool
func (mr *MockInterfaceMockRecorder) GetX509CertPool() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetX509CertPool", reflect.TypeOf((*MockInterface)(nil).GetX509CertPool))
}

// LoadBase64 mocks base method
func (m *MockInterface) LoadBase64(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LoadBase64", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// LoadBase64 indicates an expected call of LoadBase64
func (mr *MockInterfaceMockRecorder) LoadBase64(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadBase64", reflect.TypeOf((*MockInterface)(nil).LoadBase64), arg0)
}

// LoadFromFile mocks base method
func (m *MockInterface) LoadFromFile(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LoadFromFile", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// LoadFromFile indicates an expected call of LoadFromFile
func (mr *MockInterfaceMockRecorder) LoadFromFile(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadFromFile", reflect.TypeOf((*MockInterface)(nil).LoadFromFile), arg0)
}

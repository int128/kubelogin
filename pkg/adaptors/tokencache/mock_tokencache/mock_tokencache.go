// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/pkg/adaptors/tokencache (interfaces: Interface)

// Package mock_tokencache is a generated GoMock package.
package mock_tokencache

import (
	gomock "github.com/golang/mock/gomock"
	tokencache "github.com/int128/kubelogin/pkg/adaptors/tokencache"
	reflect "reflect"
)

// MockInterface is a mock of Interface interface.
type MockInterface struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceMockRecorder
}

// MockInterfaceMockRecorder is the mock recorder for MockInterface.
type MockInterfaceMockRecorder struct {
	mock *MockInterface
}

// NewMockInterface creates a new mock instance.
func NewMockInterface(ctrl *gomock.Controller) *MockInterface {
	mock := &MockInterface{ctrl: ctrl}
	mock.recorder = &MockInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockInterface) EXPECT() *MockInterfaceMockRecorder {
	return m.recorder
}

// FindByKey mocks base method.
func (m *MockInterface) FindByKey(arg0 string, arg1 tokencache.Key) (*tokencache.Value, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindByKey", arg0, arg1)
	ret0, _ := ret[0].(*tokencache.Value)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindByKey indicates an expected call of FindByKey.
func (mr *MockInterfaceMockRecorder) FindByKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindByKey", reflect.TypeOf((*MockInterface)(nil).FindByKey), arg0, arg1)
}

// Save mocks base method.
func (m *MockInterface) Save(arg0 string, arg1 tokencache.Key, arg2 tokencache.Value) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Save", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Save indicates an expected call of Save.
func (mr *MockInterfaceMockRecorder) Save(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Save", reflect.TypeOf((*MockInterface)(nil).Save), arg0, arg1, arg2)
}

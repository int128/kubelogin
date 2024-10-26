// Code generated by mockery v2.44.1. DO NOT EDIT.

package oidcserver_mock

import (
	handler "github.com/int128/kubelogin/integration_test/oidcserver/handler"
	mock "github.com/stretchr/testify/mock"

	oidcserver "github.com/int128/kubelogin/integration_test/oidcserver"
)

// MockServer is an autogenerated mock type for the Server type
type MockServer struct {
	mock.Mock
}

type MockServer_Expecter struct {
	mock *mock.Mock
}

func (_m *MockServer) EXPECT() *MockServer_Expecter {
	return &MockServer_Expecter{mock: &_m.Mock}
}

// IssuerURL provides a mock function with given fields:
func (_m *MockServer) IssuerURL() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for IssuerURL")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockServer_IssuerURL_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IssuerURL'
type MockServer_IssuerURL_Call struct {
	*mock.Call
}

// IssuerURL is a helper method to define mock.On call
func (_e *MockServer_Expecter) IssuerURL() *MockServer_IssuerURL_Call {
	return &MockServer_IssuerURL_Call{Call: _e.mock.On("IssuerURL")}
}

func (_c *MockServer_IssuerURL_Call) Run(run func()) *MockServer_IssuerURL_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockServer_IssuerURL_Call) Return(_a0 string) *MockServer_IssuerURL_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockServer_IssuerURL_Call) RunAndReturn(run func() string) *MockServer_IssuerURL_Call {
	_c.Call.Return(run)
	return _c
}

// LastTokenResponse provides a mock function with given fields:
func (_m *MockServer) LastTokenResponse() *handler.TokenResponse {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for LastTokenResponse")
	}

	var r0 *handler.TokenResponse
	if rf, ok := ret.Get(0).(func() *handler.TokenResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*handler.TokenResponse)
		}
	}

	return r0
}

// MockServer_LastTokenResponse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LastTokenResponse'
type MockServer_LastTokenResponse_Call struct {
	*mock.Call
}

// LastTokenResponse is a helper method to define mock.On call
func (_e *MockServer_Expecter) LastTokenResponse() *MockServer_LastTokenResponse_Call {
	return &MockServer_LastTokenResponse_Call{Call: _e.mock.On("LastTokenResponse")}
}

func (_c *MockServer_LastTokenResponse_Call) Run(run func()) *MockServer_LastTokenResponse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockServer_LastTokenResponse_Call) Return(_a0 *handler.TokenResponse) *MockServer_LastTokenResponse_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockServer_LastTokenResponse_Call) RunAndReturn(run func() *handler.TokenResponse) *MockServer_LastTokenResponse_Call {
	_c.Call.Return(run)
	return _c
}

// SetConfig provides a mock function with given fields: _a0
func (_m *MockServer) SetConfig(_a0 oidcserver.Config) {
	_m.Called(_a0)
}

// MockServer_SetConfig_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetConfig'
type MockServer_SetConfig_Call struct {
	*mock.Call
}

// SetConfig is a helper method to define mock.On call
//   - _a0 oidcserver.Config
func (_e *MockServer_Expecter) SetConfig(_a0 interface{}) *MockServer_SetConfig_Call {
	return &MockServer_SetConfig_Call{Call: _e.mock.On("SetConfig", _a0)}
}

func (_c *MockServer_SetConfig_Call) Run(run func(_a0 oidcserver.Config)) *MockServer_SetConfig_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(oidcserver.Config))
	})
	return _c
}

func (_c *MockServer_SetConfig_Call) Return() *MockServer_SetConfig_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockServer_SetConfig_Call) RunAndReturn(run func(oidcserver.Config)) *MockServer_SetConfig_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockServer creates a new instance of MockServer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockServer(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockServer {
	mock := &MockServer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

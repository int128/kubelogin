// Code generated by mockery v2.49.2. DO NOT EDIT.

package service_mock

import (
	service "github.com/int128/kubelogin/integration_test/oidcserver/service"
	mock "github.com/stretchr/testify/mock"
)

// MockProvider is an autogenerated mock type for the Provider type
type MockProvider struct {
	mock.Mock
}

type MockProvider_Expecter struct {
	mock *mock.Mock
}

func (_m *MockProvider) EXPECT() *MockProvider_Expecter {
	return &MockProvider_Expecter{mock: &_m.Mock}
}

// AuthenticateCode provides a mock function with given fields: req
func (_m *MockProvider) AuthenticateCode(req service.AuthenticationRequest) (string, error) {
	ret := _m.Called(req)

	if len(ret) == 0 {
		panic("no return value specified for AuthenticateCode")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(service.AuthenticationRequest) (string, error)); ok {
		return rf(req)
	}
	if rf, ok := ret.Get(0).(func(service.AuthenticationRequest) string); ok {
		r0 = rf(req)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(service.AuthenticationRequest) error); ok {
		r1 = rf(req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProvider_AuthenticateCode_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AuthenticateCode'
type MockProvider_AuthenticateCode_Call struct {
	*mock.Call
}

// AuthenticateCode is a helper method to define mock.On call
//   - req service.AuthenticationRequest
func (_e *MockProvider_Expecter) AuthenticateCode(req interface{}) *MockProvider_AuthenticateCode_Call {
	return &MockProvider_AuthenticateCode_Call{Call: _e.mock.On("AuthenticateCode", req)}
}

func (_c *MockProvider_AuthenticateCode_Call) Run(run func(req service.AuthenticationRequest)) *MockProvider_AuthenticateCode_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(service.AuthenticationRequest))
	})
	return _c
}

func (_c *MockProvider_AuthenticateCode_Call) Return(code string, err error) *MockProvider_AuthenticateCode_Call {
	_c.Call.Return(code, err)
	return _c
}

func (_c *MockProvider_AuthenticateCode_Call) RunAndReturn(run func(service.AuthenticationRequest) (string, error)) *MockProvider_AuthenticateCode_Call {
	_c.Call.Return(run)
	return _c
}

// AuthenticatePassword provides a mock function with given fields: username, password, scope
func (_m *MockProvider) AuthenticatePassword(username string, password string, scope string) (*service.TokenResponse, error) {
	ret := _m.Called(username, password, scope)

	if len(ret) == 0 {
		panic("no return value specified for AuthenticatePassword")
	}

	var r0 *service.TokenResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string, string) (*service.TokenResponse, error)); ok {
		return rf(username, password, scope)
	}
	if rf, ok := ret.Get(0).(func(string, string, string) *service.TokenResponse); ok {
		r0 = rf(username, password, scope)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(username, password, scope)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProvider_AuthenticatePassword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AuthenticatePassword'
type MockProvider_AuthenticatePassword_Call struct {
	*mock.Call
}

// AuthenticatePassword is a helper method to define mock.On call
//   - username string
//   - password string
//   - scope string
func (_e *MockProvider_Expecter) AuthenticatePassword(username interface{}, password interface{}, scope interface{}) *MockProvider_AuthenticatePassword_Call {
	return &MockProvider_AuthenticatePassword_Call{Call: _e.mock.On("AuthenticatePassword", username, password, scope)}
}

func (_c *MockProvider_AuthenticatePassword_Call) Run(run func(username string, password string, scope string)) *MockProvider_AuthenticatePassword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockProvider_AuthenticatePassword_Call) Return(_a0 *service.TokenResponse, _a1 error) *MockProvider_AuthenticatePassword_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProvider_AuthenticatePassword_Call) RunAndReturn(run func(string, string, string) (*service.TokenResponse, error)) *MockProvider_AuthenticatePassword_Call {
	_c.Call.Return(run)
	return _c
}

// Discovery provides a mock function with no fields
func (_m *MockProvider) Discovery() *service.DiscoveryResponse {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Discovery")
	}

	var r0 *service.DiscoveryResponse
	if rf, ok := ret.Get(0).(func() *service.DiscoveryResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.DiscoveryResponse)
		}
	}

	return r0
}

// MockProvider_Discovery_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Discovery'
type MockProvider_Discovery_Call struct {
	*mock.Call
}

// Discovery is a helper method to define mock.On call
func (_e *MockProvider_Expecter) Discovery() *MockProvider_Discovery_Call {
	return &MockProvider_Discovery_Call{Call: _e.mock.On("Discovery")}
}

func (_c *MockProvider_Discovery_Call) Run(run func()) *MockProvider_Discovery_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockProvider_Discovery_Call) Return(_a0 *service.DiscoveryResponse) *MockProvider_Discovery_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockProvider_Discovery_Call) RunAndReturn(run func() *service.DiscoveryResponse) *MockProvider_Discovery_Call {
	_c.Call.Return(run)
	return _c
}

// Exchange provides a mock function with given fields: req
func (_m *MockProvider) Exchange(req service.TokenRequest) (*service.TokenResponse, error) {
	ret := _m.Called(req)

	if len(ret) == 0 {
		panic("no return value specified for Exchange")
	}

	var r0 *service.TokenResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(service.TokenRequest) (*service.TokenResponse, error)); ok {
		return rf(req)
	}
	if rf, ok := ret.Get(0).(func(service.TokenRequest) *service.TokenResponse); ok {
		r0 = rf(req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(service.TokenRequest) error); ok {
		r1 = rf(req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProvider_Exchange_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Exchange'
type MockProvider_Exchange_Call struct {
	*mock.Call
}

// Exchange is a helper method to define mock.On call
//   - req service.TokenRequest
func (_e *MockProvider_Expecter) Exchange(req interface{}) *MockProvider_Exchange_Call {
	return &MockProvider_Exchange_Call{Call: _e.mock.On("Exchange", req)}
}

func (_c *MockProvider_Exchange_Call) Run(run func(req service.TokenRequest)) *MockProvider_Exchange_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(service.TokenRequest))
	})
	return _c
}

func (_c *MockProvider_Exchange_Call) Return(_a0 *service.TokenResponse, _a1 error) *MockProvider_Exchange_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProvider_Exchange_Call) RunAndReturn(run func(service.TokenRequest) (*service.TokenResponse, error)) *MockProvider_Exchange_Call {
	_c.Call.Return(run)
	return _c
}

// GetCertificates provides a mock function with no fields
func (_m *MockProvider) GetCertificates() *service.CertificatesResponse {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetCertificates")
	}

	var r0 *service.CertificatesResponse
	if rf, ok := ret.Get(0).(func() *service.CertificatesResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.CertificatesResponse)
		}
	}

	return r0
}

// MockProvider_GetCertificates_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCertificates'
type MockProvider_GetCertificates_Call struct {
	*mock.Call
}

// GetCertificates is a helper method to define mock.On call
func (_e *MockProvider_Expecter) GetCertificates() *MockProvider_GetCertificates_Call {
	return &MockProvider_GetCertificates_Call{Call: _e.mock.On("GetCertificates")}
}

func (_c *MockProvider_GetCertificates_Call) Run(run func()) *MockProvider_GetCertificates_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockProvider_GetCertificates_Call) Return(_a0 *service.CertificatesResponse) *MockProvider_GetCertificates_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockProvider_GetCertificates_Call) RunAndReturn(run func() *service.CertificatesResponse) *MockProvider_GetCertificates_Call {
	_c.Call.Return(run)
	return _c
}

// Refresh provides a mock function with given fields: refreshToken
func (_m *MockProvider) Refresh(refreshToken string) (*service.TokenResponse, error) {
	ret := _m.Called(refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for Refresh")
	}

	var r0 *service.TokenResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*service.TokenResponse, error)); ok {
		return rf(refreshToken)
	}
	if rf, ok := ret.Get(0).(func(string) *service.TokenResponse); ok {
		r0 = rf(refreshToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(refreshToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProvider_Refresh_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Refresh'
type MockProvider_Refresh_Call struct {
	*mock.Call
}

// Refresh is a helper method to define mock.On call
//   - refreshToken string
func (_e *MockProvider_Expecter) Refresh(refreshToken interface{}) *MockProvider_Refresh_Call {
	return &MockProvider_Refresh_Call{Call: _e.mock.On("Refresh", refreshToken)}
}

func (_c *MockProvider_Refresh_Call) Run(run func(refreshToken string)) *MockProvider_Refresh_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockProvider_Refresh_Call) Return(_a0 *service.TokenResponse, _a1 error) *MockProvider_Refresh_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProvider_Refresh_Call) RunAndReturn(run func(string) (*service.TokenResponse, error)) *MockProvider_Refresh_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockProvider creates a new instance of MockProvider. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockProvider(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockProvider {
	mock := &MockProvider{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

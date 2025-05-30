// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package service_mock

import (
	"github.com/int128/kubelogin/integration_test/oidcserver/service"
	"github.com/int128/kubelogin/integration_test/oidcserver/testconfig"
	mock "github.com/stretchr/testify/mock"
)

// NewMockService creates a new instance of MockService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockService(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockService {
	mock := &MockService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// MockService is an autogenerated mock type for the Service type
type MockService struct {
	mock.Mock
}

type MockService_Expecter struct {
	mock *mock.Mock
}

func (_m *MockService) EXPECT() *MockService_Expecter {
	return &MockService_Expecter{mock: &_m.Mock}
}

// AuthenticateCode provides a mock function for the type MockService
func (_mock *MockService) AuthenticateCode(req service.AuthenticationRequest) (string, error) {
	ret := _mock.Called(req)

	if len(ret) == 0 {
		panic("no return value specified for AuthenticateCode")
	}

	var r0 string
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(service.AuthenticationRequest) (string, error)); ok {
		return returnFunc(req)
	}
	if returnFunc, ok := ret.Get(0).(func(service.AuthenticationRequest) string); ok {
		r0 = returnFunc(req)
	} else {
		r0 = ret.Get(0).(string)
	}
	if returnFunc, ok := ret.Get(1).(func(service.AuthenticationRequest) error); ok {
		r1 = returnFunc(req)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// MockService_AuthenticateCode_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AuthenticateCode'
type MockService_AuthenticateCode_Call struct {
	*mock.Call
}

// AuthenticateCode is a helper method to define mock.On call
//   - req service.AuthenticationRequest
func (_e *MockService_Expecter) AuthenticateCode(req interface{}) *MockService_AuthenticateCode_Call {
	return &MockService_AuthenticateCode_Call{Call: _e.mock.On("AuthenticateCode", req)}
}

func (_c *MockService_AuthenticateCode_Call) Run(run func(req service.AuthenticationRequest)) *MockService_AuthenticateCode_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 service.AuthenticationRequest
		if args[0] != nil {
			arg0 = args[0].(service.AuthenticationRequest)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *MockService_AuthenticateCode_Call) Return(code string, err error) *MockService_AuthenticateCode_Call {
	_c.Call.Return(code, err)
	return _c
}

func (_c *MockService_AuthenticateCode_Call) RunAndReturn(run func(req service.AuthenticationRequest) (string, error)) *MockService_AuthenticateCode_Call {
	_c.Call.Return(run)
	return _c
}

// AuthenticatePassword provides a mock function for the type MockService
func (_mock *MockService) AuthenticatePassword(username string, password string, scope string) (*service.TokenResponse, error) {
	ret := _mock.Called(username, password, scope)

	if len(ret) == 0 {
		panic("no return value specified for AuthenticatePassword")
	}

	var r0 *service.TokenResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, string, string) (*service.TokenResponse, error)); ok {
		return returnFunc(username, password, scope)
	}
	if returnFunc, ok := ret.Get(0).(func(string, string, string) *service.TokenResponse); ok {
		r0 = returnFunc(username, password, scope)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = returnFunc(username, password, scope)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// MockService_AuthenticatePassword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AuthenticatePassword'
type MockService_AuthenticatePassword_Call struct {
	*mock.Call
}

// AuthenticatePassword is a helper method to define mock.On call
//   - username string
//   - password string
//   - scope string
func (_e *MockService_Expecter) AuthenticatePassword(username interface{}, password interface{}, scope interface{}) *MockService_AuthenticatePassword_Call {
	return &MockService_AuthenticatePassword_Call{Call: _e.mock.On("AuthenticatePassword", username, password, scope)}
}

func (_c *MockService_AuthenticatePassword_Call) Run(run func(username string, password string, scope string)) *MockService_AuthenticatePassword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *MockService_AuthenticatePassword_Call) Return(tokenResponse *service.TokenResponse, err error) *MockService_AuthenticatePassword_Call {
	_c.Call.Return(tokenResponse, err)
	return _c
}

func (_c *MockService_AuthenticatePassword_Call) RunAndReturn(run func(username string, password string, scope string) (*service.TokenResponse, error)) *MockService_AuthenticatePassword_Call {
	_c.Call.Return(run)
	return _c
}

// Discovery provides a mock function for the type MockService
func (_mock *MockService) Discovery() *service.DiscoveryResponse {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for Discovery")
	}

	var r0 *service.DiscoveryResponse
	if returnFunc, ok := ret.Get(0).(func() *service.DiscoveryResponse); ok {
		r0 = returnFunc()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.DiscoveryResponse)
		}
	}
	return r0
}

// MockService_Discovery_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Discovery'
type MockService_Discovery_Call struct {
	*mock.Call
}

// Discovery is a helper method to define mock.On call
func (_e *MockService_Expecter) Discovery() *MockService_Discovery_Call {
	return &MockService_Discovery_Call{Call: _e.mock.On("Discovery")}
}

func (_c *MockService_Discovery_Call) Run(run func()) *MockService_Discovery_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockService_Discovery_Call) Return(discoveryResponse *service.DiscoveryResponse) *MockService_Discovery_Call {
	_c.Call.Return(discoveryResponse)
	return _c
}

func (_c *MockService_Discovery_Call) RunAndReturn(run func() *service.DiscoveryResponse) *MockService_Discovery_Call {
	_c.Call.Return(run)
	return _c
}

// Exchange provides a mock function for the type MockService
func (_mock *MockService) Exchange(req service.TokenRequest) (*service.TokenResponse, error) {
	ret := _mock.Called(req)

	if len(ret) == 0 {
		panic("no return value specified for Exchange")
	}

	var r0 *service.TokenResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(service.TokenRequest) (*service.TokenResponse, error)); ok {
		return returnFunc(req)
	}
	if returnFunc, ok := ret.Get(0).(func(service.TokenRequest) *service.TokenResponse); ok {
		r0 = returnFunc(req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(service.TokenRequest) error); ok {
		r1 = returnFunc(req)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// MockService_Exchange_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Exchange'
type MockService_Exchange_Call struct {
	*mock.Call
}

// Exchange is a helper method to define mock.On call
//   - req service.TokenRequest
func (_e *MockService_Expecter) Exchange(req interface{}) *MockService_Exchange_Call {
	return &MockService_Exchange_Call{Call: _e.mock.On("Exchange", req)}
}

func (_c *MockService_Exchange_Call) Run(run func(req service.TokenRequest)) *MockService_Exchange_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 service.TokenRequest
		if args[0] != nil {
			arg0 = args[0].(service.TokenRequest)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *MockService_Exchange_Call) Return(tokenResponse *service.TokenResponse, err error) *MockService_Exchange_Call {
	_c.Call.Return(tokenResponse, err)
	return _c
}

func (_c *MockService_Exchange_Call) RunAndReturn(run func(req service.TokenRequest) (*service.TokenResponse, error)) *MockService_Exchange_Call {
	_c.Call.Return(run)
	return _c
}

// GetCertificates provides a mock function for the type MockService
func (_mock *MockService) GetCertificates() *service.CertificatesResponse {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetCertificates")
	}

	var r0 *service.CertificatesResponse
	if returnFunc, ok := ret.Get(0).(func() *service.CertificatesResponse); ok {
		r0 = returnFunc()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.CertificatesResponse)
		}
	}
	return r0
}

// MockService_GetCertificates_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCertificates'
type MockService_GetCertificates_Call struct {
	*mock.Call
}

// GetCertificates is a helper method to define mock.On call
func (_e *MockService_Expecter) GetCertificates() *MockService_GetCertificates_Call {
	return &MockService_GetCertificates_Call{Call: _e.mock.On("GetCertificates")}
}

func (_c *MockService_GetCertificates_Call) Run(run func()) *MockService_GetCertificates_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockService_GetCertificates_Call) Return(certificatesResponse *service.CertificatesResponse) *MockService_GetCertificates_Call {
	_c.Call.Return(certificatesResponse)
	return _c
}

func (_c *MockService_GetCertificates_Call) RunAndReturn(run func() *service.CertificatesResponse) *MockService_GetCertificates_Call {
	_c.Call.Return(run)
	return _c
}

// IssuerURL provides a mock function for the type MockService
func (_mock *MockService) IssuerURL() string {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for IssuerURL")
	}

	var r0 string
	if returnFunc, ok := ret.Get(0).(func() string); ok {
		r0 = returnFunc()
	} else {
		r0 = ret.Get(0).(string)
	}
	return r0
}

// MockService_IssuerURL_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IssuerURL'
type MockService_IssuerURL_Call struct {
	*mock.Call
}

// IssuerURL is a helper method to define mock.On call
func (_e *MockService_Expecter) IssuerURL() *MockService_IssuerURL_Call {
	return &MockService_IssuerURL_Call{Call: _e.mock.On("IssuerURL")}
}

func (_c *MockService_IssuerURL_Call) Run(run func()) *MockService_IssuerURL_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockService_IssuerURL_Call) Return(s string) *MockService_IssuerURL_Call {
	_c.Call.Return(s)
	return _c
}

func (_c *MockService_IssuerURL_Call) RunAndReturn(run func() string) *MockService_IssuerURL_Call {
	_c.Call.Return(run)
	return _c
}

// LastTokenResponse provides a mock function for the type MockService
func (_mock *MockService) LastTokenResponse() *service.TokenResponse {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for LastTokenResponse")
	}

	var r0 *service.TokenResponse
	if returnFunc, ok := ret.Get(0).(func() *service.TokenResponse); ok {
		r0 = returnFunc()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}
	return r0
}

// MockService_LastTokenResponse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LastTokenResponse'
type MockService_LastTokenResponse_Call struct {
	*mock.Call
}

// LastTokenResponse is a helper method to define mock.On call
func (_e *MockService_Expecter) LastTokenResponse() *MockService_LastTokenResponse_Call {
	return &MockService_LastTokenResponse_Call{Call: _e.mock.On("LastTokenResponse")}
}

func (_c *MockService_LastTokenResponse_Call) Run(run func()) *MockService_LastTokenResponse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockService_LastTokenResponse_Call) Return(tokenResponse *service.TokenResponse) *MockService_LastTokenResponse_Call {
	_c.Call.Return(tokenResponse)
	return _c
}

func (_c *MockService_LastTokenResponse_Call) RunAndReturn(run func() *service.TokenResponse) *MockService_LastTokenResponse_Call {
	_c.Call.Return(run)
	return _c
}

// Refresh provides a mock function for the type MockService
func (_mock *MockService) Refresh(refreshToken string) (*service.TokenResponse, error) {
	ret := _mock.Called(refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for Refresh")
	}

	var r0 *service.TokenResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string) (*service.TokenResponse, error)); ok {
		return returnFunc(refreshToken)
	}
	if returnFunc, ok := ret.Get(0).(func(string) *service.TokenResponse); ok {
		r0 = returnFunc(refreshToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string) error); ok {
		r1 = returnFunc(refreshToken)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// MockService_Refresh_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Refresh'
type MockService_Refresh_Call struct {
	*mock.Call
}

// Refresh is a helper method to define mock.On call
//   - refreshToken string
func (_e *MockService_Expecter) Refresh(refreshToken interface{}) *MockService_Refresh_Call {
	return &MockService_Refresh_Call{Call: _e.mock.On("Refresh", refreshToken)}
}

func (_c *MockService_Refresh_Call) Run(run func(refreshToken string)) *MockService_Refresh_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *MockService_Refresh_Call) Return(tokenResponse *service.TokenResponse, err error) *MockService_Refresh_Call {
	_c.Call.Return(tokenResponse, err)
	return _c
}

func (_c *MockService_Refresh_Call) RunAndReturn(run func(refreshToken string) (*service.TokenResponse, error)) *MockService_Refresh_Call {
	_c.Call.Return(run)
	return _c
}

// SetConfig provides a mock function for the type MockService
func (_mock *MockService) SetConfig(config testconfig.Config) {
	_mock.Called(config)
	return
}

// MockService_SetConfig_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetConfig'
type MockService_SetConfig_Call struct {
	*mock.Call
}

// SetConfig is a helper method to define mock.On call
//   - config testconfig.Config
func (_e *MockService_Expecter) SetConfig(config interface{}) *MockService_SetConfig_Call {
	return &MockService_SetConfig_Call{Call: _e.mock.On("SetConfig", config)}
}

func (_c *MockService_SetConfig_Call) Run(run func(config testconfig.Config)) *MockService_SetConfig_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 testconfig.Config
		if args[0] != nil {
			arg0 = args[0].(testconfig.Config)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *MockService_SetConfig_Call) Return() *MockService_SetConfig_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockService_SetConfig_Call) RunAndReturn(run func(config testconfig.Config)) *MockService_SetConfig_Call {
	_c.Run(run)
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

// AuthenticateCode provides a mock function for the type MockProvider
func (_mock *MockProvider) AuthenticateCode(req service.AuthenticationRequest) (string, error) {
	ret := _mock.Called(req)

	if len(ret) == 0 {
		panic("no return value specified for AuthenticateCode")
	}

	var r0 string
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(service.AuthenticationRequest) (string, error)); ok {
		return returnFunc(req)
	}
	if returnFunc, ok := ret.Get(0).(func(service.AuthenticationRequest) string); ok {
		r0 = returnFunc(req)
	} else {
		r0 = ret.Get(0).(string)
	}
	if returnFunc, ok := ret.Get(1).(func(service.AuthenticationRequest) error); ok {
		r1 = returnFunc(req)
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
		var arg0 service.AuthenticationRequest
		if args[0] != nil {
			arg0 = args[0].(service.AuthenticationRequest)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *MockProvider_AuthenticateCode_Call) Return(code string, err error) *MockProvider_AuthenticateCode_Call {
	_c.Call.Return(code, err)
	return _c
}

func (_c *MockProvider_AuthenticateCode_Call) RunAndReturn(run func(req service.AuthenticationRequest) (string, error)) *MockProvider_AuthenticateCode_Call {
	_c.Call.Return(run)
	return _c
}

// AuthenticatePassword provides a mock function for the type MockProvider
func (_mock *MockProvider) AuthenticatePassword(username string, password string, scope string) (*service.TokenResponse, error) {
	ret := _mock.Called(username, password, scope)

	if len(ret) == 0 {
		panic("no return value specified for AuthenticatePassword")
	}

	var r0 *service.TokenResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, string, string) (*service.TokenResponse, error)); ok {
		return returnFunc(username, password, scope)
	}
	if returnFunc, ok := ret.Get(0).(func(string, string, string) *service.TokenResponse); ok {
		r0 = returnFunc(username, password, scope)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = returnFunc(username, password, scope)
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
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *MockProvider_AuthenticatePassword_Call) Return(tokenResponse *service.TokenResponse, err error) *MockProvider_AuthenticatePassword_Call {
	_c.Call.Return(tokenResponse, err)
	return _c
}

func (_c *MockProvider_AuthenticatePassword_Call) RunAndReturn(run func(username string, password string, scope string) (*service.TokenResponse, error)) *MockProvider_AuthenticatePassword_Call {
	_c.Call.Return(run)
	return _c
}

// Discovery provides a mock function for the type MockProvider
func (_mock *MockProvider) Discovery() *service.DiscoveryResponse {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for Discovery")
	}

	var r0 *service.DiscoveryResponse
	if returnFunc, ok := ret.Get(0).(func() *service.DiscoveryResponse); ok {
		r0 = returnFunc()
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

func (_c *MockProvider_Discovery_Call) Return(discoveryResponse *service.DiscoveryResponse) *MockProvider_Discovery_Call {
	_c.Call.Return(discoveryResponse)
	return _c
}

func (_c *MockProvider_Discovery_Call) RunAndReturn(run func() *service.DiscoveryResponse) *MockProvider_Discovery_Call {
	_c.Call.Return(run)
	return _c
}

// Exchange provides a mock function for the type MockProvider
func (_mock *MockProvider) Exchange(req service.TokenRequest) (*service.TokenResponse, error) {
	ret := _mock.Called(req)

	if len(ret) == 0 {
		panic("no return value specified for Exchange")
	}

	var r0 *service.TokenResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(service.TokenRequest) (*service.TokenResponse, error)); ok {
		return returnFunc(req)
	}
	if returnFunc, ok := ret.Get(0).(func(service.TokenRequest) *service.TokenResponse); ok {
		r0 = returnFunc(req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(service.TokenRequest) error); ok {
		r1 = returnFunc(req)
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
		var arg0 service.TokenRequest
		if args[0] != nil {
			arg0 = args[0].(service.TokenRequest)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *MockProvider_Exchange_Call) Return(tokenResponse *service.TokenResponse, err error) *MockProvider_Exchange_Call {
	_c.Call.Return(tokenResponse, err)
	return _c
}

func (_c *MockProvider_Exchange_Call) RunAndReturn(run func(req service.TokenRequest) (*service.TokenResponse, error)) *MockProvider_Exchange_Call {
	_c.Call.Return(run)
	return _c
}

// GetCertificates provides a mock function for the type MockProvider
func (_mock *MockProvider) GetCertificates() *service.CertificatesResponse {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetCertificates")
	}

	var r0 *service.CertificatesResponse
	if returnFunc, ok := ret.Get(0).(func() *service.CertificatesResponse); ok {
		r0 = returnFunc()
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

func (_c *MockProvider_GetCertificates_Call) Return(certificatesResponse *service.CertificatesResponse) *MockProvider_GetCertificates_Call {
	_c.Call.Return(certificatesResponse)
	return _c
}

func (_c *MockProvider_GetCertificates_Call) RunAndReturn(run func() *service.CertificatesResponse) *MockProvider_GetCertificates_Call {
	_c.Call.Return(run)
	return _c
}

// Refresh provides a mock function for the type MockProvider
func (_mock *MockProvider) Refresh(refreshToken string) (*service.TokenResponse, error) {
	ret := _mock.Called(refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for Refresh")
	}

	var r0 *service.TokenResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string) (*service.TokenResponse, error)); ok {
		return returnFunc(refreshToken)
	}
	if returnFunc, ok := ret.Get(0).(func(string) *service.TokenResponse); ok {
		r0 = returnFunc(refreshToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*service.TokenResponse)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string) error); ok {
		r1 = returnFunc(refreshToken)
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
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *MockProvider_Refresh_Call) Return(tokenResponse *service.TokenResponse, err error) *MockProvider_Refresh_Call {
	_c.Call.Return(tokenResponse, err)
	return _c
}

func (_c *MockProvider_Refresh_Call) RunAndReturn(run func(refreshToken string) (*service.TokenResponse, error)) *MockProvider_Refresh_Call {
	_c.Call.Return(run)
	return _c
}

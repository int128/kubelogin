// Code generated by mockery v2.53.3. DO NOT EDIT.

package loader_mock

import (
	kubeconfig "github.com/int128/kubelogin/pkg/kubeconfig"

	mock "github.com/stretchr/testify/mock"
)

// MockInterface is an autogenerated mock type for the Interface type
type MockInterface struct {
	mock.Mock
}

type MockInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockInterface) EXPECT() *MockInterface_Expecter {
	return &MockInterface_Expecter{mock: &_m.Mock}
}

// GetCurrentAuthProvider provides a mock function with given fields: explicitFilename, contextName, userName
func (_m *MockInterface) GetCurrentAuthProvider(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error) {
	ret := _m.Called(explicitFilename, contextName, userName)

	if len(ret) == 0 {
		panic("no return value specified for GetCurrentAuthProvider")
	}

	var r0 *kubeconfig.AuthProvider
	var r1 error
	if rf, ok := ret.Get(0).(func(string, kubeconfig.ContextName, kubeconfig.UserName) (*kubeconfig.AuthProvider, error)); ok {
		return rf(explicitFilename, contextName, userName)
	}
	if rf, ok := ret.Get(0).(func(string, kubeconfig.ContextName, kubeconfig.UserName) *kubeconfig.AuthProvider); ok {
		r0 = rf(explicitFilename, contextName, userName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*kubeconfig.AuthProvider)
		}
	}

	if rf, ok := ret.Get(1).(func(string, kubeconfig.ContextName, kubeconfig.UserName) error); ok {
		r1 = rf(explicitFilename, contextName, userName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockInterface_GetCurrentAuthProvider_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCurrentAuthProvider'
type MockInterface_GetCurrentAuthProvider_Call struct {
	*mock.Call
}

// GetCurrentAuthProvider is a helper method to define mock.On call
//   - explicitFilename string
//   - contextName kubeconfig.ContextName
//   - userName kubeconfig.UserName
func (_e *MockInterface_Expecter) GetCurrentAuthProvider(explicitFilename interface{}, contextName interface{}, userName interface{}) *MockInterface_GetCurrentAuthProvider_Call {
	return &MockInterface_GetCurrentAuthProvider_Call{Call: _e.mock.On("GetCurrentAuthProvider", explicitFilename, contextName, userName)}
}

func (_c *MockInterface_GetCurrentAuthProvider_Call) Run(run func(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName)) *MockInterface_GetCurrentAuthProvider_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(kubeconfig.ContextName), args[2].(kubeconfig.UserName))
	})
	return _c
}

func (_c *MockInterface_GetCurrentAuthProvider_Call) Return(_a0 *kubeconfig.AuthProvider, _a1 error) *MockInterface_GetCurrentAuthProvider_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockInterface_GetCurrentAuthProvider_Call) RunAndReturn(run func(string, kubeconfig.ContextName, kubeconfig.UserName) (*kubeconfig.AuthProvider, error)) *MockInterface_GetCurrentAuthProvider_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockInterface creates a new instance of MockInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockInterface {
	mock := &MockInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

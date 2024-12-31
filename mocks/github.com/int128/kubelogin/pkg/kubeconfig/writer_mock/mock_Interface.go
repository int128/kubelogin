// Code generated by mockery v2.50.2. DO NOT EDIT.

package writer_mock

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

// UpdateAuthProvider provides a mock function with given fields: p
func (_m *MockInterface) UpdateAuthProvider(p kubeconfig.AuthProvider) error {
	ret := _m.Called(p)

	if len(ret) == 0 {
		panic("no return value specified for UpdateAuthProvider")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(kubeconfig.AuthProvider) error); ok {
		r0 = rf(p)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockInterface_UpdateAuthProvider_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateAuthProvider'
type MockInterface_UpdateAuthProvider_Call struct {
	*mock.Call
}

// UpdateAuthProvider is a helper method to define mock.On call
//   - p kubeconfig.AuthProvider
func (_e *MockInterface_Expecter) UpdateAuthProvider(p interface{}) *MockInterface_UpdateAuthProvider_Call {
	return &MockInterface_UpdateAuthProvider_Call{Call: _e.mock.On("UpdateAuthProvider", p)}
}

func (_c *MockInterface_UpdateAuthProvider_Call) Run(run func(p kubeconfig.AuthProvider)) *MockInterface_UpdateAuthProvider_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(kubeconfig.AuthProvider))
	})
	return _c
}

func (_c *MockInterface_UpdateAuthProvider_Call) Return(_a0 error) *MockInterface_UpdateAuthProvider_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_UpdateAuthProvider_Call) RunAndReturn(run func(kubeconfig.AuthProvider) error) *MockInterface_UpdateAuthProvider_Call {
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

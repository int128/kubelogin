// Code generated by mockery v2.53.3. DO NOT EDIT.

package client_mock

import (
	context "context"

	client "github.com/int128/kubelogin/pkg/oidc/client"

	mock "github.com/stretchr/testify/mock"

	oidc "github.com/int128/kubelogin/pkg/oidc"

	tlsclientconfig "github.com/int128/kubelogin/pkg/tlsclientconfig"
)

// MockFactoryInterface is an autogenerated mock type for the FactoryInterface type
type MockFactoryInterface struct {
	mock.Mock
}

type MockFactoryInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockFactoryInterface) EXPECT() *MockFactoryInterface_Expecter {
	return &MockFactoryInterface_Expecter{mock: &_m.Mock}
}

// New provides a mock function with given fields: ctx, prov, tlsClientConfig
func (_m *MockFactoryInterface) New(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config) (client.Interface, error) {
	ret := _m.Called(ctx, prov, tlsClientConfig)

	if len(ret) == 0 {
		panic("no return value specified for New")
	}

	var r0 client.Interface
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, oidc.Provider, tlsclientconfig.Config) (client.Interface, error)); ok {
		return rf(ctx, prov, tlsClientConfig)
	}
	if rf, ok := ret.Get(0).(func(context.Context, oidc.Provider, tlsclientconfig.Config) client.Interface); ok {
		r0 = rf(ctx, prov, tlsClientConfig)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.Interface)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, oidc.Provider, tlsclientconfig.Config) error); ok {
		r1 = rf(ctx, prov, tlsClientConfig)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockFactoryInterface_New_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'New'
type MockFactoryInterface_New_Call struct {
	*mock.Call
}

// New is a helper method to define mock.On call
//   - ctx context.Context
//   - prov oidc.Provider
//   - tlsClientConfig tlsclientconfig.Config
func (_e *MockFactoryInterface_Expecter) New(ctx interface{}, prov interface{}, tlsClientConfig interface{}) *MockFactoryInterface_New_Call {
	return &MockFactoryInterface_New_Call{Call: _e.mock.On("New", ctx, prov, tlsClientConfig)}
}

func (_c *MockFactoryInterface_New_Call) Run(run func(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config)) *MockFactoryInterface_New_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(oidc.Provider), args[2].(tlsclientconfig.Config))
	})
	return _c
}

func (_c *MockFactoryInterface_New_Call) Return(_a0 client.Interface, _a1 error) *MockFactoryInterface_New_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockFactoryInterface_New_Call) RunAndReturn(run func(context.Context, oidc.Provider, tlsclientconfig.Config) (client.Interface, error)) *MockFactoryInterface_New_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockFactoryInterface creates a new instance of MockFactoryInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockFactoryInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockFactoryInterface {
	mock := &MockFactoryInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

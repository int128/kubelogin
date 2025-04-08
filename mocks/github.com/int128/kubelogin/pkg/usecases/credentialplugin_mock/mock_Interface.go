// Code generated by mockery v2.53.3. DO NOT EDIT.

package credentialplugin_mock

import (
	context "context"

	credentialplugin "github.com/int128/kubelogin/pkg/usecases/credentialplugin"
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

// Do provides a mock function with given fields: ctx, in
func (_m *MockInterface) Do(ctx context.Context, in credentialplugin.Input) error {
	ret := _m.Called(ctx, in)

	if len(ret) == 0 {
		panic("no return value specified for Do")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, credentialplugin.Input) error); ok {
		r0 = rf(ctx, in)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockInterface_Do_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Do'
type MockInterface_Do_Call struct {
	*mock.Call
}

// Do is a helper method to define mock.On call
//   - ctx context.Context
//   - in credentialplugin.Input
func (_e *MockInterface_Expecter) Do(ctx interface{}, in interface{}) *MockInterface_Do_Call {
	return &MockInterface_Do_Call{Call: _e.mock.On("Do", ctx, in)}
}

func (_c *MockInterface_Do_Call) Run(run func(ctx context.Context, in credentialplugin.Input)) *MockInterface_Do_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(credentialplugin.Input))
	})
	return _c
}

func (_c *MockInterface_Do_Call) Return(_a0 error) *MockInterface_Do_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_Do_Call) RunAndReturn(run func(context.Context, credentialplugin.Input) error) *MockInterface_Do_Call {
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

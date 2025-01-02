// Code generated by mockery v2.50.3. DO NOT EDIT.

package browser_mock

import (
	context "context"

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

// Open provides a mock function with given fields: url
func (_m *MockInterface) Open(url string) error {
	ret := _m.Called(url)

	if len(ret) == 0 {
		panic("no return value specified for Open")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(url)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockInterface_Open_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Open'
type MockInterface_Open_Call struct {
	*mock.Call
}

// Open is a helper method to define mock.On call
//   - url string
func (_e *MockInterface_Expecter) Open(url interface{}) *MockInterface_Open_Call {
	return &MockInterface_Open_Call{Call: _e.mock.On("Open", url)}
}

func (_c *MockInterface_Open_Call) Run(run func(url string)) *MockInterface_Open_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockInterface_Open_Call) Return(_a0 error) *MockInterface_Open_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_Open_Call) RunAndReturn(run func(string) error) *MockInterface_Open_Call {
	_c.Call.Return(run)
	return _c
}

// OpenCommand provides a mock function with given fields: ctx, url, command
func (_m *MockInterface) OpenCommand(ctx context.Context, url string, command string) error {
	ret := _m.Called(ctx, url, command)

	if len(ret) == 0 {
		panic("no return value specified for OpenCommand")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, url, command)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockInterface_OpenCommand_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'OpenCommand'
type MockInterface_OpenCommand_Call struct {
	*mock.Call
}

// OpenCommand is a helper method to define mock.On call
//   - ctx context.Context
//   - url string
//   - command string
func (_e *MockInterface_Expecter) OpenCommand(ctx interface{}, url interface{}, command interface{}) *MockInterface_OpenCommand_Call {
	return &MockInterface_OpenCommand_Call{Call: _e.mock.On("OpenCommand", ctx, url, command)}
}

func (_c *MockInterface_OpenCommand_Call) Run(run func(ctx context.Context, url string, command string)) *MockInterface_OpenCommand_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockInterface_OpenCommand_Call) Return(_a0 error) *MockInterface_OpenCommand_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_OpenCommand_Call) RunAndReturn(run func(context.Context, string, string) error) *MockInterface_OpenCommand_Call {
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

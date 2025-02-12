// Code generated by mockery v2.52.2. DO NOT EDIT.

package reader_mock

import (
	credentialplugin "github.com/int128/kubelogin/pkg/credentialplugin"
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

// Read provides a mock function with no fields
func (_m *MockInterface) Read() (credentialplugin.Input, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 credentialplugin.Input
	var r1 error
	if rf, ok := ret.Get(0).(func() (credentialplugin.Input, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() credentialplugin.Input); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(credentialplugin.Input)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockInterface_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type MockInterface_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
func (_e *MockInterface_Expecter) Read() *MockInterface_Read_Call {
	return &MockInterface_Read_Call{Call: _e.mock.On("Read")}
}

func (_c *MockInterface_Read_Call) Run(run func()) *MockInterface_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockInterface_Read_Call) Return(_a0 credentialplugin.Input, _a1 error) *MockInterface_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockInterface_Read_Call) RunAndReturn(run func() (credentialplugin.Input, error)) *MockInterface_Read_Call {
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

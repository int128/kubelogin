// Code generated by mockery v2.44.1. DO NOT EDIT.

package jwt_mock

import (
	time "time"

	mock "github.com/stretchr/testify/mock"
)

// MockClock is an autogenerated mock type for the Clock type
type MockClock struct {
	mock.Mock
}

type MockClock_Expecter struct {
	mock *mock.Mock
}

func (_m *MockClock) EXPECT() *MockClock_Expecter {
	return &MockClock_Expecter{mock: &_m.Mock}
}

// Now provides a mock function with given fields:
func (_m *MockClock) Now() time.Time {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Now")
	}

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// MockClock_Now_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Now'
type MockClock_Now_Call struct {
	*mock.Call
}

// Now is a helper method to define mock.On call
func (_e *MockClock_Expecter) Now() *MockClock_Now_Call {
	return &MockClock_Now_Call{Call: _e.mock.On("Now")}
}

func (_c *MockClock_Now_Call) Run(run func()) *MockClock_Now_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockClock_Now_Call) Return(_a0 time.Time) *MockClock_Now_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClock_Now_Call) RunAndReturn(run func() time.Time) *MockClock_Now_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockClock creates a new instance of MockClock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockClock(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockClock {
	mock := &MockClock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

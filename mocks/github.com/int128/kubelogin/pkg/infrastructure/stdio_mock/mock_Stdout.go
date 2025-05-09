// Code generated by mockery v2.53.3. DO NOT EDIT.

package stdio_mock

import mock "github.com/stretchr/testify/mock"

// MockStdout is an autogenerated mock type for the Stdout type
type MockStdout struct {
	mock.Mock
}

type MockStdout_Expecter struct {
	mock *mock.Mock
}

func (_m *MockStdout) EXPECT() *MockStdout_Expecter {
	return &MockStdout_Expecter{mock: &_m.Mock}
}

// Write provides a mock function with given fields: p
func (_m *MockStdout) Write(p []byte) (int, error) {
	ret := _m.Called(p)

	if len(ret) == 0 {
		panic("no return value specified for Write")
	}

	var r0 int
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) (int, error)); ok {
		return rf(p)
	}
	if rf, ok := ret.Get(0).(func([]byte) int); ok {
		r0 = rf(p)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(p)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStdout_Write_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Write'
type MockStdout_Write_Call struct {
	*mock.Call
}

// Write is a helper method to define mock.On call
//   - p []byte
func (_e *MockStdout_Expecter) Write(p interface{}) *MockStdout_Write_Call {
	return &MockStdout_Write_Call{Call: _e.mock.On("Write", p)}
}

func (_c *MockStdout_Write_Call) Run(run func(p []byte)) *MockStdout_Write_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockStdout_Write_Call) Return(n int, err error) *MockStdout_Write_Call {
	_c.Call.Return(n, err)
	return _c
}

func (_c *MockStdout_Write_Call) RunAndReturn(run func([]byte) (int, error)) *MockStdout_Write_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockStdout creates a new instance of MockStdout. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockStdout(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockStdout {
	mock := &MockStdout{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

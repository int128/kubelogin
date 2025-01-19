// Code generated by mockery v2.51.0. DO NOT EDIT.

package logger_mock

import mock "github.com/stretchr/testify/mock"

// MockgoLogger is an autogenerated mock type for the goLogger type
type MockgoLogger struct {
	mock.Mock
}

type MockgoLogger_Expecter struct {
	mock *mock.Mock
}

func (_m *MockgoLogger) EXPECT() *MockgoLogger_Expecter {
	return &MockgoLogger_Expecter{mock: &_m.Mock}
}

// Printf provides a mock function with given fields: format, v
func (_m *MockgoLogger) Printf(format string, v ...interface{}) {
	var _ca []interface{}
	_ca = append(_ca, format)
	_ca = append(_ca, v...)
	_m.Called(_ca...)
}

// MockgoLogger_Printf_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Printf'
type MockgoLogger_Printf_Call struct {
	*mock.Call
}

// Printf is a helper method to define mock.On call
//   - format string
//   - v ...interface{}
func (_e *MockgoLogger_Expecter) Printf(format interface{}, v ...interface{}) *MockgoLogger_Printf_Call {
	return &MockgoLogger_Printf_Call{Call: _e.mock.On("Printf",
		append([]interface{}{format}, v...)...)}
}

func (_c *MockgoLogger_Printf_Call) Run(run func(format string, v ...interface{})) *MockgoLogger_Printf_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(args[0].(string), variadicArgs...)
	})
	return _c
}

func (_c *MockgoLogger_Printf_Call) Return() *MockgoLogger_Printf_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockgoLogger_Printf_Call) RunAndReturn(run func(string, ...interface{})) *MockgoLogger_Printf_Call {
	_c.Run(run)
	return _c
}

// NewMockgoLogger creates a new instance of MockgoLogger. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockgoLogger(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockgoLogger {
	mock := &MockgoLogger{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// Code generated by mockery v2.46.3. DO NOT EDIT.

package logger_mock

import (
	logger "github.com/int128/kubelogin/pkg/infrastructure/logger"
	mock "github.com/stretchr/testify/mock"

	pflag "github.com/spf13/pflag"
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

// AddFlags provides a mock function with given fields: f
func (_m *MockInterface) AddFlags(f *pflag.FlagSet) {
	_m.Called(f)
}

// MockInterface_AddFlags_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddFlags'
type MockInterface_AddFlags_Call struct {
	*mock.Call
}

// AddFlags is a helper method to define mock.On call
//   - f *pflag.FlagSet
func (_e *MockInterface_Expecter) AddFlags(f interface{}) *MockInterface_AddFlags_Call {
	return &MockInterface_AddFlags_Call{Call: _e.mock.On("AddFlags", f)}
}

func (_c *MockInterface_AddFlags_Call) Run(run func(f *pflag.FlagSet)) *MockInterface_AddFlags_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*pflag.FlagSet))
	})
	return _c
}

func (_c *MockInterface_AddFlags_Call) Return() *MockInterface_AddFlags_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockInterface_AddFlags_Call) RunAndReturn(run func(*pflag.FlagSet)) *MockInterface_AddFlags_Call {
	_c.Call.Return(run)
	return _c
}

// IsEnabled provides a mock function with given fields: level
func (_m *MockInterface) IsEnabled(level int) bool {
	ret := _m.Called(level)

	if len(ret) == 0 {
		panic("no return value specified for IsEnabled")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(int) bool); ok {
		r0 = rf(level)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MockInterface_IsEnabled_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsEnabled'
type MockInterface_IsEnabled_Call struct {
	*mock.Call
}

// IsEnabled is a helper method to define mock.On call
//   - level int
func (_e *MockInterface_Expecter) IsEnabled(level interface{}) *MockInterface_IsEnabled_Call {
	return &MockInterface_IsEnabled_Call{Call: _e.mock.On("IsEnabled", level)}
}

func (_c *MockInterface_IsEnabled_Call) Run(run func(level int)) *MockInterface_IsEnabled_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *MockInterface_IsEnabled_Call) Return(_a0 bool) *MockInterface_IsEnabled_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_IsEnabled_Call) RunAndReturn(run func(int) bool) *MockInterface_IsEnabled_Call {
	_c.Call.Return(run)
	return _c
}

// Printf provides a mock function with given fields: format, args
func (_m *MockInterface) Printf(format string, args ...interface{}) {
	var _ca []interface{}
	_ca = append(_ca, format)
	_ca = append(_ca, args...)
	_m.Called(_ca...)
}

// MockInterface_Printf_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Printf'
type MockInterface_Printf_Call struct {
	*mock.Call
}

// Printf is a helper method to define mock.On call
//   - format string
//   - args ...interface{}
func (_e *MockInterface_Expecter) Printf(format interface{}, args ...interface{}) *MockInterface_Printf_Call {
	return &MockInterface_Printf_Call{Call: _e.mock.On("Printf",
		append([]interface{}{format}, args...)...)}
}

func (_c *MockInterface_Printf_Call) Run(run func(format string, args ...interface{})) *MockInterface_Printf_Call {
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

func (_c *MockInterface_Printf_Call) Return() *MockInterface_Printf_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockInterface_Printf_Call) RunAndReturn(run func(string, ...interface{})) *MockInterface_Printf_Call {
	_c.Call.Return(run)
	return _c
}

// V provides a mock function with given fields: level
func (_m *MockInterface) V(level int) logger.Verbose {
	ret := _m.Called(level)

	if len(ret) == 0 {
		panic("no return value specified for V")
	}

	var r0 logger.Verbose
	if rf, ok := ret.Get(0).(func(int) logger.Verbose); ok {
		r0 = rf(level)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(logger.Verbose)
		}
	}

	return r0
}

// MockInterface_V_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'V'
type MockInterface_V_Call struct {
	*mock.Call
}

// V is a helper method to define mock.On call
//   - level int
func (_e *MockInterface_Expecter) V(level interface{}) *MockInterface_V_Call {
	return &MockInterface_V_Call{Call: _e.mock.On("V", level)}
}

func (_c *MockInterface_V_Call) Run(run func(level int)) *MockInterface_V_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *MockInterface_V_Call) Return(_a0 logger.Verbose) *MockInterface_V_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_V_Call) RunAndReturn(run func(int) logger.Verbose) *MockInterface_V_Call {
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

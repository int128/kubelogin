// Code generated by mockery v2.46.3. DO NOT EDIT.

package logger_mock

import mock "github.com/stretchr/testify/mock"

// MockVerbose is an autogenerated mock type for the Verbose type
type MockVerbose struct {
	mock.Mock
}

type MockVerbose_Expecter struct {
	mock *mock.Mock
}

func (_m *MockVerbose) EXPECT() *MockVerbose_Expecter {
	return &MockVerbose_Expecter{mock: &_m.Mock}
}

// Infof provides a mock function with given fields: format, args
func (_m *MockVerbose) Infof(format string, args ...interface{}) {
	var _ca []interface{}
	_ca = append(_ca, format)
	_ca = append(_ca, args...)
	_m.Called(_ca...)
}

// MockVerbose_Infof_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Infof'
type MockVerbose_Infof_Call struct {
	*mock.Call
}

// Infof is a helper method to define mock.On call
//   - format string
//   - args ...interface{}
func (_e *MockVerbose_Expecter) Infof(format interface{}, args ...interface{}) *MockVerbose_Infof_Call {
	return &MockVerbose_Infof_Call{Call: _e.mock.On("Infof",
		append([]interface{}{format}, args...)...)}
}

func (_c *MockVerbose_Infof_Call) Run(run func(format string, args ...interface{})) *MockVerbose_Infof_Call {
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

func (_c *MockVerbose_Infof_Call) Return() *MockVerbose_Infof_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockVerbose_Infof_Call) RunAndReturn(run func(string, ...interface{})) *MockVerbose_Infof_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockVerbose creates a new instance of MockVerbose. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockVerbose(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockVerbose {
	mock := &MockVerbose{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// Code generated by mockery v2.44.1. DO NOT EDIT.

package setup_mock

import (
	context "context"

	setup "github.com/int128/kubelogin/pkg/usecases/setup"
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

// DoStage1 provides a mock function with given fields:
func (_m *MockInterface) DoStage1() {
	_m.Called()
}

// MockInterface_DoStage1_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DoStage1'
type MockInterface_DoStage1_Call struct {
	*mock.Call
}

// DoStage1 is a helper method to define mock.On call
func (_e *MockInterface_Expecter) DoStage1() *MockInterface_DoStage1_Call {
	return &MockInterface_DoStage1_Call{Call: _e.mock.On("DoStage1")}
}

func (_c *MockInterface_DoStage1_Call) Run(run func()) *MockInterface_DoStage1_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockInterface_DoStage1_Call) Return() *MockInterface_DoStage1_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockInterface_DoStage1_Call) RunAndReturn(run func()) *MockInterface_DoStage1_Call {
	_c.Call.Return(run)
	return _c
}

// DoStage2 provides a mock function with given fields: ctx, in
func (_m *MockInterface) DoStage2(ctx context.Context, in setup.Stage2Input) error {
	ret := _m.Called(ctx, in)

	if len(ret) == 0 {
		panic("no return value specified for DoStage2")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, setup.Stage2Input) error); ok {
		r0 = rf(ctx, in)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockInterface_DoStage2_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DoStage2'
type MockInterface_DoStage2_Call struct {
	*mock.Call
}

// DoStage2 is a helper method to define mock.On call
//   - ctx context.Context
//   - in setup.Stage2Input
func (_e *MockInterface_Expecter) DoStage2(ctx interface{}, in interface{}) *MockInterface_DoStage2_Call {
	return &MockInterface_DoStage2_Call{Call: _e.mock.On("DoStage2", ctx, in)}
}

func (_c *MockInterface_DoStage2_Call) Run(run func(ctx context.Context, in setup.Stage2Input)) *MockInterface_DoStage2_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(setup.Stage2Input))
	})
	return _c
}

func (_c *MockInterface_DoStage2_Call) Return(_a0 error) *MockInterface_DoStage2_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_DoStage2_Call) RunAndReturn(run func(context.Context, setup.Stage2Input) error) *MockInterface_DoStage2_Call {
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

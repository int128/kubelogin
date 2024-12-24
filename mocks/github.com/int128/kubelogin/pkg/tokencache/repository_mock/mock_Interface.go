// Code generated by mockery v2.50.1. DO NOT EDIT.

package repository_mock

import (
	io "io"

	oidc "github.com/int128/kubelogin/pkg/oidc"
	mock "github.com/stretchr/testify/mock"

	tokencache "github.com/int128/kubelogin/pkg/tokencache"
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

// FindByKey provides a mock function with given fields: dir, key
func (_m *MockInterface) FindByKey(dir string, key tokencache.Key) (*oidc.TokenSet, error) {
	ret := _m.Called(dir, key)

	if len(ret) == 0 {
		panic("no return value specified for FindByKey")
	}

	var r0 *oidc.TokenSet
	var r1 error
	if rf, ok := ret.Get(0).(func(string, tokencache.Key) (*oidc.TokenSet, error)); ok {
		return rf(dir, key)
	}
	if rf, ok := ret.Get(0).(func(string, tokencache.Key) *oidc.TokenSet); ok {
		r0 = rf(dir, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oidc.TokenSet)
		}
	}

	if rf, ok := ret.Get(1).(func(string, tokencache.Key) error); ok {
		r1 = rf(dir, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockInterface_FindByKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByKey'
type MockInterface_FindByKey_Call struct {
	*mock.Call
}

// FindByKey is a helper method to define mock.On call
//   - dir string
//   - key tokencache.Key
func (_e *MockInterface_Expecter) FindByKey(dir interface{}, key interface{}) *MockInterface_FindByKey_Call {
	return &MockInterface_FindByKey_Call{Call: _e.mock.On("FindByKey", dir, key)}
}

func (_c *MockInterface_FindByKey_Call) Run(run func(dir string, key tokencache.Key)) *MockInterface_FindByKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(tokencache.Key))
	})
	return _c
}

func (_c *MockInterface_FindByKey_Call) Return(_a0 *oidc.TokenSet, _a1 error) *MockInterface_FindByKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockInterface_FindByKey_Call) RunAndReturn(run func(string, tokencache.Key) (*oidc.TokenSet, error)) *MockInterface_FindByKey_Call {
	_c.Call.Return(run)
	return _c
}

// Lock provides a mock function with given fields: dir, key
func (_m *MockInterface) Lock(dir string, key tokencache.Key) (io.Closer, error) {
	ret := _m.Called(dir, key)

	if len(ret) == 0 {
		panic("no return value specified for Lock")
	}

	var r0 io.Closer
	var r1 error
	if rf, ok := ret.Get(0).(func(string, tokencache.Key) (io.Closer, error)); ok {
		return rf(dir, key)
	}
	if rf, ok := ret.Get(0).(func(string, tokencache.Key) io.Closer); ok {
		r0 = rf(dir, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.Closer)
		}
	}

	if rf, ok := ret.Get(1).(func(string, tokencache.Key) error); ok {
		r1 = rf(dir, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockInterface_Lock_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Lock'
type MockInterface_Lock_Call struct {
	*mock.Call
}

// Lock is a helper method to define mock.On call
//   - dir string
//   - key tokencache.Key
func (_e *MockInterface_Expecter) Lock(dir interface{}, key interface{}) *MockInterface_Lock_Call {
	return &MockInterface_Lock_Call{Call: _e.mock.On("Lock", dir, key)}
}

func (_c *MockInterface_Lock_Call) Run(run func(dir string, key tokencache.Key)) *MockInterface_Lock_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(tokencache.Key))
	})
	return _c
}

func (_c *MockInterface_Lock_Call) Return(_a0 io.Closer, _a1 error) *MockInterface_Lock_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockInterface_Lock_Call) RunAndReturn(run func(string, tokencache.Key) (io.Closer, error)) *MockInterface_Lock_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: dir, key, tokenSet
func (_m *MockInterface) Save(dir string, key tokencache.Key, tokenSet oidc.TokenSet) error {
	ret := _m.Called(dir, key, tokenSet)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, tokencache.Key, oidc.TokenSet) error); ok {
		r0 = rf(dir, key, tokenSet)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockInterface_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type MockInterface_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - dir string
//   - key tokencache.Key
//   - tokenSet oidc.TokenSet
func (_e *MockInterface_Expecter) Save(dir interface{}, key interface{}, tokenSet interface{}) *MockInterface_Save_Call {
	return &MockInterface_Save_Call{Call: _e.mock.On("Save", dir, key, tokenSet)}
}

func (_c *MockInterface_Save_Call) Run(run func(dir string, key tokencache.Key, tokenSet oidc.TokenSet)) *MockInterface_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(tokencache.Key), args[2].(oidc.TokenSet))
	})
	return _c
}

func (_c *MockInterface_Save_Call) Return(_a0 error) *MockInterface_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockInterface_Save_Call) RunAndReturn(run func(string, tokencache.Key, oidc.TokenSet) error) *MockInterface_Save_Call {
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

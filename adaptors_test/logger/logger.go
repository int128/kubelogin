package logger

import (
	"github.com/int128/kubelogin/adaptors"
)

func New(t testingLogger) *adaptors.Logger {
	return adaptors.NewLoggerWith(&bridge{t})
}

type testingLogger interface {
	Logf(format string, v ...interface{})
}

type bridge struct {
	t testingLogger
}

func (b *bridge) Printf(format string, v ...interface{}) {
	b.t.Logf(format, v...)
}

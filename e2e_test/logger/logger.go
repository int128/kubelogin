package logger

import (
	"github.com/int128/kubelogin/adaptors/logger"
)

func New(t testingLogger) *logger.Logger {
	b := &bridge{t}
	return logger.NewWith(b, b)
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

func (b *bridge) Output(calldepth int, s string) error {
	b.t.Logf("%s", s)
	return nil
}

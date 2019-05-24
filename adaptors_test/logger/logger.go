package logger

import (
	"github.com/int128/kubelogin/adaptors/logger"
)

func New(t testingLogger) *logger.Logger {
	return logger.NewLoggerWith(&bridge{t})
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

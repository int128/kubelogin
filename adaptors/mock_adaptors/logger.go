package mock_adaptors

import (
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors"
)

func NewLogger(t testingLogger, ctrl *gomock.Controller) *Logger {
	return &Logger{
		MockLogger:    NewMockLogger(ctrl),
		testingLogger: t,
	}
}

type testingLogger interface {
	Logf(format string, v ...interface{})
}

// Logger provides mock feature but overrides output methods with actual logging.
type Logger struct {
	*MockLogger
	testingLogger testingLogger
}

func (l *Logger) Printf(format string, v ...interface{}) {
	l.testingLogger.Logf(format, v...)
}

func (l *Logger) Debugf(level adaptors.LogLevel, format string, v ...interface{}) {
	l.testingLogger.Logf(format, v...)
}

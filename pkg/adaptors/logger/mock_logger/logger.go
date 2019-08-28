package mock_logger

import (
	"fmt"

	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/spf13/pflag"
)

func New(t testingLogger) *Logger {
	return &Logger{t}
}

type testingLogger interface {
	Logf(format string, v ...interface{})
}

// Logger provides logging facility using testing.T.
type Logger struct {
	t testingLogger
}

func (*Logger) AddFlags(f *pflag.FlagSet) {
	f.IntP("v", "v", 0, "dummy flag used in the tests")
}

func (l *Logger) Printf(format string, args ...interface{}) {
	l.t.Logf(format, args...)
}

type Verbose struct {
	t     testingLogger
	level int
}

func (v *Verbose) Infof(format string, args ...interface{}) {
	v.t.Logf(fmt.Sprintf("I%d] ", v.level)+format, args...)
}

func (l *Logger) V(level int) logger.Verbose {
	return &Verbose{l.t, level}
}

func (*Logger) IsEnabled(level int) bool {
	return true
}

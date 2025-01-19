package logger

import (
	"fmt"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/spf13/pflag"
)

func New(t testingLogger) *Logger {
	return &Logger{t: t}
}

type testingLogger interface {
	Logf(format string, v ...interface{})
}

// Logger provides logging facility using testing.T.
type Logger struct {
	t        testingLogger
	maxLevel int
}

func (l *Logger) AddFlags(f *pflag.FlagSet) {
	f.IntVarP(&l.maxLevel, "v", "v", 0, "dummy flag used in the tests")
}

func (l *Logger) Printf(format string, args ...interface{}) {
	l.t.Logf(format, args...)
}

func (l *Logger) V(level int) logger.Verbose {
	if l.IsEnabled(level) {
		return &verbose{l.t, level}
	}
	return &noopVerbose{}
}

func (l *Logger) IsEnabled(level int) bool {
	return level <= l.maxLevel
}

type verbose struct {
	t     testingLogger
	level int
}

func (v *verbose) Infof(format string, args ...interface{}) {
	v.t.Logf(fmt.Sprintf("I%d] ", v.level)+format, args...)
}

type noopVerbose struct{}

func (*noopVerbose) Infof(string, ...interface{}) {}

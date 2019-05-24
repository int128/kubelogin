package logger

import (
	"log"
	"os"

	"github.com/int128/kubelogin/adaptors"
)

// New returns a Logger with the standard log.Logger for messages and debug.
func New() adaptors.Logger {
	return &Logger{
		stdLogger:   log.New(os.Stderr, "", 0),
		debugLogger: log.New(os.Stderr, "", log.Ltime|log.Lmicroseconds),
	}
}

// FromStdLogger returns a Logger with the given standard log.Logger.
func FromStdLogger(l stdLogger) *Logger {
	return &Logger{
		stdLogger:   l,
		debugLogger: l,
	}
}

type stdLogger interface {
	Printf(format string, v ...interface{})
}

// Logger wraps the standard log.Logger and just provides debug level.
type Logger struct {
	stdLogger
	debugLogger stdLogger
	level       adaptors.LogLevel
}

func (l *Logger) Debugf(level adaptors.LogLevel, format string, v ...interface{}) {
	if l.IsEnabled(level) {
		l.debugLogger.Printf(format, v...)
	}
}

func (l *Logger) SetLevel(level adaptors.LogLevel) {
	l.level = level
}

func (l *Logger) IsEnabled(level adaptors.LogLevel) bool {
	return level <= l.level
}

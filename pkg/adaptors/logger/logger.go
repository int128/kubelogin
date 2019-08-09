package logger

import (
	"fmt"
	"log"
	"os"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors"
)

// Set provides an implementation and interface for Logger.
var Set = wire.NewSet(
	New,
)

// New returns a Logger with the standard log.Logger for messages and debug.
func New() adaptors.Logger {
	return &Logger{
		stdLogger:   log.New(os.Stderr, "", 0),
		debugLogger: log.New(os.Stderr, "", log.Ltime|log.Lmicroseconds|log.Lshortfile),
	}
}

func NewWith(s stdLogger, d debugLogger) *Logger {
	return &Logger{s, d, 0}
}

type stdLogger interface {
	Printf(format string, v ...interface{})
}

type debugLogger interface {
	Output(calldepth int, s string) error
}

// Logger wraps the standard log.Logger and just provides debug level.
type Logger struct {
	stdLogger
	debugLogger
	level adaptors.LogLevel
}

func (l *Logger) Debugf(level adaptors.LogLevel, format string, v ...interface{}) {
	if l.IsEnabled(level) {
		_ = l.debugLogger.Output(2, fmt.Sprintf(format, v...))
	}
}

func (l *Logger) SetLevel(level adaptors.LogLevel) {
	l.level = level
}

func (l *Logger) IsEnabled(level adaptors.LogLevel) bool {
	return level <= l.level
}

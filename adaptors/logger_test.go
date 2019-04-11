package adaptors

import (
	"fmt"
	"testing"

	"github.com/int128/kubelogin/adaptors/interfaces"
)

type mockStdLogger struct {
	count int
}

func (l *mockStdLogger) Printf(format string, v ...interface{}) {
	l.count++
}

func TestLogger_Debugf(t *testing.T) {
	for _, c := range []struct {
		loggerLevel adaptors.LogLevel
		debugfLevel adaptors.LogLevel
		count       int
	}{
		{0, 0, 1},
		{0, 1, 0},

		{1, 0, 1},
		{1, 1, 1},
		{1, 2, 0},

		{2, 1, 1},
		{2, 2, 1},
		{2, 3, 0},
	} {
		t.Run(fmt.Sprintf("%+v", c), func(t *testing.T) {
			m := &mockStdLogger{}
			l := &Logger{debugLogger: m, level: c.loggerLevel}
			l.Debugf(c.debugfLevel, "hello")
			if m.count != c.count {
				t.Errorf("count wants %d but %d", c.count, m.count)
			}
		})
	}
}

func TestLogger_Printf(t *testing.T) {
	m := &mockStdLogger{}
	l := &Logger{stdLogger: m}
	l.Printf("hello")
	if m.count != 1 {
		t.Errorf("count wants %d but %d", 1, m.count)
	}
}

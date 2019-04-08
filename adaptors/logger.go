package adaptors

import "log"

type Logger struct{}

func (*Logger) Logf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

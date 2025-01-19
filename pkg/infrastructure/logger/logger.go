package logger

import (
	"flag"
	"log"
	"os"

	"github.com/google/wire"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

// Set provides an implementation and interface for Logger.
var Set = wire.NewSet(
	New,
)

// New returns a Logger with the standard log.Logger and klog.
func New() Interface {
	return &Logger{
		goLogger: log.New(os.Stderr, "", 0),
	}
}

type Interface interface {
	AddFlags(f *pflag.FlagSet)
	Printf(format string, args ...interface{})
	V(level int) Verbose
	IsEnabled(level int) bool
}

type Verbose interface {
	Infof(format string, args ...interface{})
}

type goLogger interface {
	Printf(format string, v ...interface{})
}

// Logger provides logging facility using log.Logger and klog.
type Logger struct {
	goLogger
}

// AddFlags adds the flags such as -v.
func (*Logger) AddFlags(f *pflag.FlagSet) {
	gf := flag.NewFlagSet("", flag.ContinueOnError)
	klog.InitFlags(gf)
	f.AddGoFlagSet(gf)
}

// V returns a logger enabled only if the level is enabled.
func (*Logger) V(level int) Verbose {
	return klog.V(klog.Level(level))
}

// IsEnabled returns true if the level is enabled.
func (*Logger) IsEnabled(level int) bool {
	return klog.V(klog.Level(level)).Enabled()
}

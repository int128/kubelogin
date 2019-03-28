package adaptors

import (
	"context"
	"fmt"
	"os"

	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

const usage = `Help:

Usage: %s [options]

  This updates kubeconfig for Kubernetes OpenID Connect (OIDC) authentication.

Options:
%s`

const (
	envInsecure        = "KUBELOGIN_INSECURE_SKIP_TLS_VERIFY"
	envListenPort      = "KUBELOGIN_LISTEN_PORT"
	envSkipOpenBrowser = "KUBELOGIN_SKIP_OPEN_BROWSER"
)

const (
	flagListenPort      = "listen-port"
	flagSkipOpenBrowser = "skip-open-browser"
)

type Cmd struct {
	Login usecases.Login
}

func (c *Cmd) Run(ctx context.Context, args []string) int {
	f := pflag.NewFlagSet(args[0], pflag.ContinueOnError)
	f.SortFlags = false
	f.Usage = func() {
		klog.Infof(usage, args[0], f.FlagUsages())
	}

	var o cmdOptions
	f.IntVar(&o.ListenPort, flagListenPort, 8000, "Port used by kubelogin to bind its server")
	f.BoolVar(&o.SkipOpenBrowser, flagSkipOpenBrowser, false, "If true, it does not open the browser on authentication")
	o.ConfigFlags = genericclioptions.NewConfigFlags()
	o.ConfigFlags.AddFlags(f)
	appendFlagEnvUsage(f.Lookup(clientcmd.RecommendedConfigPathFlag), clientcmd.RecommendedConfigPathEnvVar)
	appendFlagEnvUsage(f.Lookup(clientcmd.FlagInsecure), envInsecure)
	appendFlagEnvUsage(f.Lookup(flagListenPort), envListenPort)
	appendFlagEnvUsage(f.Lookup(flagSkipOpenBrowser), envSkipOpenBrowser)

	if err := f.Parse(args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		klog.Errorf("Invalid arguments: %s", err)
		return 1
	}
	if len(f.Args()) > 0 {
		klog.Errorf("Too many arguments")
		return 1
	}
	if err := setEnvValueIfNotChanged(f.Lookup(clientcmd.FlagInsecure), envInsecure); err != nil {
		klog.Errorf("Invalid environment variable: %s", err)
		return 1
	}
	if err := setEnvValueIfNotChanged(f.Lookup(flagListenPort), envListenPort); err != nil {
		klog.Errorf("Invalid environment variable: %s", err)
		return 1
	}
	if err := setEnvValueIfNotChanged(f.Lookup(flagSkipOpenBrowser), envSkipOpenBrowser); err != nil {
		klog.Errorf("Invalid environment variable: %s", err)
		return 1
	}

	loader := o.ConfigFlags.ToRawKubeConfigLoader()
	cfg, err := loader.RawConfig()
	if err != nil {
		klog.Errorf("Could not load kubeconfig: %s", err)
		return 1
	}

	if err := c.Login.Do(ctx, usecases.LoginIn{
		Config:          cfg,
		ConfigPath:      loader.ConfigAccess().GetDefaultFilename(),
		SkipTLSVerify:   *o.ConfigFlags.Insecure,
		SkipOpenBrowser: o.SkipOpenBrowser,
		ListenPort:      o.ListenPort,
	}); err != nil {
		klog.Errorf("Error: %s", err)
		return 1
	}
	return 0
}

type cmdOptions struct {
	ConfigFlags     *genericclioptions.ConfigFlags
	SkipOpenBrowser bool
	ListenPort      int
}

func appendFlagEnvUsage(f *pflag.Flag, key string) {
	f.Usage = fmt.Sprintf("%s [$%s]", f.Usage, key)
}

func setEnvValueIfNotChanged(f *pflag.Flag, key string) error {
	if !f.Changed {
		v := os.Getenv(key)
		if v != "" {
			if err := f.Value.Set(v); err != nil {
				return errors.Wrapf(err, "error while setting flag %s from $%s", f.Name, key)
			}
		}
	}
	return nil
}

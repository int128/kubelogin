package adaptors

import (
	"context"
	"strconv"
	"strings"

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/pflag"
	"go.uber.org/dig"
)

const usage = `Login to the OpenID Connect provider and update the kubeconfig.
kubelogin %[2]s

Examples:
  # Login to the current provider and update ~/.kube/config
  %[1]s

Options:
%[3]s
  As well as you can set the following environment variables:
      $KUBECONFIG
      $KUBELOGIN_LISTEN_PORT

Usage:
  %[1]s [options]`

const (
	envKubeConfig = "KUBECONFIG"
	envListenPort = "KUBELOGIN_LISTEN_PORT"
)

func NewCmd(i Cmd) adaptors.Cmd {
	return &i
}

type Cmd struct {
	dig.In
	Login  usecases.Login
	Env    adaptors.Env
	Logger adaptors.Logger
}

func (cmd *Cmd) Run(ctx context.Context, args []string, version string) int {
	executable := executableName(args[0])
	f := pflag.NewFlagSet(executable, pflag.ContinueOnError)
	f.SortFlags = false
	f.Usage = func() {
		cmd.Logger.Printf(usage, executable, version, f.FlagUsages())
	}
	var o cmdOptions
	f.StringVar(&o.KubeConfig, "kubeconfig", cmd.defaultKubeConfig(), "Path to the kubeconfig file")
	f.StringVar(&o.KubeContext, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.KubeUser, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.IntVar(&o.ListenPort, "listen-port", cmd.defaultListenPort(), "Port used by kubelogin to bind its local server")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	f.IntVarP(&o.Verbose, "v", "v", 0, "If set to 1 or greater, it shows debug log")

	if err := f.Parse(args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		cmd.Logger.Printf("Error: invalid arguments: %s", err)
		return 1
	}
	if len(f.Args()) > 0 {
		cmd.Logger.Printf("Error: too many arguments")
		return 1
	}

	cmd.Logger.SetLevel(adaptors.LogLevel(o.Verbose))
	in := usecases.LoginIn{
		KubeConfigFilename: o.KubeConfig,
		KubeContextName:    o.KubeContext,
		KubeUserName:       o.KubeUser,
		ListenPort:         o.ListenPort,
		SkipTLSVerify:      o.SkipTLSVerify,
		SkipOpenBrowser:    o.SkipOpenBrowser,
	}
	if err := cmd.Login.Do(ctx, in); err != nil {
		cmd.Logger.Printf("Error: %s", err)
		return 1
	}
	return 0
}

func (cmd *Cmd) defaultKubeConfig() string {
	if v := cmd.Env.Getenv(envKubeConfig); v != "" {
		return v
	}
	c, err := homedir.Expand("~/.kube/config")
	if err != nil {
		cmd.Logger.Debugf(1, "Error: could not determine the home directory: %s", err)
		return ""
	}
	return c
}

func (cmd *Cmd) defaultListenPort() int {
	if v := cmd.Env.Getenv(envListenPort); v != "" {
		i, err := strconv.Atoi(v)
		if err != nil {
			cmd.Logger.Printf("Error: invalid $%s: %s", envListenPort, err)
			return 8000
		}
		return i
	}
	return 8000
}

type cmdOptions struct {
	KubeConfig      string
	KubeContext     string
	KubeUser        string
	SkipTLSVerify   bool
	ListenPort      int
	SkipOpenBrowser bool
	Verbose         int
}

func executableName(arg0 string) string {
	if strings.HasPrefix(arg0, "kubectl-") {
		return strings.ReplaceAll(strings.ReplaceAll(arg0, "-", " "), "_", "-")
	}
	return arg0
}

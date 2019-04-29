package adaptors

import (
	"context"
	"strconv"
	"strings"

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/int128/kubelogin/usecases/interfaces"
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
	f.StringVar(&o.KubeConfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.KubeContext, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.KubeUser, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.IntVar(&o.ListenPort, "listen-port", cmd.defaultListenPort(), "Port used by kubelogin to bind its local server")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
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
		KubeConfigFilename:           o.KubeConfig,
		KubeContextName:              kubeconfig.ContextName(o.KubeContext),
		KubeUserName:                 kubeconfig.UserName(o.KubeUser),
		CertificateAuthorityFilename: o.CertificateAuthority,
		SkipTLSVerify:                o.SkipTLSVerify,
		ListenPort:                   o.ListenPort,
		SkipOpenBrowser:              o.SkipOpenBrowser,
	}
	if err := cmd.Login.Do(ctx, in); err != nil {
		cmd.Logger.Printf("Error: %s", err)
		return 1
	}
	return 0
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
	KubeConfig           string
	KubeContext          string
	KubeUser             string
	CertificateAuthority string
	SkipTLSVerify        bool
	ListenPort           int
	SkipOpenBrowser      bool
	Verbose              int
}

func executableName(arg0 string) string {
	if strings.HasPrefix(arg0, "kubectl-") {
		return strings.ReplaceAll(strings.ReplaceAll(arg0, "-", " "), "_", "-")
	}
	return arg0
}

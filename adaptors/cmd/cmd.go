package cmd

import (
	"context"
	"strings"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/spf13/pflag"
)

const usage = `Login to the OpenID Connect provider and update the kubeconfig.
kubelogin %[2]s

Examples:
  # Login to the provider using authorization code grant.
  %[1]s

  # Login to the provider using resource owner password credentials grant.
  %[1]s --username USERNAME --password PASSWORD

Options:
%[3]s
Usage:
  %[1]s [options]`

var defaultListenPort = []int{8000, 18000}

type Cmd struct {
	Login  usecases.Login
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
	f.StringVar(&o.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.Context, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.User, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.IntSliceVar(&o.ListenPort, "listen-port", defaultListenPort, "Port to bind to the local server. If multiple ports are given, it will try the ports in order")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.Username, "username", "", "If set, perform the resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "If set, use the password instead of asking it")
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
		KubeconfigFilename: o.Kubeconfig,
		KubeconfigContext:  kubeconfig.ContextName(o.Context),
		KubeconfigUser:     kubeconfig.UserName(o.User),
		CACertFilename:     o.CertificateAuthority,
		SkipTLSVerify:      o.SkipTLSVerify,
		ListenPort:         o.ListenPort,
		SkipOpenBrowser:    o.SkipOpenBrowser,
		Username:           o.Username,
		Password:           o.Password,
	}
	if err := cmd.Login.Do(ctx, in); err != nil {
		cmd.Logger.Printf("Error: %s", err)
		return 1
	}
	return 0
}

type cmdOptions struct {
	Kubeconfig           string
	Context              string
	User                 string
	ListenPort           []int
	SkipOpenBrowser      bool
	Username             string
	Password             string
	CertificateAuthority string
	SkipTLSVerify        bool
	Verbose              int
}

func executableName(arg0 string) string {
	if strings.HasPrefix(arg0, "kubectl-") {
		return strings.ReplaceAll(strings.ReplaceAll(arg0, "-", " "), "_", "-")
	}
	return arg0
}

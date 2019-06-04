package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const examples = `  # Login to the provider using authorization code grant.
  %[1]s

  # Login to the provider using resource owner password credentials grant.
  %[1]s --username USERNAME --password PASSWORD`

var defaultListenPort = []int{8000, 18000}

type Cmd struct {
	Login  usecases.Login
	Logger adaptors.Logger
}

func (cmd *Cmd) Run(ctx context.Context, args []string, version string) int {
	executable := executableName(args[0])
	var o struct {
		kubectlOptions
		kubeloginOptions
	}
	rootCmd := cobra.Command{
		Use:     executable,
		Short:   fmt.Sprintf("Login to the OpenID Connect provider and update the kubeconfig (%s %s)", executable, version),
		Example: fmt.Sprintf(examples, executable),
		Args:    cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
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
			return cmd.Login.Do(ctx, in)
		},
	}
	o.kubectlOptions.register(rootCmd.Flags())
	o.kubeloginOptions.register(rootCmd.Flags())

	rootCmd.SetArgs(args[1:])
	if err := rootCmd.Execute(); err != nil {
		cmd.Logger.Printf("Error: %s", err)
		return 1
	}
	return 0
}

type kubectlOptions struct {
	Kubeconfig           string
	Context              string
	User                 string
	CertificateAuthority string
	SkipTLSVerify        bool
	Verbose              int
}

func (o *kubectlOptions) register(f *pflag.FlagSet) {
	f.StringVar(&o.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.Context, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.User, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	f.IntVarP(&o.Verbose, "v", "v", 0, "If set to 1 or greater, it shows debug log")
}

type kubeloginOptions struct {
	ListenPort      []int
	SkipOpenBrowser bool
	Username        string
	Password        string
}

func (o *kubeloginOptions) register(f *pflag.FlagSet) {
	f.IntSliceVar(&o.ListenPort, "listen-port", defaultListenPort, "Port to bind to the local server. If multiple ports are given, it will try the ports in order")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.Username, "username", "", "If set, perform the resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "If set, use the password instead of asking it")
}

func executableName(arg0 string) string {
	base := filepath.Base(arg0)
	if strings.HasPrefix(base, "kubectl-") {
		return strings.ReplaceAll(strings.ReplaceAll(base, "-", " "), "_", "-")
	}
	return base
}

package cmd

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

const longDescription = `Login to the OpenID Connect provider.

You need to set up the OIDC provider, role binding, Kubernetes API server and kubeconfig.
Run the following command to show the setup instruction:

	kubectl oidc-login setup

See https://github.com/int128/kubelogin for more.
`

// rootOptions represents the options for the root command.
type rootOptions struct {
	Kubeconfig           string
	Context              string
	User                 string
	ListenPort           []int
	SkipOpenBrowser      bool
	Username             string
	Password             string
	CertificateAuthority string
	SkipTLSVerify        bool
}

func (o *rootOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.StringVar(&o.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.Context, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.User, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.IntSliceVar(&o.ListenPort, "listen-port", defaultListenPort, "Port to bind to the local server. If multiple ports are given, it will try the ports in order")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.Username, "username", "", "If set, perform the resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "If set, use the password instead of asking it")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
}

type Root struct {
	Standalone standalone.Interface
	Logger     logger.Interface
}

func (cmd *Root) New(ctx context.Context, executable string) *cobra.Command {
	var o rootOptions
	rootCmd := &cobra.Command{
		Use:   executable,
		Short: "Login to the OpenID Connect provider",
		Long:  longDescription,
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			in := standalone.Input{
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
			if err := cmd.Standalone.Do(ctx, in); err != nil {
				return xerrors.Errorf("error: %w", err)
			}
			return nil
		},
	}
	o.register(rootCmd.Flags())
	cmd.Logger.AddFlags(rootCmd.PersistentFlags())
	return rootCmd
}

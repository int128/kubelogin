package cmd

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
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
	Kubeconfig            string
	Context               string
	User                  string
	CertificateAuthority  string
	SkipTLSVerify         bool
	authenticationOptions authenticationOptions
}

func (o *rootOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.StringVar(&o.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.Context, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.User, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	o.authenticationOptions.register(f)
}

type authenticationOptions struct {
	GrantType       string
	ListenPort      []int
	SkipOpenBrowser bool
	Username        string
	Password        string
}

func (o *authenticationOptions) register(f *pflag.FlagSet) {
	f.StringVar(&o.GrantType, "grant-type", "auto", "The authorization grant type to use. One of (auto|authcode|password)")
	f.IntSliceVar(&o.ListenPort, "listen-port", defaultListenPort, "Port to bind to the local server. If multiple ports are given, it will try the ports in order")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.Username, "username", "", "If set, perform the resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "If set, use the password instead of asking it")
}

func (o *authenticationOptions) toUseCaseOptions() (*authentication.AuthCodeOption, *authentication.ROPCOption, error) {
	if o.GrantType == "authcode" || (o.GrantType == "auto" && o.Username == "") {
		return &authentication.AuthCodeOption{
			BindAddress:     translateListenPortToBindAddress(o.ListenPort),
			SkipOpenBrowser: o.SkipOpenBrowser,
		}, nil, nil
	}
	if o.GrantType == "password" || (o.GrantType == "auto" && o.Username != "") {
		return nil, &authentication.ROPCOption{
			Username: o.Username,
			Password: o.Password,
		}, nil
	}
	return nil, nil, xerrors.Errorf("grant-type must be one of (auto|authcode|password)")
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
			authCodeOption, ropcOption, err := o.authenticationOptions.toUseCaseOptions()
			if err != nil {
				return xerrors.Errorf("invalid option: %w", err)
			}
			in := standalone.Input{
				KubeconfigFilename: o.Kubeconfig,
				KubeconfigContext:  kubeconfig.ContextName(o.Context),
				KubeconfigUser:     kubeconfig.UserName(o.User),
				CACertFilename:     o.CertificateAuthority,
				SkipTLSVerify:      o.SkipTLSVerify,
				AuthCodeOption:     authCodeOption,
				ROPCOption:         ropcOption,
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

package cmd

import (
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
	Kubeconfig            string
	Context               string
	User                  string
	CertificateAuthority  string
	SkipTLSVerify         bool
	authenticationOptions authenticationOptions
}

func (o *rootOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.Context, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.User, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	o.authenticationOptions.addFlags(f)
}

type Root struct {
	Standalone standalone.Interface
	Logger     logger.Interface
}

func (cmd *Root) New() *cobra.Command {
	var o rootOptions
	c := &cobra.Command{
		Use:   "kubelogin",
		Short: "Login to the OpenID Connect provider",
		Long:  longDescription,
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			grantOptionSet, err := o.authenticationOptions.grantOptionSet()
			if err != nil {
				return xerrors.Errorf("invalid option: %w", err)
			}
			in := standalone.Input{
				KubeconfigFilename: o.Kubeconfig,
				KubeconfigContext:  kubeconfig.ContextName(o.Context),
				KubeconfigUser:     kubeconfig.UserName(o.User),
				CACertFilename:     o.CertificateAuthority,
				SkipTLSVerify:      o.SkipTLSVerify,
				GrantOptionSet:     grantOptionSet,
			}
			if err := cmd.Standalone.Do(c.Context(), in); err != nil {
				return xerrors.Errorf("login: %w", err)
			}
			return nil
		},
	}
	c.Flags().SortFlags = false
	o.addFlags(c.Flags())
	cmd.Logger.AddFlags(c.PersistentFlags())
	return c
}
